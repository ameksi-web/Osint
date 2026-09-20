"""Асинхронный HTTP-клиент OsintX.

Возможности:
  * ретраи с экспоненциальной задержкой на 429/5xx и сетевые ошибки;
  * лимит одновременных запросов на хост (вежливость к источникам);
  * свой User-Agent, опциональный прокси;
  * статистика: сколько запросов сделано, сколько упало, объём трафика;
  * корректное РАЗЛИЧЕНИЕ «404 = не найдено» и «сайт заблокировал нас» —
    это критично, чтобы не выдавать ошибку за результат.
"""
from __future__ import annotations

import asyncio
import random
import ssl
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..config import Settings, get_settings

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

BLOCK_MARKERS = (
    "captcha", "cf-challenge", "cf_chl", "checking your browser", "are you a human",
    "unusual traffic", "access denied", "just a moment", "attention required",
    "проверка безопасности", "подтвердите, что вы не робот", "ddos-guard", "cloudflare",
    "enable javascript and cookies", "request blocked", "bot detection",
    "client challenge", "cf-please-wait", "ddos protection by", "please verify you are a human",
    "access to this page has been denied", "your request has been blocked", "captcha-delivery",
    "verify you are human", "проверка, что вы не робот", "suspicious activity",
)


@dataclass
class Stats:
    requests: int = 0
    ok: int = 0
    errors: int = 0
    blocked: int = 0
    bytes: int = 0
    by_host: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self) -> dict[str, Any]:
        return {"requests": self.requests, "ok": self.ok, "errors": self.errors,
                "blocked": self.blocked, "bytes": self.bytes, "hosts": len(self.by_host)}


class Response:
    """Обёртка над httpx.Response + наши метки."""

    def __init__(self, resp: httpx.Response | None, *, url: str, error: str = "",
                 latency_ms: int = 0, blocked: bool = False):
        self._resp = resp
        self.url = str(resp.url) if resp is not None else url
        self.error = error
        self.latency_ms = latency_ms
        self.blocked = blocked

    @property
    def status_code(self) -> int:
        return self._resp.status_code if self._resp is not None else 0

    @property
    def text(self) -> str:
        if self._resp is None:
            return ""
        try:
            return self._resp.text
        except Exception:  # pragma: no cover - экзотические кодировки
            return self._resp.content.decode("utf-8", "ignore")

    @property
    def headers(self) -> httpx.Headers:
        return self._resp.headers if self._resp is not None else httpx.Headers()

    @property
    def history(self):
        return getattr(self._resp, "history", []) if self._resp is not None else []

    @property
    def ok(self) -> bool:
        return self._resp is not None and 200 <= self.status_code < 400

    def json(self) -> Any:
        if self._resp is None:
            return None
        try:
            return self._resp.json()
        except Exception:
            return None

    def snippet(self, limit: int = 300) -> str:
        text = " ".join(self.text.split())
        return text[:limit]

    def looks_blocked(self) -> bool:
        if self.blocked:
            return True
        if self.status_code in (403, 429, 503, 999, 1020):
            return True
        low = self.text[:6000].lower()
        return any(m in low for m in BLOCK_MARKERS)


class HttpClient:
    """Общий async HTTP-клиент на весь процесс поиска."""

    def __init__(self, settings: Settings | None = None, *, timeout: float | None = None,
                 concurrency: int | None = None, client: httpx.AsyncClient | None = None):
        self.settings = settings or get_settings()
        self.timeout = timeout or self.settings.timeout
        self.sem = asyncio.Semaphore(concurrency or self.settings.concurrency)
        self.host_sem: dict[str, asyncio.Semaphore] = {}
        self.host_limit = 6
        self.stats = Stats()
        self._lock = asyncio.Lock()
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=min(10.0, self.timeout)),
            follow_redirects=True,
            verify=self._tls_verify(),
            proxy=self.settings.proxy or None,
            limits=httpx.Limits(max_connections=max(20, self.settings.concurrency * 2),
                                max_keepalive_connections=20),
            headers=self._base_headers(),
        )

    def _tls_verify(self):
        """True (certifi) или SSLContext с системными корнями (корп. прокси/песочницы)."""
        if not self.settings.verify_tls:
            return False
        if self.settings.ca_bundle:
            try:
                return ssl.create_default_context(cafile=self.settings.ca_bundle)
            except Exception:
                return True
        return True

    def _base_headers(self) -> dict[str, str]:
        ua = self.settings.user_agent or random.choice(DEFAULT_UAS)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
        }

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self.host_sem:
            self.host_sem[host] = asyncio.Semaphore(self.host_limit)
        return self.host_sem[host]

    async def request(self, method: str, url: str, *, retries: int = 2, follow_redirects: bool | None = None,
                      headers: dict[str, str] | None = None, params: dict | None = None,
                      data: dict | str | None = None, json: dict | None = None,
                      timeout: float | None = None, allow_redirects: bool | None = None,
                      **kwargs) -> Response:
        host = httpx.URL(url).host or "unknown"
        attempt = 0
        last_error = ""
        start = time.perf_counter()
        follow = follow_redirects if follow_redirects is not None else (allow_redirects if allow_redirects is not None else True)
        while attempt <= retries:
            attempt += 1
            try:
                async with self.sem, self._host_sem(host):
                    async with self._lock:
                        self.stats.requests += 1
                        self.stats.by_host[host] += 1
                    resp = await self._client.request(
                        method.upper(), url, headers=headers, params=params, data=data, json=json,
                        timeout=timeout or self.timeout, follow_redirects=follow, **kwargs)
                latency = int((time.perf_counter() - start) * 1000)
                async with self._lock:
                    self.stats.bytes += len(resp.content or b"")
                wrapped = Response(resp, url=url, latency_ms=latency)
                if wrapped.looks_blocked():
                    async with self._lock:
                        self.stats.blocked += 1
                else:
                    async with self._lock:
                        self.stats.ok += 1
                if resp.status_code in (429, 500, 502, 503, 504) and attempt <= retries:
                    await asyncio.sleep(min(2 ** attempt * 0.6, 6) + random.random() * 0.4)
                    continue
                return wrapped
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError,
                    httpx.NetworkError, httpx.ProxyError, httpx.TooManyRedirects, httpx.HTTPError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"[:300]
                if attempt <= retries:
                    await asyncio.sleep(min(2 ** attempt * 0.5, 5) + random.random() * 0.3)
                    continue
            except Exception as exc:  # pragma: no cover - непредвиденное
                last_error = f"{type(exc).__name__}: {exc}"[:300]
                break
        async with self._lock:
            self.stats.errors += 1
        latency = int((time.perf_counter() - start) * 1000)
        return Response(None, url=url, error=last_error or "request failed", latency_ms=latency)

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw) -> Response:
        kw.setdefault("follow_redirects", True)
        return await self.request("HEAD", url, **kw)

    async def check_reachable(self, url: str, timeout: float = 8.0) -> tuple[bool, str]:
        """Быстрая проверка доступности хоста (для команды doctor)."""
        resp = await self.get(url, retries=1, timeout=timeout)
        if resp.error:
            return False, resp.error
        return True, f"HTTP {resp.status_code}"
