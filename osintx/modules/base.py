"""Базовый класс модулей и универсальный «проверяльщик источников».

Любой сайт из реестра проверяется одной из стратегий:

  status_code      — есть/нет по HTTP-коду (404 = не найден)
  message_exclude  — найден, ЕСЛИ в теле НЕТ ни одной строки из ``not_found_msgs``
  message_include  — найден, ЕСЛИ в теле ЕСТЬ строка из ``found_msgs``
  json_path        — найден, ЕСЛИ значение по JSON-пути удовлетворяет условию
  regex            — найден по регулярке
  redirect         — найден, если редирект отличается от ожидаемого «нет»

Отдельно определяется БЛОКИРОВКА (Cloudflare/captcha/403/429/1020): такие
ответы никогда не превращаются в «найден» или «не найден», а помечаются
как ``blocked`` — иначе отчёт был бы фейковым.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re as _re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import quote, quote_plus

from ..config import Settings
from ..core.http import HttpClient, Response
from ..core.models import Finding, ModuleResult, SourceStatus
from ..core.store import Store

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


async def _noop(_: dict[str, Any]) -> None:
    return None


@dataclass
class Context:
    """Общий контекст выполнения: клиент, хранилище, опции, поток событий."""
    settings: Settings
    http: HttpClient
    store: Store
    options: dict[str, Any] = field(default_factory=dict)
    emit: EmitFn = _noop
    cancel_event: asyncio.Event | None = None

    @property
    def deep(self) -> bool:
        return bool(self.options.get("deep"))

    @property
    def use_keys(self) -> bool:
        return self.options.get("use_keys", True)

    def key(self, name: str) -> str:
        return self.settings.key(name) if self.use_keys else ""

    async def notify(self, **payload: Any) -> None:
        try:
            await self.emit(payload)
        except Exception:
            pass

    def cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())


class Module:
    name: str = "module"
    title: str = "Модуль"
    categories: tuple[str, ...] = ()
    target_types: tuple[str, ...] = ()

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:  # pragma: no cover
        raise NotImplementedError

    # --------------------------- утилиты ---------------------------
    @staticmethod
    def add_finding(result: ModuleResult, **kw: Any) -> Finding:
        finding = Finding(**kw)
        result.findings.append(finding)
        return finding

    @staticmethod
    def add_status(result: ModuleResult, status: SourceStatus) -> None:
        result.statuses.append(status)


def render_url(site: dict[str, Any], target: str, extra: dict[str, str] | None = None) -> str:
    """Подставляет цель в шаблон URL/данные источника."""
    email = target
    phone_digits = "".join(ch for ch in target if ch.isdigit())
    mapping = {
        "username": target.lstrip("@"),
        "user": target.lstrip("@"),
        "email": email,
        "email_url": quote(email, safe=""),
        "email_plus": quote_plus(email),
        "email_hash": hashlib.md5(email.strip().lower().encode()).hexdigest(),
        "email_local": email.split("@")[0] if "@" in email else email,
        "email_domain": email.split("@")[-1] if "@" in email else "",
        "phone": target,
        "phone_digits": phone_digits,
        "phone_e164": target if target.startswith("+") else f"+{phone_digits}",
        "phone_no_plus": phone_digits,
        "domain": target.lower(),
        "ip": target,
        "query": quote_plus(target),
        "target": target,
    }
    if extra:
        mapping.update(extra)
    template = site.get("url", "")
    try:
        return template.format(**mapping)
    except (KeyError, IndexError):
        # неизвестный плейсхолдер — подставляем что можем, остальное вырезаем
        out = template
        for k, v in mapping.items():
            out = out.replace("{" + k + "}", str(v))
        return _re.sub(r"\{[^}]+\}", "", out)


def _dig(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def evaluate(site: dict[str, Any], resp: Response) -> tuple[str, str]:
    """Возвращает (status, evidence): found | not_found | blocked | error."""
    if resp.error:
        return "error", resp.error
    if resp.looks_blocked():
        return "blocked", f"HTTP {resp.status_code}: сайт вернул страницу-заглушку/капчу"

    strategy = site.get("strategy", "status_code")
    body = resp.text
    code = resp.status_code

    if strategy == "status_code":
        found_codes = site.get("found_codes", [200])
        if code in found_codes:
            return "found", f"HTTP {code} ∈ {found_codes}"
        if code in site.get("not_found_codes", [404, 410]):
            return "not_found", f"HTTP {code} (профиль отсутствует)"
        if code in (401, 403, 429):
            return "blocked", f"HTTP {code}"
        if code >= 500:
            return "error", f"HTTP {code}"
        return "not_found", f"HTTP {code} вне списка найденных кодов"

    if strategy in ("message_exclude", "message"):
        needles = site.get("not_found_msgs", [])
        if any(n.lower() in body.lower() for n in needles):
            hit = next(n for n in needles if n.lower() in body.lower())
            return "not_found", f"в ответе есть «{hit}»"
        if code == 404:
            return "not_found", "HTTP 404"
        if code >= 400:
            return "error", f"HTTP {code} и нет маркеров «не найден»"
        return "found", "нет маркеров «не найден»"

    if strategy == "message_include":
        needles = site.get("found_msgs", [])
        for n in needles:
            if n.lower() in body.lower():
                return "found", f"в ответе есть «{n}»"
        return "not_found", "нет маркеров «найден»"

    if strategy == "regex":
        pattern = site.get("pattern", "")
        m = _re.search(pattern, body, _re.MULTILINE | _re.DOTALL)
        return ("found", f"совпало с /{pattern}/: {m.group(0)[:80]}") if m else ("not_found", "регексп не совпал")

    if strategy == "json_path":
        spec = site.get("json_found", {})
        path = spec.get("path", "")
        data = resp.json()
        if data is None:
            return ("error", "ответ не JSON") if body.strip() else ("not_found", "пустой ответ")
        value = _dig(data, path) if path else data
        op = spec.get("op", "exists")
        expected = spec.get("value")
        ok = False
        if op == "exists":
            ok = bool(value)
        elif op == "exists_strict":
            ok = value is not None
        elif op == "equals":
            ok = value == expected
        elif op == "not_equals":
            ok = value != expected
        elif op == "contains":
            ok = isinstance(value, (str, list)) and any(str(x).lower() == str(expected).lower()
                                                         if isinstance(value, list) else str(expected).lower() in str(value).lower()
                                                         for x in ([value] if isinstance(value, str) else value))
        elif op == "empty":
            ok = not value
        elif op == "non_empty":
            ok = bool(value)
        return (("found" if ok else "not_found"),
                f"{path or '<root>'} = {json.dumps(value, ensure_ascii=False)[:120]} (op={op})")

    if strategy == "redirect":
        bad = site.get("not_found_redirect", "")
        final = str(resp.url)
        if bad and bad in final:
            return "not_found", f"редирект на {final}"
        return ("found", f"финальный URL {final}") if resp.ok else ("not_found", f"HTTP {code}")

    if strategy == "unsupported":
        return "unsupported", site.get("note", "источник не даёт достоверного признака")

    return "error", f"неизвестная стратегия {strategy}"


class SiteChecker:
    """Проверяет список сайтов параллельно и превращает результат в находки."""

    def __init__(self, ctx: Context, category: str):
        self.ctx = ctx
        self.category = category

    async def check_one(self, site: dict[str, Any], target: str,
                        extra: dict[str, str] | None = None) -> tuple[SourceStatus, dict[str, Any] | None]:
        url = render_url(site, target, extra)
        method = site.get("method", "GET").upper()
        payload = site.get("payload") or site.get("data")
        json_body = site.get("json_body")
        headers = dict(site.get("headers", {}))
        params = None
        if site.get("params"):
            params = {k: render_url({"url": str(v)}, target, extra) for k, v in site["params"].items()}
        if payload:
            payload = {k: render_url({"url": v}, target, extra) for k, v in payload.items()} \
                if isinstance(payload, dict) else str(payload).format(target=target)
        if json_body:
            raw = json.dumps(json_body).replace("{target}", target).replace("{email}", target)
            json_body = json.loads(raw)
        started = time.perf_counter()
        resp = await self.ctx.http.request(
            method, url, headers=headers or None, data=payload, json=json_body, params=params,
            follow_redirects=site.get("follow_redirects", True), retries=site.get("retries", 2),
            timeout=site.get("timeout"),
        )
        latency = int((time.perf_counter() - started) * 1000)
        status, evidence = evaluate(site, resp)
        if self.ctx.cancelled():
            status = "skipped"
        st = SourceStatus(source=site["name"], category=self.category, status=status,  # type: ignore[arg-type]
                          url=url, http_code=resp.status_code or None, latency_ms=latency,
                          error=resp.error, detail=evidence)
        if status == "found":
            return st, {"url": resp.url if resp._resp is not None else url, "evidence": evidence,
                        "http_code": resp.status_code, "site": site, "latency_ms": latency,
                        "body": resp.text if site.get("store_body") else ""}
        if status in ("not_found", "blocked", "error", "unsupported"):
            self.ctx.store.save_site_health(site["name"], self.category, status, resp.status_code or None, evidence)
        return st, None

    async def check_many(self, sites: list[dict[str, Any]], target: str, result: ModuleResult,
                         *, extra: dict[str, str] | None = None,
                         on_found: Callable[[dict[str, Any], dict[str, Any]], None] | None = None) -> int:
        """Проверяет пачку сайтов, наполняя result. Возвращает число находок."""
        max_concurrency = 25 if not self.ctx.deep else 12
        sem = asyncio.Semaphore(max_concurrency)
        found_counter = 0
        lock = asyncio.Lock()

        async def worker(site: dict[str, Any]) -> None:
            nonlocal found_counter
            if self.ctx.cancelled():
                return
            async with sem:
                try:
                    st, hit = await self.check_one(site, target, extra)
                except Exception as exc:  # модуль не должен падать целиком
                    st, hit = SourceStatus(source=site.get("name", "?"), category=self.category,
                                           status="error", error=f"{type(exc).__name__}: {exc}"[:200]), None
                async with lock:
                    result.statuses.append(st)
                    if hit:
                        found_counter += 1
                        if on_found:
                            on_found(hit, site)
                        await self.ctx.notify(kind="hit", source=site["name"], url=st.url,
                                              detail=st.detail, target=target)

        await asyncio.gather(*(worker(s) for s in sites))
        return found_counter


def make_finding(site: dict[str, Any], target: str, hit: dict[str, Any], *, category: str,
                 title: str | None = None, kind: str | None = None,
                 data: dict[str, Any] | None = None, confidence: str | None = None) -> Finding:
    return Finding(
        source=site["name"],
        category=category,
        kind=kind or site.get("kind", "account"),
        title=title or site.get("title") or f"{site['name']}: аккаунт найден",
        url=str(hit.get("url", "")),
        value=target,
        data={**(site.get("meta") or {}), **(data or {})},
        confidence=(confidence or site.get("confidence", "medium")),  # type: ignore[arg-type]
        evidence=hit.get("evidence", ""),
        http_code=hit.get("http_code"),
        tags=list(site.get("tags", [])),
    )


# ─────────────────────────── сборка графа сущностей ───────────────────────────
def add_entity(result: ModuleResult, etype: str, value: str, **meta: Any) -> None:
    result.meta.setdefault("entities", []).append({"type": etype, "value": value, "meta": meta})


def add_edge(result: ModuleResult, src: str, dst: str, relation: str,
             weight: float = 1.0, evidence: str = "") -> None:
    result.meta.setdefault("edges", []).append(
        {"src": src, "dst": dst, "relation": relation, "weight": weight, "evidence": evidence})


def entity_id(etype: str, value: str) -> str:
    return f"{etype}:{value}"
