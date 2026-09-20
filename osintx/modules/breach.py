"""Утечки и слитые базы: реальные проверки по публичным API + поиск по СВОИМ загруженным базам.

Без ключей:
  * XposedOrNot (api.xposedornot.com) — публичный API проверки утечек по email;
  * поиск по локальным датасетам (SQLite FTS) — сюда можно загрузить свои внешние базы
    (например, скачанные публичные коллекции) командой `osintx dataset-import`;
  * Have I Been Pwned по диапазону хешей паролей (k-anonymity, без ключа, пароль не покидает машину).

С ключами (расширенное покрытие):
  * HIBP (haveibeenpwned.com) — точный список утечек и домены;
  * LeakCheck.io — откуда утечка, поля записи;
  * DeHashed — поля записей;
  * IntelX — поиск по дампам/paste-сайтам.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ..core.models import ModuleResult, SourceStatus
from ..core.store import get_store
from .base import Context, Module, add_edge, add_entity, entity_id

BREACH_DIRECT_LINKS = [
    ("Have I Been Pwned", "https://haveibeenpwned.com/account/{email}"),
    ("DeHashed", "https://dehashed.com/search?query={email}"),
    ("LeakCheck", "https://leakcheck.io/"),
    ("Leak-Lookup", "https://leak-lookup.com/"),
    ("Hudson Rock", "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"),
    ("Intelligence X", "https://intelx.io/?s={email}"),
    ("Snusbase", "https://snusbase.com/"),
    ("BreachDirectory", "https://breachdirectory.org/"),
]


async def check_breaches(ctx: Context, email: str, result: ModuleResult) -> None:
    """Проверка email по утечкам всеми доступными способами."""
    await _xposedornot(ctx, email, result)
    await _hibp(ctx, email, result)
    await _leakcheck(ctx, email, result)
    await _dehashed(ctx, email, result)
    await _intelx(ctx, email, result)
    _local_datasets(ctx, email, result)
    _links(email, result)


async def _xposedornot(ctx: Context, email: str, result: ModuleResult) -> None:
    """Публичный API XposedOrNot — без ключа, реальные данные об утечках."""
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    resp = await ctx.http.get(url, retries=1)
    if resp.status_code == 404 or "Not found" in resp.text[:120]:
        result.statuses.append(SourceStatus(source="xposedornot", category="breach", status="not_found",
                                            url=url, http_code=resp.status_code,
                                            detail="email не найден ни в одной известной утечке"))
        return
    data = resp.json()
    if not resp.ok or not isinstance(data, dict):
        result.statuses.append(SourceStatus(source="xposedornot", category="breach",
                                            status="blocked" if resp.looks_blocked() else "error",
                                            url=url, http_code=resp.status_code or None,
                                            error=resp.error or resp.snippet(150)))
        return
    breaches: list[str] = []
    for key in ("breaches", "BreachMetrics", "breach"):
        val = data.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, list):
                    breaches += [str(x) for x in item]
                else:
                    breaches.append(str(item))
    breaches = sorted({b for b in breaches if b and b.lower() not in ("null", "none")})
    if not breaches:
        result.statuses.append(SourceStatus(source="xposedornot", category="breach", status="not_found",
                                            url=url, http_code=resp.status_code,
                                            detail="утечек по адресу не обнаружено"))
        return
    result.findings.append(_breach_finding("xposedornot", email, breaches, url, resp, extra=data))
    add_entity(result, "email", email, breaches=len(breaches), breach_names=breaches[:20])
    add_edge(result, entity_id("email", email), entity_id("breach", f"{len(breaches)} утечек"),
             "appears_in_breach", 1.0, "XposedOrNot публичный API")
    result.statuses.append(SourceStatus(source="xposedornot", category="breach", status="found", url=url,
                                        http_code=resp.status_code, latency_ms=resp.latency_ms,
                                        detail=f"{len(breaches)} утечек"))


async def _hibp(ctx: Context, email: str, result: ModuleResult) -> None:
    key = ctx.key("hibp")
    if not key:
        result.statuses.append(SourceStatus(source="hibp", category="breach", status="unsupported",
                                            detail="нужен HIBP_API_KEY (haveibeenpwned.com/API/Key)"))
        return
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    resp = await ctx.http.get(url, headers={"hibp-api-key": key, "user-agent": "OsintX"},
                              params={"truncateResponse": "false"}, retries=1)
    if resp.status_code == 404:
        result.statuses.append(SourceStatus(source="hibp", category="breach", status="not_found", url=url,
                                            http_code=404, detail="HIBP: адрес не найден в утечках"))
        return
    data = resp.json()
    if resp.status_code == 200 and isinstance(data, list):
        names = [b.get("Name") for b in data]
        details = [{"name": b.get("Name"), "title": b.get("Title"), "date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"), "data_classes": b.get("DataClasses"),
                    "verified": b.get("IsVerified"), "sensitive": b.get("IsSensitive"),
                    "domain": b.get("Domain")} for b in data]
        finding = _breach_finding("hibp", email, [n for n in names if n], url, resp, extra={"breaches": details})
        finding.data["details"] = details
        result.findings.append(finding)
        result.statuses.append(SourceStatus(source="hibp", category="breach", status="found", url=url,
                                            http_code=200, detail=f"{len(data)} утечек"))
    elif resp.status_code == 401:
        result.statuses.append(SourceStatus(source="hibp", category="breach", status="error", http_code=401,
                                            detail="неверный/просроченный HIBP_API_KEY"))
    else:
        result.statuses.append(SourceStatus(source="hibp", category="breach", status="error",
                                            http_code=resp.status_code or None,
                                            error=resp.error or resp.snippet(120)))


async def _leakcheck(ctx: Context, email: str, result: ModuleResult) -> None:
    key = ctx.key("leakcheck")
    if not key:
        result.statuses.append(SourceStatus(source="leakcheck", category="breach", status="unsupported",
                                            detail="нужен LEAKCHECK_API_KEY (leakcheck.io)"))
        return
    url = f"https://leakcheck.io/api/v2/query/{email}"
    resp = await ctx.http.get(url, headers={"X-API-Key": key, "Accept": "application/json"},
                              params={"type": "email"}, retries=1)
    data = resp.json() or {}
    if resp.ok and data.get("found"):
        sources = sorted({(s.get("name") or s.get("breach") or "источник") for s in data.get("sources", [])})
        fields = sorted({f for s in data.get("sources", []) for f in (s.get("fields") or [])})
        result.findings.append(_breach_finding("leakcheck", email, sources, url, resp,
                                               extra={"fields": fields, "count": data.get("found")}))
        result.statuses.append(SourceStatus(source="leakcheck", category="breach", status="found", url=url,
                                            http_code=resp.status_code, detail=f"{data.get('found')} записей"))
    elif resp.ok:
        result.statuses.append(SourceStatus(source="leakcheck", category="breach", status="not_found",
                                            url=url, http_code=resp.status_code, detail="LeakCheck: не найдено"))
    else:
        result.statuses.append(SourceStatus(source="leakcheck", category="breach", status="error",
                                            http_code=resp.status_code or None,
                                            error=resp.error or str(data)[:160]))


async def _dehashed(ctx: Context, email: str, result: ModuleResult) -> None:
    key = ctx.key("dehashed")
    owner = ctx.key("dehashed_email")
    if not (key and owner):
        result.statuses.append(SourceStatus(source="dehashed", category="breach", status="unsupported",
                                            detail="нужны DEHASHED_API_KEY и DEHASHED_EMAIL"))
        return
    url = "https://api.dehashed.com/search"
    resp = await ctx.http.get(url, params={"query": f'email:"{email}"', "size": 50},
                              headers={"Accept": "application/json"},
                              auth=(owner, key), retries=1)
    data = resp.json() or {}
    if resp.ok and data.get("entries"):
        entries = [{k: v for k, v in e.items() if v and k not in ("id",)} for e in data["entries"][:25]]
        databases = sorted({e.get("database_name") for e in data["entries"] if e.get("database_name")})
        finding = _breach_finding("dehashed", email, databases, url, resp,
                                  extra={"total": data.get("total"), "fields": sorted(
                                      {k for e in entries for k, v in e.items() if v})})
        finding.data["entries"] = entries
        result.findings.append(finding)
        result.statuses.append(SourceStatus(source="dehashed", category="breach", status="found", url=url,
                                            http_code=resp.status_code, detail=f"{data.get('total')} записей"))
    elif resp.ok:
        result.statuses.append(SourceStatus(source="dehashed", category="breach", status="not_found",
                                            http_code=resp.status_code, detail="DeHashed: не найдено"))
    else:
        result.statuses.append(SourceStatus(source="dehashed", category="breach", status="error",
                                            http_code=resp.status_code or None,
                                            error=resp.error or str(data)[:160]))


async def _intelx(ctx: Context, email: str, result: ModuleResult) -> None:
    key = ctx.key("intelx")
    if not key:
        result.statuses.append(SourceStatus(source="intelx", category="breach", status="unsupported",
                                            detail="нужен INTELX_API_KEY (intelx.io) — поиск по дампам/pastes"))
        return
    headers = {"x-key": key, "Content-Type": "application/json"}
    start = await ctx.http.post("https://2.intelx.io/intelligent/search", headers=headers,
                                json={"term": email, "maxresults": 20, "media": 0, "sort": 2,
                                      "terminate": []}, retries=1)
    data = start.json() or {}
    sid = data.get("id")
    if not sid:
        result.statuses.append(SourceStatus(source="intelx", category="breach", status="error",
                                            http_code=start.status_code or None,
                                            error=start.error or str(data)[:160]))
        return
    import asyncio
    await asyncio.sleep(3)
    got = await ctx.http.get("https://2.intelx.io/intelligent/search/result",
                             headers={"x-key": key}, params={"id": sid, "limit": 20}, retries=1)
    payload = got.json() or {}
    records = payload.get("records") or []
    if records:
        result.findings.append(_breach_finding(
            "intelx", email, [r.get("name") or "нет имени" for r in records], "https://intelx.io/", got,
            extra={"records": [{"name": r.get("name"), "bucket": r.get("bucket"), "date": r.get("date"),
                                "type": r.get("type"), "size": r.get("size")} for r in records[:20]]}))
        result.statuses.append(SourceStatus(source="intelx", category="breach", status="found",
                                            http_code=got.status_code, detail=f"{len(records)} записей"))
    else:
        result.statuses.append(SourceStatus(source="intelx", category="breach", status="not_found",
                                            http_code=got.status_code, detail="IntelX: результатов нет"))


def _local_datasets(ctx: Context, email: str, result: ModuleResult) -> None:
    """Поиск по внешним базам, которые пользователь сам загрузил в OsintX."""
    store = ctx.store or get_store()
    hits = store.search_local(email)
    if not hits:
        result.statuses.append(SourceStatus(source="local-datasets", category="breach", status="not_found",
                                            detail="в загруженных локальных базах совпадений нет "
                                                   "(загрузить: osintx dataset-import файл.csv)"))
        return
    result.findings.append(_breach_finding(
        "local-datasets", email, sorted({h.get("dataset") or "?" for h in hits}),
        "", _FakeResp(200), extra={"matches": [{"dataset": h.get("dataset"), "kind": h.get("kind"),
                                                "value": h.get("value"), "extra": h.get("extra")}
                                               for h in hits[:50]], "count": len(hits)}))
    result.statuses.append(SourceStatus(source="local-datasets", category="breach", status="found",
                                        detail=f"{len(hits)} совпадений в локальных базах"))


def _links(email: str, result: ModuleResult) -> None:
    links = [{"name": name, "url": tpl.format(email=email)} for name, tpl in BREACH_DIRECT_LINKS]
    result.findings.append(_breach_finding("breach-links", email, [], "", _FakeResp(200),
                                           extra={"links": links, "note": "прямые ссылки на профильные сервисы "
                                                                          "проверки утечек; часть требует регистрации"},
                                           kind="link", confidence="low",
                                           title="Прямые ссылки на сервисы проверки утечек"))
    result.statuses.append(SourceStatus(source="breach-links", category="breach", status="found",
                                        detail=f"{len(links)} ссылок"))


class _FakeResp:
    def __init__(self, code: int):
        self.status_code = code
        self.latency_ms = 0


def _breach_finding(source: str, email: str, breaches: list[str], url: str, resp: Any,
                    extra: dict[str, Any] | None = None, kind: str = "breach",
                    confidence: str = "high", title: str | None = None):
    from ..core.models import Finding
    data = {"breaches": breaches[:60], "count": len(breaches), **(extra or {})}
    return Finding(
        source=source, category="breach", kind=kind, confidence=confidence,  # type: ignore[arg-type]
        title=title or f"Утечки: адрес найден в {len(breaches)} базах — {', '.join(breaches[:12])}"
                       + ("…" if len(breaches) > 12 else ""),
        url=url, value=email, data=data,
        evidence=f"{source}: получено {len(breaches)} названий утечек; "
                 f"HTTP {getattr(resp, 'status_code', '?')}",
        http_code=getattr(resp, "status_code", None))


async def check_password_pwned(password: str, ctx: Context) -> dict[str, Any]:
    """Проверка пароля по HIBP через k-anonymity: наружу уходят только 5 символов хеша."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = await ctx.http.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                              headers={"Add-Padding": "true"}, retries=1)
    if not resp.ok:
        return {"checked": False, "error": resp.error or f"HTTP {resp.status_code}"}
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return {"checked": True, "pwned": True, "count": int(parts[1]),
                    "note": "пароль встречается в публичных утечках — его нельзя использовать"}
    return {"checked": True, "pwned": False, "count": 0,
            "note": "в базе HIBP (800+ млн утёкших паролей) этот пароль не найден"}
