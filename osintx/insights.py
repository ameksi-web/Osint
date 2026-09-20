"""Инсайты: то, что нельзя получить из одного источника, — выводы по всем находкам.

Запускается движком после всех модулей и добавляет в отчёт отдельный модуль
``insights`` со «сводными» находками:

  * **Где живёт** — все публичные упоминания местоположения (GitHub/GitLab/Keybase,
    bio в Telegram, подписи сайтов, страна номера телефона) сводятся в один вывод
    с указанием, ГДЕ именно это сказано. Каждое утверждение проверяемо ссылкой.
  * **Под какими именами/никами известен** — display name из каждого источника.
  * **История изменений** — сравнение с предыдущими поисками по этой же цели
    (локальная база): ник/имя/био/город изменились — видно, когда и с чего на что.
  * **Хронология** — даты создания аккаунтов, домены, снимки веб-архива.
  * **Контакты** — единый список найденных email/телефонов/сайтов/Telegram.

Важный принцип: инсайт — это НЕ догадка. Он либо пересказывает подтверждённые
данные источника, либо явно помечен как «предположение» с низким доверием.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .core import gazetteer
from .core.models import Finding, ModuleResult, Report
from .core.utils import human_ms

# ключи в data находок, откуда берём текст для гео-анализа
TEXT_KEYS = ("bio", "description", "og_description", "about", "about_me", "aboutMe", "summary",
             "location", "currentLocation", "current_location", "city", "country", "address",
             "company", "status", "tw_description")
NAME_KEYS = ("name", "display_name", "full_name", "real_name", "realname", "nickname", "person_name",
             "title_name", "username", "login")


def is_derived(finding: Finding) -> bool:
    """Находка создана самими инсайтами (а не источником) — повторно её не анализируем."""
    return finding.source.startswith("insights") or "insights" in (finding.tags or [])


def _iter_texts(report: Report) -> list[tuple[str, str, str]]:
    """(источник, ссылка, текст) по всем находкам — только публичные описания."""
    out: list[tuple[str, str, str]] = []
    for f in report.findings:
        if is_derived(f):     # не пересказываем собственные выводы
            continue
        chunks: list[str] = []
        for key in TEXT_KEYS:
            value = f.data.get(key)
            if isinstance(value, str) and value.strip():
                chunks.append(value.strip())
            elif isinstance(value, list):
                chunks.extend(str(v).strip() for v in value if str(v).strip())
        for key in ("og", "meta", "api"):
            nested = f.data.get(key)
            if isinstance(nested, dict):
                for nkey in ("og_title", "og_description", "description", "title"):
                    value = nested.get(nkey)
                    if isinstance(value, str) and value.strip():
                        chunks.append(value.strip())
        if not chunks and f.kind in ("profile", "meta") and f.title:
            chunks.append(f.title)
        if chunks:
            out.append((f.source, f.url, " · ".join(dict.fromkeys(chunks))))
    return out


def _names(report: Report) -> list[dict[str, Any]]:
    """Имена и ники, под которыми цель видна в источниках."""
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for f in report.findings:
        if is_derived(f):
            continue
        for key in NAME_KEYS:
            value = f.data.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()
            if len(value) > 120 or value.isdigit():
                continue
            pair = (f.source, value)
            if pair in seen:
                continue
            seen.add(pair)
            found.append({"source": f.source, "field": key, "value": value,
                          "url": f.url, "confidence": f.confidence})
    return found


def _location_statements(report: Report) -> list[dict[str, Any]]:
    """Все упоминания местоположения с указанием источника и ссылки."""
    statements: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source, url, text in _iter_texts(report):
        for match in gazetteer.find_location(text):
            key = (match.code, match.city, source)
            if key in seen:          # один и тот же источник не повторяем
                continue
            seen.add(key)
            statements.append({"source": source, "url": url, "code": match.code, "country": match.country,
                               "city": match.city, "matched": match.matched, "text": text[:220]})
    return statements


def _phone_countries(report: Report) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in report.findings:
        if f.category != "phone" or is_derived(f):
            continue
        number = f.data.get("e164") or f.value or ""
        code = f.data.get("region") or gazetteer.country_from_phone(str(number))
        if code:
            out.append({"source": f.source, "url": f.url, "code": str(code).upper(),
                        "country": gazetteer.country_name(str(code)), "number": number,
                        "carrier": f.data.get("carrier", ""), "text": f.title[:200]})
    return out


def _tag_derived(findings: list[Finding]) -> list[Finding]:
    """Помечает находки как производные от инсайтов (тег + удаление при повторном вызове)."""
    for finding in findings:
        if "insights" not in finding.tags:
            finding.tags.append("insights")
    return findings


def build_geo_findings(report: Report) -> list[Finding]:
    """«Где живёт»: каждое утверждение отдельно + один сводный вывод с доверием по числу источников."""
    findings: list[Finding] = []
    statements = _location_statements(report)
    phones = _phone_countries(report)

    for item in statements:
        label = f"{item['city']}, {item['country']}" if item["city"] else item["country"]
        findings.append(Finding(
            source=f"geo:{item['source']}", category="geo", kind="location",
            confidence="high" if item["city"] else "medium",
            title=f"Упоминание местоположения: {label} (текст: «{item['matched']}»)",
            url=item["url"], value=label, data=dict(item),
            evidence=f"в публичном описании источника {item['source']} найдено «{item['matched']}»: "
                     f"{item['text'][:160]}"))
    for item in phones:
        findings.append(Finding(
            source=f"geo:{item['source']}", category="geo", kind="location", confidence="high",
            title=f"Страна номера {item['number']}: {item['country']}" +
                  (f" (оператор: {item['carrier']})" if item["carrier"] else ""),
            url=item["url"], value=item["country"],
            data={**item, "type": "phone_region"},
            evidence=f"код номера {item['number']} принадлежит {item['country']} "
                     f"(определено по E.164/региону)"))

    counter: Counter[str] = Counter()
    cities: Counter[str] = Counter()
    sources: dict[str, list[str]] = {}
    for item in statements:
        counter[item["country"]] += 1
        if item["city"]:
            cities[item["city"]] += 1
        sources.setdefault(item["country"], []).append(item["source"])
    for item in phones:
        counter[item["country"]] += 1
        sources.setdefault(item["country"], []).append(f"{item['source']}(телефон)")

    if counter:
        top_country, votes = counter.most_common(1)[0]
        top_city = cities.most_common(1)[0][0] if cities else ""
        independent = len(set(sources.get(top_country, [])))
        confidence = "high" if independent >= 2 else "medium"
        label = f"{top_city}, {top_country}" if top_city else top_country
        alternative = ", ".join(f"{c} ({n})" for c, n in counter.most_common()[1:4]) or "нет"
        findings.append(Finding(
            source="insights:geo", category="geo", kind="meta", confidence=confidence,
            title=f"Вероятное местоположение: {label} — упоминаний {votes}, независимых источников {independent}",
            value=label,
            data={"country": top_country, "city": top_city, "votes": votes,
                  "by_country": dict(counter), "by_city": dict(cities),
                  "sources": {k: sorted(set(v)) for k, v in sources.items()},
                  "alternatives": alternative, "statements": statements[:20]},
            evidence=f"сводка по {len(statements)} текстовым упоминаниям местоположения в публичных "
                     f"профилях и {len(phones)} телефонным данным; источники: "
                     f"{', '.join(sorted(set(sources.get(top_country, [])))[:8])}"))
    return _tag_derived(findings)


def build_name_findings(report: Report) -> list[Finding]:
    """«Под какими именами известен» + варианты написания."""
    names = _names(report)
    if not names:
        return []
    by_value: dict[str, list[str]] = {}
    for item in names:
        by_value.setdefault(item["value"], []).append(item["source"])
    findings: list[Finding] = []
    primary = sorted(by_value.items(), key=lambda kv: -len(kv[1]))
    for value, srcs in primary[:12]:
        findings.append(Finding(
            source="insights:names", category="identity", kind="name", confidence="medium",
            title=f"Известен как «{value}» (источники: {', '.join(sorted(set(srcs))[:5])})",
            value=value, data={"sources": sorted(set(srcs))},
            evidence=f"имя/ник взято из публичных полей профилей: {', '.join(sorted(set(srcs))[:6])}"))
    findings.append(Finding(
        source="insights:names", category="identity", kind="meta", confidence="medium",
        title=f"Всего имён/ников в источниках: {len(by_value)}",
        value=", ".join(list(by_value)[:8]),
        data={"names": [{"value": v, "sources": sorted(set(s))} for v, s in by_value.items()]},
        evidence="сводка по полям name/nickname/username публичных профилей и архивных снимков"))
    return _tag_derived(findings)


def build_timeline_findings(report: Report) -> list[Finding]:
    """Хронология: когда аккаунты созданы, когда появились снимки архива."""
    events: list[dict[str, Any]] = []
    for f in report.findings:
        if is_derived(f):
            continue
        for key, label in (("created_at", "аккаунт создан"), ("timecreated", "аккаунт создан"),
                           ("created", "дата создания"), ("registered", "регистрация"),
                           ("first_seen", "первое появление (архив)"), ("snapshot_first", "первый снимок архива"),
                           ("updated_at", "обновлено"), ("last_snapshot", "последний снимок архива")):
            value = f.data.get(key)
            if isinstance(value, str) and re.match(r"\d{4}", value.strip()):
                events.append({"date": value.strip(), "event": label, "source": f.source,
                               "url": f.url, "title": f.title})
    if not events:
        return []
    events.sort(key=lambda e: e["date"])
    span = f"{events[0]['date'][:10]} … {events[-1]['date'][:10]}"
    return _tag_derived([Finding(
        source="insights:timeline", category="timeline", kind="meta", confidence="high",
        title=f"Хронология цели: {span} ({len(events)} событий)",
        value=span, data={"events": events[:40]},
        evidence="даты взяты из публичных полей источников (created_at/timecreated/снимки архива)")])


def build_contact_findings(report: Report) -> list[Finding]:
    """«Всё, что доступно»: единый список контактов и площадок."""
    buckets: dict[str, set[str]] = {"email": set(), "phone": set(), "telegram": set(),
                                    "username": set(), "site": set(), "crypto": set()}
    for f in report.findings:
        if is_derived(f):
            continue
        value = (f.value or "").strip()
        if not value:
            continue
        if f.category in ("email", "phone", "telegram", "crypto", "username"):
            buckets[f.category].add(value)
        urls = [f.url] + [str(u) for u in (f.data.get("links") or [])]
        for url in urls:
            if isinstance(url, str) and url.startswith("http"):
                host = re.sub(r"^https?://", "", url).split("/")[0]
                if host and not host.endswith(("google.com", "bing.com", "yandex.ru", "duckduckgo.com")):
                    buckets["site"].add(host)
    if not any(buckets.values()):
        return _tag_derived([Finding(
            source="insights:contacts", category="contacts", kind="meta", confidence="high",
            title="Контактов и связанных аккаунтов не найдено (проверьте покрытие источников)",
            value="", data={"contacts": {k: [] for k in buckets}},
            evidence="по подтверждённым находкам ни одного контакта не выявлено — это не «данных нет», "
                     "а «источники не отдали данных»")])
    parts = [f"{k}: {len(v)}" for k, v in buckets.items() if v]
    return _tag_derived([Finding(
        source="insights:contacts", category="contacts", kind="meta", confidence="high",
        title="Все найденные контакты и площадки: " + ", ".join(parts),
        value=", ".join(sorted(buckets["email"])[:5]),
        data={"contacts": {k: sorted(v) for k, v in buckets.items()}},
        evidence="объединение подтверждённых находок по всем модулям (email, телефон, Telegram, "
                 "логины, домены/сайты, криптоадреса)")])


SNAPSHOT_KEYS = ("display_name", "name", "nickname", "bio", "description", "location",
                 "currentLocation", "city", "country", "username", "login", "avatar",
                 "subscribers", "followers", "public_repos", "company", "registrar",
                 "created_at", "timecreated", "provider", "breaches")


def snapshots_from_report(report: Report) -> list[dict[str, str]]:
    """Какие «изменяемые» поля стоит запомнить для отслеживания истории.

    Плюс общая сводка (сколько находок, сколько источников ответило) — полезный
    сигнал «появились новые данные» даже там, где нет имени/локации (домен, email).
    """
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for f in report.findings:
        if is_derived(f):
            continue
        for key in SNAPSHOT_KEYS:
            value = f.data.get(key)
            if isinstance(value, list):
                if not value:
                    continue
                value = ", ".join(str(v) for v in value[:5]) if all(
                    isinstance(v, str) for v in value[:5]) else f"{len(value)} шт."
            if isinstance(value, (str, int)) and str(value).strip():
                pair = (f.source, key)
                if pair in seen:
                    continue
                seen.add(pair)
                out.append({"source": f.source, "field": key, "value": str(value).strip()[:500],
                            "url": f.url})

    summary = report.summary or report.compute_summary()
    out.append({"source": "osintx", "field": "находок всего", "value": str(summary["findings"]), "url": ""})
    out.append({"source": "osintx", "field": "находок high-доверия",
                "value": str(summary.get("by_confidence", {}).get("high", 0)), "url": ""})
    out.append({"source": "osintx", "field": "источников ответило",
                "value": str(summary["sources_ok"]), "url": ""})
    return out


def apply(report: Report, *, store: Any = None, record: bool = True,
          previous: list[dict[str, Any]] | None = None) -> ModuleResult:
    """Добавляет инсайты в отчёт. Ничего не выдумывает: только сводка находок."""
    findings: list[Finding] = []
    findings += build_geo_findings(report)
    findings += build_name_findings(report)
    findings += build_timeline_findings(report)
    findings += build_contact_findings(report)

    for old_module in [m for m in report.modules if m.module == "insights"]:
        report.modules.remove(old_module)           # вызов могли сделать раньше (bot/web/cli)
    report.findings = [f for f in report.findings if not is_derived(f)]
    module = ModuleResult(module="insights", target=report.target,
                          duration_ms=0)
    module.findings = findings

    # история изменений по сравнению с прошлыми поисками
    if store is not None:
        if record:
            try:
                module.meta["snapshots"] = snapshots_from_report(report)
                store.record_snapshots(report.target, module.meta["snapshots"], report.search_id)
            except Exception as exc:  # pragma: no cover
                report.warnings.append(f"Не удалось записать историю изменений: {exc}")
        try:
            changes = store.profile_changes(report.target)
        except Exception:  # pragma: no cover
            changes = []
        if changes:
            text = "; ".join(f"{c['field']} в {c['source']}: «{c['old']}» → «{c['new']}» ({c['changed_at'][:10]})"
                             for c in changes[:6])
            module.findings.append(Finding(
                source="insights:changes", category="history", kind="change", confidence="high",
                title=f"Изменения с прошлых проверок: {len(changes)}",
                value=text[:400], data={"changes": changes[:40]},
                evidence="сравнение текущих публичных значений с сохранёнными в локальной базе "
                         "при предыдущих поисках по этой цели (наблюдения самого OsintX)"))
            module.meta["changes"] = changes[:40]
        module.meta["snapshot_count"] = store.snapshot_stats(report.target)

    if previous:
        module.meta["previous_searches"] = previous[:5]

    report.merge(module)
    report.meta["insights"] = {
        "location": next((f.value for f in findings if f.source == "insights:geo"), ""),
        "names": [f.value for f in findings if f.category == "identity" and f.kind == "name"][:8],
        "changes": len(module.meta.get("changes", [])),
    }
    report.compute_summary()
    return module


def summary_lines(report: Report, limit: int = 8) -> list[str]:
    """Короткая сводка инсайтов для CLI/бота."""
    module = next((m for m in report.modules if m.module == "insights"), None)
    if not module:
        return []
    lines: list[str] = []
    for f in module.findings:
        if f.confidence == "low":
            continue
        lines.append(f"• {f.title}")
        if len(lines) >= limit:
            break
    loc = report.meta.get("insights", {}).get("location")
    if loc:
        lines.insert(0, f"📍 Местоположение: {loc}")
    return lines


def format_changes(changes: list[dict[str, Any]], target: str = "") -> str:
    """Человекочитаемая история изменений (для CLI /changes и бота)."""
    if not changes:
        return (f"История изменений по «{target}» пуста: цель наблюдалась один раз или данные не менялись.\n"
                "Каждый новый поиск по этой цели добавляет наблюдение — изменения будут видны здесь.")
    lines = [f"История изменений по «{target}» ({len(changes)}):"]
    for item in changes:
        lines.append(f"  {item['changed_at'][:16].replace('T', ' ')} — {item['source']}.{item['field']}: "
                     f"«{item['old'][:60]}» → «{item['new'][:60]}»")
        if item.get("url"):
            lines.append(f"      {item['url']}")
    return "\n".join(lines)


def stat_line(module: ModuleResult | None) -> str:
    if not module:
        return ""
    return f"инсайты: {len(module.findings)} выводов, {human_ms(module.duration_ms)}"
