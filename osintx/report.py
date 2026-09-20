"""Отчёты OsintX: текст, JSON, Markdown, CSV, HTML, граф (Mermaid/DOT).

Каждый отчёт содержит не только находки, но и покрытие источников: сколько
проверено, сколько недоступно и почему — чтобы результат нельзя было принять
за «полный», если половина источников не ответила.
"""
from __future__ import annotations

import csv
import html as html_mod
import io
import json
from pathlib import Path
from typing import Any

from .core.models import Report
from .core.utils import human_ms

CONF_ICON = {"high": "🟢", "medium": "🟡", "low": "⚪"}
STATUS_ICON = {"found": "✅", "not_found": "➖", "error": "⚠️", "blocked": "🚫",
               "unsupported": "⛔", "skipped": "⏭"}


# ───────────────────────────── текст ─────────────────────────────
def to_text(report: Report, *, verbose: bool = False, max_per_category: int = 40) -> str:
    report.compute_summary()
    s = report.summary
    out: list[str] = []
    add = out.append
    add("=" * 78)
    add(f"  OsintX — отчёт по цели: {report.target}  (тип: {report.target_type})")
    add(f"  ID поиска: {report.search_id} | {report.started_at} | {human_ms(report.duration_ms)}")
    add("=" * 78)
    add("")
    add(f"  Находок: {s['findings']}   |   Источников проверено: {s['sources_checked']} "
        f"(ответили {s['sources_ok']}, недоступно {s['sources_failed']})   |   "
        f"Покрытие: {s['coverage']}%")
    add(f"  Оценка цифровой экспозиции: {s['risk_score']}/100")
    if s.get("by_confidence"):
        add("  Достоверность находок: " + ", ".join(f"{k}: {v}" for k, v in s["by_confidence"].items()))
    if s.get("by_category"):
        add("  По категориям: " + ", ".join(f"{k}: {v}" for k, v in s["by_category"].items()))
    insights = report.meta.get("insights") or {}
    if insights:
        if insights.get("location"):
            add(f"  📍 Местоположение: {insights['location']}")
        if insights.get("names"):
            add(f"  🏷 Известен как: {', '.join(insights['names'][:5])}")
        if insights.get("changes"):
            add(f"  🕓 Изменений с прошлых проверок: {insights['changes']}")
        names = insights.get("usernames") or {}
        if names.get("current"):
            line = f"  🏷 Юзернеймы: @{names['current']}"
            if names.get("previous"):
                line += " · ранее: " + ", ".join(f"@{n}" for n in names["previous"][:6])
            add(line)
    add("")
    if report.warnings:
        add("  ⚠ Предупреждения:")
        for w in report.warnings:
            add(f"    - {w}")
        add("")

    by_cat: dict[str, list] = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)
    for category, findings in by_cat.items():
        add(f"── {category.upper()} " + "─" * (72 - len(category)))
        for f in findings[:max_per_category]:
            icon = CONF_ICON.get(f.confidence, "•")
            add(f"{icon} [{f.source}] {f.title}")
            if f.url:
                add(f"    ↳ {f.url}")
            if f.evidence:
                add(f"    доказательство: {f.evidence[:220]}")
            extra = _short_details(f.data)
            if extra:
                add(f"    данные: {extra}")
        if len(findings) > max_per_category:
            add(f"    … ещё {len(findings) - max_per_category} находок (см. JSON/HTML)")
        add("")

    add("── ИСТОЧНИКИ " + "─" * 66)
    for m in report.modules:
        add(f"\n[{m.module}] проверено {m.checked}, найдено {m.found}, недоступно {m.failed}, {human_ms(m.duration_ms)}")
        if verbose:
            for st in m.statuses:
                line = f"   {STATUS_ICON.get(st.status, '?')} {st.source:<24} {st.status:<12}"
                if st.http_code:
                    line += f" HTTP {st.http_code}"
                if st.latency_ms:
                    line += f" {st.latency_ms}мс"
                line += f" {st.detail or st.error}"
                add(line[:200])
        for err in m.errors:
            add(f"   ⚠ {err}")
    if not verbose:
        add("\n  (для детального списка каждого источника запустите с --verbose)")
    add("")
    add("─" * 78)
    add("Отчёт содержит только данные из открытых источников, полученные в реальном времени.")
    add("Недоступные источники помечены как error/blocked и НЕ считаются «не найдено».")
    return "\n".join(out)


def _short_details(data: dict[str, Any], limit: int = 260) -> str:
    if not data:
        return ""
    skip = {"evidence", "content"}
    parts = []
    for k, v in data.items():
        if k in skip or v in (None, "", [], {}):
            continue
        if isinstance(v, list):
            if len(v) > 6:
                v = v[:6] + [f"…+{len(v) - 6}"]
        if isinstance(v, dict):
            v = {kk: vv for kk, vv in list(v.items())[:6]}
        parts.append(f"{k}={json.dumps(v, ensure_ascii=False)}")
        if sum(len(p) for p in parts) > limit:
            break
    text = "; ".join(parts)
    return text[:limit] + ("…" if len(text) > limit else "")


# ───────────────────────────── JSON / CSV ─────────────────────────────
def to_json(report: Report, indent: int = 2) -> str:
    return report.to_json(indent=indent)


def to_csv(report: Report) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["category", "source", "kind", "confidence", "title", "value", "url", "evidence", "http_code"])
    for f in report.findings:
        writer.writerow([f.category, f.source, f.kind, f.confidence, f.title, f.value, f.url, f.evidence,
                         f.http_code or ""])
    return buf.getvalue()


# ───────────────────────────── Markdown ─────────────────────────────
def to_markdown(report: Report) -> str:
    report.compute_summary()
    s = report.summary
    out = [f"# OsintX — отчёт по цели `{report.target}`",
           "",
           f"- **Тип цели:** {report.target_type}",
           f"- **ID поиска:** `{report.search_id}`",
           f"- **Начато:** {report.started_at}, длительность: {human_ms(report.duration_ms)}",
           f"- **Находок:** {s['findings']}",
           f"- **Источников проверено:** {s['sources_checked']} (недоступно {s['sources_failed']}, "
           f"покрытие {s['coverage']}%)",
           f"- **Оценка экспозиции:** {s['risk_score']}/100", ""]
    if report.warnings:
        out += ["## Предупреждения", ""] + [f"- {w}" for w in report.warnings] + [""]
    out += ["## Находки", "", "| Достоверность | Категория | Источник | Что найдено | Ссылка |",
            "|---|---|---|---|---|"]
    for f in report.findings:
        title = f.title.replace("|", "\\|")
        out.append(f"| {CONF_ICON.get(f.confidence, '')} {f.confidence} | {f.category} | {f.source} "
                   f"| {title} | {f.url or '—'} |")
    out += ["", "## Покрытие источников", "", "| Модуль | Проверено | Найдено | Недоступно | Время |",
            "|---|---|---|---|---|"]
    for m in report.modules:
        out.append(f"| {m.module} | {m.checked} | {m.found} | {m.failed} | {human_ms(m.duration_ms)} |")
    if report.entities:
        out += ["", "## Сущности", "", "| Тип | Значение | Детали |", "|---|---|---|"]
        for e in report.entities[:120]:
            out.append(f"| {e.type} | `{e.value}` | {json.dumps(e.meta, ensure_ascii=False)[:120]} |")
    if report.edges:
        out += ["", "## Связи", "", "| Откуда | Куда | Связь | Вес | Подтверждение |", "|---|---|---|---|---|"]
        for e in report.edges[:200]:
            out.append(f"| `{e.src}` | `{e.dst}` | {e.relation} | {e.weight} | {e.evidence[:80]} |")
    out += ["", "---", "", "_Данные получены из открытых источников в реальном времени. "
                "Недоступные источники отмечены отдельно и не считаются «не найдено»._"]
    return "\n".join(out)


# ───────────────────────────── Граф ─────────────────────────────
def to_mermaid(report: Report) -> str:
    lines = ["graph LR"]
    nodes: dict[str, str] = {}

    def node_id(name: str) -> str:
        if name not in nodes:
            nodes[name] = f"n{len(nodes)}"
        return nodes[name]

    def label(node: str) -> str:
        t, _, v = node.partition(":")
        return f"{t}: {v[:28]}".replace('"', "'")

    for e in report.edges[:300]:
        a, b = node_id(e.src), node_id(e.dst)
        lines.append(f'    {a}["{label(e.src)}"] -->|{e.relation}| {b}["{label(e.dst)}"]')
    if not report.edges:
        lines.append(f'    root["{report.target_type}: {report.target}"]')
    return "\n".join(lines)


def to_dot(report: Report) -> str:
    out = ["digraph osintx {", '  rankdir=LR; node [shape=box, style=rounded, fontname="Helvetica"];']
    ids: dict[str, str] = {}

    def nid(name: str) -> str:
        if name not in ids:
            ids[name] = f"n{len(ids)}"
        return ids[name]

    colors = {"email": "lightblue", "username": "lightgreen", "phone": "lightyellow", "domain": "lightpink",
              "ip": "lavender", "telegram": "skyblue", "person": "wheat", "crypto": "palegoldenrod"}
    for e in report.edges[:300]:
        for node in (e.src, e.dst):
            t = node.split(":", 1)[0]
            value = node.split(":", 1)[1] if ":" in node else node
            out.append(f'  {nid(node)} [label="{t}: {value[:30]}", fillcolor="{colors.get(t, "white")}", style="filled,rounded"];')
        out.append(f'  {nid(e.src)} -> {nid(e.dst)} [label="{e.relation}"];')
    out.append("}")
    return "\n".join(out)


# ───────────────────────────── HTML ─────────────────────────────
_HTML_TPL = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OsintX — отчёт по {target}</title>
<style>
:root{{--bg:#0f1117;--card:#171a23;--muted:#8b93a7;--fg:#e6e9f0;--acc:#4f8cff;--ok:#3ecf8e;--warn:#ffb84d;--bad:#ff6b6b}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
header{{padding:26px 22px;border-bottom:1px solid #232838;background:linear-gradient(180deg,#141824,#0f1117)}}
h1{{margin:0 0 6px;font-size:22px}} h2{{margin:30px 0 12px;font-size:18px;border-left:3px solid var(--acc);padding-left:10px}}
.wrap{{max-width:1120px;margin:0 auto;padding:0 18px 60px}}
.stats{{display:flex;flex-wrap:wrap;gap:12px;margin-top:14px}}
.stat{{background:var(--card);border:1px solid #232838;border-radius:10px;padding:10px 14px;min-width:130px}}
.stat b{{display:block;font-size:20px}} .stat span{{color:var(--muted);font-size:12px}}
.finding{{background:var(--card);border:1px solid #232838;border-left:4px solid var(--acc);border-radius:10px;padding:12px 14px;margin:10px 0}}
.finding.high{{border-left-color:var(--ok)}} .finding.medium{{border-left-color:var(--warn)}} .finding.low{{border-left-color:#5a6478}}
.finding .t{{font-weight:600;margin-bottom:4px}}
.finding .m{{color:var(--muted);font-size:12.5px}}
.ev{{margin-top:7px;padding:7px 9px;background:#0c0e14;border-radius:7px;font:12.5px/1.45 ui-monospace,Menlo,Consolas,monospace;color:#a9b3c9;white-space:pre-wrap;word-break:break-word}}
a{{color:var(--acc);text-decoration:none}} a:hover{{text-decoration:underline}}
table{{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:8px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #232838;vertical-align:top}}
th{{color:var(--muted);font-weight:600;background:#141824}}
.badge{{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;background:#212636;color:#c3cbdd;margin-right:6px}}
.warn{{background:#2a1f14;border:1px solid #543a1b;color:#ffcf8f;padding:10px 12px;border-radius:9px;margin:8px 0}}
details{{background:var(--card);border:1px solid #232838;border-radius:9px;padding:8px 12px;margin:7px 0}}
summary{{cursor:pointer;color:#c8d0e0}}
code{{background:#0c0e14;padding:1px 5px;border-radius:5px}}
footer{{color:var(--muted);font-size:12.5px;margin-top:40px;border-top:1px solid #232838;padding-top:14px}}
</style></head><body>
<header><div class="wrap" style="padding:0">
<h1>OsintX — отчёт по цели <code>{target}</code></h1>
<div>Тип цели: <b>{target_type}</b> · ID: <code>{search_id}</code> · {started_at} · длительность {duration}</div>
<div class="stats">
  <div class="stat"><b>{findings}</b><span>находок</span></div>
  <div class="stat"><b>{checked}</b><span>источников проверено</span></div>
  <div class="stat"><b>{failed}</b><span>недоступно</span></div>
  <div class="stat"><b>{coverage}%</b><span>покрытие</span></div>
  <div class="stat"><b>{risk}/100</b><span>экспозиция</span></div>
</div></div></header>
<div class="wrap">
{warnings}
<h2>Находки ({findings})</h2>
{findings_html}
<h2>Сущности и связи</h2>
{entities_html}
<h2>Покрытие источников</h2>
{coverage_html}
<footer>OsintX {version} · данные получены из открытых источников в реальном времени.
Недоступные источники помечены и не считаются «не найдено». Отчёт сгенерирован {generated}.</footer>
</div></body></html>
"""


def to_html(report: Report) -> str:
    report.compute_summary()
    s = report.summary
    parts_findings: list[str] = []
    by_cat: dict[str, list] = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)
    for cat, items in by_cat.items():
        parts_findings.append(f"<h3>{html_mod.escape(cat)} — {len(items)}</h3>")
        for f in items:
            url = html_mod.escape(f.url) if f.url else ""
            data = html_mod.escape(json.dumps(f.data, ensure_ascii=False, indent=1)) if f.data else ""
            code_badge = f'<span class="badge">HTTP {f.http_code}</span>' if f.http_code else ""
            link = (f'<a href="{url}" target="_blank" rel="noopener">{url[:110]}</a>') if url else ""
            evidence = (f'<div class="ev">Доказательство: {html_mod.escape(f.evidence)}</div>'
                        if f.evidence else "")
            details = (f'<details><summary>структурированные данные</summary>'
                       f'<div class="ev">{data}</div></details>') if data else ""
            parts_findings.append(
                f'<div class="finding {f.confidence}">'
                f'<div class="t">{html_mod.escape(f.title)}</div>'
                f'<div class="m"><span class="badge">{html_mod.escape(f.source)}</span>'
                f'<span class="badge">достоверность: {f.confidence}</span>{code_badge} {link}</div>'
                f'{evidence}{details}</div>')
    if not report.findings:
        parts_findings.append('<div class="warn">Находок нет. Это не значит «человека не существует» — '
                              'проверьте список недоступных источников ниже.</div>')

    ent_rows = "".join(
        f"<tr><td>{html_mod.escape(e.type)}</td><td><code>{html_mod.escape(e.value)}</code></td>"
        f"<td>{html_mod.escape(json.dumps(e.meta, ensure_ascii=False)[:300])}</td></tr>"
        for e in report.entities[:150])
    edge_rows = "".join(
        f"<tr><td><code>{html_mod.escape(e.src)}</code></td><td>{html_mod.escape(e.relation)}</td>"
        f"<td><code>{html_mod.escape(e.dst)}</code></td><td>{e.weight}</td>"
        f"<td>{html_mod.escape(e.evidence[:110])}</td></tr>" for e in report.edges[:250])
    entities_html = (f"<table><tr><th>Тип</th><th>Значение</th><th>Детали</th></tr>{ent_rows}</table>"
                     + (f"<h3>Связи ({len(report.edges)})</h3><table><tr><th>Откуда</th><th>Связь</th><th>Куда</th>"
                        f"<th>Вес</th><th>Подтверждение</th></tr>{edge_rows}</table>" if edge_rows else ""))

    cov_rows = []
    for m in report.modules:
        details = "".join(
            f"<tr><td>{STATUS_ICON.get(st.status, '?')} {html_mod.escape(st.source)}</td>"
            f"<td>{st.status}</td><td>{st.http_code or ''}</td>"
            f"<td>{html_mod.escape(st.detail or st.error)[:220]}</td></tr>" for st in m.statuses)
        cov_rows.append(
            f"<details><summary><b>{m.module}</b> — проверено {m.checked}, найдено {m.found}, "
            f"недоступно {m.failed}, время {human_ms(m.duration_ms)}</summary>"
            f"<table><tr><th>Источник</th><th>Статус</th><th>HTTP</th><th>Детали</th></tr>{details}</table>"
            + ("".join(f'<div class="warn">{html_mod.escape(e)}</div>' for e in m.errors))
            + "</details>")

    warnings = "".join(f'<div class="warn">⚠ {html_mod.escape(w)}</div>' for w in report.warnings)
    import time as _t
    return _HTML_TPL.format(
        target=html_mod.escape(report.target), target_type=html_mod.escape(report.target_type),
        search_id=report.search_id, started_at=report.started_at, duration=human_ms(report.duration_ms),
        findings=s["findings"], checked=s["sources_checked"], failed=s["sources_failed"],
        coverage=s["coverage"], risk=s["risk_score"], warnings=warnings,
        findings_html="\n".join(parts_findings), entities_html=entities_html,
        coverage_html="".join(cov_rows) or "<i>нет данных</i>",
        version=report.meta.get("version", "1.0.0"),
        generated=_t.strftime("%Y-%m-%d %H:%M UTC", _t.gmtime()))


# ───────────────────────────── сохранение ─────────────────────────────
FORMATS = {
    "txt": (to_text, "txt"), "text": (to_text, "txt"),
    "json": (to_json, "json"), "csv": (to_csv, "csv"), "md": (to_markdown, "md"),
    "markdown": (to_markdown, "md"), "html": (to_html, "html"),
    "mermaid": (to_mermaid, "mmd"), "dot": (to_dot, "dot"),
}


def save(report: Report, path: str | Path, fmt: str | None = None, **kw) -> Path:
    path = Path(path)
    fmt = (fmt or path.suffix.lstrip(".") or "json").lower()
    if fmt not in FORMATS:
        raise ValueError(f"неизвестный формат: {fmt} (доступны: {', '.join(FORMATS)})")
    func, _ext = FORMATS[fmt]
    if path.suffix.lower().lstrip(".") != FORMATS[fmt][1] and not path.suffix:
        path = path.with_suffix("." + FORMATS[fmt][1])
    path.parent.mkdir(parents=True, exist_ok=True)
    content = func(report, **kw) if fmt in {"txt", "text"} else func(report)
    path.write_text(content, encoding="utf-8")
    return path
