"""UI-слой Telegram-бота: клавиатуры, сводки, пивот-переходы, пагинация.

Ключевые улучшения против простого «отправил цель → получил текст»:

* **Пивот (drill-down):** под сводкой появляются кнопки по найденным сущностям —
  нажатие запускает новый поиск по этой сущности (email → его домен, логин → Telegram и т.д.).
* **Пагинация:** находок может быть десятки, Telegram не съест их одним сообщением —
  показываем постранично с кнопками «◀/▶» и счётчиком.
* **Кнопка веб-отчёта** появляется, если задан WEB_PUBLIC_URL.
* **Память отчётов:** последние отчёты держим в памяти с TTL, чтобы кнопки работали
  даже если пользователь вернулся к сообщению позже.
"""
from __future__ import annotations

import html
import time
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from ..core.models import Report
from ..core.utils import human_ms, mask_email, mask_phone

# категории, по которым имеет смысл запускать новый поиск
PIVOT_ICONS = {
    "email": "✉️", "username": "👤", "domain": "🌐", "ip": "📍",
    "telegram": "📨", "phone": "📞", "crypto": "🪙", "person": "🧑", "breach": "🔓",
}
PIVOT_PRIORITY = ["email", "telegram", "username", "domain", "ip", "phone", "crypto"]
MASKED_LABELS = {"email", "phone"}          # в кнопках маскируем персональные данные
CALLBACK_VALUE_LIMIT = 44                   # Telegram: callback_data ≤ 64 байт

# ─────────────────────────── память отчётов ───────────────────────────
REPORTS: dict[str, tuple[float, Report]] = {}
REPORT_TTL = 6 * 3600


def remember(report: Report) -> str:
    REPORTS[report.search_id] = (time.time(), report)
    if len(REPORTS) > 200:
        for key in sorted(REPORTS, key=lambda k: REPORTS[k][0])[:50]:
            REPORTS.pop(key, None)
    return report.search_id


def recall(search_id: str) -> Report | None:
    entry = REPORTS.get(search_id)
    if entry and time.time() - entry[0] < REPORT_TTL:
        return entry[1]
    return None


# ─────────────────────────── пивот-цели ───────────────────────────
def _short(value: str, limit: int = CALLBACK_VALUE_LIMIT) -> str:
    value = (value or "").strip()
    if len(value.encode("utf-8")) <= limit:
        return value
    out = ""
    for char in value:
        if len((out + char).encode("utf-8")) > limit:
            break
        out += char
    return out


def pivot_targets(report: Report, limit: int = 3) -> list[tuple[str, str, str]]:
    """Что можно раскрутить дальше: [(иконка+подпись, тип, значение)].

    Берём только подтверждённые находки (не low) с пригодным для нового поиска значением,
    исключаем ссылки/дубли и обрезаем значение под лимит callback_data.
    """
    found: dict[str, tuple[str, str]] = {}
    for finding in report.findings:
        category = finding.category
        if category not in PIVOT_PRIORITY or finding.confidence == "low":
            continue
        value = (finding.value or "").strip()
        if not value or value.lower() in {"", "—"} or "@" == value:
            continue
        if category in MASKED_LABELS and ":" in value and "@" not in value:
            continue
        if category not in found:
            found[category] = (value, finding.source)
    ordered = sorted(found.items(), key=lambda kv: PIVOT_PRIORITY.index(kv[0]))

    buttons: list[tuple[str, str, str]] = []
    for category, (value, _source) in ordered:
        if len(buttons) >= limit:
            break
        shown = value
        if category == "email":
            shown = mask_email(value)
        elif category == "phone":
            shown = mask_phone(value)
        label = f"{PIVOT_ICONS.get(category, '🔎')} {_short(shown, 26)}"
        buttons.append((label, category, _short(value)))
    return buttons


# ─────────────────────────── сводка с пагинацией ───────────────────────────
CONF_ICON = {"high": "🟢", "medium": "🟡", "low": "⚪"}


def summary_pages(report: Report, per_page: int = 8) -> list[list[Any]]:
    ordered = sorted(report.findings, key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f.confidence],
                                                     f.category))
    return [ordered[i:i + per_page] for i in range(0, len(ordered), per_page)] or [[]]


def summary_text(report: Report, page: int = 0, per_page: int = 8) -> tuple[str, int, int]:
    """Возвращает (текст, текущая страница, всего страниц)."""
    summary = report.summary or report.compute_summary()
    pages = summary_pages(report, per_page)
    page = max(0, min(page, len(pages) - 1))
    findings = pages[page]

    lines = [
        f"🔎 <b>OsintX:</b> <code>{html.escape(report.target)}</code> "
        f"<i>({html.escape(report.target_type)})</i> — {human_ms(report.duration_ms)}",
        f"Находок: <b>{summary['findings']}</b> · источников проверено {summary['sources_checked']} "
        f"(недоступно {summary['sources_failed']}, покрытие {summary['coverage']}%) · "
        f"экспозиция {summary['risk_score']}/100",
    ]
    insights = report.meta.get("insights") or {}
    if insights.get("location"):
        lines.append(f"📍 <b>Где живёт:</b> {html.escape(str(insights['location']))}")
    if insights.get("changes"):
        lines.append(f"🕓 <b>Изменений с прошлых проверок:</b> {insights['changes']} "
                     f"(подробнее — /changes <code>{html.escape(report.target[:24])}</code>)")
    names = insights.get("usernames") or {}
    if names.get("current"):
        line = f"🏷 <b>Юзернеймы:</b> @{html.escape(str(names['current']))}"
        if names.get("previous"):
            line += " · ранее: " + ", ".join(f"@{html.escape(str(n))}" for n in names["previous"][:5])
            line += f" · /usernames <code>{html.escape(report.target[:24])}</code>"
        lines.append(line)
    if summary["coverage"] < 50 and summary["sources_checked"]:
        lines.append("⚠️ Большая часть источников недоступна из вашей сети — результат неполный "
                     "(не путать с «ничего не найдено»).")
    lines.append(f"<i>Страница {page + 1}/{len(pages)}</i>" if len(pages) > 1 else "")
    lines.append("")

    if not report.findings:
        lines.append("Находок нет. Проверьте блок «покрытие источников» в веб-отчёте — "
                     "отказ источника не означает, что данных нет.")
    for finding in findings:
        icon = CONF_ICON.get(finding.confidence, "•")
        title = html.escape(finding.title[:220])
        lines.append(f"{icon} <b>{html.escape(finding.source)}</b>: {title}")
        if finding.url:
            lines.append(f'   <a href="{html.escape(finding.url)}">открыть источник</a>')

    best = [f for f in report.findings if f.confidence == "high"][:1]
    if best and page == 0 and len(report.findings) > 1:
        lines.append("")
        lines.append(f"💡 Всего подтверждённых находок (high): "
                     f"{sum(1 for f in report.findings if f.confidence == 'high')}. "
                     f"Жмите кнопки ниже, чтобы раскрутить найденное дальше.")
    return "\n".join(line for line in lines if line != ""), page, len(pages)


# ─────────────────────────── клавиатуры ───────────────────────────
def report_keyboard(report: Report, page: int = 0, pages: int = 1, *, deep: bool = False,
                    web_url: str = "") -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    pivots = pivot_targets(report)
    if pivots:
        rows.append([InlineKeyboardButton("🔗 Раскрутить дальше:", callback_data="noop")])
        for label, category, value in pivots:
            rows.append([InlineKeyboardButton(label, callback_data=f"pivot:{category}:{value}")])

    nav: list[InlineKeyboardButton] = []
    if pages > 1:
        nav.append(InlineKeyboardButton("◀", callback_data=f"page:{report.search_id}:{page - 1}"))
        nav.append(InlineKeyboardButton(f"{page + 1}/{pages}", callback_data="noop"))
        nav.append(InlineKeyboardButton("▶", callback_data=f"page:{report.search_id}:{page + 1}"))
    if nav:
        rows.append(nav)

    rows.append([
        InlineKeyboardButton("📄 HTML", callback_data=f"dl:html:{report.search_id}"),
        InlineKeyboardButton("🧾 JSON", callback_data=f"dl:json:{report.search_id}"),
        InlineKeyboardButton("📊 CSV", callback_data=f"dl:csv:{report.search_id}"),
    ])
    last_row = [InlineKeyboardButton("🧠 Глубже", callback_data=f"deep:{report.search_id}"),
                InlineKeyboardButton("📈 Граф", callback_data=f"graph:{report.search_id}")]
    if web_url:
        last_row.append(InlineKeyboardButton("🌍 Веб-отчёт",
                                             url=f"{web_url.rstrip('/')}/report/{report.search_id}"))
    rows.append(last_row)
    return InlineKeyboardMarkup(rows)


MODULES = [
    ("email", "✉️ email"),
    ("username", "👤 логины"),
    ("phone", "📞 телефон"),
    ("telegram", "📨 Telegram"),
    ("domain", "🌐 домен"),
    ("ip", "📍 IP"),
    ("person", "🧑 ФИО"),
    ("crypto", "🪙 крипта"),
]


def modules_keyboard(selected: list[str] | None = None) -> InlineKeyboardMarkup:
    """Выбор модулей: нажатие переключает галочку."""
    selected = selected or []
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for name, label in MODULES:
        mark = "✅ " if name in selected else ""
        row.append(InlineKeyboardButton(mark + label, callback_data=f"mod:{name}"))
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("▶️ Запустить поиск",
                                      callback_data="run_modules")])
    rows.append([InlineKeyboardButton("♻️ Сбросить (авто по типу цели)",
                                      callback_data="mod_reset")])
    return InlineKeyboardMarkup(rows)


def settings_keyboard(prefs: dict[str, Any]) -> InlineKeyboardMarkup:
    def mark(flag: bool) -> str:
        return "✅" if flag else "⬜️"

    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"{mark(prefs['deep'])} Глубокий поиск", callback_data="set:deep"),
         InlineKeyboardButton(f"{mark(prefs['variants'])} Варианты написания", callback_data="set:variants")],
        [InlineKeyboardButton(f"{mark(prefs['save'])} Сохранять в историю", callback_data="set:save"),
         InlineKeyboardButton(f"{mark(prefs['use_keys'])} API-ключи", callback_data="set:use_keys")],
        [InlineKeyboardButton("🧹 Забыть настройки", callback_data="set:reset")],
    ])


def prefs_text(prefs: dict[str, Any]) -> str:
    modules = ", ".join(prefs.get("modules") or []) or "авто (по типу цели)"
    return ("⚙️ <b>Настройки поиска</b>\n"
            f"• Глубокий режим: {'вкл' if prefs['deep'] else 'выкл'}\n"
            f"• Варианты написания: {'вкл' if prefs['variants'] else 'выкл'}\n"
            f"• Сохранять в историю: {'да' if prefs['save'] else 'нет'}\n"
            f"• Использовать API-ключи: {'да' if prefs['use_keys'] else 'нет'}\n"
            f"• Модули: {modules}\n\n"
            "Настройки применяются к обычным поискам (текст сообщением, /search).")
