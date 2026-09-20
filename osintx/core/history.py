"""Загрузка сохранённого поиска в объект Report.

Используется веб-интерфейсом (`/report/{id}`) и Telegram-ботом (`/report`, кнопки
скачивания), чтобы отчёт из истории можно было отдать в любом формате.
"""
from __future__ import annotations

import json
from typing import Any

from .models import Finding, ModuleResult, Report, SourceStatus


def report_from_row(data: dict[str, Any]) -> Report:
    """Собирает Report из строки таблицы searches (+ findings)."""
    summary: dict[str, Any] = {}
    try:
        summary = json.loads(data.get("summary_json") or "{}")
    except json.JSONDecodeError:
        summary = {}
    report = Report(target=data["target"], target_type=data["target_type"], search_id=data["id"],
                    started_at=data.get("started_at") or "", duration_ms=data.get("duration_ms") or 0)
    report.summary = summary
    module_names = list((summary.get("modules") or {}).keys()) or ["history"]
    for name in module_names:
        stats = (summary.get("modules") or {}).get(name, {})
        module = ModuleResult(module=name, target=data["target"], duration_ms=stats.get("duration_ms", 0))
        for index in range(int(stats.get("checked", 0))):
            module.statuses.append(SourceStatus(source=f"источник #{index + 1}", category=name, status="found"))
        report.modules.append(module)
    for row in data.get("findings", []):
        try:
            payload = json.loads(row.get("data_json") or "{}")
        except json.JSONDecodeError:
            payload = {}
        report.findings.append(Finding(
            source=row.get("source") or "?", category=row.get("category") or "meta",
            kind=row.get("kind") or "meta", title=row.get("title") or "", url=row.get("url") or "",
            value=row.get("value") or "", data=payload, confidence=row.get("confidence") or "medium"))
    report.compute_summary()
    return report


def load_report(search_id: str, store: Any) -> Report | None:
    """Достаёт отчёт из базы по id поиска."""
    data = store.get_search(search_id)
    if not data:
        return None
    return report_from_row(data)
