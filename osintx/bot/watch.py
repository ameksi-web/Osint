"""Наблюдение за целями: сравнение находок между проверками.

Используется и командой /watch check, и фоновым заданием бота (JobQueue):
если по цели появились НОВЫЕ данные — пользователю приходит уведомление,
если ничего не изменилось — тишина.
"""
from __future__ import annotations

import json
from typing import Any

from ..core.store import Store, get_store
from ..engine import Engine


def fingerprint(findings: list[Any]) -> str:
    """Подпись текущего состояния находок (для сравнения с прошлым разом)."""
    return json.dumps(sorted(f"{f.source}:{f.kind}:{f.value or f.url or f.title}" for f in findings),
                      ensure_ascii=False)


def diff(previous: str | None, current: str) -> list[str]:
    if not previous:
        return []
    try:
        old = set(json.loads(previous))
        new = set(json.loads(current))
    except (json.JSONDecodeError, TypeError):
        return []
    return sorted(new - old)


async def check_target(engine: Engine, store: Store, row: dict[str, Any], *,
                       deep: bool = False, timeout: float = 15) -> dict[str, Any]:
    """Одна проверка цели наблюдения. Возвращает сводку изменений."""
    report = await engine.search(row["target"], deep=deep, variant_probe=False, timeout=timeout,
                                 no_save=not bool(row.get("chat_id")))
    current = fingerprint(report.findings)
    new_items = diff(row.get("last_fingerprint"), current)
    store.watch_update(row["target"], current)
    return {"target": row["target"], "target_type": row.get("target_type") or report.target_type,
            "chat_id": row.get("chat_id"), "findings": len(report.findings),
            "new": new_items, "first_time": not row.get("last_fingerprint"),
            "search_id": report.search_id, "risk": report.summary.get("risk_score", 0),
            "coverage": report.summary.get("coverage", 0)}


async def check_all(*, store: Store | None = None, engine: Engine | None = None,
                    only_due: bool = False, chat_id: int | None = None,
                    limit: int = 10, deep: bool = False) -> list[dict[str, Any]]:
    """Проверяет цели наблюдения (все, для конкретного чата или только «просроченные»)."""
    store = store or get_store()
    engine = engine or Engine()
    rows = store.watch_due() if only_due else store.watch_list(chat_id=chat_id)
    if only_due and chat_id is not None:
        rows = [r for r in rows if r.get("chat_id") in (chat_id, None)]
    results = []
    for row in rows[:limit]:
        try:
            results.append(await check_target(engine, store, row, deep=deep))
        except Exception as exc:  # одна цель не должна ломать остальные
            results.append({"target": row["target"], "error": f"{type(exc).__name__}: {exc}"[:200],
                            "chat_id": row.get("chat_id"), "new": [], "findings": 0})
    return results
