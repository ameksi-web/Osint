"""Реестр источников: загрузка, фильтрация, пользовательские расширения.

База источников лежит в ``osintx/data/sites_*.json`` и её можно расширять
без правки кода — файлом ``$OSINTX_DATA_DIR/sites_user.json`` со списком
дополнительных записей (они объединяются с базовыми по имени).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..config import get_settings

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

CATEGORIES = {
    "email": "sites_email.json",
    "username": "sites_username.json",
    "phone": "sites_phone.json",
}

CONFIDENCE_WEIGHT = {"high": 3, "medium": 2, "low": 1}


@lru_cache(maxsize=8)
def _load_file(name: str) -> tuple[dict[str, Any], ...]:
    path = DATA_DIR / name
    if not path.exists():
        return ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise RuntimeError(f"битый файл реестра {path}: {exc}") from exc
    items = payload.get("sites", payload) if isinstance(payload, dict) else payload
    return tuple(items)


def _user_sites() -> dict[str, list[dict[str, Any]]]:
    path = get_settings().data_dir / "sites_user.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    if isinstance(payload, dict):
        for cat, items in payload.items():
            if isinstance(items, list):
                out[cat] = items
    return out


def load_sites(category: str, *, min_confidence: str | None = None,
               tags: list[str] | None = None, include_user: bool = True) -> list[dict[str, Any]]:
    """Все источники категории (email/username) с учётом пользовательских дополнений."""
    filename = CATEGORIES.get(category)
    if not filename:
        raise ValueError(f"неизвестная категория: {category}")
    base = [dict(s) for s in _load_file(filename)]
    extra = _user_sites().get(category, []) if include_user else []
    merged: dict[str, dict[str, Any]] = {s["name"]: s for s in base if s.get("name")}
    for s in extra:
        if s.get("name"):
            merged[s["name"]] = {**merged.get(s["name"], {}), **s, "user_defined": True}
    sites = list(merged.values())

    if min_confidence:
        floor = CONFIDENCE_WEIGHT.get(min_confidence, 0)
        sites = [s for s in sites if CONFIDENCE_WEIGHT.get(s.get("confidence", "medium"), 2) >= floor]
    if tags:
        tagset = {t.lower() for t in tags}
        sites = [s for s in sites if tagset & {t.lower() for t in s.get("tags", [])}]
    sites = [s for s in sites if not s.get("disabled")]
    return sites


def all_categories() -> list[str]:
    return list(CATEGORIES)


def count_sources() -> dict[str, int]:
    out = {}
    for cat in CATEGORIES:
        out[cat] = len(load_sites(cat))
    out["user_extra"] = sum(len(v) for v in _user_sites().values())
    return out


def find_site(category: str, name: str) -> dict[str, Any] | None:
    for site in load_sites(category):
        if site["name"].lower() == name.lower():
            return site
    return None


def describe_site(site: dict[str, Any]) -> str:
    return (f"{site['name']:<22} {site.get('strategy', '?'):<14} "
            f"{site.get('confidence', 'medium'):<7} {site.get('url', '')}")
