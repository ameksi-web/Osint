"""Импорт публичных датасетов площадок: WhatsMyName и Sherlock.

Зачем: у OsintX свой выверенный реестр (~150 площадок с калибровкой), но в
WhatsMyName (Micah Hoffman, CC BY-SA 4.0) и Sherlock собраны **сотни** сайтов с
готовыми правилами «найден/не найден». Вместо копирования их «на глазок» мы
конвертируем датасет в наш формат и кладём в пользовательский реестр
(``$OSINTX_DATA_DIR/sites_user.json``) — базовые файлы остаются нетронутыми,
датасет можно удалить одной командой.

Конвертация честная: правила из датасета переносятся как есть
(``e_string`` → message_include, ``m_string`` → message_exclude, иначе коды),
источник помечается тегом датасета и пониженным доверием — включать его
проверки стоит вместе с калибровкой, которая отсеивает сайты-обманки.

Команды:
    osintx sources --import-wmn            # скачать и подключить (≈700 площадок)
    osintx sources --import-wmn path.json  # из локального файла
    osintx sources --import-sherlock       # датасет Sherlock
    osintx sources --import-clear          # удалить импортированные
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"

WMN_LICENSE = ("WhatMyName (Micah Hoffman) — CC BY-SA 4.0: "
               "https://github.com/WebBreacher/WhatsMyName")
SHERLOCK_LICENSE = "Sherlock Project — MIT: https://github.com/sherlock-project/sherlock"


def _clean(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def convert_wmn(payload: dict, *, include_nsfw: bool = False, limit: int | None = None) -> list[dict]:
    """WhatsMyName → записи OsintX."""
    sites = payload.get("sites", payload) if isinstance(payload, dict) else payload
    out: list[dict] = []
    for site in sites or []:
        if not isinstance(site, dict) or site.get("valid") is False:
            continue
        cat = _clean(site.get("cat")) or "misc"
        if cat.lower().startswith("xx nsfw") and not include_nsfw:
            continue
        uri = _clean(site.get("uri_check")) or _clean(site.get("uri_pretty"))
        if not uri or "{account}" not in uri:
            continue
        url = uri.replace("{account}", "{username}")
        entry: dict[str, Any] = {
            "name": f"wmn:{_clean(site.get('name')) or url}",
            "url": url,
            "kind": "profile",
            "confidence": "medium" if (_clean(site.get("e_string")) or _clean(site.get("m_string"))) else "low",
            "tags": ["wmn", cat.lower()] + (["nsfw"] if cat.lower().startswith("xx nsfw") else []),
            "dataset": "wmn",
            "dataset_ref": _clean(site.get("uri_pretty")) or uri,
            "protection": site.get("protection") or [],
        }
        e_string, m_string = _clean(site.get("e_string")), _clean(site.get("m_string"))
        e_code, m_code = site.get("e_code"), site.get("m_code")
        if m_string:
            entry["strategy"] = "message_exclude"
            entry["not_found_msgs"] = [m_string]
            if isinstance(m_code, int) and m_code not in (200, 0):
                entry["not_found_codes"] = [m_code]
        elif e_string:
            entry["strategy"] = "message_include"
            entry["found_msgs"] = [e_string]
            if isinstance(e_code, int):
                entry["found_codes"] = [e_code]
        else:
            entry["strategy"] = "status_code"
            entry["found_codes"] = [e_code] if isinstance(e_code, int) else [200]
            entry["not_found_codes"] = [m_code] if isinstance(m_code, int) else [404, 410]
        post_body = _clean(site.get("post_body") or site.get("postBody"))
        if post_body:
            entry["method"] = "POST"
            entry["payload"] = post_body.replace("{account}", "{username}")
            if site.get("headers"):
                entry["headers"] = site["headers"]
        elif site.get("headers"):
            entry["headers"] = site["headers"]
        if site.get("strip_bad_char"):
            entry["strip_bad_char"] = site["strip_bad_char"]
        out.append(entry)
        if limit and len(out) >= limit:
            break
    return out


def convert_sherlock(payload: dict, *, limit: int | None = None) -> list[dict]:
    """Sherlock data.json → записи OsintX."""
    out: list[dict] = []
    for name, site in (payload or {}).items():
        if not isinstance(site, dict):
            continue
        url = _clean(site.get("url"))
        if "{username}" not in url:
            continue
        error_type = _clean(site.get("errorType"))
        error_msg = _clean(site.get("errorMsg"))
        entry: dict[str, Any] = {
            "name": f"sherlock:{name}",
            "url": url,
            "kind": "profile",
            "tags": ["sherlock"] + [_clean(site.get("urlMain"))],
            "dataset": "sherlock",
            "dataset_ref": _clean(site.get("urlMain")),
            "confidence": "medium" if error_type == "status_code" else "low",
        }
        if error_type == "message" and error_msg:
            entry["strategy"] = "message_exclude"
            entry["not_found_msgs"] = [error_msg]
        else:
            entry["strategy"] = "status_code"
            entry["found_codes"] = [200]
            entry["not_found_codes"] = [404, 410]
        out.append(entry)
        if limit and len(out) >= limit:
            break
    return out


def parse_payload(text: str) -> dict:
    """Разбор скачанного файла датасета (JSON)."""
    data = json.loads(text)
    if not isinstance(data, (dict, list)):
        raise ValueError("датасет не похож на JSON-объект")
    return data


async def fetch_dataset(url: str, *, timeout: float = 60) -> str:
    """Скачать датасет (используется httpx из общего клиента)."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": "OsintX/1.0 (+registry import)"})
        resp.raise_for_status()
        return resp.text


def render_wmn(payload: dict, *, include_nsfw: bool = False, limit: int | None = None) -> str:
    """JSON для сайта-импорта: {\"title\": ..., \"sites\": [...]}."""
    return json.dumps({
        "title": "WhatMyName import",
        "updated": _now(),
        "license": WMN_LICENSE,
        "sites": convert_wmn(payload, include_nsfw=include_nsfw, limit=limit),
    }, ensure_ascii=False, indent=1)


def render_sherlock(payload: dict, *, limit: int | None = None) -> str:
    return json.dumps({
        "title": "Sherlock import",
        "updated": _now(),
        "license": SHERLOCK_LICENSE,
        "sites": convert_sherlock(payload, limit=limit),
    }, ensure_ascii=False, indent=1)


def _now() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_import_path(data_dir: Path) -> Path:
    return Path(data_dir) / "sites_user.json"


def merge_username_sites(path: Path, new_sites: list[dict], *, replace_datasets: bool = True) -> dict:
    """Добавить площадки в пользовательский реестр, не затирая свои записи."""
    path = Path(path)
    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    if not isinstance(existing, dict):
        existing = {}
    previous = [s for s in existing.get("username", []) if isinstance(s, dict)]
    datasets = {s.get("dataset") for s in new_sites if s.get("dataset")}
    kept = [s for s in previous
            if not (replace_datasets and s.get("dataset") in datasets)] if datasets else previous
    by_name = {s.get("name"): s for s in kept}
    for site in new_sites:
        by_name.setdefault(site.get("name"), site)
    merged = list(by_name.values())
    payload = {**existing, "username": merged, "updated": _now(),
               "datasets": {**(existing.get("datasets") or {}),
                            **{d: len([s for s in merged if s.get("dataset") == d]) for d in datasets}}}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"added": len(merged) - len(kept), "total_user": len(merged),
            "replaced": len(previous) - len(kept)}


def clear_datasets(path: Path, datasets: set[str] | None = None) -> int:
    """Удалить импортированные площадки из пользовательского реестра."""
    path = Path(path)
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    sites = [s for s in payload.get("username", []) if isinstance(s, dict)]
    targets = datasets or {s.get("dataset") for s in sites if s.get("dataset")}
    kept = [s for s in sites if s.get("dataset") not in targets]
    removed = len(sites) - len(kept)
    payload["username"] = kept
    payload["datasets"] = {k: v for k, v in (payload.get("datasets") or {}).items() if k not in targets}
    payload["updated"] = _now()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return removed
