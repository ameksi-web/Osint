"""Веб-приложение OsintX: форма поиска, живые результаты (SSE), отчёты, история, базы.

Запуск:
    osintx serve                 # http://0.0.0.0:8000
    uvicorn osintx.web.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import get_settings
from ..core.models import Report
from ..core.registry import count_sources, load_sites
from ..core.store import get_store
from ..core.utils import detect_target_type
from ..engine import Engine, PLAN
from ..report import FORMATS, to_mermaid, to_text

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="OsintX", version=__version__,
              description="OSINT-поиск по открытым источникам: email, логины, телефон, Telegram, домен, IP, ФИО, крипта")

JOBS: dict[str, dict[str, Any]] = {}
JOB_TTL = 3600


def _gc_jobs() -> None:
    now = time.time()
    for jid in [j for j, job in JOBS.items() if now - job["created"] > JOB_TTL]:
        JOBS.pop(jid, None)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    store = get_store()
    sources = count_sources()
    stats = store.stats()
    return templates.TemplateResponse(request, "index.html", {
        "version": __version__,
        "source_counts": sources,
        "stats": stats,
        "history": store.history(limit=25),
        "datasets": store.datasets(),
        "plan": {k: v for k, v in PLAN.items() if v},
        "env": {
            "mtproto": bool(get_settings().tg_api_id and get_settings().tg_api_hash),
            "bot": bool(get_settings().bot_token),
            "api_keys": sorted([k for k, v in get_settings().keys.items() if v]),
            "searxng": bool(get_settings().searxng_url),
        },
    })


@app.get("/api/meta")
async def api_meta() -> JSONResponse:
    return JSONResponse({
        "version": __version__,
        "sources": count_sources(),
        "plan": {k: v for k, v in PLAN.items() if v},
        "capabilities": {
            "email": "валидация, DNS/SPF/DMARC/DKIM, провайдер, disposable, Gravatar, ~200 регистраций, утечки",
            "username": "проверка логина по реестру площадок с калибровкой + GitHub/GitLab/Keybase/Reddit/HN API",
            "phone": "libphonenumber (страна/оператор/тип/таймзона) + онлайн-API по ключам",
            "telegram": "t.me (канал/бот/юзер), подписчики, публичные посты, fragment.com; MTProto — ID/DC/поиск",
            "domain": "DNS, RDAP, crt.sh, поддомены, urlscan, Wayback, security.txt, технологии",
            "ip": "гео, ASN, BGP, RDAP, Shodan InternetDB (порты/CVE), Tor, спам-базы",
            "person": "варианты ФИО, Wikidata/Wikipedia, OpenSanctions, проверка логинов, MX-проверка адресов",
            "breach": "XposedOrNot (без ключа), HIBP/LeakCheck/DeHashed/IntelX (с ключами), локальные базы",
            "crypto": "Bitcoin (blockstream), Ethereum (blockchair/ethplorer)",
        },
    })


@app.post("/api/search")
async def api_search(payload: dict[str, Any]) -> JSONResponse:
    _gc_jobs()
    target = (payload.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "Не указана цель поиска")
    job_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    JOBS[job_id] = {"created": time.time(), "queue": queue, "report": None, "target": target,
                    "status": "running", "events": []}

    async def on_event(ev: dict[str, Any]) -> None:
        JOBS[job_id]["events"].append(ev)
        await queue.put(ev)

    async def runner() -> None:
        try:
            engine = Engine()
            report = await engine.search(
                target,
                deep=bool(payload.get("deep")),
                variant_probe=bool(payload.get("variants")),
                smtp=bool(payload.get("smtp")),
                modules=[m for m in (payload.get("modules") or []) if m] or None,
                use_keys=payload.get("use_keys", True) is not False,
                timeout=float(payload.get("timeout") or 0) or None,
                on_event=on_event)
            JOBS[job_id]["report"] = report
            JOBS[job_id]["status"] = "done"
        except Exception as exc:  # pragma: no cover
            JOBS[job_id]["status"] = "error"
            await queue.put({"kind": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            await queue.put({"kind": "__end__"})

    asyncio.create_task(runner())
    return JSONResponse({"job_id": job_id, "target": target, "target_type": detect_target_type(target)})


@app.get("/api/stream/{job_id}")
async def api_stream(job_id: str) -> StreamingResponse:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Задача не найдена или истекла")

    async def generator():
        # сначала отдаём уже накопленные события, затем новые
        sent = 0
        while True:
            events = JOBS.get(job_id, {}).get("events", [])
            while sent < len(events):
                yield f"data: {json.dumps(events[sent], ensure_ascii=False)}\n\n"
                sent += 1
            if JOBS.get(job_id, {}).get("status") != "running" and sent >= len(JOBS.get(job_id, {}).get("events", [])):
                break
            try:
                ev = await asyncio.wait_for(job["queue"].get(), timeout=25)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                continue
            if ev.get("kind") == "__end__":
                while sent < len(JOBS.get(job_id, {}).get("events", [])):
                    events = JOBS[job_id]["events"]
                    yield f"data: {json.dumps(events[sent], ensure_ascii=False)}\n\n"
                    sent += 1
                break
            # события отдаём через общий буфер ниже
        yield f"data: {json.dumps({'kind': 'stream_end'})}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/report/{job_id}")
async def api_report(job_id: str) -> JSONResponse:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Задача не найдена")
    if job["status"] == "running" and job["report"] is None:
        return JSONResponse({"status": "running", "events": len(job["events"])})
    if job["report"] is None:
        return JSONResponse({"status": job["status"]}, status_code=500)
    report: Report = job["report"]
    return JSONResponse(report.to_dict())


@app.get("/report/{search_id}", response_class=HTMLResponse)
async def report_page(request: Request, search_id: str) -> HTMLResponse:
    report = _load_report(search_id)
    if report is None:
        raise HTTPException(404, "Отчёт не найден")
    report.compute_summary()
    return templates.TemplateResponse(request, "report.html", {
        "version": __version__, "report": report, "summary": report.summary,
        "report_html": _html_fragment(report), "mermaid": to_mermaid(report),
        "text_report": to_text(report, verbose=False),
    })


@app.get("/report/{search_id}/download")
async def report_download(search_id: str, fmt: str = "json") -> PlainTextResponse:
    report = _load_report(search_id)
    if report is None:
        raise HTTPException(404, "Отчёт не найден")
    if fmt not in FORMATS:
        raise HTTPException(400, f"Формат {fmt} не поддерживается. Доступны: {', '.join(FORMATS)}")
    func, ext = FORMATS[fmt]
    content = func(report)
    return PlainTextResponse(content, media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="osintx_{search_id}.{ext}"'})


@app.get("/api/history")
async def api_history(limit: int = 50, target: str | None = None) -> JSONResponse:
    return JSONResponse(get_store().history(limit=limit, target=target))


@app.get("/api/search/{search_id}")
async def api_search_by_id(search_id: str) -> JSONResponse:
    data = get_store().get_search(search_id)
    if not data:
        raise HTTPException(404, "Не найдено")
    return JSONResponse(data)


@app.get("/api/graph")
async def api_graph(target: str, type: str | None = None, depth: int = 2) -> JSONResponse:
    store = get_store()
    etype = type or detect_target_type(target)
    data = store.entity_neighbours(etype, target, depth=depth)
    data["mermaid"] = _mermaid_from_edges(data["edges"])
    return JSONResponse(data)


@app.get("/api/sources")
async def api_sources(category: str = "username", tags: str | None = None,
                      min_confidence: str | None = None) -> JSONResponse:
    sites = load_sites(category, tags=[t for t in tags.split(",")] if tags else None,
                       min_confidence=min_confidence)
    return JSONResponse({"category": category, "count": len(sites), "sites": sites})


@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    return JSONResponse(get_store().stats())


# ───────────────────────── внешние базы ─────────────────────────
@app.post("/api/datasets")
async def api_dataset_upload(file: UploadFile = File(...), name: str = Form(""), kind: str = Form("auto"),
                             column: str = Form("")) -> JSONResponse:
    settings = get_settings()
    target = settings.data_dir / "uploads" / (file.filename or "dataset.csv")
    target.parent.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    target.write_bytes(content)
    result = get_store().import_dataset(target, name=name or Path(file.filename or "dataset").stem,
                                        kind=kind, value_column=column or None)
    return JSONResponse(result)


@app.delete("/api/datasets/{name}")
async def api_dataset_drop(name: str) -> JSONResponse:
    store = get_store()
    store.drop_dataset(name)
    return JSONResponse({"dropped": name})


@app.get("/api/datasets")
async def api_datasets() -> JSONResponse:
    store = get_store()
    return JSONResponse({"datasets": store.datasets(),
                         "search": store.search_local("") if False else []})


@app.get("/api/datasets/search")
async def api_dataset_search(value: str, limit: int = 50) -> JSONResponse:
    return JSONResponse({"value": value, "hits": get_store().search_local(value, limit=limit)})


# ───────────────────────── служебное ─────────────────────────
@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "version": __version__, "jobs": len(JOBS)})


@app.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request, category: str = "username") -> HTMLResponse:
    sites = load_sites(category)
    return templates.TemplateResponse(request, "sources.html", {
        "version": __version__, "category": category, "sites": sites, "counts": count_sources(),
        "categories": ["username", "email", "phone"]})


def _load_report(search_id: str) -> Report | None:
    for job in JOBS.values():
        rep = job.get("report")
        if rep and rep.search_id == search_id:
            return rep
    data = get_store().get_search(search_id)
    if not data:
        return None
    return _report_from_row(data)


def _report_from_row(data: dict[str, Any]) -> Report:
    from ..core.models import Finding, ModuleResult, SourceStatus

    summary = {}
    try:
        summary = json.loads(data.get("summary_json") or "{}")
    except json.JSONDecodeError:
        pass
    report = Report(target=data["target"], target_type=data["target_type"], search_id=data["id"],
                    started_at=data.get("started_at") or "", duration_ms=data.get("duration_ms") or 0)
    report.summary = summary
    module_names = list((summary.get("modules") or {}).keys()) or ["history"]
    for name in module_names:
        mstats = (summary.get("modules") or {}).get(name, {})
        module = ModuleResult(module=name, target=data["target"], duration_ms=mstats.get("duration_ms", 0))
        for i in range(mstats.get("checked", 0)):
            module.statuses.append(SourceStatus(source=f"источник #{i + 1}", category=name, status="found"))
        report.modules.append(module)
    for row in data["findings"]:
        try:
            payload = json.loads(row["data_json"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        report.findings.append(Finding(
            source=row["source"], category=row["category"], kind=row["kind"], title=row["title"],
            url=row["url"] or "", value=row["value"] or "", data=payload,
            confidence=row["confidence"] or "medium"))
    report.compute_summary()
    return report


def _html_fragment(report: Report) -> str:
    """Готовый HTML-отчёт (тот же рендерер, что и для файла)."""
    from ..report import to_html

    html = to_html(report)
    start = html.find("<body>")
    end = html.find("</body>")
    return html[start + 6:end] if start != -1 and end != -1 else html


def _mermaid_from_edges(edges: list[dict[str, Any]]) -> str:
    lines = ["graph LR"]
    for e in edges[:200]:
        src = e["src"].replace('"', "'")
        dst = e["dst"].replace('"', "'")
        lines.append(f'    "{src}" -->|{e["relation"]}| "{dst}"')
    return "\n".join(lines)
