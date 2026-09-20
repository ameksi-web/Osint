"""Движок OsintX: планирование модулей, запуск, сборка графа, сохранение истории."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from .config import Settings, get_settings
from .core.http import HttpClient
from .core.models import Edge, Entity, ModuleResult, Report
from .core.store import Store, get_store
from .core.utils import detect_target_type, normalize
from .modules.base import Context, Module, entity_id
from .modules.crypto import CryptoModule
from .modules.domain import DomainModule
from .modules.email import EmailModule
from .modules.ip import IpModule
from .modules.person import PersonModule
from .modules.phone import PhoneModule
from .modules.telegram import TelegramModule
from .modules.username import UsernameModule

MODULES: dict[str, Module] = {
    "email": EmailModule(),
    "username": UsernameModule(),
    "phone": PhoneModule(),
    "telegram": TelegramModule(),
    "domain": DomainModule(),
    "ip": IpModule(),
    "person": PersonModule(),
    "crypto": CryptoModule(),
    "breach": None,  # вызывается из email-модуля
}

# какие модули запускать для какого типа цели
PLAN: dict[str, list[str]] = {
    "email": ["email", "domain", "telegram", "username"],
    "username": ["username", "telegram", "email"],
    "telegram": ["telegram", "username"],
    "phone": ["phone", "telegram"],
    "domain": ["domain"],
    "ip": ["ip"],
    "person": ["person"],
    "crypto": ["crypto"],
    "url": ["domain"],
    "unknown": [],
}

DEFAULTS = {
    "deep": False,
    "use_keys": True,
    "modules": None,          # список имён, иначе — по плану
    "no_save": False,
    "variant_probe": False,
    "smtp": False,
    "subdomains": True,
    "timeout": None,
}


class Engine:
    def __init__(self, settings: Settings | None = None, store: Store | None = None):
        self.settings = settings or get_settings()
        self.store = store or get_store()
        self.http: HttpClient | None = None

    # ─────────────────────────── запуск поиска ───────────────────────────
    async def search(self, target: str, **options: Any) -> Report:
        opts = {**DEFAULTS, **options}
        target = normalize(target)
        target_type = opts.get("target_type") or detect_target_type(target)
        started = time.perf_counter()
        report = Report(target=target, target_type=target_type)
        report.meta.update({
            "options": {k: v for k, v in opts.items() if k != "on_event"},
            "version": _version(),
            "started_human": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        })
        module_names = opts.get("modules") or PLAN.get(target_type, [])
        if not module_names:
            report.warnings.append(f"Тип цели «{target_type}» не поддерживается — уточните данные "
                                   f"(email, логин, телефон, домен, IP, ФИО, криптоадрес)")
            report.compute_summary()
            return report

        on_event = opts.get("on_event")
        cancel_event = opts.get("cancel_event")
        timeout = opts.get("timeout") or self.settings.timeout
        async with HttpClient(self.settings, timeout=timeout) as http:
            self.http = http
            ctx = Context(settings=self.settings, http=http, store=self.store, options=opts,
                          emit=on_event or _noop, cancel_event=cancel_event)
            await ctx.notify(kind="start", target=target, target_type=target_type, modules=module_names)
            for name in module_names:
                if ctx.cancelled():
                    report.warnings.append("Поиск остановлен пользователем")
                    break
                module = self._build(name, opts)
                if module is None:
                    continue
                await ctx.notify(kind="module_start", module=name, title=module.title)
                module_result = ModuleResult(module=name, target=target)
                module_started = time.perf_counter()
                try:
                    await module.run(ctx, target, module_result)
                except Exception as exc:  # модуль не должен ломать весь поиск
                    module_result.errors.append(f"Модуль {name} упал: {type(exc).__name__}: {exc}")
                module_result.duration_ms = int((time.perf_counter() - module_started) * 1000)
                report.merge(module_result)
                await ctx.notify(kind="module_done", module=name, findings=len(module_result.findings),
                                 checked=module_result.checked, duration_ms=module_result.duration_ms)
            report.meta["http_stats"] = http.stats.to_dict()
        report.duration_ms = int((time.perf_counter() - started) * 1000)
        self._finalize(report)
        if not opts.get("no_save"):
            try:
                self.store.save_report(report)
            except Exception as exc:  # pragma: no cover
                report.warnings.append(f"Не удалось сохранить поиск в БД: {exc}")
        if on_event:
            await _call(on_event, {"kind": "done", "search_id": report.search_id,
                                   "findings": len(report.findings), "duration_ms": report.duration_ms,
                                   "summary": report.summary})
        return report

    def search_sync(self, target: str, **options: Any) -> Report:
        return asyncio.run(self.search(target, **options))

    # ─────────────────────────── внутреннее ───────────────────────────
    def _build(self, name: str, opts: dict[str, Any]) -> Module | None:
        if name == "email":
            return EmailModule(include_breaches=True, include_sites=True,
                               smtp=bool(opts.get("smtp")), variants=bool(opts.get("variant_probe", True)))
        if name == "username":
            return UsernameModule(calibrate=not opts.get("no_calibrate"), variants=bool(opts.get("variant_probe")),
                                  max_sites=None if not opts.get("max_sites") else int(opts["max_sites"]))
        if name == "domain":
            return DomainModule(brute_subdomains=bool(opts.get("subdomains", True)),
                                wordlist_limit=400 if opts.get("deep") else 150)
        if name == "person":
            return PersonModule(probe_limit=40 if opts.get("deep") else 20)
        return MODULES.get(name)

    def _finalize(self, report: Report) -> None:
        report.dedupe()
        seen_entities: dict[str, Entity] = {}
        for module in report.modules:
            for ent in module.meta.get("entities", []):
                key = f"{ent['type']}:{ent['value']}"
                if key not in seen_entities:
                    seen_entities[key] = Entity(type=ent["type"], value=ent["value"], meta=ent.get("meta", {}))
                else:
                    seen_entities[key].meta.update(ent.get("meta", {}))
        # сущности из находок
        for f in report.findings:
            if f.value and f.category in {"email", "username", "phone", "domain", "ip", "telegram", "crypto"}:
                key = f"{f.category}:{f.value}"
                seen_entities.setdefault(key, Entity(type=f.category, value=f.value, meta={}))
        if report.target_type in seen_entities or True:
            seen_entities.setdefault(entity_id(report.target_type, report.target),
                                     Entity(type=report.target_type, value=report.target, meta={}))
        report.entities = list(seen_entities.values())

        edges: dict[tuple[str, str, str], Edge] = {}
        for module in report.modules:
            for edge in module.meta.get("edges", []):
                key = (edge["src"], edge["dst"], edge["relation"])
                existing = edges.get(key)
                if existing is None or edge.get("weight", 0) > existing.weight:
                    edges[key] = Edge(src=edge["src"], dst=edge["dst"], relation=edge["relation"],
                                      weight=float(edge.get("weight", 1.0)), evidence=edge.get("evidence", ""))
        report.edges = list(edges.values())
        report.compute_summary()

    # ─────────────────────────── вспомогательное ───────────────────────────
    def modules_for(self, target: str) -> list[str]:
        return PLAN.get(detect_target_type(target), [])


async def _noop(_: dict[str, Any]) -> None:
    return None


async def _call(fn: Callable[[dict[str, Any]], Any], payload: dict[str, Any]) -> None:
    result = fn(payload)
    if asyncio.iscoroutine(result):
        await result


def _version() -> str:
    from . import __version__
    return __version__


def quick_search(target: str, **options: Any) -> Report:
    """Удобная точка входа для бота и скриптов."""
    return Engine().search_sync(target, **options)
