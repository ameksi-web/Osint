"""CLI OsintX — консольный интерфейс (Rich).

Примеры:
    osintx search ivan.petrov@example.com
    osintx search @durov --deep --html --out durov.html
    osintx search "Иван Петров" --modules person --variants
    osintx history --limit 20
    osintx dataset-import base.csv --name mydump
    osintx dataset-search user@example.com
    osintx password 'qwerty123'
    osintx serve --port 8000
    osintx bot
    osintx doctor
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .config import get_settings
from .core.registry import count_sources, load_sites, describe_site
from .core.store import get_store
from .core.utils import detect_target_type
from .engine import Engine, PLAN
from .report import FORMATS, save as save_report, to_text

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    RICH = True
except ImportError:  # pragma: no cover
    RICH = False

console = Console() if RICH else None


def _print(msg: str = "", **kw) -> None:
    if console:
        console.print(msg, **kw)
    else:
        print(msg)


def _rule(title: str = "") -> None:
    if console:
        console.rule(f"[bold cyan]{title}" if title else "")
    else:
        print("-" * 60, title)


def _kv_table(title: str, data: dict, key_name: str = "Параметр") -> None:
    if console:
        table = Table(title=title, show_header=True, header_style="bold magenta", expand=False)
        table.add_column(key_name)
        table.add_column("Значение")
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)[:200]
            table.add_row(str(k), str(v))
        console.print(table)
    else:
        print(f"== {title} ==")
        for k, v in data.items():
            print(f"  {k}: {v}")


# ───────────────────────────── поиск ─────────────────────────────
class SearchProgress:
    """Живой прогресс поиска в терминале (по событиям движка)."""

    def __init__(self, use_rich: bool = True):
        self.events: list[str] = []
        self.hit_count = 0
        self.module = ""
        self.use_rich = use_rich and RICH
        self.live = None
        self._status = None

    async def on_event(self, ev: dict) -> None:
        kind = ev.get("kind")
        if kind == "hit":
            self.hit_count += 1
            line = (f"[green]●[/green] найдено: {ev.get('source')} — {str(ev.get('url') or '')[:80]}"
                    if self.use_rich else f"● найдено: {ev.get('source')} — {ev.get('url')}")
            self.events.append(line)
            if self.live:
                self.live.update(self._render())
        elif kind == "module_start":
            self.module = ev.get("title", ev.get("module", ""))
            if self.live:
                self.live.update(self._render())
        elif kind == "stage":
            self.module = ev.get("message", self.module)
            if self.live:
                self.live.update(self._render())

    def _render(self):
        from rich.panel import Panel
        lines = [f"[bold]Модуль:[/bold] {self.module}", f"[bold]Найдено:[/bold] {self.hit_count}", ""]
        lines += self.events[-14:]
        return Panel("\n".join(lines), title="OsintX — поиск идёт", border_style="cyan")


def cmd_search(args: argparse.Namespace) -> int:
    settings = get_settings()
    progress = SearchProgress(use_rich=not args.quiet)

    modules = [m.strip() for m in args.modules.split(",")] if args.modules else None
    target = args.target

    async def run():
        engine = Engine(settings)
        if progress.use_rich and not args.quiet:
            with Live(progress._render(), console=console, refresh_per_second=4) as live:
                progress.live = live
                return await engine.search(
                    target, deep=args.deep, modules=modules, use_keys=not args.no_keys,
                    variant_probe=args.variants, smtp=args.smtp, no_save=args.no_save,
                    timeout=args.timeout, target_type=args.type, on_event=progress.on_event,
                    max_sites=args.max_sites, no_calibrate=args.no_calibrate,
                    subdomains=not args.no_subdomains)
        return await engine.search(
            target, deep=args.deep, modules=modules, use_keys=not args.no_keys,
            variant_probe=args.variants, smtp=args.smtp, no_save=args.no_save,
            timeout=args.timeout, target_type=args.type, on_event=progress.on_event,
            max_sites=args.max_sites, no_calibrate=args.no_calibrate, subdomains=not args.no_subdomains)

    if not args.quiet:
        _rule(f"OsintX {__version__} — поиск по цели: {target}")
        _print(f"Тип цели: [bold]{detect_target_type(target)}[/bold]"
               if RICH else f"Тип цели: {detect_target_type(target)}")
    report = asyncio.run(run())

    # файлы отчётов пишем всегда — даже в quiet-режиме (удобно для скриптов)
    written: list[Path] = []
    if args.out:
        fmt = args.format or Path(args.out).suffix.lstrip(".") or "json"
        written.append(save_report(report, args.out, fmt=fmt if fmt in FORMATS else None))
    for extra_fmt in (args.json_out, args.html_out, args.md_out, args.csv_out):
        if extra_fmt:
            fmt = Path(extra_fmt).suffix.lstrip(".") or Path(extra_fmt).name.split(".")[-1]
            written.append(save_report(report, extra_fmt, fmt=fmt if fmt in FORMATS else None))

    if args.quiet:
        print(report.to_json())
        for path in written:
            _print(f"Сохранено: {path}") if not RICH else None
        return 0

    _print(to_text(report, verbose=args.verbose))
    for path in written:
        _print(f"\n[green]Отчёт сохранён:[/green] {path}" if RICH else f"\nОтчёт сохранён: {path}")
    return 0


# ───────────────────────────── история/БД ─────────────────────────────
def cmd_changes(args: argparse.Namespace) -> int:
    """osintx changes <цель> — как менялись ник/имя/био/город между проверками."""
    from .insights import format_changes

    store = get_store()
    target = args.target
    changes = store.profile_changes(target, limit=args.limit)
    stats = store.snapshot_stats(target)
    latest = store.latest_snapshots(target)
    if not stats["total"]:
        _print(f"По цели «{target}» наблюдений пока нет.\n"
               f"Выполните поиск (osintx search {target}) — OsintX запомнит публичные поля "
               f"(ник, имя, био, город, подписчики) и будет показывать изменения при следующих проверках.\n"
               f"Автоматически проверять цель можно командой: osintx watch add {target}")
        return 0
    print(format_changes(changes, target))
    print(f"\nНаблюдений всего: {stats['total']} (полей: {len(stats['fields'])})")
    if latest:
        print("\nПоследние известные значения:")
        for key, value in sorted(latest.items()):
            print(f"  {key} = {value[:100]}")
    return 0


def cmd_geo(args: argparse.Namespace) -> int:
    """osintx geo <цель> — где живёт: страна/город по публичным профилям."""
    from .engine import Engine

    engine = Engine()
    modules = (["geo", "telegram", "username", "wayback"] if args.deep
               else ["geo", "telegram", "username"])
    report = engine.search_sync(args.target, modules=modules, no_save=args.no_save)

    geo = [f for f in report.findings if f.category == "geo"]
    if not geo:
        _print("Гео-данных не найдено. Это не значит, что их нет: проверьте блок «источники» ниже — "
               "если источники помечены blocked/error, сеть не дала получить данные.")
    else:
        for f in geo:
            print(f"[{f.confidence}] {f.title}")
            if f.url:
                print(f"    ↳ {f.url}")
            if f.evidence:
                print(f"    доказательство: {f.evidence[:200]}")
    location = report.meta.get("insights", {}).get("location")
    if location:
        print(f"\n📍 Вероятное местоположение: {location}")
    if args.verbose:
        print()
        print(report.to_text(verbose=True))
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    store = get_store()
    rows = store.history(limit=args.limit, target=args.target)
    if not rows:
        _print("История пуста.")
        return 0
    if RICH:
        table = Table(title=f"История поисков ({len(rows)})", header_style="bold magenta")
        for col in ("ID", "Цель", "Тип", "Когда", "Находок", "Покрытие", "Риск"):
            table.add_column(col)
        for r in rows:
            table.add_row(r["id"][:10], r["target"][:32], r["target_type"], (r["started_at"] or "")[:19],
                          str(r["findings"]), f"{r['coverage']}%", str(r["risk"]))
        console.print(table)
    else:
        for r in rows:
            print(f"{r['id'][:10]} {r['started_at']} {r['target_type']:8} {r['target'][:40]} "
                  f"находок={r['findings']} покрытие={r['coverage']}%")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    store = get_store()
    data = store.get_search_by_target(args.target) if args.target else store.get_search(args.search_id)
    if not data:
        _print("Не найдено в истории.")
        return 1
    _kv_table(f"Поиск {data['id']}", {
        "Цель": data["target"], "Тип": data["target_type"], "Начато": data["started_at"],
        "Находок": data["findings"], "Покрытие": f"{data['coverage']}%", "Экспозиция": f"{data['risk']}/100"})
    for f in data["findings"]:
        conf = {"high": "[green]высокая[/green]", "medium": "[yellow]средняя[/yellow]",
                "low": "[dim]низкая[/dim]"}.get(f["confidence"], f["confidence"])
        _print(f"\n[{conf}] {f['source']} — {f['title']}")
        if f["url"]:
            _print(f"    {f['url']}")
        if f["data_json"]:
            try:
                payload = json.loads(f["data_json"])
                _print("    " + json.dumps(payload, ensure_ascii=False)[:300])
            except json.JSONDecodeError:
                pass
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    store = get_store()
    stats = store.stats()
    _kv_table("База OsintX", {
        "Файл БД": stats["db_path"], "Поисков": stats["searches"], "Находок": stats["findings"],
        "Сущностей в графе": stats["entities"], "Связей": stats["edges"],
        "Находки по категориям": stats["findings_by_category"], "Сущности по типам": stats["entities_by_type"]})
    if stats["datasets"]:
        _kv_table("Загруженные внешние базы", {d["name"]: f"{d['rows']} строк, {d['imported_at']}"
                                               for d in stats["datasets"]})
    return 0


# ───────────────────────────── датасеты ─────────────────────────────
def cmd_dataset_import(args: argparse.Namespace) -> int:
    store = get_store()
    result = store.import_dataset(args.path, name=args.name, kind=args.kind, value_column=args.column)
    _print(f"[green]Импортировано:[/green] {result['dataset']} — {result['rows']} строк, "
           f"типы: {', '.join(result['kinds'])}" if RICH else
           f"Импортировано {result['dataset']}: {result['rows']} строк")
    _print("Теперь эти данные проверяются автоматически в каждом поиске (источник local-datasets).")
    return 0


def cmd_dataset_search(args: argparse.Namespace) -> int:
    store = get_store()
    hits = store.search_local(args.value, limit=args.limit)
    if not hits:
        _print("Совпадений нет.")
        return 0
    if RICH:
        table = Table(title=f"Найдено в локальных базах: {len(hits)}")
        for col in ("База", "Тип", "Значение", "Доп. данные"):
            table.add_column(col)
        for h in hits:
            table.add_row(str(h.get("dataset")), str(h.get("kind")), str(h.get("value")),
                          str(h.get("extra"))[:120])
        console.print(table)
    else:
        for h in hits:
            print(json.dumps(h, ensure_ascii=False))
    return 0


def cmd_dataset_list(args: argparse.Namespace) -> int:
    rows = get_store().datasets()
    if not rows:
        _print("Внешние базы не загружены. Загрузите: osintx dataset-import <файл.csv>")
        return 0
    _kv_table("Внешние базы в OsintX", {r["name"]: f"{r['rows']} строк, {r['source']} ({r['imported_at']})"
                                        for r in rows})
    return 0


def cmd_dataset_drop(args: argparse.Namespace) -> int:
    get_store().drop_dataset(args.name)
    _print(f"База «{args.name}» удалена из индекса.")
    return 0


# ───────────────────────────── прочее ─────────────────────────────
def cmd_password(args: argparse.Namespace) -> int:
    from .modules.breach import check_password_pwned
    from .core.http import HttpClient

    password = args.password if args.password != "-" else sys.stdin.readline().rstrip("\n")
    if not password:
        _print("Пустой пароль.")
        return 1

    async def run():
        async with HttpClient(get_settings()) as http:
            from .modules.base import Context
            from .core.store import get_store as gs
            ctx = Context(settings=get_settings(), http=http, store=gs())
            return await check_password_pwned(password, ctx)

    result = asyncio.run(run())
    if not result.get("checked"):
        _print(f"Не удалось проверить: {result.get('error')}")
        return 1
    if result["pwned"]:
        _print(f"[bold red]ПАРОЛЬ В УТЕЧКАХ:[/bold red] встречается {result['count']:,} раз в базе HIBP. "
               f"Смените его везде, где он использовался." if RICH else
               f"ПАРОЛЬ В УТЕЧКАХ: {result['count']} совпадений")
    else:
        _print("[green]В базе HIBP (800+ млн утёкших паролей) пароль не найден.[/green]"
               if RICH else "Пароль в базе не найден.")
    _print("Проверка выполнена по k-anonymity: наружу уходили только первые 5 символов SHA-1 хеша, "
           "сам пароль не передавался.")
    return 0


def cmd_sources(args: argparse.Namespace) -> int:
    if args.stats:
        _kv_table("Количество источников по категориям", count_sources())
        return 0
    sites = load_sites(args.category, min_confidence=args.min_confidence,
                       tags=[t.strip() for t in args.tags.split(",")] if args.tags else None)
    if RICH:
        table = Table(title=f"Источники ({args.category}): {len(sites)}", header_style="bold magenta")
        for col in ("Имя", "Стратегия", "Доверие", "URL", "Теги", "Контроль", "Примечание"):
            table.add_column(col, overflow="fold")
        for s in sites:
            table.add_row(s["name"], s.get("strategy", ""), s.get("confidence", ""), s.get("url", ""),
                          ",".join(s.get("tags", [])), s.get("control_user", "") or "—",
                          (s.get("note", "") or "")[:80])
        console.print(table)
    else:
        for s in sites:
            print(describe_site(s))
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    store = get_store()
    etype = args.type or detect_target_type(args.target)
    data = store.entity_neighbours(etype, args.target, depth=args.depth)
    if not data["edges"]:
        _print("Связей для этой цели в базе нет — сначала выполните поиск.")
        return 1
    if args.format == "mermaid":
        print("graph LR")
        for e in data["edges"]:
            print(f'    "{e["src"]}" -->|{e["relation"]}| "{e["dst"]}"')
    else:
        print("digraph osintx {")
        for e in data["edges"]:
            print(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["relation"]}"];')
        print("}")
    return 0


def cmd_net(args: argparse.Namespace) -> int:
    """osintx net — почему не подключается Telegram / pip (DNS, TCP, TLS)."""
    from .netcheck import diagnose

    report, ok = diagnose()
    print(report)
    return 0 if ok else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    """Проверка окружения: зависимости, доступность источников, ключи."""
    settings = get_settings()
    checks: dict[str, str] = {}
    for module in ("httpx", "phonenumbers", "dns", "fastapi", "telegram", "telethon", "rich"):
        try:
            __import__(module)
            checks[f"python-модуль {module}"] = "✅ установлен"
        except ImportError:
            checks[f"python-модуль {module}"] = "❌ НЕТ (pip install -r requirements.txt)"
    checks["системные CA-сертификаты"] = settings.ca_bundle or "по умолчанию (certifi)"
    checks["прокси"] = settings.proxy or "не используется"
    checks["ключи API"] = ", ".join(f"{k}:{'✅' if v else '—'}" for k, v in settings.keys.items())
    if not any(settings.keys.values()):
        checks["ключи API"] += "  (все опциональны — базовые источники работают без ключей)"
    checks["Telegram MTProto"] = ("✅ настроен" if settings.tg_api_id and settings.tg_api_hash
                                  else "— не настроен (числовой ID/DC/поиск по сообщениям недоступны)")
    checks["Telegram-бот"] = "✅ токен есть" if settings.bot_token else "— токен не задан"
    checks["каталог данных"] = str(settings.data_dir)

    hosts = [("GitHub API", "https://api.github.com"), ("PyPI", "https://pypi.org"),
             ("DNS-over-HTTPS", "https://dns.google/resolve?name=example.com&type=A"),
             ("crt.sh", "https://crt.sh/?q=example.com&output=json"),
             ("RDAP", "https://rdap.org/domain/example.com"), ("t.me", "https://t.me/durov"),
             ("HIBP (пароли)", "https://api.pwnedpasswords.com/range/5BAA6"),
             ("XposedOrNot", "https://api.xposedornot.com/v1/check-email/test@example.com")]

    async def run():
        from .core.http import HttpClient
        out = {}
        async with HttpClient(settings, timeout=8) as http:
            for name, url in hosts:
                ok, detail = await http.check_reachable(url)
                out[name] = f"{'✅' if ok else '❌'} {detail}"
        return out

    checks.update(asyncio.run(run()))
    _kv_table("Диагностика OsintX", checks, key_name="Проверка")
    _print("\nЕсли много ❌ — проверьте интернет, VPN/прокси (OSINTX_PROXY) или попробуйте позже.\n"
           "Часть сайтов блокирует автоматические проверки — это нормально, они будут помечены "
           "как blocked/error, а не как «не найдено».")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    from .wizard import run_wizard
    return run_wizard(args)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    settings = get_settings()
    host = args.host or settings.host
    port = args.port or settings.port
    _print(f"OsintX Web UI: http://{host}:{port}  (Ctrl+C — остановить)")
    uvicorn.run("osintx.web.app:app", host=host, port=port, reload=args.reload, log_level="info")
    return 0


def cmd_bot(args: argparse.Namespace) -> int:
    from .bot import run as bot_run
    if getattr(args, "check", False):
        from argparse import Namespace
        return bot_run.check_bot(Namespace(token=getattr(args, "token", "")))
    return bot_run.main()


def cmd_tgauth(args: argparse.Namespace) -> int:
    from .tg_auth import main as auth_main
    return auth_main()


def cmd_watch(args: argparse.Namespace) -> int:
    store = get_store()
    if args.action == "add":
        store.watch_add(args.target, args.type or detect_target_type(args.target), args.note or "")
        _print(f"Добавлено в наблюдение: {args.target}")
    elif args.action == "list":
        rows = store.watch_list()
        if not rows:
            _print("Список наблюдения пуст.")
            return 0
        for r in rows:
            _print(f"{r['target']:32} {r['target_type']:9} добавлено {r['created_at'][:19]}  "
                   f"последняя проверка: {r['last_check'] or '—'}")
    elif args.action == "rm":
        store.watch_remove(args.target)
        _print(f"Удалено из наблюдения: {args.target}")
    elif args.action == "check":
        rows = store.watch_list()
        if not rows:
            _print("Список наблюдения пуст.")
            return 0
        _rule("Проверка списка наблюдения")
        for row in rows:
            report = Engine().search_sync(row["target"], deep=False, no_save=False, variant_probe=False)
            fingerprint = json.dumps(sorted(f"{f.source}:{f.value or f.url}" for f in report.findings))
            previous = row.get("last_fingerprint")
            new_items = []
            if previous:
                old = set(json.loads(previous))
                new_items = [x for x in json.loads(fingerprint) if x not in old]
            store.watch_update(row["target"], fingerprint)
            status = f"🆕 новых находок: {len(new_items)}" if previous and new_items else \
                     ("✅ без изменений" if previous else "первая проверка")
            _print(f"{row['target']:32} находок {len(report.findings):3}  {status}")
    return 0


# ───────────────────────────── парсер ─────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osintx",
        description="OsintX — OSINT-поиск по открытым источникам: email, логины, телефоны, Telegram, домены, IP, ФИО, крипта.",
        epilog="Данные берутся только из открытых источников. Используйте ответственно и законно.")
    parser.add_argument("--version", action="version", version=f"OsintX {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("search", aliases=["s"], help="Запустить поиск по цели")
    p.add_argument("target", help="email | логин | @telegram | телефон | домен | IP | ФИО | криптоадрес")
    p.add_argument("--modules", "-m", help=f"Список модулей через запятую: {', '.join(m for m in PLAN if PLAN[m])}")
    p.add_argument("--type", "-t", help="Тип цели принудительно (email/username/phone/telegram/domain/ip/person/crypto)")
    p.add_argument("--deep", "-d", action="store_true", help="Глубокий режим: больше источников и времени")
    p.add_argument("--variants", "-V", action="store_true", help="Проверять варианты написания (логины/адреса)")
    p.add_argument("--smtp", action="store_true", help="SMTP RCPT-проверка существования ящика (email)")
    p.add_argument("--no-keys", action="store_true", help="Не использовать API-ключи из .env")
    p.add_argument("--no-save", action="store_true", help="Не сохранять результат в базу")
    p.add_argument("--no-calibrate", action="store_true", help="Не калибровать источники (быстрее, но возможны ложные срабатывания)")
    p.add_argument("--max-sites", type=int, help="Ограничить число проверяемых сайтов")
    p.add_argument("--timeout", type=float, help="Таймаут одного запроса, сек")
    p.add_argument("--no-subdomains", action="store_true", help="Не перебирать поддомены (модуль domain)")
    p.add_argument("--out", "-o", help="Сохранить отчёт в файл (формат — по расширению)")
    p.add_argument("--format", "-f", choices=sorted(FORMATS), help="Формат отчёта (txt/json/html/md/csv/mermaid/dot)")
    p.add_argument("--json-out", help="Дополнительно сохранить JSON")
    p.add_argument("--html-out", help="Дополнительно сохранить HTML")
    p.add_argument("--md-out", help="Дополнительно сохранить Markdown")
    p.add_argument("--csv-out", help="Дополнительно сохранить CSV")
    p.add_argument("--verbose", "-v", action="store_true", help="Показывать статус каждого источника")
    p.add_argument("--quiet", "-q", action="store_true", help="Только JSON в stdout")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("changes", help="Что менялось у цели: ник, имя, био, город (между проверками)")
    p.add_argument("target")
    p.add_argument("--limit", "-n", type=int, default=30)
    p.set_defaults(func=cmd_changes)

    p = sub.add_parser("geo", help="Где живёт цель: страна/город по публичным профилям")
    p.add_argument("target")
    p.add_argument("--deep", action="store_true", help="Добавить веб-архив и логин-площадки")
    p.add_argument("--no-save", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true", help="Показать полный отчёт")
    p.set_defaults(func=cmd_geo)

    p = sub.add_parser("history", help="История поисков")
    p.add_argument("--limit", "-n", type=int, default=30)
    p.add_argument("--target", "-t")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("show", help="Показать сохранённый поиск")
    p.add_argument("search_id", nargs="?")
    p.add_argument("--target", "-t")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("stats", help="Статистика локальной базы")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("dataset-import", aliases=["import"], help="Загрузить внешнюю базу (CSV/JSON/TXT) в индекс")
    p.add_argument("path")
    p.add_argument("--name", "-n")
    p.add_argument("--kind", default="auto")
    p.add_argument("--column", help="Колонка со значением (email/телефон/логин)")
    p.set_defaults(func=cmd_dataset_import)

    p = sub.add_parser("dataset-search", help="Поиск по загруженным внешним базам")
    p.add_argument("value")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_dataset_search)

    p = sub.add_parser("dataset-list", help="Список загруженных баз")
    p.set_defaults(func=cmd_dataset_list)

    p = sub.add_parser("dataset-drop", help="Удалить базу из индекса")
    p.add_argument("name")
    p.set_defaults(func=cmd_dataset_drop)

    p = sub.add_parser("password", help="Проверить пароль по утечкам (k-anonymity, без передачи пароля)")
    p.add_argument("password", help="Пароль или '-' для чтения из stdin")
    p.set_defaults(func=cmd_password)

    p = sub.add_parser("sources", help="Показать реестр источников")
    p.add_argument("--category", "-c", default="username", choices=["username", "email", "phone"])
    p.add_argument("--min-confidence", choices=["high", "medium", "low"])
    p.add_argument("--tags")
    p.add_argument("--stats", action="store_true", help="Только количество")
    p.set_defaults(func=cmd_sources)

    p = sub.add_parser("graph", help="Граф связей цели (mermaid/dot)")
    p.add_argument("target")
    p.add_argument("--type", "-t")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--format", choices=["mermaid", "dot"], default="mermaid")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("doctor", help="Проверить окружение и доступность источников")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("net", help="Диагностика сети: DNS, TCP, TLS, прокси (для бота и поиска)")
    p.set_defaults(func=cmd_net)

    p = sub.add_parser("init", aliases=["setup", "wizard"],
                       help="Мастер настройки: токен бота, ключи API, прокси → .env")
    p.add_argument("--token", help="Токен Telegram-бота (без вопросов)")
    p.add_argument("--no-input", action="store_true", help="Ничего не спрашивать (для скриптов)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("serve", help="Запустить веб-интерфейс")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("bot", help="Запустить Telegram-бота")
    p.add_argument("--check", action="store_true",
                   help="Проверить токен и настройки (getMe), не запуская бота")
    p.add_argument("--token", help="Токен бота (если не задан в .env)")
    p.set_defaults(func=cmd_bot)

    p = sub.add_parser("tgauth", aliases=["tg-auth"], help="Авторизовать MTProto-сессию Telegram")
    p.set_defaults(func=cmd_tgauth)

    p = sub.add_parser("watch", help="Наблюдение за целями (отслеживание новых находок)")
    p.add_argument("action", choices=["add", "list", "rm", "check"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--type", "-t")
    p.add_argument("--note")
    p.set_defaults(func=cmd_watch)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _print("\nПрервано пользователем.")
        return 130
    except Exception as exc:
        _print(f"[red]Ошибка:[/red] {type(exc).__name__}: {exc}" if RICH else f"Ошибка: {exc}")
        if "--debug" in (argv or sys.argv):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
