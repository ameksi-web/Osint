#!/usr/bin/env python3
"""OsintX — запуск Telegram-бота:  python bot.py

Это удобная обёртка над osintx.bot.run. Ничего настраивать в коде не нужно:
все параметры берутся из .env (или из переменных окружения).

Примеры:
    python bot.py                     # запустить бота
    python bot.py --check             # проверить токен и настройки, не запуская
    python bot.py --net               # диагностика сети: DNS, TCP, TLS, прокси
    python bot.py --token 123:AA...   # запустить с токеном из аргумента
    python bot.py --init              # открыть мастер настройки (.env)
    python bot.py tgauth              # вход в MTProto (номер + код из Telegram)
    python bot.py cli search durov    # любая команда osintx — если «osintx» не в PATH

Если зависимости ещё не установлены, скрипт подскажет точную команду.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _missing_dependencies(need_bot: bool = True) -> list[str]:
    """Чего не хватает для запуска. Для CLI-команд python-telegram-bot не нужен."""
    checks = [("httpx", "httpx"), ("phonenumbers", "phonenumbers"), ("dns", "dnspython")]
    if need_bot:
        checks.insert(0, ("telegram", "python-telegram-bot"))
    missing = []
    for module, package in checks:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    return missing


def _print_install_help(missing: list[str]) -> None:
    venv_python = ROOT / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    print("Не установлены зависимости: " + ", ".join(missing))
    print("\nУстановите их одной из команд (из каталога проекта):")
    if venv_python.exists():
        print(f'  "{venv_python}" -m pip install -r requirements.txt')
    else:
        print("  python -m venv .venv")
        print("  .venv/bin/activate        # Windows: .venv\\Scripts\\activate")
        print("  pip install -r requirements.txt")
    print("\nЛибо просто запустите готовый скрипт: ./start_bot.sh (Windows: start_bot.bat)")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `python bot.py tgauth` — вход в MTProto тем же способом, что и `osintx tgauth`
    if argv and argv[0] in ("tgauth", "tg-auth"):
        from osintx.tg_auth import main as auth_main
        return auth_main()

    # `python bot.py cli <команда> …` — любая команда osintx без установки в PATH
    if argv and argv[0] == "cli":
        rest = argv[1:]
        if not rest:
            print("Использование: python bot.py cli <команда> [аргументы]\n"
                  "Примеры:\n"
                  "  python bot.py cli search durov -m telegram\n"
                  "  python bot.py cli usernames durov\n"
                  "  python bot.py cli sources --import-wmn\n"
                  "Полный список команд: python bot.py cli --help")
            return 1
        from osintx.cli import main as cli_main
        return cli_main(rest)

    if "--init" in argv or "--setup" in argv:
        from osintx.wizard import run_wizard
        from argparse import Namespace
        token = ""
        if "--token" in argv:
            index = argv.index("--token")
            if index + 1 < len(argv):
                token = argv[index + 1]
        return run_wizard(Namespace(token=token, no_input=("--no-input" in argv)))

    missing = _missing_dependencies(need_bot=True)
    if missing:
        _print_install_help(missing)
        return 1

    token = ""
    if "--token" in argv:
        index = argv.index("--token")
        if index + 1 < len(argv):
            token = argv[index + 1].strip()

    if "--check" in argv or token:
        from argparse import Namespace
        from osintx.bot.run import check_bot
        if token:
            import os
            os.environ["TELEGRAM_BOT_TOKEN"] = token
            from osintx import config
            config.get_settings(reload=True)
        return check_bot(Namespace(token=token))

    if "--net" in argv:
        from osintx.netcheck import diagnose
        report, ok = diagnose()
        print(report)
        return 0 if ok else 1

    from osintx.bot.run import main as bot_main
    return bot_main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
        raise SystemExit(130)
    except Exception as exc:  # сетевые сбои показываем понятным текстом, а не трейсбеком
        text = str(exc)
        if "getaddrinfo" in text or "ConnectError" in text or "NetworkError" in text:
            from osintx.netcheck import explain_network_error
            print(explain_network_error(exc))
            raise SystemExit(2)
        raise
