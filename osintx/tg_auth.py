"""Авторизация MTProto-сессии Telegram (Telethon) для глубокого модуля.

Запуск:  python -m osintx.tg_auth      (или osintx tgauth)

Нужны TG_API_ID и TG_API_HASH из https://my.telegram.org → API development tools.
После входа в аккаунт создаётся файл сессии в каталоге данных, и модуль telegram
сможет получать: числовой ID, access_hash, DC, дату регистрации, общие чаты,
bio, а также выполнять глобальный поиск по сообщениям (как Void OSINT).

Сессия равносильна входу в аккаунт: не передавайте файл .session третьим лицам.
"""
from __future__ import annotations

import sys

from .config import get_settings


def main() -> int:
    settings = get_settings()
    if not settings.tg_api_id or not settings.tg_api_hash:
        print("Сначала заполните TG_API_ID и TG_API_HASH в .env (получить: https://my.telegram.org)")
        return 1
    try:
        from telethon import TelegramClient
    except ImportError:
        print("Telethon не установлен:  pip install telethon")
        return 1

    session_path = str(settings.data_dir / settings.tg_session)
    print(f"Файл сессии: {session_path}.session")
    client = TelegramClient(session_path, settings.tg_api_id, settings.tg_api_hash,
                            device_model="OsintX CLI", system_version="1.0", app_version="1.0")

    async def run() -> None:
        await client.start()
        me = await client.get_me()
        print("\nУспешный вход в Telegram (MTProto).")
        print(f"  Аккаунт: {me.first_name or ''} {me.last_name or ''}".rstrip())
        print(f"  Username: @{me.username}" if me.username else "  Username: нет")
        print(f"  Телефон: {me.phone}")
        print(f"  Числовой ID: {me.id}")
        print("\nТеперь доступны: /id в боте, MTProto-раздел в CLI и веб-поиске.")
        await client.disconnect()

    try:
        client.loop.run_until_complete(run())
    except KeyboardInterrupt:
        print("\nПрервано.")
        return 130
    except Exception as exc:
        print(f"Ошибка авторизации: {type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
