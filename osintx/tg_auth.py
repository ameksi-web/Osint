"""Авторизация MTProto-сессии Telegram (Telethon) для глубокого модуля.

Запуск:  osintx tgauth    (то же самое: osintx tg-auth, python -m osintx.tg_auth)

Важно: вход выполняется как ОБЫЧНЫЙ АККАУНТ (номер телефона), а не как бот. Бот-сессия
(если ввести токен бота) не умеет глобальный поиск сообщений и GetCommonChats — это
ограничение Telegram. Пересоздать сессию:  osintx tgauth --reset

Сессию с ограничениями бота показывает сам модуль: статус «mtproto:session» в отчёте.

Порядок действий:

  1. Вписать TG_API_ID и TG_API_HASH в ``.env`` (получить: https://my.telegram.org →
     API development tools; это обычное приложение Telegram, регистрация бесплатная);
  2. Запустить команду и ответить на вопросы:
       • номер телефона в международном формате (например +79991234567);
       • код из Telegram (приходит сообщением в сам Telegram, не по SMS);
       • пароль двухфакторной защиты (только если он включён);
  3. Готово: в каталоге данных появится файл сессии ``<TG_SESSION>.session``.

Что открывается после входа (только ваш собственный аккаунт, никакого доступа к
чужим сессиям): числовой ID и access_hash цели, DC, дата регистрации, bio целиком,
**общие группы (GetCommonChats)**, список юзернеймов аккаунта и глобальный поиск
сообщений (аналог Void OSINT).

Сессия равносильна входу в аккаунт: не передавайте файл .session третьим лицам
и не публикуйте его. Отозвать можно в Telegram: Настройки → Устройства.
"""
from __future__ import annotations

import sys
from urllib.parse import unquote, urlparse

from .config import get_settings

HELP_HINT = ("Подсказка: ключи выдаются на https://my.telegram.org → API development tools. "
             "Можно ответить мастеру настройки: osintx init")


def _telethon_proxy(url: str) -> dict | None:
    """Прокси из .env (http/socks4/socks5) → параметр ``proxy`` для Telethon.

    Понимает формат ``scheme://user:pass@host:port``. Нужен там, где Telegram
    блокируется: тот же адрес, что и TELEGRAM_PROXY у бота.
    """
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https", "socks4", "socks5"):
        return None
    if not parsed.hostname or not parsed.port:
        return None
    proxy = {"proxy_type": "http" if scheme in ("http", "https") else scheme,
             "addr": parsed.hostname, "port": int(parsed.port), "rdns": True}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    return proxy


def _proxy_support_error(proxy: dict) -> str | None:
    """Telethon для любого прокси (и HTTP, и SOCKS) требует пакет python-socks.

    Проверяем заранее, иначе Telethon молча игнорирует прокси и падает
    с загадочным «No module named 'socks'».
    """
    try:
        import python_socks  # noqa: F401
    except ImportError:
        return ("Telethon для работы через прокси нужен пакет python-socks:\n"
                '   pip install "python-socks[asyncio]"\n'
                "   (прокси указан в TELEGRAM_PROXY/OSINTX_PROXY; без него Telegram напрямую — "
                "просто уберите эту строку из .env)")
    return None


def reset_session(path: str) -> list[str]:
    """Удалить сохранённую сессию (файлы .session и .session-journal)."""
    import os

    removed: list[str] = []
    for candidate in (f"{path}.session", f"{path}.session-journal"):
        if os.path.exists(candidate):
            try:
                os.remove(candidate)
                removed.append(candidate)
            except OSError as exc:  # pragma: no cover
                print(f"Не удалось удалить {candidate}: {exc}")
    return removed


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    settings = get_settings()
    session_path = str(settings.data_dir / settings.tg_session)
    if any(flag in args for flag in ("--reset", "--relogin", "--re-login")):
        removed = reset_session(session_path)
        print("Старая сессия удалена: " + (", ".join(removed) if removed else "файлов не было"))
    if not settings.tg_api_id or not settings.tg_api_hash:
        print("Сначала заполните TG_API_ID и TG_API_HASH в .env (получить: https://my.telegram.org)")
        print(HELP_HINT)
        return 1
    try:
        from telethon import TelegramClient
    except ImportError:
        print("Telethon не установлен:  pip install telethon")
        print("(или сразу с прокси:  pip install \"telethon[proxy]\" \"python-socks[asyncio]\"")
        return 1

    proxy_url = (settings.telegram_proxy or settings.proxy or "").strip()
    proxy = _telethon_proxy(proxy_url)
    if proxy_url and not proxy:
        print(f"Прокси указан неверно и будет проигнорирован: {proxy_url!r}")
        print("Формат: http://host:port, socks5://user:pass@host:port")
    if proxy:
        error = _proxy_support_error(proxy)
        if error:
            print(error)
            return 1
        print(f"Прокси: {proxy['proxy_type']}://{proxy['addr']}:{proxy['port']}")

    print(f"Файл сессии: {session_path}.session")
    print("Сейчас спросят номер телефона, затем код из Telegram (и пароль 2FA, если включён).")
    client = TelegramClient(session_path, settings.tg_api_id, settings.tg_api_hash,
                            device_model="OsintX CLI", system_version="1.0", app_version="1.0",
                            proxy=proxy)

    async def run() -> None:
        await client.start()
        me = await client.get_me()
        if getattr(me, "bot", False):
            print("\n⚠ Это сессия БОТА, а не вашего аккаунта.")
            print(f"  Бот: @{me.username} (id {me.id})")
            print("Telegram запрещает ботам глобальный поиск сообщений (SearchGlobal) и список общих")
            print("групп (GetCommonChats) — они останутся недоступными, а доступно будет только чтение")
            print("публичных каналов.")
            print("\nЧтобы получить «где писал», общие группы и числовой ID цели — войдите как обычный")
            print("аккаунт (номер телефона вместо токена бота):")
            print("   osintx tgauth --reset      # удалит эту сессию")
            print("   osintx tgauth              # номер в формате +79991234567, затем код из Telegram")
            await client.disconnect()
            return
        print("\nУспешный вход в Telegram (MTProto).")
        print(f"  Аккаунт: {me.first_name or ''} {me.last_name or ''}".rstrip())
        print(f"  Username: @{me.username}" if me.username else "  Username: нет")
        print(f"  Телефон: {me.phone}")
        print(f"  Числовой ID: {me.id}")
        print("\nТеперь работают: /id в боте, MTProto-раздел в CLI и веб-поиске, "
              "общие группы (GetCommonChats) и глобальный поиск по сообщениям.")
        print("Проверка:  osintx search <цель> -m telegram --verbose")
        await client.disconnect()

    try:
        client.loop.run_until_complete(run())
    except KeyboardInterrupt:
        print("\nПрервано.")
        return 130
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc)
        print(f"Ошибка авторизации: {name}: {message}")
        lowered = f"{name} {message}".lower()
        if "flood" in lowered or "too many" in lowered:
            print("Слишком много попыток: подождите несколько часов и повторите.")
        elif "password" in lowered or "two" in lowered:
            print("Неверный пароль двухфакторной защиты — проверьте его в Telegram: "
                  "Настройки → Конфиденциальность → Двухэтапная проверка.")
        elif "phone" in lowered or "code" in lowered:
            print("Код/номер не подошли. Код приходит сообщением в Telegram (не по SMS) и живёт "
                  "несколько минут — запросите новый повторным запуском.")
        elif isinstance(exc, ModuleNotFoundError) and "socks" in lowered:
            print('Прокси требует пакет python-socks:  pip install "python-socks[asyncio]"')
        elif (isinstance(exc, (ConnectionError, OSError, TimeoutError))
              or any(word in lowered for word in ("connect", "dns", "timeout", "read", "closed",
                                                  "unreachable", "refused"))):
            print("Похоже, сеть не пускает к Telegram. Варианты:\n"
                  "  1) TELEGRAM_PROXY=socks5://127.0.0.1:1080 (или http://host:port) в .env — "
                  "адрес вашего VPN/прокси-клиента;\n"
                  "  2) проверить сеть:  python bot.py --net")
        else:
            print(HELP_HINT)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
