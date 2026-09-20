"""Мастер настройки OsintX: пошагово заполняет .env и проверяет токен бота.

Запуск:  osintx init        (алиасы: setup, wizard)
         osintx init --token 123456:AA... --no-input     # без вопросов, для скриптов

Что делает:
  1. создаёт .env из .env.example (если файла нет);
  2. спрашивает токен Telegram-бота и проверяет его реальным запросом getMe;
  3. по желанию — TG_API_ID/TG_API_HASH для MTProto (числовой ID, DC, поиск по сообщениям);
  4. по желанию — API-ключи (HIBP, Hunter, Shodan, VirusTotal…);
  5. записывает всё в .env, сохраняя остальные строки;
  6. показывает, что делать дальше.
"""
from __future__ import annotations

import asyncio
import os

from .config import PROJECT_ROOT, clean_env_value

ENV_PATH = PROJECT_ROOT / ".env"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"

KEY_PROMPTS = [
    ("HIBP_API_KEY", "Have I Been Pwned — список утечек по email (haveibeenpwned.com/API/Key)"),
    ("HUNTER_API_KEY", "Hunter.io — верификация адресов и связанные адреса домена (hunter.io)"),
    ("SHODAN_API_KEY", "Shodan — полные данные по IP: порты, сервисы, баннеры (shodan.io)"),
    ("VIRUSTOTAL_API_KEY", "VirusTotal — репутация IP/доменов (virustotal.com)"),
    ("LEAKCHECK_API_KEY", "LeakCheck — источники утечек (leakcheck.io)"),
    ("INTELX_API_KEY", "Intelligence X — поиск по дампам и paste-сайтам (intelx.io)"),
]


def _read_env() -> dict[str, str]:
    data: dict[str, str] = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, raw_value = line.partition("=")
            value = clean_env_value(raw_value)
            if value.startswith("#") or not value:
                continue  # незаполненные подсказки из шаблона не считаем значениями
            data[key.strip()] = value
    return data


def _write_env(data: dict[str, str]) -> None:
    """Обновляет .env, сохраняя комментарии и порядок существующих строк."""
    if ENV_PATH.exists():
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    elif ENV_EXAMPLE.exists():
        lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    else:
        lines = []
    out: list[str] = []
    written: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in data:
                out.append(f"{key}={data[key]}")
                written.add(key)
                continue
            # если в шаблоне есть ключ, который мы не трогали — оставляем как есть
        out.append(line)
    rest = {k: v for k, v in data.items() if k not in written}
    if rest:
        if out and out[-1].strip():
            out.append("")
        out.append("# ─── заполнено мастером osintx init ───")
        out.extend(f"{k}={v}" for k, v in rest.items())
    ENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)  # в .env лежат токен бота и ключи API
    except OSError:
        pass


async def _check_token(token: str) -> tuple[bool, str]:
    from .bot.run import _probe_token
    return await _probe_token(token)


def run_wizard(args) -> int:
    interactive = not getattr(args, "no_input", False)
    token = (getattr(args, "token", "") or "").strip()
    print("=" * 68)
    print("  Настройка OsintX — пошаговый мастер")
    print("=" * 68)
    env = _read_env()
    updates: dict[str, str] = {}
    if ENV_PATH.exists():
        print(f"Найден существующий {ENV_PATH} — обновим только то, что вы введёте (Enter = пропустить).")
    else:
        print(f"Создаю {ENV_PATH} (шаблон: {ENV_EXAMPLE.name}).")

    # ── 1. токен бота ──
    if not token and interactive:
        print("\n[1/4] Токен Telegram-бота (получить: @BotFather → /newbot → скопировать токен)")
        print("      Оставьте пустым, если бот пока не нужен (можно создать позже: osintx init).")
        token = input("      TELEGRAM_BOT_TOKEN: ").strip()
    token = token or env.get("TELEGRAM_BOT_TOKEN", "").strip()

    if token:
        ok, message = asyncio.run(_check_token(token))
        print("      " + message.replace("\n", "\n      "))
        if ok and interactive:
            try:
                print("\n      ВАЖНО про доступ: если оставить пустым, ботом сможет пользоваться любой,")
                print("      кто знает его @username. Свой ID бот сообщит, если написать ему /start.")
                allowed = input("      TELEGRAM_ALLOWED_IDS (ваш ID, можно через запятую): ").strip()
                if allowed:
                    updates["TELEGRAM_ALLOWED_IDS"] = allowed
            except EOFError:
                pass
        elif not ok and interactive:
            answer = input("      Продолжить с этим токеном всё равно? [y/N]: ").strip().lower()
            if answer not in ("y", "yes", "д", "да"):
                print("      Отменено.")
                return 1

    # ── 2. MTProto ──
    if interactive:
        print("\n[2/4] MTProto (необязательно): даёт числовой Telegram ID, привязку к DC,")
        print("      общие чаты и глобальный поиск по сообщениям. Ключи: my.telegram.org → API development tools")
        api_id = input("      TG_API_ID (Enter — пропустить): ").strip()
        if api_id.isdigit():
            updates["TG_API_ID"] = api_id
            api_hash = input("      TG_API_HASH: ").strip()
            if api_hash:
                updates["TG_API_HASH"] = api_hash
                print("      После сохранения выполните: osintx tgauth   (вход по номеру и коду)")

    # ── 3. API-ключи ──
    if interactive:
        print("\n[3/4] API-ключи источников (все необязательны — базовые проверки работают без них).")
        for key, description in KEY_PROMPTS:
            if env.get(key):
                print(f"      {key}: уже задан")
                continue
            print(f"      • {description}")
            value = input(f"        {key} (Enter — пропустить): ").strip()
            if value:
                updates[key] = value

    # ── 4. прокси/сохранение ──
    if interactive:
        print("\n[4/4] Прокси (нужен, если интернет блокирует источники; формат socks5://user:pass@host:port)")
        proxy = input("      OSINTX_PROXY (Enter — не использовать): ").strip()
        if proxy:
            updates["OSINTX_PROXY"] = proxy

    if token:
        updates["TELEGRAM_BOT_TOKEN"] = token
    _write_env(updates)
    print(f"\n✅ Настройки сохранены: {ENV_PATH}")
    if updates:
        print("   Записано: " + ", ".join(f"{k}=…" if "TOKEN" in k or "KEY" in k or "HASH" in k else f"{k}={v}"
                                          for k, v in updates.items()))

    print("\nДальше:")
    if token:
        print("  1) osintx bot            — запустить бота (Ctrl+C — остановить)")
        print("     osintx bot --check    — ещё раз проверить токен без запуска")
    else:
        print("  1) osintx init           — вернуться к мастеру и вписать токен бота")
    print("  2) osintx doctor         — проверить, какие источники доступны из вашей сети")
    print("  3) osintx search <цель>  — тестовый поиск из терминала")
    print("  4) osintx serve          — поднять веб-интерфейс на http://localhost:8000")
    if token:
        print("\nЕсли бот не отвечает на команды — напишите ему /start в Telegram.")
    return 0
