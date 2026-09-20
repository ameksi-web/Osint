"""Диагностика сети для OsintX: DNS, TCP, прокси.

Главная причина, по которой OsintX (и pip, и бот) «не запускается» на Windows —
не сама программа, а сеть:

  * ``getaddrinfo failed / Errno 11002`` — не работает DNS: система не может
    превратить имя (api.telegram.org, files.pythonhosted.org) в IP-адрес;
  * DNS работает, но соединение не устанавливается — блокировка на уровне сети
    или провайдера (в РФ Telegram и часть источников бывают недоступны напрямую).

Модуль умеет честно показать, что именно сломано, и подсказать конкретные шаги.
Никаких внешних зависимостей — только стандартная библиотека.
"""
from __future__ import annotations

import os
import socket
import ssl
import time
from dataclasses import dataclass, field

DEFAULT_HOSTS = (
    ("api.telegram.org", "Telegram Bot API — без него бот не работает"),
    ("pypi.org", "PyPI — установка зависимостей"),
    ("files.pythonhosted.org", "файлы пакетов PyPI (на нём падает pip)"),
    ("github.com", "GitHub"),
)


@dataclass
class Result:
    host: str
    note: str = ""
    ips: list[str] = field(default_factory=list)
    dns_error: str = ""
    tcp_ok: bool = False
    tcp_ms: int = 0
    tcp_error: str = ""
    tls_ok: bool = False
    tls_error: str = ""

    @property
    def status(self) -> str:
        if self.dns_error:
            return "dns-fail"
        if not self.tcp_ok:
            return "tcp-fail"
        if not self.tls_ok:
            return "tls-fail"
        return "ok"


def check_host(host: str, note: str = "", *, port: int = 443, timeout: float = 6.0) -> Result:
    result = Result(host=host, note=note)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        result.ips = sorted({info[4][0] for info in infos})[:4]
    except socket.gaierror as exc:
        result.dns_error = f"{exc}"
        return result
    except OSError as exc:
        result.dns_error = f"{type(exc).__name__}: {exc}"
        return result

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result.tcp_ms = int((time.perf_counter() - started) * 1000)
            result.tcp_ok = True
    except OSError as exc:
        result.tcp_error = f"{type(exc).__name__}: {exc}"
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                result.tls_ok = tls.version() is not None
    except Exception as exc:  # ssl.SSLError, certificate errors и т.п.
        result.tls_error = f"{type(exc).__name__}: {exc}"
    return result


def proxies_from_env() -> dict[str, str]:
    keys = ("OSINTX_PROXY", "TELEGRAM_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
    return {key: os.environ[key] for key in keys if os.environ.get(key, "").strip()}


def diagnose(hosts: tuple[tuple[str, str], ...] = DEFAULT_HOSTS) -> tuple[str, bool]:
    """Полная проверка: DNS → TCP → TLS для ключевых хостов.

    Возвращает (текст отчёта, всё_ли_в_порядке).
    """
    results = [check_host(host, note) for host, note in hosts]
    proxies = proxies_from_env()
    all_ok = all(item.status == "ok" for item in results)
    dns_broken = [item for item in results if item.status == "dns-fail"]
    tcp_broken = [item for item in results if item.status in ("tcp-fail", "tls-fail")]

    lines: list[str] = ["Проверка сети OsintX", "-" * 46]
    for item in results:
        icon = {"ok": "✅", "dns-fail": "❌", "tcp-fail": "🚫", "tls-fail": "⚠️"}[item.status]
        detail = ""
        if item.status == "ok":
            detail = f"{', '.join(item.ips)} · TCP {item.tcp_ms} мс · TLS ok"
        elif item.status == "dns-fail":
            detail = f"DNS не разрешается: {item.dns_error}"
        elif item.status == "tcp-fail":
            detail = f"DNS ok ({', '.join(item.ips)}), но соединение не устанавливается: {item.tcp_error}"
        else:
            detail = f"TLS-ошибка: {item.tls_error}"
        lines.append(f"{icon} {item.host:<24} {detail}")
        if item.note:
            lines.append(f"   ({item.note})")

    lines.append("")
    if proxies:
        lines.append("Прокси из переменных окружения: " + ", ".join(f"{k}={v}" for k, v in proxies.items()))
    else:
        lines.append("Прокси не задан (OSINTX_PROXY / TELEGRAM_PROXY пустые).")

    lines.append("")
    if dns_broken and len(dns_broken) == len(results):
        lines += [
            "ДИАГНОЗ: DNS не работает вовсе — система не может разрешать имена.",
            "Что делать (Windows):",
            "  1) откройте «Параметры → Сеть и Интернет → Изменить свойства адаптера»",
            "     → IPv4 → Свойства → «Использовать следующие адреса DNS-серверов»:",
            "     8.8.8.8 и 1.1.1.1 (или 77.88.8.8 — Яндекс DNS);",
            "  2) в командной строке: ipconfig /flushdns",
            "  3) проверьте: nslookup api.telegram.org   → должен вернуть IP;",
            "     если не вернул: nslookup api.telegram.org 8.8.8.8",
            "  4) если DNS ломает VPN/прокси-клиент — временно выключите его и повторите.",
        ]
    elif tcp_broken:
        names = ", ".join(item.host for item in tcp_broken)
        lines += [
            f"ДИАГНОЗ: DNS работает, но соединение к {names} не проходит "
            "(блокировка провайдера, файрвола или антивируса).",
            "Для Telegram нужен прокси или VPN. Многие VPN-клиенты поднимают локальный",
            "SOCKS5-прокси — укажите его в .env и перезапустите:",
            "  TELEGRAM_PROXY=socks5://127.0.0.1:1080",
            "  OSINTX_PROXY=socks5://127.0.0.1:1080       # для самого поиска",
            "Для SOCKS нужен пакет socksio:  pip install \"httpx[socks]\" socksio",
        ]
    elif not all_ok:
        lines += ["Часть хостов недоступна — бот может работать, но отдельные источники будут отмечены "
                  "как blocked/error (это нормально и не считается «не найдено»)."]
    else:
        lines.append("Всё в порядке: DNS, TCP и TLS работают для ключевых хостов. "
                     "Если бот всё равно не отвечает — проверьте токен: python bot.py --check")
    return "\n".join(lines), all_ok


def explain_network_error(exc: BaseException | str) -> str:
    """Человеческое объяснение сетевой ошибки (вместо простыни трейсбека)."""
    text = str(exc)
    if "getaddrinfo" in text or "11001" in text or "11002" in text or "NameResolution" in text:
        reason = ("не работает DNS: система не смогла определить IP-адрес сервера "
                  "(api.telegram.org). Чаще всего это сбой DNS-сервера провайдера, "
                  "конфликт VPN/прокси или антивирусного фильтра.")
    elif "ConnectError" in text or "ConnectTimeout" in text or "timed out" in text.lower():
        reason = "соединение с api.telegram.org не устанавливается (сеть блокирует или нет маршрута)."
    elif "ReadTimeout" in text or "PoolTimeout" in text:
        reason = "сервер не отвечает — соединение обрывается по таймауту."
    elif "Unauthorized" in text or "401" in text:
        reason = "токен бота неверный или отозван."
    elif "Proxy" in text:
        reason = "ошибка прокси, указанного в настройках."
    else:
        reason = f"сеть недоступна ({type(exc).__name__})."

    lines = [
        "",
        "❌ Не удалось подключиться к Telegram: " + reason,
        "",
    ]
    if "не работает DNS" in reason or "соединение" in reason:
        lines += [
            "Полная диагностика (проверит DNS, TCP и TLS):",
            "    python bot.py --net",
            "",
            "Быстрая проверка DNS (в командной строке Windows):",
            "    nslookup api.telegram.org",
            "    ipconfig /flushdns",
            "",
            "Решение 1 — сменить DNS на 8.8.8.8 / 1.1.1.1 (Параметры → Сеть → Адаптер → IPv4).",
            "Решение 2 — прокси/VPN: впишите в .env и перезапустите бота:",
            "    TELEGRAM_PROXY=socks5://127.0.0.1:1080      # адрес локального прокси VPN-клиента",
            "    OSINTX_PROXY=socks5://127.0.0.1:1080        # чтобы и поиск шёл через прокси",
            "    (для SOCKS-прокси нужен пакет: pip install \"httpx[socks]\" socksio)",
            "Решение 3 — запустить бота там, где Telegram доступен (VPS/другая сеть).",
        ]
    return "\n".join(lines)
