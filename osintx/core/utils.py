"""Утилиты: определение типа цели, нормализация, транслитерация, парсинг."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-!#$&'*/=?^`{|}~]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._\-]{1,31}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9\-]{1,63}(?<!-))+$")
BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

RU_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
    "я": "ya", "і": "i", "ї": "i", "є": "e", "ґ": "g",
}


def translit(text: str) -> str:
    """Русский/украинский → латиница (для генерации юзернеймов из ФИО)."""
    out = []
    low = text.lower().replace(" ", "")
    for ch in low:
        out.append(RU_TRANSLIT.get(ch, ch))
    return "".join(out)


def normalize(text: str) -> str:
    """NFC-нормализация + обрезка пробелов, устойчиво к юникод-хакам."""
    return unicodedata.normalize("NFC", text or "").strip()


def clean_domain(value: str) -> str:
    value = normalize(value).lower()
    for prefix in ("https://", "http://", "//"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/")[0].split("?")[0]
    if ":" in value and not value.count(":") > 1:
        value = value.split(":")[0]
    return value.strip(".")


def clean_phone(value: str) -> str:
    return re.sub(r"[^\d+]", "", normalize(value))


def parse_dork_target(target: str) -> list[str]:
    """Ссылки на поисковики для цели (используются как реальные ссылки в отчёте)."""
    from urllib.parse import quote_plus
    q = quote_plus(target)
    return [
        f"https://www.google.com/search?q={q}",
        f"https://yandex.ru/search/?text={q}",
        f"https://www.bing.com/search?q={q}",
        f"https://duckduckgo.com/?q={q}",
        f"https://search.marcia.cc/search?q={q}",
        f"https://www.google.com/search?q={q}&tbm=isch",
        f'https://www.google.com/search?q=site:pastebin.com+{q}',
        f'https://www.google.com/search?q=site:github.com+{q}',
        f'https://www.google.com/search?q=filetype:pdf+{q}',
    ]


def detect_target_type(target: str) -> str:
    """Определяет тип цели: email | phone | telegram | username | name | domain | ip | url | crypto."""
    t = normalize(target)
    if not t:
        return "unknown"
    low = t.lower()

    if low.startswith(("http://", "https://")):
        host = urlparse(low).netloc.split(":")[0]
        if host in {"t.me", "telegram.me", "telegram.dog"}:
            return "telegram"
        if _is_ip(host):
            return "ip"
        return "domain"

    if low.startswith(("t.me/", "telegram.me/", "telegram.dog/", "@t.me/")):
        return "telegram"

    if EMAIL_RE.match(t):
        return "email"

    # телефон: только цифры/плюс/скобки/дефисы и достаточно цифр
    digits = re.sub(r"\D", "", t)
    if re.fullmatch(r"[+\d()\-\s.]+", t) and 7 <= len(digits) <= 15:
        return "phone"

    if _is_ip(t):
        return "ip"
    if BTC_RE.match(t) or ETH_RE.match(t):
        return "crypto"

    # t.me/<name> или @name → telegram-username
    if low.startswith("@") and USERNAME_RE.match(low[1:]):
        return "telegram"
    if USERNAME_RE.match(t) and not DOMAIN_RE.match(low) and " " not in t:
        # один токен без TLD-структуры → считаем username
        if "." in t and low.split(".")[-1] in {"com", "ru", "net", "org", "io", "me", "dev", "ai", "xyz", "info", "ua", "kz", "by"}:
            return "domain"
        return "username"

    if DOMAIN_RE.match(low):
        return "domain"

    if " " in t:
        return "person"
    return "person" if any(ch.isalpha() for ch in t) else "unknown"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(normalize(value)))


def mask_email(value: str) -> str:
    try:
        local, _, domain = value.partition("@")
    except ValueError:
        return value
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[0]}***{local[-1]}@{domain}"


def mask_phone(value: str) -> str:
    d = re.sub(r"\D", "", value)
    if len(d) < 7:
        return value
    return f"+{d[:3]}***{d[-2:]}"


def human_ms(ms: int | None) -> str:
    if ms is None:
        return "—"
    return f"{ms} мс" if ms < 1000 else f"{ms / 1000:.2f} с"


def chunked(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]
