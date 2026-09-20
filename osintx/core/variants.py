"""Генерация вариаций цели: email-трюки, варианты юзернеймов, ФИО→логин.

Это то, что превращает один запрос в серию: человек почти всегда использует
схожие шаблоны логина на разных сервисах, поэтому поиск по «вариациям»
даёт в разы больше реальных находок.
"""
from __future__ import annotations

import re
from itertools import product

from .utils import translit

EMAIL_SEPARATORS = ["", ".", "_", "-"]
COMMON_PROVIDERS = ["gmail.com", "yandex.ru", "mail.ru", "outlook.com", "yahoo.com", "icloud.com",
                    "proton.me", "protonmail.com", "list.ru", "bk.ru", "inbox.ru", "rambler.ru",
                    "hotmail.com", "live.com", "aol.com", "gmx.com", "zoho.com", "tutanota.com"]
YEARS = ["", "1", "01", "7", "77", "99", "2000", "2024", "12", "13", "123", "007", "x", "xx"]


def email_variants(email: str, limit: int = 40) -> list[str]:
    """Вариации email: +tag, точки в gmail, смена провайдера, подчёркивания."""
    email = email.strip().lower()
    if "@" not in email:
        return []
    local, _, domain = email.partition("@")
    variants: list[str] = [email]

    base = local.split("+")[0]
    if "+" in local and base:
        variants.append(f"{base}@{domain}")

    # точки в local-part (gmail игнорирует точки)
    parts = [p for p in re.split(r"[._\-]", base) if p]
    if len(parts) == 2:
        for sep in EMAIL_SEPARATORS:
            variants.append(f"{parts[0]}{sep}{parts[1]}@{domain}")
        if domain in {"gmail.com", "googlemail.com"}:
            variants.append(f"{parts[0]}{parts[1]}@googlemail.com" if domain == "gmail.com"
                            else f"{parts[0]}{parts[1]}@gmail.com")
    elif len(parts) == 3:
        for sep in EMAIL_SEPARATORS:
            variants.append(f"{parts[0]}{sep}{parts[1]}{sep}{parts[2]}@{domain}")

    # смена провайдера на популярные
    for provider in COMMON_PROVIDERS[:6]:
        if provider != domain:
            variants.append(f"{base}@{provider}")

    seen, out = set(), []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out[:limit]


def _split_name(name: str) -> list[str]:
    return [p for p in re.split(r"[\s._\-]+", name.strip()) if p]


def name_to_usernames(full_name: str, extra: list[str] | None = None, limit: int = 60) -> list[str]:
    """ФИО → список реалистичных логинов (с транслитерацией для русского)."""
    name = full_name.strip()
    parts = _split_name(name)
    if not parts:
        return []
    latin_parts = [translit(p) if re.search(r"[а-яёіїєґ]", p.lower()) else p.lower() for p in parts]
    latin_parts = [re.sub(r"[^a-z0-9]", "", p) for p in latin_parts if p]
    out: list[str] = []
    if len(latin_parts) >= 2:
        first, last = latin_parts[0], latin_parts[-1]
        middles = latin_parts[1:-1]
        for sep in ["", ".", "_", "-"]:
            out += [f"{first}{sep}{last}", f"{last}{sep}{first}"]
            out += [f"{first[0]}{sep}{last}", f"{first}{sep}{last[0]}"]
            if middles:
                out.append(f"{first}{sep}{middles[0][0]}{sep}{last}" if sep else f"{first}{middles[0][0]}{last}")
    else:
        out.append(latin_parts[0])
    for base, tail in product(list(dict.fromkeys(out))[:12], YEARS):
        if tail:
            out.append(f"{base}{tail}")
    out += [re.sub(r"\W", "", p.lower()) for p in parts if re.search(r"[A-Za-z0-9]", p)]
    if extra:
        out += [re.sub(r"\W", "", e.lower()) for e in extra]
    seen, unique = set(), []
    for u in out:
        u = u.strip("._-")
        if 2 <= len(u) <= 32 and u not in seen:
            seen.add(u)
            unique.append(u)
    return unique[:limit]


def username_variants(username: str, limit: int = 40) -> list[str]:
    """Вариации юзернейма: разделители, цифры, год, регистр, замена o↔0 и т.п."""
    u = username.strip().lstrip("@")
    if not u:
        return []
    variants = [u]
    parts = [p for p in re.split(r"[._\-]", u) if p]
    if len(parts) == 2:
        for sep in ["", ".", "_", "-"]:
            variants.append(f"{parts[0]}{sep}{parts[1]}")
    if len(parts) == 1:
        m = re.match(r"^([A-Za-z]+?)(\d{1,4})$", u)
        if m:
            variants += [m.group(1), f"{m.group(1)}{m.group(2)}"]
            variants += [f"{m.group(1)}_{m.group(2)}", f"{m.group(1)}.{m.group(2)}"]
        m2 = re.match(r"^([a-z]+)([A-Z].*)$", u)
        if m2:
            variants.append(f"{m2.group(1)}_{m2.group(2).lower()}")
            variants.append(f"{m2.group(1)}.{m2.group(2).lower()}")
    for tail in ["", "1", "01", "_", "7", "77", "99", "007", "_official", "official", "real"]:
        variants.append(f"{u}{tail}")
    variants += [u.lower(), u.upper(), u.capitalize()]
    variants += [u.replace("o", "0"), u.replace("0", "o"), u.replace("e", "3"), u.replace("a", "4")]
    seen, unique = set(), []
    for v in variants:
        v = v.strip("._-")
        if 2 <= len(v) <= 32 and v.lower() not in seen and re.fullmatch(r"[A-Za-z0-9._\-]+", v):
            seen.add(v.lower())
            unique.append(v)
    return unique[:limit]


def email_local_parts(email: str) -> list[str]:
    """Локальная часть email как кандидат в юзернеймы (ivan.petrov@ → ivanpetrov, ivan_petrov)."""
    local = email.split("@")[0].lower()
    return username_variants(local, limit=20)


def domain_variants(domain: str) -> list[str]:
    """Варианты домена: www, без www, разные TLD-зеркала."""
    d = domain.lower().strip(".")
    out = {d}
    if d.startswith("www."):
        out.add(d[4:])
    else:
        out.add("www." + d)
    root, _, tld = d.rpartition(".")
    if root == "www":  # www.example.com → example.com
        out.add(d[4:])
    for alt in ["com", "net", "org", "ru", "io", "co"]:
        if tld and tld != alt:
            out.add(f"{root}.{alt}")
    return sorted(out)[:12]
