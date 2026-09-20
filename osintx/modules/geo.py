"""Гео-модуль: где живёт цель — по реальным публичным данным.

Источники (все — официальные публичные API/страницы, без ключей и «пробивов»):

  * **Gravatar** — ``gravatar.com/<md5(email)>.json``: у многих профилей открыто
    указаны город/страна, «о себе», личные сайты и связанные аккаунты. Ключ — сам
    email, поэтому для email-цели это самый прямой источник местоположения.
  * **Keybase** — ``keybase.io/_/api/1.0/user/lookup.json`` по логину ИЛИ по email:
    открыто отдаёт имя, локацию и криптографически подтверждённые proofs
    (GitHub, Twitter, сайт, DNS-запись домена).
  * **Steam** — ``steamcommunity.com/id/<login>/?xml=1``: публичный XML профиля с
    городом/страной, реальным именем и датой создания аккаунта.
  * **Телефон** — страна/оператор/часовой пояс по номеру (E.164).

Дополнительно тексты (bio, «о себе», описания) разбираются офлайн-словарём
стран и городов в :mod:`osintx.insights` — там же собирается сводный вывод
«вероятное местоположение» с указанием источников.

Честность: если источник не отдал данные — это ``not_found``/``blocked``,
а не «локация не определена навсегда». Ничего не додумываем.
"""
from __future__ import annotations

import hashlib
import html
import re

from ..core import gazetteer
from ..core.models import ModuleResult, SourceStatus
from .base import Context, Module, add_edge, add_entity, entity_id

STEAM_LOC = re.compile(r"<location>(.*?)</location>", re.DOTALL)
STEAM_NAME = re.compile(r"<realname>(.*?)</realname>", re.DOTALL)
STEAM_CREATED = re.compile(r"<timecreated>(.*?)</timecreated>", re.DOTALL)
STEAM_ID = re.compile(r"<steamID64>(.*?)</steamID64>", re.DOTALL)
STEAM_COUNTRY = re.compile(r"<loccountrycode>(.*?)</loccountrycode>", re.DOTALL)
STEAM_SUMMARY = re.compile(r"<summary>(.*?)</summary>", re.DOTALL)


def _tag(pattern: re.Pattern[str], text: str) -> str:
    """Значение XML-тега или пустая строка (без исключений на отсутствии)."""
    found = pattern.search(text)
    return found.group(1).strip() if found else ""


class GeoModule(Module):
    name = "geo"
    title = "Гео: страна/город из публичных профилей, Gravatar, Keybase, Steam"
    categories = ("geo",)
    target_types = ("username", "email", "telegram", "phone", "person")

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        target_type = str(ctx.options.get("target_type") or "")
        original = str(ctx.options.get("original_target") or target)
        login = target.lstrip("@").strip()

        if target_type == "email" or "@" in original:
            await self._gravatar(ctx, original, result)
            await self._keybase(ctx, original, result, by_email=True)
        elif target_type == "phone" or target.startswith("+") or (target.isdigit() and len(target) >= 9):
            await self._phone(ctx, original, result)
        else:
            await self._steam(ctx, login, result)
            await self._keybase(ctx, login, result, by_email=False)

        await ctx.notify(stage="geo:done", message="Гео-проверки завершены")

    # ─────────────────────────── Gravatar ───────────────────────────
    async def _gravatar(self, ctx: Context, email: str, result: ModuleResult) -> None:
        digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        api = f"https://gravatar.com/{digest}.json"
        resp = await ctx.http.get(api, retries=1)
        if resp.error or resp.status_code >= 500:
            self.add_status(result, SourceStatus(source="gravatar", category="geo", status="error",
                                                 url=api, error=resp.error or f"HTTP {resp.status_code}"))
            return
        data = resp.json()
        entries = (data or {}).get("entry") if isinstance(data, dict) else None
        profile = entries[0] if isinstance(entries, list) and entries else None
        if not isinstance(profile, dict):
            self.add_status(result, SourceStatus(source="gravatar", category="geo", status="not_found",
                                                 url=api, http_code=resp.status_code,
                                                 detail="публичного Gravatar-профиля для этого email нет "
                                                        "(его видят только те, у кого он открыт)"))
            return
        location = (profile.get("currentLocation") or "").strip()
        about = (profile.get("aboutMe") or "").strip()
        display = (profile.get("displayName") or profile.get("name", {}).get("formatted") or "").strip()
        accounts = [{"domain": a.get("domain"), "url": a.get("url"),
                     "username": a.get("username"), "verified": a.get("verified")}
                    for a in (profile.get("accounts") or [])]
        urls = [{"title": u.get("title"), "url": u.get("value")} for u in (profile.get("urls") or [])]
        found_location = gazetteer.find_location(" · ".join([location, about]))
        country = found_location[0].country if found_location else ""
        city = found_location[0].city if found_location else ""
        self.add_finding(
            result, source="gravatar", category="geo", kind="profile", confidence="high",
            title=(f"Gravatar: {display or 'профиль найден'}"
                   + (f" — {location}" if location else "")
                   + (f" (связанных аккаунтов: {len(accounts)})" if accounts else "")),
            url=profile.get("profileUrl") or api, value=email,
            data={"location": location, "country": country, "city": city, "about": about[:600],
                  "display_name": display, "accounts": accounts, "urls": urls,
                  "avatar": profile.get("thumbnailUrl"), "preferred_username": profile.get("preferredUsername"),
                  "hash": digest},
            evidence=f"gravatar.com/{digest[:12]}….json → entry[0]: "
                     f"currentLocation={location!r}, accounts={len(accounts)}, urls={len(urls)}",
            http_code=resp.status_code, tags=["gravatar", "profile", "geo"])
        self.add_status(result, SourceStatus(source="gravatar", category="geo", status="found",
                                             url=api, http_code=resp.status_code))
        add_entity(result, "email", email, gravatar=digest, location=location or None)
        for account in accounts:
            if account.get("url"):
                add_edge(result, entity_id("email", email), entity_id("link", account["url"]),
                         "linked_account", 0.9, f"Gravatar: подтверждённый аккаунт {account.get('domain')}")
        if location:
            add_edge(result, entity_id("email", email), entity_id("location", location),
                     "location", 0.8, "location указана владельцем в публичном Gravatar-профиле")

    # ─────────────────────────── Keybase ───────────────────────────
    async def _keybase(self, ctx: Context, value: str, result: ModuleResult, *, by_email: bool) -> None:
        param = {"email": value} if by_email else {"username": value.lstrip("@")}
        api = "https://keybase.io/_/api/1.0/user/lookup.json"
        resp = await ctx.http.get(api, params={**param, "fields": "basics,profile,proofs"},
                                  retries=1)
        data = resp.json() or {}
        if resp.error or not isinstance(data, dict):
            self.add_status(result, SourceStatus(source="keybase-geo", category="geo", status="error",
                                                 url=api, error=resp.error or "ответ не JSON"))
            return
        them = data.get("them") or []
        user = them[0] if isinstance(them, list) and them else (them if isinstance(them, dict) else {})
        status_code = (data.get("status") or {}).get("code")
        if status_code != 0 or not user:
            self.add_status(result, SourceStatus(source="keybase-geo", category="geo", status="not_found",
                                                 url=api, detail=(data.get("status") or {}).get("desc", "нет профиля")))
            return
        profile = user.get("profile") or {}
        location = (profile.get("location") or "").strip()
        bio = (profile.get("bio") or "").strip()
        full_name = (profile.get("full_name") or "").strip()
        proofs = [p.get("service_url") or p.get("nametag") or p.get("service")
                  for p in ((user.get("proofs_summary") or {}).get("all") or [])]
        found = gazetteer.find_location(" · ".join([location, bio]))
        self.add_finding(
            result, source="keybase-geo", category="geo", kind="profile", confidence="high",
            title=("Keybase: " + (full_name or value) + (f" — {location}" if location else "")
                   + (f" (proofs: {len(proofs)})" if proofs else "")),
            url=f"https://keybase.io/{user.get('username')}" if user.get("username") else api,
            value=value,
            data={"location": location, "bio": bio[:400], "name": full_name,
                  "country": found[0].country if found else "", "city": found[0].city if found else "",
                  "proofs": proofs[:15], "username": user.get("username"),
                  "id": user.get("id"), "avatar": (user.get("pictures") or {}).get("primary", {}).get("url")},
            evidence=f"keybase lookup {'email' if by_email else 'username'}={value!r} → "
                     f"profile.location={location!r}, proofs={len(proofs)}",
            http_code=resp.status_code, tags=["keybase", "profile", "geo"])
        self.add_status(result, SourceStatus(source="keybase-geo", category="geo", status="found",
                                             url=api, http_code=resp.status_code))
        if location:
            add_edge(result, entity_id("email" if by_email else "username", value),
                     entity_id("location", location), "location", 0.8,
                     "location в публичном профиле Keybase")

    # ─────────────────────────── Steam ───────────────────────────
    async def _steam(self, ctx: Context, login: str, result: ModuleResult) -> None:
        url = f"https://steamcommunity.com/id/{login}/?xml=1"
        resp = await ctx.http.get(url, retries=1)
        if resp.error or resp.looks_blocked():
            self.add_status(result, SourceStatus(source="steam-geo", category="geo",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 url=url, http_code=resp.status_code or None,
                                                 error=resp.error or "страница-заглушка/капча"))
            return
        text = resp.text
        if resp.status_code == 200 and ("profile could not be found" in text
                                       or "<error>" in text or "<location>" not in text):
            self.add_status(result, SourceStatus(source="steam-geo", category="geo", status="not_found",
                                                 url=url, http_code=200,
                                                 detail="профиля Steam с таким vanity-логином нет"))
            return
        if resp.status_code != 200:
            self.add_status(result, SourceStatus(source="steam-geo", category="geo", status="error",
                                                 url=url, http_code=resp.status_code))
            return
        location = html.unescape(_tag(STEAM_LOC, text))
        real_name = html.unescape(_tag(STEAM_NAME, text))
        created = _tag(STEAM_CREATED, text)
        steam_id = _tag(STEAM_ID, text)
        country_code = _tag(STEAM_COUNTRY, text)
        summary = html.unescape(re.sub(r"<!\[CDATA\[|\]\]>", "", _tag(STEAM_SUMMARY, text))).strip()
        country = gazetteer.country_name(country_code) if country_code else ""
        if not country and location:
            found = gazetteer.find_location(location)
            country = found[0].country if found else ""
        self.add_finding(
            result, source="steam-geo", category="geo", kind="profile", confidence="high",
            title=("Steam: " + (real_name or login)
                   + (f" — {location}" if location else "")
                   + (f" [{country}]" if country and country != location else "")),
            url=f"https://steamcommunity.com/id/{login}", value=login,
            data={"location": location, "country": country, "name": real_name, "created_at": created,
                  "steam_id": steam_id, "summary": summary[:400], "account_created": created},
            evidence=f"public XML steamcommunity.com/id/{login}/?xml=1 → location={location!r}, "
                     f"realname={real_name!r}, timecreated={created!r}",
            http_code=200, tags=["steam", "profile", "geo"])
        self.add_status(result, SourceStatus(source="steam-geo", category="geo", status="found",
                                             url=url, http_code=200))
        if location:
            add_edge(result, entity_id("username", login), entity_id("location", location),
                     "location", 0.8, "location в публичном профиле Steam")

    # ─────────────────────────── телефон ───────────────────────────
    async def _phone(self, ctx: Context, target: str, result: ModuleResult) -> None:
        digits = "".join(ch for ch in target if ch.isdigit())
        e164 = target if target.startswith("+") else f"+{digits}"
        code = gazetteer.country_from_phone(e164)
        if not code:
            self.add_status(result, SourceStatus(source="geo:phone", category="geo", status="error",
                                                 detail=f"не удалось определить страну по номеру {e164}: "
                                                        "номер не полный или код не в справочнике"))
            return
        country = gazetteer.country_name(code)
        cities = gazetteer.cities_of(code)[:6]
        carrier, timezone = "", ""
        try:
            import phonenumbers
            from phonenumbers import carrier as pn_carrier
            from phonenumbers import timezone as pn_timezone

            number = phonenumbers.parse(e164, None)
            carrier = pn_carrier.name_for_number(number, "ru") or pn_carrier.name_for_number(number, "en") or ""
            timezone = ", ".join(pn_timezone.time_zones_for_number(number))
        except Exception:
            pass
        self.add_finding(
            result, source="geo:phone", category="geo", kind="location", confidence="high",
            title=f"Телефон {e164} зарегистрирован в стране: {country}" +
                  (f" (оператор: {carrier})" if carrier else "") +
                  (f" — часовой пояс {timezone}" if timezone else ""),
            value=country, data={"country": country, "country_code": code, "e164": e164,
                                 "carrier": carrier, "timezone": timezone, "cities_example": cities,
                                 "note": "страна номера — это НЕ доказательство проживания: "
                                         "номер может быть куплен или быть виртуальным"},
            evidence=f"код страны номера {e164} → {code} ({country}); "
                     f"оператор={carrier or 'н/д'}, tz={timezone or 'н/д'}")
        self.add_status(result, SourceStatus(source="geo:phone", category="geo", status="found",
                                             detail=f"регион {code} ({country})"))
        add_entity(result, "location", country, country_code=code, source="телефон")
        add_edge(result, entity_id("phone", e164), entity_id("location", country), "region", 0.7,
                 f"код номера соответствует стране {country}")
