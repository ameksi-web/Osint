"""Телефон: разбор номера (libphonenumber), гео/оператор, онлайн-API, реестр сайтов, мессенджеры.

Офлайн (всегда работает, без интернета):
  * страна, код страны, регион/город, оператор, тип линии (мобильный/стационарный/VoIP),
    часовые пояса, возможность отправки SMS, корректность номера (libphonenumber).
  * сразу видно, номера каких стран не поддерживаются в Google libphonenumber.

Онлайн (реальные запросы):
  * numverify / veriphone (с ключом) — оператор, тип, гео;
  * реестр сайтов, где номер виден публично (по стратегиям реестра);
  * ссылки на мессенджеры (wa.me / t.me / viber) — как точки проверки, а не утверждения.
"""
from __future__ import annotations

from typing import Any

from ..core.models import ModuleResult, SourceStatus
from ..core.registry import load_sites
from ..core.utils import clean_phone
from .base import Context, Module, SiteChecker, add_entity, entity_id, add_edge, make_finding

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_timezone
    PHONENUMBERS_OK = True
except ImportError:  # pragma: no cover
    PHONENUMBERS_OK = False

LINE_TYPES = {
    0: "стационарный (FIXED_LINE)", 1: "мобильный", 2: "стационарный или мобильный",
    3: "бесплатный (toll free)", 4: "премиум (платный)", 5: "общий номер (shared cost)",
    6: "VoIP", 7: "личный номер", 8: "пейджер", 9: "UAN", 10: "голосовая почта",
    27: "мобильный или VoIP",
}


class PhoneModule(Module):
    name = "phone"
    title = "Телефон: libphonenumber, оператор, регион, публичные упоминания"
    categories = ("phone",)
    target_types = ("phone",)

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        raw = clean_phone(target)
        if not PHONENUMBERS_OK:
            result.errors.append("Библиотека phonenumbers не установлена — офлайн-разбор номера недоступен "
                                 "(pip install phonenumbers)")
        if PHONENUMBERS_OK:
            await self._offline(ctx, raw, result)
        await self._online(ctx, target, result)
        await self._sites(ctx, target, result)
        self._messengers(target, result)

    # ─────────────────────── офлайн-разбор ───────────────────────
    async def _offline(self, ctx: Context, raw: str, result: ModuleResult) -> None:
        parsed = None
        for region in (None, "RU", "UA", "KZ", "BY", "US", "GB", "DE", "TR"):
            try:
                candidate = phonenumbers.parse(raw, region)
                if phonenumbers.is_possible_number(candidate):
                    parsed = candidate
                    break
            except Exception:
                continue
        if parsed is None:
            self.add_status(result, SourceStatus(source="libphonenumber", category="phone", status="not_found",
                                                 detail=f"номер «{raw}» не распознан ни в одном регионе"))
            result.errors.append(f"«{target}» не распознан как телефонный номер (проверь код страны)")
            return
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)
        region_code = phonenumbers.region_code_for_number(parsed)
        operator = carrier.name_for_number(parsed, "ru") or carrier.name_for_number(parsed, "en")
        geo = geocoder.description_for_number(parsed, "ru") or geocoder.description_for_number(parsed, "en")
        tz = list(pn_timezone.time_zones_for_number(parsed))
        line = LINE_TYPES.get(parsed.number_type, f"тип {parsed.number_type}")
        formats = {
            "E164": e164,
            "международный": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "национальный": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "RFC3966": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966),
        }
        self.add_finding(result, source="libphonenumber", category="phone", kind="meta",
                         confidence="high" if valid else "medium",
                         title=f"{tuple(formats.values())[1]} — {geo or region_code or '?'}"
                               f"{', ' + operator if operator else ''} ({line})",
                         value=e164, url=f"https://www.google.com/search?q=%22{e164}%22",
                         data={"valid": valid, "possible": possible, "region": region_code,
                               "operator": operator or None, "geocoded": geo or None,
                               "line_type": line, "timezones": tz, "country_code": parsed.country_code,
                               "national_number": parsed.national_number,
                               "is_mobile": parsed.number_type in (1, 2, 27),
                               "can_sms": parsed.number_type in (1, 2, 6, 27), "formats": formats},
                         evidence=f"libphonenumber: is_valid={valid}, is_possible={possible}, "
                                  f"region={region_code}, type={line}")
        add_entity(result, "phone", e164, region=region_code, operator=operator or None, valid=valid)
        if not valid:
            result.errors.append(f"Номер не проходит проверку libphonenumber (is_valid=False) — "
                                 f"возможно, выдуман или не присвоен")
        self.add_status(result, SourceStatus(source="libphonenumber", category="phone",
                                             status="found" if valid else "not_found",
                                             detail=f"valid={valid}, region={region_code}"))

    # ─────────────────────── онлайн-API ───────────────────────
    async def _online(self, ctx: Context, target: str, result: ModuleResult) -> None:
        digits = clean_phone(target)
        if ctx.key("numverify"):
            resp = await ctx.http.get("https://apilayer.net/api/validate",
                                      params={"access_key": ctx.key("numverify"), "number": digits,
                                              "format": 1}, retries=1)
            data = resp.json() or {}
            if data.get("valid") is not None:
                self.add_finding(result, source="numverify", category="phone", kind="meta", confidence="high",
                                 title=f"Numverify: {data.get('carrier') or 'оператор неизвестен'}, "
                                       f"{data.get('location') or '?'}",
                                 url="https://numverify.com/", value=digits,
                                 data={k: data.get(k) for k in
                                       ("valid", "number", "local_format", "international_format", "country_name",
                                        "location", "carrier", "line_type")},
                                 evidence=f"apilayer numverify → valid={data.get('valid')}, "
                                          f"carrier={data.get('carrier')}, line_type={data.get('line_type')}",
                                 http_code=resp.status_code)
                self.add_status(result, SourceStatus(source="numverify", category="phone", status="found",
                                                     http_code=resp.status_code))
            else:
                self.add_status(result, SourceStatus(source="numverify", category="phone",
                                                     status="error" if resp.status_code >= 400 else "not_found",
                                                     http_code=resp.status_code, error=str(data)[:150]))
        if ctx.key("veriphone"):
            resp = await ctx.http.get("https://api.veriphone.io/v2/verify",
                                      params={"phone": digits, "key": ctx.key("veriphone")}, retries=1)
            data = resp.json() or {}
            if data.get("status") == "success":
                self.add_finding(result, source="veriphone", category="phone", kind="meta", confidence="high",
                                 title=f"Veriphone: {data.get('carrier') or '?'}, "
                                       f"{data.get('region') or '?'} ({data.get('phone_type') or '?'})",
                                 url="https://veriphone.io/", value=digits,
                                 data={"carrier": data.get("carrier"), "phone_type": data.get("phone_type"),
                                       "region": data.get("region"), "country": data.get("country"),
                                       "valid": data.get("phone_valid")},
                                 evidence=f"veriphone → carrier={data.get('carrier')}, "
                                          f"type={data.get('phone_type')}, valid={data.get('phone_valid')}",
                                 http_code=resp.status_code)
                self.add_status(result, SourceStatus(source="veriphone", category="phone", status="found",
                                                     http_code=resp.status_code))
        # бесплатные публичные API, не требующие ключей
        free_apis = [
            ("phoneinfoga-numverify-free", "https://api.numverify.com/validate?number={phone_digits}"),
        ]
        for name, url_tpl in free_apis:
            url = url_tpl.replace("{phone_digits}", digits)
            resp = await ctx.http.get(url, retries=0, timeout=8)
            self.add_status(result, SourceStatus(source=name, category="phone",
                                                 status="found" if resp.ok else
                                                 ("blocked" if resp.looks_blocked() else "error"),
                                                 url=url, http_code=resp.status_code or None,
                                                 error=resp.error or resp.snippet(100)))

    # ─────────────────────── реестр сайтов ───────────────────────
    async def _sites(self, ctx: Context, target: str, result: ModuleResult) -> None:
        sites = load_sites("phone") if _registry_has("phone") else []
        if not sites:
            return
        checker = SiteChecker(ctx, "phone")

        def on_found(hit: dict[str, Any], site: dict[str, Any]) -> None:
            result.findings.append(make_finding(site, target, hit, category="phone"))
            add_edge(result, entity_id("phone", target), entity_id("site", site["name"]), "phone_public_on",
                     1.0, hit.get("evidence", ""))

        await checker.check_many(sites, target, result, on_found=on_found)

    # ─────────────────────── мессенджеры ───────────────────────
    def _messengers(self, target: str, result: ModuleResult) -> None:
        digits = clean_phone(target).lstrip("+")
        links = {
            "WhatsApp": f"https://wa.me/{digits}",
            "Telegram": f"https://t.me/+{digits}",
            "Viber": f"viber://chat?number=%2B{digits}",
            "Signal": f"https://signal.me/#p/+{digits}",
            "VK": f"https://vk.com/search?c%5Bsection%5D=people&c%5Bq%5D={digits}",
        }
        self.add_finding(result, source="messengers", category="phone", kind="link", confidence="low",
                         title="Ссылки на мессенджеры (открыть и проверить наличие профиля вручную)",
                         value=clean_phone(target), url=links["Telegram"],
                         data={"links": links, "note": "наличие профиля эти ссылки не подтверждают — "
                                                       "только открывают чат/поиск"},
                         evidence="шаблоны deep-link мессенджеров; автоматической проверки существования нет")

    async def _unused(self) -> None:  # pragma: no cover
        return None


def _registry_has(category: str) -> bool:
    from ..core.registry import CATEGORIES
    return category in CATEGORIES
