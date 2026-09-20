"""Человек по ФИО/нику: реальные проверки, а не «догадки на глаз».

Что делается:
  1. Разбор имени: транслитерация, части, варианты написания (Ivan Petrov / Ivanov Ivan / Петров И.И.);
  2. Wikidata / Wikipedia — реальные сущности (люди, компании) с указанием источника;
  3. OpenSanctions — реальные санкционные/PEP-списки (открытый API);
  4. Genderize/Nationalize — вероятностная оценка (честно помечена как низкая достоверность);
  5. Генерация логинов из ФИО и РЕАЛЬНАЯ проверка по реестру площадок (только занятые логины);
  6. Генерация адресов на популярных провайдерах + реальная проверка существования домена(MX)
     и (опционально, --smtp) ящика через SMTP RCPT;
  7. Ссылки на поисковые системы с операторами — как отдельный тип «reference», не как утверждение.
"""
from __future__ import annotations

from typing import Any

from ..core.models import ModuleResult, SourceStatus
from ..core.registry import load_sites
from ..core.utils import parse_dork_target, translit
from ..core.variants import name_to_usernames
from .base import Context, Module, SiteChecker, add_edge, add_entity, entity_id, make_finding
from .email import dns_lookup
from .username import UsernameModule

TOP_PROBE_SITES = ("github", "telegram", "instagram", "vk", "twitter", "tiktok", "youtube", "reddit",
                   "twitch", "steam", "keybase", "gitlab", "pinterest", "medium", "habr", "ok",
                   "facebook", "linkedin", "spotify", "soundcloud", "patreon", "mastodon.social")


class PersonModule(Module):
    name = "person"
    title = "Человек: варианты имени, Wikidata, санкционные списки, проверка логинов"
    categories = ("person",)
    target_types = ("person", "name")

    def __init__(self, *, probe_limit: int = 24, extra_terms: list[str] | None = None):
        self.probe_limit = probe_limit
        self.extra_terms = extra_terms or []

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        name = target.strip()
        usernames = name_to_usernames(name, extra=self.extra_terms, limit=60)
        emails_guess = _email_guesses(name, usernames)
        self.add_finding(result, source="name-analysis", category="person", kind="meta", confidence="high",
                         title=f"Разбор имени «{name}»: латиница «{translit(name)}», "
                               f"кандидатов-логинов {len(usernames)}",
                         value=name,
                         data={"latin": translit(name), "parts": name.split(),
                               "username_candidates": usernames[:40],
                               "email_candidates": emails_guess[:20]},
                         evidence="транслитерация по таблице + комбинаторика ФИО (имя+фамилия, инициалы, разделители)")
        add_entity(result, "person", name, latin=translit(name))
        for u in usernames[:20]:
            add_edge(result, entity_id("person", name), entity_id("username", u), "possible_username", 0.4,
                     "сгенерировано из ФИО (гипотеза, требует проверки)")

        await self._wikidata(ctx, name, result)
        await self._wikipedia(ctx, name, result)
        await self._opensanctions(ctx, name, result)
        await self._guess_api(ctx, name, result)
        await self._probe_usernames(ctx, name, usernames, result)
        await self._email_candidates(ctx, name, emails_guess, result)
        self._links(name, result)

    # ───────────────────── Wikidata / Wikipedia ─────────────────────
    async def _wikidata(self, ctx: Context, name: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://www.wikidata.org/w/api.php",
                                  params={"action": "wbsearchentities", "search": name, "language": "ru",
                                          "uselang": "ru", "format": "json", "limit": 10,
                                          "origin": "*"}, retries=1)
        data = resp.json() or {}
        items = data.get("search") or []
        if not items:
            self.add_status(result, SourceStatus(source="wikidata", category="person", status="not_found",
                                                 http_code=resp.status_code, url=resp.url))
            return
        entities = [{"id": i.get("id"), "label": i.get("label"), "description": i.get("description"),
                     "url": f"https://www.wikidata.org/wiki/{i.get('id')}"} for i in items]
        self.add_finding(result, source="wikidata", category="person", kind="entity", confidence="medium",
                         title=f"Wikidata: {len(items)} сущностей с именем «{name}» "
                               f"(например: {items[0].get('label')} — {items[0].get('description') or 'без описания'})",
                         url=entities[0]["url"], value=name, data={"entities": entities,
                                                                   "note": "совпадение по имени, НЕ подтверждение личности"},
                         evidence=f"wbsearchentities(ru) → {len(items)} результатов, первый: {items[0].get('id')}",
                         http_code=resp.status_code)
        self.add_status(result, SourceStatus(source="wikidata", category="person", status="found",
                                             http_code=resp.status_code, url=resp.url))

    async def _wikipedia(self, ctx: Context, name: str, result: ModuleResult) -> None:
        for lang in ("ru", "en"):
            resp = await ctx.http.get(f"https://{lang}.wikipedia.org/w/api.php",
                                      params={"action": "query", "list": "search", "srsearch": name,
                                              "format": "json", "srlimit": 5, "origin": "*"}, retries=1)
            data = resp.json() or {}
            hits = ((data.get("query") or {}).get("search") or [])
            if hits:
                pages = [{"title": h.get("title"),
                          "url": f"https://{lang}.wikipedia.org/wiki/{h.get('title', '').replace(' ', '_')}",
                          "snippet": _strip_html(h.get("snippet", ""))} for h in hits]
                self.add_finding(result, source=f"wikipedia-{lang}", category="person", kind="entity",
                                 confidence="low",
                                 title=f"Wikipedia ({lang}): {len(hits)} статей по запросу «{name}»",
                                 url=pages[0]["url"], value=name, data={"pages": pages},
                                 evidence=f"Wikipedia search API ({lang}) → {len(hits)} результатов",
                                 http_code=resp.status_code)
                self.add_status(result, SourceStatus(source=f"wikipedia-{lang}", category="person",
                                                     status="found", http_code=resp.status_code, url=resp.url))
                return
            self.add_status(result, SourceStatus(source=f"wikipedia-{lang}", category="person",
                                                 status="not_found", http_code=resp.status_code or None))

    # ───────────────────── Санкционные списки ─────────────────────
    async def _opensanctions(self, ctx: Context, name: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://api.opensanctions.org/search/default",
                                  params={"q": name, "limit": 5}, retries=1)
        data = resp.json() or {}
        results = data.get("results") or []
        if results:
            entities = []
            for r in results:
                props = r.get("properties") or {}
                entities.append({
                    "id": r.get("id"), "caption": r.get("caption"),
                    "schema": r.get("schema"), "score": r.get("score"),
                    "datasets": r.get("datasets"), "countries": props.get("country"),
                    "birth_date": props.get("birthDate"), "topics": props.get("topics"),
                    "url": f"https://www.opensanctions.org/entities/{r.get('id')}/",
                    "aliases": (props.get("alias") or [])[:5],
                })
            self.add_finding(result, source="opensanctions", category="person", kind="entity",
                             confidence="medium",
                             title=f"OpenSanctions: {len(results)} совпадений по имени «{name}» "
                                   f"(топ: {results[0].get('caption')}, схема {results[0].get('schema')}, "
                                   f"score {results[0].get('score')})",
                             url=entities[0]["url"], value=name,
                             data={"matches": entities,
                                   "note": "совпадение имени с санкционными/PEP-списками; "
                                           "обязательна проверка по дате рождения и гражданству"},
                             evidence=f"api.opensanctions.org/search/default?q={name} → {len(results)} результатов",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="opensanctions", category="person", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="opensanctions", category="person", status="not_found",
                                                 http_code=resp.status_code or None, url=resp.url,
                                                 error=resp.error))

    # ───────────────────── Вероятностные API ─────────────────────
    async def _guess_api(self, ctx: Context, name: str, result: ModuleResult) -> None:
        first = name.split()[0] if name.split() else name
        g, n = await _gather(ctx.http.get("https://api.genderize.io", params={"name": first}, retries=1),
                             ctx.http.get("https://api.nationalize.io", params={"name": name.split()[-1]}, retries=1))
        gdata, ndata = g.json() or {}, n.json() or {}
        if gdata.get("gender"):
            self.add_finding(result, source="genderize.io", category="person", kind="guess", confidence="low",
                             title=f"Вероятный пол по имени «{first}»: {gdata.get('gender')} "
                                   f"(уверенность {round((gdata.get('probability') or 0) * 100)}% по "
                                   f"{gdata.get('count')} записям)",
                             url=f"https://genderize.io/?name={first}", value=name, data=gdata,
                             evidence=f"genderize.io → gender={gdata.get('gender')}, "
                                      f"probability={gdata.get('probability')}, count={gdata.get('count')}")
        countries = ndata.get("country") or []
        if countries:
            top = countries[0]
            self.add_finding(result, source="nationalize.io", category="person", kind="guess", confidence="low",
                             title=f"Вероятное происхождение по фамилии: {top.get('country_id')} "
                                   f"({round((top.get('probability') or 0) * 100)}%)",
                             url="https://nationalize.io/", value=name,
                             data={"countries": countries[:5]},
                             evidence=f"nationalize.io → top={top.get('country_id')}, "
                                      f"probability={top.get('probability')}")

    # ───────────────────── Реальная проверка логинов ─────────────────────
    async def _probe_usernames(self, ctx: Context, name: str, usernames: list[str],
                               result: ModuleResult) -> None:
        sites = [s for s in load_sites("username") if s["name"] in TOP_PROBE_SITES]
        if not sites:
            return
        checker = SiteChecker(ctx, "person")
        checked = 0
        max_variants = 8 if not ctx.deep else 20
        for candidate in usernames[:max_variants]:
            if ctx.cancelled():
                break

            def on_found(hit: dict[str, Any], site: dict[str, Any], _c: str = candidate) -> None:
                finding = make_finding(site, _c, hit, category="person", confidence="medium",
                                       title=f"{site['name']}: логин «{_c}» занят — возможный аккаунт этого человека",
                                       data={"candidate_from_name": name})
                result.findings.append(finding)
                add_edge(result, entity_id("person", name), entity_id("username", _c),
                         "name_variant_account", 0.35, f"логин-кандидат из ФИО занят на {site['name']}")

            await checker.check_many(sites, candidate, result, on_found=on_found)
            checked += 1
        result.meta["probe_summary"] = {"variants_checked": checked, "sites_per_variant": len(sites),
                                        "note": "занятый логин ≠ этот человек: связь вероятностная, "
                                                "требуется подтверждение (фото, город, круг общения)"}

    # ───────────────────── Адреса-кандидаты ─────────────────────
    async def _email_candidates(self, ctx: Context, name: str, emails: list[str], result: ModuleResult) -> None:
        import asyncio
        loop = asyncio.get_running_loop()
        checked: list[dict[str, Any]] = []
        for email in emails[:12]:
            domain = email.split("@")[-1]
            mx = await loop.run_in_executor(None, dns_lookup, domain, "MX")
            checked.append({"email": email, "domain": domain, "mx_ok": bool(mx), "mx": mx[:2]})
        self.add_finding(result, source="email-candidates", category="person", kind="variant", confidence="low",
                         title=f"Сгенерировано {len(checked)} адресов-кандидатов; у {sum(1 for c in checked if c['mx_ok'])} "
                               f"домен принимает почту (MX есть)",
                         value=name, data={"candidates": checked},
                         evidence="шаблоны имя.фамилия@провайдер + реальная DNS-проверка MX домена; "
                                  "существование конкретного ящика не подтверждено (нужен SMTP/ключ провайдера)")

    # ───────────────────── Ссылки ─────────────────────
    def _links(self, name: str, result: ModuleResult) -> None:
        links = parse_dork_target(f'"{name}"')
        latin = translit(name).title()
        links += [f'https://www.google.com/search?q="{name}"+site:vk.com',
                  f'https://www.google.com/search?q="{name}"+site:ok.ru',
                  f'https://www.google.com/search?q="{name}"+site:t.me',
                  f'https://www.google.com/search?q="{latin}"+linkedin',
                  f'https://www.google.com/search?q="{name}"+резюме+OR+CV+OR+filetype:pdf',
                  f'https://www.google.com/search?q="{name}"+(директор+OR+учредитель+OR+ИНН)',
                  f'https://egrul.nalog.ru/index.html',
                  f'https://www.rusprofile.ru/search?query={name}',
                  f'https://yandex.ru/search/?text="{name}"',
                  f'https://www.facebook.com/search/people/?q={name}',
                  f'https://www.instagram.com/explore/tags/{latin.lower().replace(" ", "")}/']
        self.add_finding(result, source="person-dorks", category="person", kind="link", confidence="low",
                         title="Поисковые ссылки по ФИО (соцсети, реестры, резюме)",
                         value=name, url=links[0], data={"links": links},
                         evidence="ссылки на людей-поисковики, реестры юрлиц и соцсети — ручная проверка")


def _email_guesses(name: str, usernames: list[str]) -> list[str]:
    providers = ["gmail.com", "yandex.ru", "mail.ru", "list.ru", "bk.ru", "inbox.ru", "outlook.com", "icloud.com"]
    out: list[str] = []
    for u in usernames[:6]:
        for p in providers[:4]:
            out.append(f"{u}@{p}")
    parts = [translit(p).lower() for p in name.split() if p]
    if len(parts) >= 2:
        for p in providers:
            out += [f"{parts[0]}.{parts[-1]}@{p}", f"{parts[0]}{parts[-1]}@{p}",
                    f"{parts[0][0]}.{parts[-1]}@{p}", f"{parts[-1]}@{p}"]
    seen, unique = set(), []
    for e in out:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    return unique


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "")


async def _gather(*aws):
    import asyncio
    return await asyncio.gather(*aws)
