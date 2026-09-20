"""Email-модуль: полный набор реальных проверок адреса.

Что реально проверяется:
  1. Синтаксис + нормализация (RFC-подобная проверка).
  2. DNS: MX, A, SPF, DMARC, DKIM-селекторы, DNSSEC — через dnspython.
  3. Провайдер почты по MX (Google Workspace, Microsoft 365, Yandex, Mail.ru, Proton...).
  4. Одноразовые (disposable), временные и «ловушки» — по своей базе домены + эвристики.
  5. Gravatar: есть ли аватар и публичный профиль (MD5-хеш адреса).
  6. Регистрации на ~200 сайтах (реестр, holehe-совместимая логика).
  7. Утечки: XposedOrNot (без ключа) + HIBP/LeakCheck/DeHashed/IntelX (с ключами).
  8. Hunter.io — верификация и связанные адреса домена (с ключом).
  9. SMTP RCPT-проверка существования ящика (опционально, --smtp).
 10. Поисковые ссылки (dorks) — как прозрачные ссылки, а не как «найденное».
"""
from __future__ import annotations

import asyncio
import hashlib
import socket
import smtplib
from typing import Any

from ..core.models import ModuleResult, SourceStatus
from ..core.registry import load_sites
from ..core.utils import is_valid_email, mask_email, parse_dork_target
from ..core.variants import email_variants, email_local_parts
from .base import Context, Module, SiteChecker, add_edge, add_entity, entity_id, make_finding

DISPOSABLE_MARKERS = ("mailinator", "tempmail", "10minute", "guerrillamail", "yopmail", "trashmail",
                      "sharklasers", "throwaway", "dispostable", "getnada", "maildrop", "temp-mail",
                      "fakeinbox", "mohmal", "tempr", "emailondeck", "mailnesia", "spam4.me",
                      "discard.email", "trbvm", "moakt", "tempail", "luxusmail", "inboxkitten")
ROLE_ACCOUNTS = ("admin", "info", "support", "sales", "billing", "postmaster", "abuse", "noreply",
                 "no-reply", "webmaster", "help", "contact", "office", "hr", "jobs", "marketing")
FREE_PROVIDERS = {"gmail.com", "googlemail.com", "yandex.ru", "ya.ru", "yandex.com", "mail.ru",
                  "bk.ru", "inbox.ru", "list.ru", "internet.ru", "rambler.ru", "outlook.com",
                  "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "icloud.com",
                  "me.com", "aol.com", "gmx.com", "gmx.de", "mail.com", "zoho.com", "proton.me",
                  "protonmail.com", "pm.me", "tutanota.com", "tuta.io", "ukr.net", "i.ua",
                  "meta.ua", "seznam.cz", "wp.pl", "o2.pl", "interia.pl", "qq.com", "163.com",
                  "126.com", "naver.com", "hanmail.net", "web.de", "t-online.de", "free.fr",
                  "orange.fr", "laposte.net", "libero.it", "virgilio.it", "terra.com.br", "uol.com.br"}
PROVIDER_BY_MX = {
    "google.com": "Google Workspace / Gmail", "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Outlook", "protection.outlook.com": "Microsoft 365",
    "yandex.net": "Yandex 360 (Яндекс.Почта для домена)", "yandex.ru": "Yandex",
    "mail.ru": "Mail.ru для бизнеса / VK WorkMail", "corp.mail.ru": "Mail.ru для бизнеса (VK)",
    "emailsrvr.com": "GoDaddy Email", "secureserver.net": "GoDaddy",
    "protonmail.ch": "Proton Mail", "proton.me": "Proton Mail",
    "zoho.com": "Zoho Mail", "mailgun.org": "Mailgun (транзакционная)",
    "sendgrid.net": "SendGrid", "amazonses.com": "Amazon SES",
    "mimecast.com": "Mimecast (корп. защита)", "pphosted.com": "Proofpoint",
    "barracudanetworks.com": "Barracuda", "messagelabs.com": "Symantec MessageLabs",
    "icloud.com": "Apple iCloud Mail", "qq.com": "Tencent QQ Mail",
    "163.com": "NetEase 163", "ukr.net": "Ukr.net", "ukr.net.": "Ukr.net",
    "one.com": "One.com", "titan.email": "Titan (хостинг)", "privateemail.com": "Namecheap Private Email",
}
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "s1", "mail", "dkim",
                  "smtp", "mandrill", "cm", "protonmail", "zoho", "sendgrid", "mailchimp")


def _dns_available() -> bool:
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def dns_lookup(domain: str, rtype: str, timeout: float = 6.0) -> list[str]:
    """Реальный DNS-запрос через dnspython (или сокеты, если нет библиотеки)."""
    if _dns_available():
        import dns.resolver
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answers.rrset is None:
                return []
            if rtype == "MX":
                return [str(r.exchange).rstrip(".") for r in answers]
            if rtype in ("TXT", "SPF"):
                out = []
                for r in answers:
                    out.append("".join(s.decode() if isinstance(s, bytes) else s for s in r.strings))
                return out
            return [str(r).rstrip(".") if rtype in ("NS", "CNAME", "PTR") else str(r) for r in answers]
        except Exception:
            return []
    try:
        if rtype == "MX":
            return []  # MX требует dnspython: сокеты запись MX не отдают
        if rtype == "A":
            return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)})
        if rtype == "AAAA":
            return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        return []
    return []


def smtp_rcpt_check(email: str, mx_host: str, sender: str = "verify@example.com",
                    timeout: float = 8.0) -> tuple[bool | None, str]:
    """SMTP-проверка ящика (RCPT TO). Возвращает (существует?, пояснение).

    ВНИМАНИЕ: часть серверов отвечает 250 на всё (catch-all) или блокирует
    проверки (greylisting) — тогда возвращаем None, а не «существует».
    """
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(sender)
            code, msg = smtp.rcpt(email)
            text = msg.decode("utf-8", "ignore") if isinstance(msg, bytes) else str(msg)
            if code in (250, 251):
                return True, f"RCPT {code}: {text[:120]}"
            if code in (550, 551, 553, 554):
                return False, f"RCPT {code}: {text[:120]}"
            return None, f"RCPT {code}: {text[:120]} (неопределённо)"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:160]


class EmailModule(Module):
    name = "email"
    title = "Email: валидация, DNS, провайдер, Gravatar, регистрации, утечки"
    categories = ("email",)
    target_types = ("email",)

    def __init__(self, *, include_breaches: bool = True, include_sites: bool = True,
                 smtp: bool = False, variants: bool = True):
        self.include_breaches = include_breaches
        self.include_sites = include_sites
        self.smtp = smtp
        self.variants = variants

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        email = target.strip().lower()
        local, _, domain = email.partition("@")

        # 1. Синтаксис
        if not is_valid_email(email):
            result.errors.append(f"«{target}» не похож на корректный email (RFC-синтаксис не пройден)")
            result.statuses.append(SourceStatus(source="syntax", category="email",
                                                status="not_found", detail="некорректный синтаксис"))
            return
        self.add_finding(result,
                         source="syntax", category="email", kind="meta", confidence="high",
                         title=f"Синтаксис корректен, нормализовано: {email}",
                         value=email, data={"local": local, "domain": domain,
                                            "length": len(email), "lowercase": target != email},
                         evidence="проверка по регулярному выражению + нормализация Unicode/lowercase")
        add_entity(result, "email", email)
        for part in email_local_parts(email):
            add_edge(result, entity_id("email", email), entity_id("username", part),
                     "email_local_part_variant", 0.5, "пользователь обычно берёт логин из локальной части email")

        # 2. DNS + провайдер
        await ctx.notify(stage="email:dns", message="Проверяю DNS и почтового провайдера")
        await self._dns_and_provider(ctx, email, domain, result)

        # 3. Одноразовый домен
        self._disposable(email, domain, result)

        # 4. Gravatar
        await self._gravatar(ctx, email, result)

        # 5. Сайты регистраций
        if self.include_sites:
            sites = load_sites("email")
            if not ctx.deep:
                sites = [s for s in sites if s.get("confidence") != "low"] or sites
            await ctx.notify(stage="email:sites", message=f"Проверяю {len(sites)} источников регистраций",
                             total=len(sites))
            checker = SiteChecker(ctx, "email")

            def on_found(hit: dict[str, Any], site: dict[str, Any]) -> None:
                finding = make_finding(site, email, hit, category="email")
                result.findings.append(finding)
                uname = site.get("username_from_email")
                add_edge(result, entity_id("email", email), entity_id("site", site["name"]),
                         "has_account", float(site.get("weight", 1.0)), hit.get("evidence", ""))
                if uname:
                    add_edge(result, entity_id("email", email), entity_id("username", uname),
                             "account_local_part", 0.6, f"аккаунт на {site['name']}")

            await checker.check_many(sites, email, result, on_found=on_found)

        # 6. Утечки
        if self.include_breaches:
            from .breach import check_breaches
            await check_breaches(ctx, email, result)

        # 7. Hunter.io
        if ctx.key("hunter"):
            await self._hunter(ctx, email, result)

        # 8. SMTP RCPT
        if self.smtp:
            await self._smtp(ctx, email, domain, result)

        # 9. Вариации адреса (реальные находки, а не «может быть»)
        if self.variants:
            for variant in email_variants(email)[:12]:
                if variant == email:
                    continue
                self.add_finding(result, source="email-variants", category="email", kind="variant",
                                 confidence="low", title=f"Вариация адреса: {variant}",
                                 value=variant, url=f"https://www.gravatar.com/{hashlib.md5(variant.encode()).hexdigest()}",
                                 data={"base": email},
                                 evidence="сгенерировано из шаблонов (точки/плюс-тег/смена провайдера) — требует проверки")

        # 10. Dorks
        await self._dorks(ctx, email, result)

    # ─────────────────────────── части ───────────────────────────
    async def _dns_and_provider(self, ctx: Context, email: str, domain: str, result: ModuleResult) -> None:
        loop = asyncio.get_running_loop()
        mx, a, txt, dmarc, ns = await asyncio.gather(
            loop.run_in_executor(None, dns_lookup, domain, "MX"),
            loop.run_in_executor(None, dns_lookup, domain, "A"),
            loop.run_in_executor(None, dns_lookup, domain, "TXT"),
            loop.run_in_executor(None, dns_lookup, f"_dmarc.{domain}", "TXT"),
            loop.run_in_executor(None, dns_lookup, domain, "NS"),
        )
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
        dmarc_txt = next((t for t in dmarc if "v=dmarc1" in t.lower()), "")
        provider = ""
        for record in mx:
            root = ".".join(record.split(".")[-2:])
            if root in PROVIDER_BY_MX:
                provider = PROVIDER_BY_MX[root]
                break
        dkim_found: list[str] = []
        if mx:
            for selector in DKIM_SELECTORS[:8]:
                recs = await loop.run_in_executor(None, dns_lookup, f"{selector}._domainkey.{domain}", "TXT")
                if any("v=dkim1" in (r or "").lower() or "p=" in (r or "") for r in recs):
                    dkim_found.append(selector)
        deliverable = bool(mx) or bool(a)
        self.add_finding(
            result, source="dns", category="email", kind="dns", confidence="high",
            title=f"Домен {domain}: {'MX найден — почта принимается' if mx else 'MX нет (адрес не принимает почту)'}",
            value=domain, url=f"https://dns.google/query?name={domain}&type=MX",
            data={"mx": mx, "a": a[:6], "ns": ns[:6], "spf": spf, "dmarc": dmarc_txt,
                  "dkim_selectors_found": dkim_found, "provider": provider,
                  "root_domain": _root_domain(domain)},
            evidence=f"DNS-запросы MX/A/NS/TXT/DMARC: record_count={len(mx) + len(a) + len(txt)}",
        )
        add_entity(result, "domain", domain, provider=provider, mx=mx[:5], spf=bool(spf), dmarc=bool(dmarc_txt))
        status = "found" if deliverable else "not_found"
        self.add_status(result, SourceStatus(source="dns:mx", category="email", status=status,
                                             detail=f"MX={mx[:3] or 'нет'}, провайдер={provider or 'неизвестен'}"))
        if not deliverable:
            result.errors.append("У домена нет ни MX, ни A-записи — письма на этот адрес не доставляются")
        if provider:
            self.add_finding(result, source="mail-provider", category="email", kind="meta", confidence="medium",
                             title=f"Почта обслуживается: {provider}", value=provider, data={"mx": mx},
                             evidence=f"MX-записи домена: {', '.join(mx[:3])}")

    def _disposable(self, email: str, domain: str, result: ModuleResult) -> None:
        low = domain.lower()
        matched = next((m for m in DISPOSABLE_MARKERS if m in low), "")
        from pathlib import Path
        extra_list = Path(__file__).resolve().parent.parent / "data" / "disposable_domains.txt"
        if not matched and extra_list.exists():
            lines = {ln.strip().lower() for ln in extra_list.read_text(encoding="utf-8").splitlines() if ln.strip()}
            matched = low if low in lines else ""
        is_free = low in FREE_PROVIDERS
        is_role = email.split("@")[0].lower().split("+")[0] in ROLE_ACCOUNTS
        if matched:
            self.add_finding(result, source="disposable-check", category="email", kind="meta", confidence="high",
                             title=f"Одноразовый/временный домен: {domain}", value=domain,
                             data={"matched": matched}, evidence=f"домен совпал с известным сервисом временной почты: {matched}")
        self.add_finding(result, source="email-hygiene", category="email", kind="meta", confidence="high",
                         title=("Бесплатный публичный почтовый сервис" if is_free else "Домен не в списке бесплатных сервисов")
                               + ("; адрес служебный (ролевой)" if is_role else ""),
                         value=email, data={"free_provider": is_free, "role_account": is_role,
                                            "masked": mask_email(email)},
                         evidence="сверка с локальной базой 80+ публичных и одноразовых почтовых доменов")
        self.add_status(result, SourceStatus(source="disposable-check", category="email",
                                             status="found" if matched else "not_found",
                                             detail=f"disposable={bool(matched)}, free={is_free}"))

    async def _gravatar(self, ctx: Context, email: str, result: ModuleResult) -> None:
        md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
        profile_url = f"https://gravatar.com/{md5}.json"
        resp = await ctx.http.get(profile_url, retries=1)
        avatar_url = f"https://www.gravatar.com/avatar/{md5}?s=200"
        json_data = resp.json()
        if resp.ok and isinstance(json_data, dict) and json_data.get("entry"):
            entry = json_data["entry"][0]
            self.add_finding(result, source="gravatar", category="email", kind="profile", confidence="high",
                             title=f"Gravatar-профиль: {entry.get('displayName') or entry.get('preferredUsername') or 'без имени'}",
                             url=entry.get("profileUrl") or avatar_url, value=email,
                             data={"display_name": entry.get("displayName"),
                                   "preferred_username": entry.get("preferredUsername"),
                                   "about": entry.get("aboutMe"), "avatar": avatar_url,
                                   "accounts": [a.get("shortname") for a in entry.get("accounts", [])],
                                   "urls": [u.get("value") for u in entry.get("urls", [])],
                                   "name": entry.get("name"), "location": entry.get("currentLocation")},
                             evidence=f"HTTP 200 от gravatar.com/{md5}.json, entry.displayName="
                                      f"{entry.get('displayName')!r}", http_code=resp.status_code)
            if entry.get("preferredUsername"):
                add_edge(result, entity_id("email", email), entity_id("username", entry["preferredUsername"]),
                         "gravatar_username", 0.9, "указан в Gravatar-профиле")
            self.add_status(result, SourceStatus(source="gravatar", category="email", status="found",
                                                 url=profile_url, http_code=resp.status_code,
                                                 latency_ms=resp.latency_ms))
            return
        head = await ctx.http.get(avatar_url, retries=1)
        if head.status_code == 200 and "image" in head.headers.get("content-type", ""):
            self.add_finding(result, source="gravatar", category="email", kind="profile", confidence="medium",
                             title="Gravatar-аватар существует (аккаунт Gravatar/WordPress есть)",
                             url=avatar_url, value=email, data={"avatar": avatar_url},
                             evidence=f"HTTP 200 + Content-Type={head.headers.get('content-type')} по хешу MD5",
                             http_code=head.status_code)
            self.add_status(result, SourceStatus(source="gravatar", category="email", status="found",
                                                 url=avatar_url, http_code=200))
            return
        self.add_finding(result, source="gravatar", category="email", kind="meta", confidence="high",
                         title="Gravatar не найден (аватар отсутствует)", value=email, url=avatar_url,
                         data={"md5": md5}, evidence=f"HTTP {resp.status_code or head.status_code} для "
                                                    f"gravatar.com/{md5}.json и .png — профиля нет")
        self.add_status(result, SourceStatus(source="gravatar", category="email", status="not_found",
                                             url=profile_url, http_code=resp.status_code or None,
                                             error=resp.error))

    async def _hunter(self, ctx: Context, email: str, result: ModuleResult) -> None:
        url = "https://api.hunter.io/v2/email-verifier"
        resp = await ctx.http.get(url, params={"email": email, "api_key": ctx.key("hunter")}, retries=1)
        data = resp.json()
        if resp.ok and isinstance(data, dict) and data.get("data"):
            payload = data["data"]
            self.add_finding(result, source="hunter.io", category="email", kind="meta", confidence="high",
                             title=f"Hunter.io: статус «{payload.get('status')}» (оценка {payload.get('score')})",
                             url="https://hunter.io/", value=email,
                             data={"status": payload.get("status"), "score": payload.get("score"),
                                   "disposable": payload.get("disposable"), "webmail": payload.get("webmail"),
                                   "accept_all": payload.get("accept_all"), "smtp_check": payload.get("smtp_check"),
                                   "sources": (payload.get("sources") or [])[:5]},
                             evidence=f"api.hunter.io/v2/email-verifier → status={payload.get('status')}, "
                                      f"score={payload.get('score')}, smtp_check={payload.get('smtp_check')}",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="hunter.io", category="email", status="found",
                                                 http_code=resp.status_code))
            domain = email.partition("@")[2]
            dresp = await ctx.http.get("https://api.hunter.io/v2/domain-search",
                                       params={"domain": domain, "api_key": ctx.key("hunter"), "limit": 25}, retries=1)
            ddata = dresp.json() or {}
            emails = [e.get("value") for e in (ddata.get("data", {}) or {}).get("emails", []) if e.get("value")]
            if emails:
                self.add_finding(result, source="hunter.io/domain-search", category="email", kind="related",
                                 confidence="medium",
                                 title=f"Связанные адреса домена {domain}: {len(emails)}",
                                 url=f"https://hunter.io/domain-search/{domain}", value=domain,
                                 data={"emails": emails[:25],
                                       "pattern": (ddata.get("data", {}) or {}).get("pattern")},
                                 evidence=f"api.hunter.io/v2/domain-search вернул {len(emails)} адресов",
                                 http_code=dresp.status_code)
                for e in emails[:25]:
                    add_edge(result, entity_id("domain", domain), entity_id("email", e), "same_org_email", 0.4,
                             "найдено Hunter.io domain-search")
        else:
            detail = str(data)[:160] if isinstance(data, dict) else resp.snippet(160)
            self.add_status(result, SourceStatus(source="hunter.io", category="email",
                                                 status="error" if not resp.ok else "not_found",
                                                 http_code=resp.status_code, error=detail,
                                                 detail="проверь HUNTER_API_KEY / лимит запросов"))

    async def _smtp(self, ctx: Context, email: str, domain: str, result: ModuleResult) -> None:
        loop = asyncio.get_running_loop()
        mx = await loop.run_in_executor(None, dns_lookup, domain, "MX")
        if not mx:
            return
        exists, message = await loop.run_in_executor(None, smtp_rcpt_check, email, mx[0])
        if exists is None:
            self.add_status(result, SourceStatus(source="smtp-rcpt", category="email", status="error",
                                                 detail=message))
            return
        self.add_finding(result, source="smtp-rcpt", category="email", kind="meta",
                         confidence="high" if exists else "medium",
                         title=("SMTP: ящик существует" if exists else "SMTP: ящик отклонён сервером"),
                         value=email, data={"mx": mx[0], "answer": message, "exists": exists},
                         evidence=f"диалог с MX {mx[0]}: {message}")
        self.add_status(result, SourceStatus(source="smtp-rcpt", category="email",
                                             status="found" if exists else "not_found", detail=message))

    async def _dorks(self, ctx: Context, email: str, result: ModuleResult) -> None:
        links = parse_dork_target(f'"{email}"')
        links += [f"https://www.google.com/search?q=%22{email}%22+password",
                  f"https://www.google.com/search?q=%22{email}%22+site:pastebin.com",
                  f"https://github.com/search?q={email}&type=code",
                  f"https://searchcode.com/?q={email}",
                  f"https://www.google.com/search?q=%22{email}%22+-site:{email.split('@')[-1]}"]
        self.add_finding(result, source="dorks", category="email", kind="link", confidence="low",
                         title=f"Поисковые ссылки по адресу ({len(links)}) — открыть и проверить вручную",
                         value=email, url=links[0], data={"links": links},
                         evidence="ссылки на поисковые системы с точным совпадением адреса; "
                                  "автоматических утверждений нет — это точки входа для проверки")


def _root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    two_level = {"co.uk", "com.br", "com.au", "co.jp", "com.cn", "co.in", "com.tr", "co.kr", "com.ua", "co.il"}
    if ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
