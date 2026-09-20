"""Домен: DNS, RDAP/whois, сертификаты (crt.sh), поддомены, веб-технологии, почтовый контур.

Все данные берутся из открытых источников в реальном времени:
  * DNS (A/AAAA/MX/NS/TXT/SOA/CAA/DNSSEC) — dnspython;
  * RDAP — регистратор, даты, статусы, abuse-контакты (протокол вместо устаревшего whois);
  * crt.sh — Certificate Transparency: все поддомены, попадавшие в TLS-сертификаты;
  * HackerTarget hostsearch + перебор словарём поддоменов с реальным DNS-резолвом;
  * Wayback Machine + urlscan.io — история и сканы;
  * security.txt, robots.txt, sitemap.xml, HTTP-заголовки и определение технологий;
  * попытка AXFR (передача зоны) — обычно запрещена, но проверка реальная;
  * связанные домены на том же IP (обратный IP-поиск).
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from ..core.models import ModuleResult, SourceStatus
from ..core.utils import clean_domain
from .base import Context, Module, add_edge, add_entity, entity_id
from .email import dns_lookup

SUBDOMAIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "email", "api", "api2", "rest", "graphql",
    "app", "apps", "dev", "develop", "test", "testing", "stage", "staging", "beta", "demo", "sandbox",
    "old", "new", "legacy", "admin", "panel", "cpanel", "whm", "manage", "portal", "my", "account",
    "auth", "sso", "login", "id", "oauth", "vpn", "remote", "rdp", "ftp", "sftp", "files", "file",
    "docs", "doc", "wiki", "confluence", "jira", "git", "gitlab", "github", "bitbucket", "svn", "ci",
    "jenkins", "build", "deploy", "docker", "k8s", "kube", "registry", "ns", "ns1", "ns2", "dns",
    "dns1", "dns2", "cdn", "static", "assets", "img", "images", "media", "video", "stream", "download",
    "uploads", "upload", "store", "shop", "cart", "pay", "payment", "billing", "invoice", "crm", "erp",
    "1c", "hr", "jobs", "career", "support", "help", "helpdesk", "status", "monitoring", "grafana",
    "prometheus", "kibana", "elk", "logs", "metrics", "analytics", "stats", "bi", "db", "database",
    "sql", "mysql", "postgres", "mongo", "redis", "cache", "queue", "rabbit", "kafka", "mq", "sms",
    "msg", "chat", "call", "voip", "pbx", "sip", "intranet", "internal", "extranet", "partner",
    "partners", "clients", "customer", "vendor", "shop2", "mobile", "m", "wap", "tv", "radio", "news",
    "blog", "forum", "board", "community", "social", "s3", "storage", "backup", "bkp", "vps", "host",
    "server", "node", "web", "web1", "web2", "www2", "www3", "proxy", "gateway", "gw", "router",
    "firewall", "fw", "edge", "lb", "nlb", "haproxy", "nginx", "apache", "iis", "tomcat", "jboss",
    "phpmyadmin", "pma", "adminer", "php", "ws", "wss", "ws2", "realtime", "push", "notify", "feed",
    "rss", "xml", "json", "export", "import", "sync", "git2", "mirror", "repo", "packages", "npm",
    "pypi", "maven", "artifactory", "nexus", "seafile", "nextcloud", "owncloud", "cloud", "drive",
    "share", "zoom", "meet", "jitsi", "mattermost", "slack", "rocket", "discourse", "osticket",
    "zabbix", "nagios", "victor", "sentry", "sonar", "gitea", "gogs", "drone", "argo", "vault",
    "consul", "etcd", "traefik", "rancher", "openshift", "azure", "aws", "gcp", "oracle", "1cweb",
]
TECH_SIGNATURES = {
    "nginx": ("server", "nginx"), "apache": ("server", "apache"), "iis": ("server", "microsoft-iis"),
    "cloudflare": ("server", "cloudflare"), "gunicorn": ("server", "gunicorn"),
    "wordpress": ("x-powered-by+body", "wp-content"), "bitrix": ("body", "bitrix"),
    "joomla": ("body", "joomla"), "drupal": ("body", "drupal"), "react": ("body", "__react"),
    "next.js": ("body", "_next/static"), "vue": ("body", "vue.js"), "angular": ("body", "ng-version"),
    "jquery": ("body", "jquery"), "bootstrap": ("body", "bootstrap"), "laravel": ("cookie", "laravel_session"),
    "php": ("x-powered-by", "php"), "asp.net": ("x-powered-by", "asp.net"), "express": ("x-powered-by", "express"),
    "django": ("cookie", "csrftoken"), "shopify": ("body", "shopify"), "tilda": ("body", "tilda"),
    "wix": ("body", "wix"), "google-analytics": ("body", "google-analytics"),
    "yandex-metrica": ("body", "mc.yandex.ru"), "hotjar": ("body", "hotjar"),
}


class DomainModule(Module):
    name = "domain"
    title = "Домен: DNS, RDAP, поддомены, сертификаты, веб-разведка"
    categories = ("domain",)
    target_types = ("domain", "email", "url")

    def __init__(self, *, brute_subdomains: bool = True, wordlist_limit: int = 250):
        self.brute_subdomains = brute_subdomains
        self.wordlist_limit = wordlist_limit

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        domain = clean_domain(target if "@" not in target else target.split("@")[-1])
        add_entity(result, "domain", domain)
        loop = asyncio.get_running_loop()

        await ctx.notify(stage="domain:dns", message=f"DNS-разведка {domain}")
        records = await self._dns(ctx, domain, loop, result)
        await asyncio.gather(
            self._rdap(ctx, domain, result),
            self._crt(ctx, domain, result),
            self._wayback(ctx, domain, result),
            self._urlscan(ctx, domain, result),
            self._hackertarget(ctx, domain, result),
            self._web(ctx, domain, records, result),
        )
        if self.brute_subdomains:
            await self._brute(ctx, domain, loop, records, result)
        await self._reverse_ip(ctx, records, result)
        self._dorks(domain, result)

    # ───────────────────────── DNS ─────────────────────────
    async def _dns(self, ctx: Context, domain: str, loop, result: ModuleResult) -> dict[str, list[str]]:
        types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"]
        queries = {t: loop.run_in_executor(None, dns_lookup, domain, t) for t in types}
        records: dict[str, list[str]] = {}
        for t, fut in queries.items():
            records[t] = await fut
        spf = next((t for t in records["TXT"] if t.lower().startswith("v=spf1")), "")
        dmarc = await loop.run_in_executor(None, dns_lookup, f"_dmarc.{domain}", "TXT")
        dmarc_txt = next((t for t in dmarc if "v=dmarc1" in t.lower()), "")
        dkim_google = await loop.run_in_executor(None, dns_lookup, f"google._domainkey.{domain}", "TXT")
        dnssec = await loop.run_in_executor(None, self._dnssec_check, domain)
        axfr = await loop.run_in_executor(None, self._axfr_check, domain, records["NS"][:1])

        self.add_finding(result, source="dns", category="domain", kind="dns", confidence="high",
                         title=f"DNS {domain}: A={len(records['A'])}, MX={len(records['MX'])}, "
                               f"NS={len(records['NS'])}, TXT={len(records['TXT'])}"
                               f"{', SPF есть' if spf else ', SPF НЕТ'}{', DMARC есть' if dmarc_txt else ', DMARC НЕТ'}",
                         value=domain, url=f"https://dns.google/query?name={domain}&type=ANY",
                         data={**records, "spf": spf, "dmarc": dmarc_txt,
                               "dkim_google": dkim_google, "dnssec": dnssec, "axfr": axfr,
                               "email_security": {
                                   "spf": bool(spf), "dmarc": bool(dmarc_txt),
                                   "dmarc_policy": _dmarc_policy(dmarc_txt),
                                   "dkim": bool(dkim_google)},
                               "zone_transfer_possible": axfr.get("possible", False)},
                         evidence=f"DNS-запросы: {sum(len(v) for v in records.values())} записей; "
                                  f"SPF={'да' if spf else 'нет'}, DMARC={_dmarc_policy(dmarc_txt) or 'нет'}")
        for ip in records["A"] + records["AAAA"]:
            add_edge(result, entity_id("domain", domain), entity_id("ip", ip), "resolves_to", 1.0,
                     "A/AAAA запись DNS")
        for mx in records["MX"]:
            add_edge(result, entity_id("domain", domain), entity_id("domain", mx), "mx_record", 1.0,
                     "MX-запись домена")
        if spf:
            for include in re.findall(r"include:([\w.\-]+)", spf):
                add_edge(result, entity_id("domain", domain), entity_id("domain", include), "spf_include", 0.7,
                         "SPF-запись ссылается на сервис")
        self.add_status(result, SourceStatus(source="dns", category="domain",
                                             status="found" if records["A"] or records["MX"] else "not_found",
                                             detail=f"A={records['A'][:2]}, MX={records['MX'][:2]}"))
        return records

    @staticmethod
    def _dnssec_check(domain: str) -> dict[str, Any]:
        if not _dns_lib():
            return {"checked": False, "reason": "dnspython не установлен"}
        import dns.resolver
        try:
            res = dns.resolver.Resolver()
            res.lifetime = 6
            ans = res.resolve(domain, "A", want_dnssec=True)
            return {"checked": True, "secure": bool(ans.response.flags & 0x20),
                    "ad_flag": bool(ans.response.flags & 0x20)}
        except Exception as exc:
            return {"checked": False, "reason": f"{type(exc).__name__}: {exc}"[:160]}

    @staticmethod
    def _axfr_check(domain: str, ns: list[str]) -> dict[str, Any]:
        """Реальная попытка передачи зоны — почти всегда отклоняется, но проверка настоящая."""
        if not _dns_lib() or not ns:
            return {"attempted": False}
        import dns.query
        import dns.zone
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns[0], domain, timeout=8))
            names = [str(n) for n in zone.nodes.keys()][:50]
            return {"attempted": True, "possible": True, "nameserver": ns[0], "records": len(zone.nodes),
                    "sample": names}
        except Exception as exc:
            return {"attempted": True, "possible": False, "nameserver": ns[0],
                    "error": f"{type(exc).__name__}: {exc}"[:160]}

    # ───────────────────────── RDAP ─────────────────────────
    async def _rdap(self, ctx: Context, domain: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://rdap.org/domain/{domain}", retries=1)
        data = resp.json()
        if not isinstance(data, dict) or resp.status_code >= 400:
            self.add_status(result, SourceStatus(source="rdap", category="domain", status="error",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:150]))
            return
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        registrar = ""
        abuse_email = ""
        for entity in data.get("entities", []):
            if "registrar" in (entity.get("roles") or []):
                registrar = _vcard_name(entity) or registrar
                for sub in entity.get("entities", []) or []:
                    if "abuse" in (sub.get("roles") or []):
                        abuse_email = _vcard_email(sub) or abuse_email
            if not abuse_email:
                abuse_email = _vcard_email(entity) or abuse_email
        nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]
        self.add_finding(result, source="rdap", category="domain", kind="rdap", confidence="high",
                         title=f"RDAP: регистратор {registrar or '?'}, создан {str(events.get('registration'))[:10]}, "
                               f"истекает {str(events.get('expiration'))[:10]}, статусы: {', '.join(data.get('status', [])[:4])}",
                         url=f"https://rdap.org/domain/{domain}", value=domain,
                         data={"registrar": registrar, "events": events, "status": data.get("status"),
                               "nameservers": nameservers, "abuse_email": abuse_email,
                               "handle": data.get("handle"), "dnssec": bool(data.get("secureDNS")),
                               "links": [l.get("href") for l in data.get("links", [])]},
                         evidence=f"RDAP-ответ: registrar={registrar!r}, registration={events.get('registration')}, "
                                  f"nameservers={nameservers[:3]}", http_code=resp.status_code)
        add_entity(result, "domain", domain, registrar=registrar,
                   registered=events.get("registration"), expires=events.get("expiration"))
        if abuse_email:
            add_edge(result, entity_id("domain", domain), entity_id("email", abuse_email.lower()),
                     "abuse_contact", 0.8, "контакт abuse из RDAP")
        for ns in nameservers:
            add_edge(result, entity_id("domain", domain), entity_id("domain", ns), "nameserver", 1.0,
                     "NS-запись из RDAP")
        self.add_status(result, SourceStatus(source="rdap", category="domain", status="found", url=resp.url,
                                             http_code=resp.status_code, latency_ms=resp.latency_ms))

    # ───────────────────────── Certificate Transparency ─────────────────────────
    async def _crt(self, ctx: Context, domain: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                                  retries=1, timeout=40)
        data = resp.json()
        if not isinstance(data, list):
            self.add_status(result, SourceStatus(source="crt.sh", category="domain",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error or "пустой/не-JSON ответ"))
            return
        subs: dict[str, set[str]] = {}
        issuers: dict[str, int] = {}
        for entry in data:
            for name in (entry.get("name_value") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subs.setdefault(name, set()).add(str(entry.get("not_before", ""))[:10])
            issuer = (entry.get("issuer_name") or "")
            m = re.search(r"O=([^,]+)", issuer)
            if m:
                issuers[m.group(1).strip()] = issuers.get(m.group(1).strip(), 0) + 1
        subdomains = sorted(subs)
        self.add_finding(result, source="crt.sh", category="domain", kind="subdomains", confidence="high",
                         title=f"Certificate Transparency: {len(subdomains)} поддоменов {domain} "
                               f"из {len(data)} сертификатов",
                         url=f"https://crt.sh/?q=%25.{domain}", value=domain,
                         data={"subdomains": subdomains[:200], "count": len(subdomains),
                               "certificates": len(data), "issuers": dict(sorted(issuers.items(),
                                                                                 key=lambda x: -x[1])[:8])},
                         evidence=f"crt.sh JSON: {len(data)} сертификатов, "
                                  f"{len(subdomains)} уникальных поддоменов", http_code=resp.status_code)
        for sub in subdomains[:200]:
            add_edge(result, entity_id("domain", domain), entity_id("domain", sub), "subdomain", 0.9,
                     "найден в сертификатах CT")
        add_entity(result, "domain", domain, subdomains=len(subdomains))
        self.add_status(result, SourceStatus(source="crt.sh", category="domain", status="found", url=resp.url,
                                             http_code=resp.status_code, latency_ms=resp.latency_ms))

    # ───────────────────────── Wayback ─────────────────────────
    async def _wayback(self, ctx: Context, domain: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://archive.org/wayback/available",
                                  params={"url": domain, "timestamp": "2010"}, retries=1)
        data = resp.json() or {}
        snap = ((data.get("archived_snapshots") or {}).get("closest") or {})
        if snap.get("url"):
            self.add_finding(result, source="wayback", category="domain", kind="archive", confidence="high",
                             title=f"Wayback Machine: сохранённая копия от {snap.get('timestamp', '')[:8]}",
                             url=snap["url"], value=domain, data=snap,
                             evidence=f"archive.org API вернул снимок {snap.get('timestamp')} ({snap.get('status')})",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="wayback", category="domain", status="found",
                                                 url=snap["url"], http_code=resp.status_code))
        else:
            self.add_status(result, SourceStatus(source="wayback", category="domain", status="not_found",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error))

    # ───────────────────────── urlscan.io ─────────────────────────
    async def _urlscan(self, ctx: Context, domain: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://urlscan.io/api/v1/search/",
                                  params={"q": f"domain:{domain}", "size": 20}, retries=1)
        data = resp.json() or {}
        results = data.get("results") or []
        if results:
            self.add_finding(result, source="urlscan.io", category="domain", kind="scans", confidence="high",
                             title=f"urlscan.io: {data.get('total', len(results))} публичных сканов домена",
                             url=f"https://urlscan.io/domain/{domain}", value=domain,
                             data={"scans": [{"url": r.get("page", {}).get("url"), "ip": r.get("page", {}).get("ip"),
                                              "server": r.get("page", {}).get("server"),
                                              "date": r.get("task", {}).get("time"),
                                              "result": f"https://urlscan.io/result/{r.get('_id')}/",
                                              "country": r.get("page", {}).get("country")}
                                             for r in results[:12]],
                                   "total": data.get("total")},
                             evidence=f"urlscan.io API: total={data.get('total')}, получено {len(results)}",
                             http_code=resp.status_code)
            for r in results[:12]:
                ip = (r.get("page") or {}).get("ip")
                if ip:
                    add_edge(result, entity_id("domain", domain), entity_id("ip", ip), "hosted_on_seen", 0.7,
                             "IP из публичного скана urlscan.io")
            self.add_status(result, SourceStatus(source="urlscan.io", category="domain", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="urlscan.io", category="domain", status="not_found",
                                                 http_code=resp.status_code or None, error=resp.error))

    # ───────────────────────── HackerTarget ─────────────────────────
    async def _hackertarget(self, ctx: Context, domain: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://api.hackertarget.com/hostsearch/",
                                  params={"q": domain}, retries=1, timeout=25)
        text = resp.text.strip()
        if not resp.ok or not text or "API count exceeded" in text or "error" in text.lower()[:60]:
            self.add_status(result, SourceStatus(source="hackertarget", category="domain",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error or text[:120]))
            return
        hosts = []
        for line in text.splitlines()[:300]:
            host, _, ip = line.partition(",")
            if host.strip():
                hosts.append({"host": host.strip(), "ip": ip.strip()})
        if hosts:
            self.add_finding(result, source="hackertarget", category="domain", kind="subdomains", confidence="medium",
                             title=f"HackerTarget: {len(hosts)} хостов домена с IP-адресами",
                             url=f"https://hackertarget.com/find-dns-records/?q={domain}", value=domain,
                             data={"hosts": hosts[:120]},
                             evidence=f"api.hackertarget.com/hostsearch/?q={domain} → {len(hosts)} строк",
                             http_code=resp.status_code)
            for h in hosts[:120]:
                if h["ip"]:
                    add_edge(result, entity_id("domain", h["host"]), entity_id("ip", h["ip"]), "resolves_to", 0.9,
                             "hostsearch HackerTarget")
        self.add_status(result, SourceStatus(source="hackertarget", category="domain",
                                             status="found" if hosts else "not_found",
                                             http_code=resp.status_code, url=resp.url))

    # ───────────────────────── Web-разведка ─────────────────────────
    async def _web(self, ctx: Context, domain: str, records: dict[str, list[str]], result: ModuleResult) -> None:
        https = await ctx.http.get(f"https://{domain}", retries=1, timeout=min(ctx.http.timeout, 12))
        if not https.ok or https.looks_blocked():
            http = await ctx.http.get(f"http://{domain}", retries=1, timeout=min(ctx.http.timeout, 12))
            if http.ok:
                self.add_finding(result, source="http", category="domain", kind="meta", confidence="medium",
                                 title=f"HTTPS недоступен, но HTTP отвечает (HTTP {http.status_code}) — трафик без шифрования",
                                 url=f"http://{domain}", value=domain, data={"https_error": https.error or https.status_code},
                                 evidence=f"GET https://{domain} → {https.error or https.status_code}; "
                                          f"GET http://{domain} → 200")
            else:
                self.add_status(result, SourceStatus(source="http", category="domain", status="error",
                                                     url=f"https://{domain}", http_code=https.status_code or None,
                                                     error=https.error or https.snippet(120)))
            web_resp = http if http.ok else https
        else:
            web_resp = https
        if not web_resp.ok and web_resp.error:
            return
        headers = {k.lower(): v for k, v in web_resp.headers.items()}
        body = web_resp.text[:400_000]
        tech: list[str] = []
        for name, (where, needle) in TECH_SIGNATURES.items():
            haystack = ""
            if "server" in where:
                haystack = headers.get("server", "")
            elif "x-powered-by" in where:
                haystack = headers.get("x-powered-by", "")
            elif "cookie" in where:
                haystack = headers.get("set-cookie", "")
            else:
                haystack = body.lower()
            if needle.lower() in haystack.lower():
                tech.append(name)
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.DOTALL | re.IGNORECASE)
        if m:
            title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:200]
        emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", body)))[:40]
        phones = sorted({re.sub(r"[^\d+]", "", p) for p in re.findall(r"\+?\d[\d\s()\-]{9,}\d", body)})[:20]
        socials = sorted(set(re.findall(
            r"https?://(?:www\.)?(t\.me|vk\.com|instagram\.com|facebook\.com|twitter\.com|x\.com|youtube\.com|"
            r"linkedin\.com|github\.com|wa\.me|whatsapp\.com|telegram\.me)/[\w./@-]+", body)))  # noqa
        social_links = sorted(set(re.findall(
            r"https?://(?:www\.)?(?:t\.me|vk\.com|instagram\.com|facebook\.com|twitter\.com|x\.com|youtube\.com"
            r"|linkedin\.com|github\.com|wa\.me)/(?:[\w.@/-]{2,60})", body)))[:30]
        self.add_finding(result, source="http", category="domain", kind="meta", confidence="high",
                         title=f"Веб-сервер отвечает (HTTP {web_resp.status_code}): "
                               f"{headers.get('server', 'сервер не раскрыт')}, технологии: "
                               f"{', '.join(tech) or 'не определены'}",
                         url=str(web_resp.url), value=domain,
                         data={"status": web_resp.status_code, "title": title, "server": headers.get("server"),
                               "x_powered_by": headers.get("x-powered-by"), "technologies": tech,
                               "emails_on_site": emails, "phones_on_site": phones, "social_links": social_links,
                               "headers": {k: v for k, v in headers.items() if k in
                                           ("server", "x-powered-by", "content-type", "strict-transport-security",
                                            "content-security-policy", "x-frame-options", "location",
                                            "set-cookie", "x-generator", "via", "cf-ray")},
                               "redirect_chain": [str(h.headers.get("location")) for h in web_resp.history[:5]]},
                         evidence=f"GET {web_resp.url} → HTTP {web_resp.status_code}, "
                                  f"Server={headers.get('server')!r}, найдено email={len(emails)}, тел={len(phones)}",
                         http_code=web_resp.status_code)
        for email in emails[:20]:
            add_edge(result, entity_id("domain", domain), entity_id("email", email.lower()), "email_on_site", 0.7,
                     "адрес опубликован на сайте домена")
        for phone in phones[:10]:
            add_edge(result, entity_id("domain", domain), entity_id("phone", phone), "phone_on_site", 0.6,
                     "номер опубликован на сайте домена")
        for link in social_links[:15]:
            m2 = re.search(r"https?://(?:www\.)?([^/]+)/([\w.@-]+)", link)
            if m2:
                host, handle = m2.group(1), m2.group(2)
                if host in ("t.me", "telegram.me") :
                    add_edge(result, entity_id("domain", domain), entity_id("telegram", handle),
                             "telegram_on_site", 0.8, "ссылка на Telegram-аккаунт с сайта")
                elif host in ("github.com", "vk.com", "instagram.com", "twitter.com", "x.com", "youtube.com",
                              "facebook.com", "linkedin.com"):
                    add_edge(result, entity_id("domain", domain), entity_id("username", handle),
                             f"social_{host.split('.')[0]}_on_site", 0.7, f"ссылка на {host} с сайта")

        for path, kind in (("/.well-known/security.txt", "security.txt"),
                           ("/robots.txt", "robots.txt"),
                           ("/sitemap.xml", "sitemap.xml")):
            r = await ctx.http.get(f"https://{domain}{path}", retries=0, timeout=10)
            if r.ok and r.text.strip() and "<html" not in r.text[:200].lower():
                body_text = r.text[:2500]
                found = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", body_text)))[:10]
                disallow = sorted(set(re.findall(r"Disallow:\s*(\S+)", body_text)))[:40]
                self.add_finding(result, source=kind, category="domain", kind="file", confidence="high",
                                 title=f"Найден /{path.lstrip('/')} "
                                       + (f"({len(found)} адресов)" if found else
                                          f"({len(disallow)} закрытых путей)" if disallow else ""),
                                 url=f"https://{domain}{path}", value=domain,
                                 data={"content": body_text[:2000], "emails": found, "disallow": disallow,
                                       "locs": re.findall(r"Sitemap:\s*(\S+)", body_text)[:10]},
                                 evidence=f"HTTP 200, не HTML, размер {len(r.text)} байт", http_code=r.status_code)
                for email in found:
                    add_edge(result, entity_id("domain", domain), entity_id("email", email.lower()),
                             f"{kind}_contact", 0.8, f"указан в {path}")
                self.add_status(result, SourceStatus(source=kind, category="domain", status="found",
                                                     url=f"https://{domain}{path}", http_code=r.status_code))
            else:
                self.add_status(result, SourceStatus(source=kind, category="domain", status="not_found",
                                                     url=f"https://{domain}{path}",
                                                     http_code=r.status_code or None,
                                                     error=r.error or f"HTTP {r.status_code}"))

    # ───────────────────────── перебор поддоменов ─────────────────────────
    async def _brute(self, ctx: Context, domain: str, loop, records: dict[str, list[str]],
                     result: ModuleResult) -> None:
        words = SUBDOMAIN_WORDLIST[: self.wordlist_limit]
        sem = asyncio.Semaphore(60)

        async def probe(word: str) -> tuple[str, list[str]]:
            host = f"{word}.{domain}"
            async with sem:
                ips = await loop.run_in_executor(None, dns_lookup, host, "A")
            return host, ips

        results = await asyncio.gather(*(probe(w) for w in words))
        alive = {host: ips for host, ips in results if ips}
        self.add_finding(result, source="subdomain-brute", category="domain", kind="subdomains",
                         confidence="high" if alive else "medium",
                         title=f"Перебор поддоменов по словарю ({len(words)} слов): найдено {len(alive)} живых",
                         url=f"https://dns.google/query?name={domain}&type=A", value=domain,
                         data={"alive": alive, "count": len(alive), "wordlist_size": len(words)},
                         evidence=f"реальный DNS-резолв {len(words)} имён, положительный ответ для {len(alive)}")
        for host, ips in alive.items():
            for ip in ips:
                add_edge(result, entity_id("domain", host), entity_id("ip", ip), "resolves_to", 1.0,
                         "перебор поддоменов + DNS-резолв")
            add_edge(result, entity_id("domain", domain), entity_id("domain", host), "subdomain", 0.9,
                     "поддомен из словаря, DNS отвечает")
        self.add_status(result, SourceStatus(source="subdomain-brute", category="domain",
                                             status="found" if alive else "not_found",
                                             detail=f"{len(alive)}/{len(words)} имён резолвятся"))

    # ───────────────────────── обратный IP ─────────────────────────
    async def _reverse_ip(self, ctx: Context, records: dict[str, list[str]], result: ModuleResult) -> None:
        ips = (records.get("A") or [])[:2]
        for ip in ips:
            resp = await ctx.http.get("https://api.hackertarget.com/reverseiplookup/",
                                      params={"q": ip}, retries=1, timeout=20)
            text = resp.text.strip()
            if not resp.ok or "error" in text.lower()[:40] or "API count exceeded" in text:
                self.add_status(result, SourceStatus(source="reverse-ip", category="domain",
                                                     status="blocked" if resp.looks_blocked() else "error",
                                                     url=resp.url, http_code=resp.status_code or None,
                                                     error=resp.error or text[:100]))
                continue
            domains = [d.strip() for d in text.splitlines() if d.strip()][:200]
            if domains:
                self.add_finding(result, source="reverse-ip", category="domain", kind="related", confidence="medium",
                                 title=f"На IP {ip} размещено ещё {len(domains)} доменов (общий хостинг)",
                                 url=f"https://hackertarget.com/reverse-ip-lookup/?q={ip}", value=ip,
                                 data={"ip": ip, "domains": domains[:100]},
                                 evidence=f"api.hackertarget.com/reverseiplookup/?q={ip} → {len(domains)} доменов",
                                 http_code=resp.status_code)
                for d in domains[:100]:
                    add_edge(result, entity_id("ip", ip), entity_id("domain", d), "co_hosted", 0.4,
                             "общий IP-адрес (сосед по хостингу)")
            self.add_status(result, SourceStatus(source="reverse-ip", category="domain",
                                                 status="found" if domains else "not_found",
                                                 url=resp.url, http_code=resp.status_code))

    # ───────────────────────── dorks ─────────────────────────
    def _dorks(self, domain: str, result: ModuleResult) -> None:
        links = [
            f"https://www.google.com/search?q=site%3A{domain}",
            f"https://www.google.com/search?q=site%3A{domain}+filetype%3Apdf",
            f"https://www.google.com/search?q=site%3A{domain}+filetype%3Axls+OR+filetype%3Axlsx",
            f"https://www.google.com/search?q=site%3A{domain}+%22%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C%22+OR+%22%D0%BB%D0%BE%D0%B3%D0%B8%D0%BD%22",
            f"https://www.google.com/search?q=%22%40{domain}%22+-site%3A{domain}",
            f"https://search.marcia.cc/search?q=site:{domain}",
            f"https://web.archive.org/web/*/{domain}/*",
            f"https://github.com/search?q=%22%40{domain}%22&type=code",
            f"https://www.shodan.io/search?query=hostname%3A{domain}",
            f"https://www.bing.com/search?q=ip%3A{domain}",
        ]
        self.add_finding(result, source="dorks", category="domain", kind="link", confidence="low",
                         title=f"Поисковые операторы (dorks) по домену {domain}",
                         value=domain, url=links[0], data={"links": links},
                         evidence="готовые ссылки с поисковыми операторами — для ручного анализа")


def _dns_lib() -> bool:
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def _dmarc_policy(txt: str) -> str:
    m = re.search(r"p=(\w+)", txt or "")
    return m.group(1) if m else ""


def _vcard_name(entity: dict[str, Any]) -> str:
    for item in entity.get("vcardArray", [[], []])[1] if entity.get("vcardArray") else []:
        if item and item[0] == "fn":
            return str(item[3])
    return ""


def _vcard_email(entity: dict[str, Any]) -> str:
    for item in entity.get("vcardArray", [[], []])[1] if entity.get("vcardArray") else []:
        if item and item[0] == "email":
            return str(item[3]).replace("mailto:", "")
    return ""
