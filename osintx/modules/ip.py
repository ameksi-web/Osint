"""IP-адрес: гео, ASN, владелец сети, открытые порты, репутация, Tor, спам-базы.

Источники (все реальные, большинство — без ключей):
  * ipwho.is / ip-api.com / ipinfo.io — геолокация, провайдер, ASN, тип соединения;
  * Shodan InternetDB — открытые порты, CVE, hostnames (бесплатно, без ключа);
  * RDAP (rdap.org/ip) — владелец блока, abuse-контакты;
  * RIPE Stat — whois-данные RIR;
  * BGPView — префикс, ASN, IRR-источник;
  * PTR-запись + обратный IP-поиск (домены на адресе);
  * Tor Onionoo — является ли адрес exit-нодой Tor;
  * StopForumSpam — спам-репутация;
  * AbuseIPDB / VirusTotal / Shodan (при наличии ключей).
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from ..core.models import ModuleResult, SourceStatus
from .base import Context, Module, add_edge, add_entity, entity_id
from .email import dns_lookup


class IpModule(Module):
    name = "ip"
    title = "IP: гео, ASN, порты (Shodan InternetDB), репутация, Tor, RDAP"
    categories = ("ip",)
    target_types = ("ip",)

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        ip = target.strip().strip("[]")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            result.errors.append(f"«{target}» не является IP-адресом")
            return
        add_entity(result, "ip", ip)
        loop = asyncio.get_running_loop()
        await asyncio.gather(
            self._geo(ctx, ip, result),
            self._internetdb(ctx, ip, result),
            self._rdap(ctx, ip, result),
            self._bgp(ctx, ip, result),
            self._ptr(ctx, ip, loop, result),
            self._tor(ctx, ip, result),
            self._spam(ctx, ip, result),
            self._reverse_ip(ctx, ip, result),
            self._ripe(ctx, ip, result),
        )
        await self._keyed(ctx, ip, result)

    # ─────────────────────────── геолокация ───────────────────────────
    async def _geo(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://ipwho.is/{ip}", retries=1)
        data = resp.json() or {}
        if data.get("success") and data.get("country"):
            conn = data.get("connection") or {}
            self.add_finding(result, source="ipwho.is", category="ip", kind="geo", confidence="high",
                             title=f"{data.get('country')}, {data.get('region') or ''} {data.get('city') or ''} — "
                                   f"{conn.get('isp') or conn.get('org') or 'провайдер неизвестен'} "
                                   f"(AS{conn.get('asn')})",
                             url=f"https://ipwho.is/{ip}", value=ip,
                             data={"country": data.get("country"), "country_code": data.get("country_code"),
                                   "region": data.get("region"), "city": data.get("city"),
                                   "postal": data.get("postal"), "latitude": data.get("latitude"),
                                   "longitude": data.get("longitude"), "timezone": (data.get("timezone") or {}).get("id"),
                                   "isp": conn.get("isp"), "org": conn.get("org"), "asn": conn.get("asn"),
                                   "domain": conn.get("domain"), "type": data.get("type"),
                                   "is_eu": (data.get("eu") or False)},
                             evidence=f"ipwho.is → {data.get('country')}/{data.get('city')}, "
                                      f"ISP={conn.get('isp')}, ASN=AS{conn.get('asn')}",
                             http_code=resp.status_code)
            add_entity(result, "ip", ip, asn=f"AS{conn.get('asn')}", isp=conn.get("isp"),
                       country=data.get("country"))
            if conn.get("domain"):
                add_edge(result, entity_id("ip", ip), entity_id("domain", conn["domain"]), "isp_domain", 0.6,
                         "домен провайдера, обслуживающего IP")
            self.add_status(result, SourceStatus(source="ipwho.is", category="ip", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="ipwho.is", category="ip", status="error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:150]))
        # второй, независимый источник гео — сверка
        resp2 = await ctx.http.get(f"https://ipapi.co/{ip}/json/", retries=1)
        d2 = resp2.json() or {}
        if resp2.ok and d2.get("country_name"):
            self.add_finding(result, source="ipapi.co", category="ip", kind="geo", confidence="high",
                             title=f"Сверка гео: {d2.get('country_name')}, {d2.get('city') or ''}, "
                                   f"{d2.get('org') or ''}",
                             url=f"https://ipapi.co/{ip}/json/", value=ip,
                             data={"country": d2.get("country_name"), "city": d2.get("city"),
                                   "region": d2.get("region"), "org": d2.get("org"), "asn": d2.get("asn"),
                                   "timezone": d2.get("timezone"), "network": d2.get("network")},
                             evidence=f"ipapi.co → {d2.get('country_name')}/{d2.get('city')}, org={d2.get('org')}",
                             http_code=resp2.status_code)
            self.add_status(result, SourceStatus(source="ipapi.co", category="ip", status="found",
                                                 http_code=resp2.status_code, url=resp2.url))

    # ─────────────────────────── Shodan InternetDB ───────────────────────────
    async def _internetdb(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://internetdb.shodan.io/{ip}", retries=1)
        data = resp.json() or {}
        if resp.status_code == 404:
            self.add_status(result, SourceStatus(source="shodan-internetdb", category="ip", status="not_found",
                                                 url=resp.url, http_code=404,
                                                 detail="Shodan не имеет данных об этом IP (порты не сканировались)"))
            return
        if not resp.ok:
            self.add_status(result, SourceStatus(source="shodan-internetdb", category="ip", status="error",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error or resp.snippet(120)))
            return
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        self.add_finding(result, source="shodan-internetdb", category="ip", kind="ports",
                         confidence="high" if ports else "medium",
                         title=f"Открытые порты (Shodan InternetDB): {', '.join(map(str, ports)) or 'нет данных'}"
                               + (f"; известные CVE: {len(vulns)}" if vulns else ""),
                         url=f"https://www.shodan.io/host/{ip}", value=ip,
                         data={"ports": ports, "cpes": data.get("cpes"), "hostnames": data.get("hostnames"),
                               "tags": data.get("tags"), "vulns": vulns},
                         evidence=f"internetdb.shodan.io/{ip} → ports={ports}, vulns={vulns}, "
                                  f"hostnames={data.get('hostnames')}", http_code=resp.status_code)
        add_entity(result, "ip", ip, ports=ports, vulns=vulns)
        for host in data.get("hostnames") or []:
            add_edge(result, entity_id("ip", ip), entity_id("domain", host), "ptr_hostname", 0.8,
                     "hostname из данных Shodan")
        for cve in vulns:
            add_edge(result, entity_id("ip", ip), entity_id("cve", cve), "vulnerable_to", 0.9,
                     "CVE из Shodan InternetDB")
        self.add_status(result, SourceStatus(source="shodan-internetdb", category="ip", status="found",
                                             http_code=resp.status_code, url=resp.url))

    # ─────────────────────────── RDAP ───────────────────────────
    async def _rdap(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://rdap.org/ip/{ip}", retries=1)
        data = resp.json()
        if not isinstance(data, dict) or resp.status_code >= 400:
            self.add_status(result, SourceStatus(source="rdap-ip", category="ip", status="error",
                                                 url=resp.url, http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:120]))
            return
        name = data.get("name") or data.get("handle") or ""
        org = ""
        abuse = ""
        for entity in data.get("entities", []) or []:
            for item in (entity.get("vcardArray") or [[], []])[1]:
                if item[0] == "fn":
                    org = org or str(item[3])
                if item[0] == "email" and "abuse" in str(item[1]).lower():
                    abuse = str(item[3]).replace("mailto:", "")
        self.add_finding(result, source="rdap-ip", category="ip", kind="rdap", confidence="high",
                         title=f"Блок {data.get('startAddress')}–{data.get('endAddress')} "
                               f"({data.get('name') or data.get('handle')}), владелец: {org or 'не указан'}",
                         url=f"https://rdap.org/ip/{ip}", value=ip,
                         data={"name": name, "handle": data.get("handle"), "country": data.get("country"),
                               "type": data.get("type"), "start": data.get("startAddress"),
                               "end": data.get("endAddress"), "org": org, "abuse_email": abuse,
                               "events": data.get("events"), "parent_handle": data.get("parentHandle")},
                         evidence=f"RDAP: name={name!r}, range={data.get('startAddress')}-{data.get('endAddress')}, "
                                  f"org={org!r}", http_code=resp.status_code)
        if abuse:
            add_edge(result, entity_id("ip", ip), entity_id("email", abuse.lower()), "abuse_contact", 0.8,
                     "abuse-контакт владельца блока из RDAP")
        self.add_status(result, SourceStatus(source="rdap-ip", category="ip", status="found",
                                             http_code=resp.status_code, url=resp.url))

    # ─────────────────────────── BGP ───────────────────────────
    async def _bgp(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get(f"https://api.bgpview.io/ip/{ip}", retries=1)
        data = resp.json() or {}
        if data.get("status") == "ok" and data.get("data"):
            payload = data["data"]
            prefixes = payload.get("prefixes") or []
            rips = payload.get("rir_allocation") or {}
            self.add_finding(result, source="bgpview", category="ip", kind="net", confidence="high",
                             title=f"BGP: префикс(ы) {', '.join(p.get('prefix', '') for p in prefixes[:4]) or '—'}, "
                                   f"RIR {rips.get('rir_name') or '?'}, страна {rips.get('country_code') or '?'}",
                             url=f"https://bgpview.io/ip/{ip}", value=ip,
                             data={"prefixes": [{"prefix": p.get("prefix"), "asn": (p.get("asn") or {}).get("asn"),
                                                 "name": (p.get("asn") or {}).get("name"),
                                                 "description": (p.get("asn") or {}).get("description")}
                                                for p in prefixes[:10]],
                                   "rir": rips, "rir_allocation": rips},
                             evidence=f"api.bgpview.io/ip/{ip} → prefixes={len(prefixes)}, "
                                      f"rir={rips.get('rir_name')}", http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="bgpview", category="ip", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="bgpview", category="ip", status="error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:120]))

    # ─────────────────────────── RIPE Stat ───────────────────────────
    async def _ripe(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://stat.ripe.net/data/whois/data.json",
                                  params={"resource": ip}, retries=1)
        data = resp.json() or {}
        records = ((data.get("data") or {}).get("records") or [])
        flat: list[dict[str, Any]] = [r for grp in records for r in grp] if records and isinstance(records[0], list) else records
        key_fields: dict[str, str] = {}
        for rec in flat[:200]:
            key = (rec.get("key") or "").lower()
            if key in ("netname", "descr", "org-name", "country", "abuse-mailbox", "org", "admin-c"):
                key_fields.setdefault(key, str(rec.get("value"))[:200])
        if key_fields:
            self.add_finding(result, source="ripestat", category="ip", kind="whois", confidence="high",
                             title=f"WHOIS RIR: {key_fields.get('netname') or key_fields.get('org') or ip}"
                                   f"{' / ' + key_fields['descr'] if key_fields.get('descr') else ''}"
                                   f"{' (' + key_fields['country'] + ')' if key_fields.get('country') else ''}",
                             url=f"https://stat.ripe.net/data/whois/data.json?resource={ip}", value=ip,
                             data=key_fields,
                             evidence=f"stat.ripe.net whois: {len(flat)} записей, netname={key_fields.get('netname')}",
                             http_code=resp.status_code)
            if key_fields.get("abuse-mailbox"):
                add_edge(result, entity_id("ip", ip), entity_id("email", key_fields["abuse-mailbox"].lower()),
                         "abuse_contact", 0.8, "abuse-mailbox из whois RIR")
            self.add_status(result, SourceStatus(source="ripestat", category="ip", status="found",
                                                 http_code=resp.status_code, url=resp.url))
        else:
            self.add_status(result, SourceStatus(source="ripestat", category="ip", status="not_found",
                                                 http_code=resp.status_code or None, url=resp.url))

    # ─────────────────────────── PTR ───────────────────────────
    async def _ptr(self, ctx: Context, ip: str, loop, result: ModuleResult) -> None:
        rev = ipaddress.ip_address(ip).reverse_pointer
        names = await loop.run_in_executor(None, dns_lookup, rev, "PTR")
        if not names and ctx.deep:
            # пробуем через DoH, если системный резолвер молчит
            resp = await ctx.http.get("https://dns.google/resolve", params={"name": rev, "type": "PTR"}, retries=0)
            data = resp.json() or {}
            names = [a.get("data", "").rstrip(".") for a in data.get("Answer", []) if a.get("type") == 12]
        if names:
            self.add_finding(result, source="reverse-dns", category="ip", kind="dns", confidence="high",
                             title=f"PTR: {', '.join(names)}", value=ip, data={"ptr": names},
                             url=f"https://dns.google/query?name={rev}&type=PTR",
                             evidence=f"DNS PTR-запрос {rev} → {names}")
            for name in names:
                add_edge(result, entity_id("ip", ip), entity_id("domain", name), "ptr", 1.0,
                         "обратная DNS-запись")
            self.add_status(result, SourceStatus(source="reverse-dns", category="ip", status="found",
                                                 detail=f"PTR={names}"))
        else:
            self.add_status(result, SourceStatus(source="reverse-dns", category="ip", status="not_found",
                                                 detail="PTR-запись отсутствует"))

    # ─────────────────────────── Tor ───────────────────────────
    async def _tor(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://onionoo.torproject.org/details",
                                  params={"search": ip, "type": "relay"}, retries=1)
        data = resp.json() or {}
        relays = data.get("relays") or []
        if relays:
            r = relays[0]
            self.add_finding(result, source="tor-onionoo", category="ip", kind="reputation", confidence="high",
                             title=f"IP является узлом Tor: {r.get('nickname')} "
                                   f"({'exit-нода' if r.get('exit_addresses') or r.get('flags') and 'Exit' in r['flags'] else 'релей'}), "
                                   f"AS {r.get('as_name')}, страна {r.get('country')}",
                             url=f"https://metrics.torproject.org/rs.html#details/{r.get('fingerprint')}",
                             value=ip,
                             data={"nickname": r.get("nickname"), "fingerprint": r.get("fingerprint"),
                                   "flags": r.get("flags"), "country": r.get("country"),
                                   "as_name": r.get("as_name"), "as_number": r.get("as_number"),
                                   "first_seen": r.get("first_seen"), "running": r.get("running"),
                                   "exit_addresses": r.get("exit_addresses")},
                             evidence=f"onionoo: найдена нода {r.get('nickname')} с fingerprint {r.get('fingerprint')}",
                             http_code=resp.status_code)
            self.add_status(result, SourceStatus(source="tor-onionoo", category="ip", status="found",
                                                 http_code=resp.status_code))
        else:
            self.add_status(result, SourceStatus(source="tor-onionoo", category="ip", status="not_found",
                                                 detail="IP не значится как Tor-узел", http_code=resp.status_code or None))

    # ─────────────────────────── Спам-репутация ───────────────────────────
    async def _spam(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://api.stopforumspam.org/api",
                                  params={"ip": ip, "json": 1}, retries=1)
        data = resp.json() or {}
        entry = data.get("ip") if isinstance(data.get("ip"), dict) else None
        if isinstance(data.get("ip"), list) and data["ip"]:
            entry = data["ip"][0]
        if entry is not None:
            appeared = entry.get("appears")
            if appeared:
                self.add_finding(result, source="stopforumspam", category="ip", kind="reputation",
                                 confidence="high",
                                 title=f"IP в базах спама: {appeared} срабатываний "
                                       f"(частота {entry.get('frequency')}%, последний раз {entry.get('lastseen')})",
                                 url=f"https://www.stopforumspam.com/ipcheck/{ip}", value=ip,
                                 data={"appears": appeared, "frequency": entry.get("frequency"),
                                       "lastseen": entry.get("lastseen"), "confidence": entry.get("confidence")},
                                 evidence=f"stopforumspam API: appears={appeared}", http_code=resp.status_code)
                self.add_status(result, SourceStatus(source="stopforumspam", category="ip", status="found",
                                                     http_code=resp.status_code))
            else:
                self.add_status(result, SourceStatus(source="stopforumspam", category="ip", status="not_found",
                                                     detail="в спам-базах не найден", http_code=resp.status_code))
        else:
            self.add_status(result, SourceStatus(source="stopforumspam", category="ip", status="error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or str(data)[:120]))

    # ─────────────────────────── Соседи по IP ───────────────────────────
    async def _reverse_ip(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        resp = await ctx.http.get("https://api.hackertarget.com/reverseiplookup/",
                                  params={"q": ip}, retries=1, timeout=20)
        text = resp.text.strip()
        if not resp.ok or "error" in text.lower()[:40]:
            self.add_status(result, SourceStatus(source="reverse-ip", category="ip",
                                                 status="blocked" if resp.looks_blocked() else "error",
                                                 http_code=resp.status_code or None,
                                                 error=resp.error or text[:120]))
            return
        domains = [d.strip() for d in text.splitlines() if d.strip()][:300]
        if domains:
            self.add_finding(result, source="reverse-ip", category="ip", kind="related", confidence="medium",
                             title=f"На IP размещено {len(domains)} доменов (virtual hosting)",
                             url=f"https://hackertarget.com/reverse-ip-lookup/?q={ip}", value=ip,
                             data={"domains": domains[:150], "count": len(domains)},
                             evidence=f"reverseiplookup → {len(domains)} доменов, первые: {domains[:5]}",
                             http_code=resp.status_code)
            for d in domains[:150]:
                add_edge(result, entity_id("ip", ip), entity_id("domain", d), "co_hosted", 0.4,
                         "домен размещён на том же IP")
        self.add_status(result, SourceStatus(source="reverse-ip", category="ip",
                                             status="found" if domains else "not_found",
                                             http_code=resp.status_code or None, url=resp.url))

    # ─────────────────────────── Ключевые API ───────────────────────────
    async def _keyed(self, ctx: Context, ip: str, result: ModuleResult) -> None:
        if ctx.key("shodan"):
            resp = await ctx.http.get(f"https://api.shodan.io/shodan/host/{ip}",
                                      params={"key": ctx.key("shodan")}, retries=1)
            data = resp.json() or {}
            if data.get("ports"):
                self.add_finding(result, source="shodan", category="ip", kind="ports", confidence="high",
                                 title=f"Shodan (полный): {len(data.get('ports', []))} портов, "
                                       f"ОС: {data.get('os') or '?'}, организация: {data.get('org') or '?'}",
                                 url=f"https://www.shodan.io/host/{ip}", value=ip,
                                 data={"ports": data.get("ports"), "os": data.get("os"), "org": data.get("org"),
                                       "hostnames": data.get("hostnames"), "domains": data.get("domains"),
                                       "isp": data.get("isp"), "country_name": data.get("country_name"),
                                       "city": data.get("city"), "vulns": list((data.get("vulns") or {}).keys()),
                                       "services": [{"port": s.get("port"), "product": s.get("product"),
                                                     "version": s.get("version"), "banner": (s.get("data") or "")[:200]}
                                                    for s in (data.get("data") or [])[:15]]},
                                 evidence=f"api.shodan.io → ports={data.get('ports')}, org={data.get('org')}",
                                 http_code=resp.status_code)
        if ctx.key("virustotal"):
            resp = await ctx.http.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                                      headers={"x-apikey": ctx.key("virustotal")}, retries=1)
            data = (resp.json() or {}).get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats") or {}
            if stats:
                self.add_finding(result, source="virustotal", category="ip", kind="reputation", confidence="high",
                                 title=f"VirusTotal: {stats.get('malicious', 0)} движков считают IP вредоносным "
                                       f"(harmless: {stats.get('harmless', 0)})",
                                 url=f"https://www.virustotal.com/gui/ip-address/{ip}", value=ip,
                                 data={"stats": stats, "as_owner": data.get("as_owner"),
                                       "reputation": data.get("reputation"),
                                       "tags": data.get("tags"), "whois": (data.get("whois") or "")[:800]},
                                 evidence=f"VirusTotal API: last_analysis_stats={stats}", http_code=resp.status_code)
        if ctx.key("abuseipdb"):
            return  # поддерживается опциональным ключом abuseipdb (см. settings.keys)
        if ctx.settings.key("ipinfo"):
            resp = await ctx.http.get(f"https://ipinfo.io/{ip}/json",
                                      params={"token": ctx.settings.key("ipinfo")}, retries=1)
            data = resp.json() or {}
            if data.get("ip"):
                self.add_finding(result, source="ipinfo", category="ip", kind="geo", confidence="high",
                                 title=f"ipinfo.io: {data.get('org') or '?'}, {data.get('city') or ''} "
                                       f"{data.get('country') or ''}",
                                 url=f"https://ipinfo.io/{ip}", value=ip, data=data,
                                 evidence=f"ipinfo.io → org={data.get('org')}, hostname={data.get('hostname')}",
                                 http_code=resp.status_code)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _clean_phone(value: str) -> str:
    return re.sub(r"[^\d+]", "", value)
