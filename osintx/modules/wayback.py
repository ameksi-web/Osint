"""Веб-архив (Wayback Machine): история страницы во времени.

Что даёт — то, чего нет ни в одном живом профиле:

  * **Как менялся ник/имя/описание**: берём самые ранние и самые поздние снимки
    профиля (``t.me/<логин>``, сайт, страница) и сравниваем имя и био. Если в 2019
    профиль назывался иначе — это подтверждённый факт с датой и ссылкой на снимок.
  * **История существования**: сколько снимков, с какого по какое время, как часто —
    косвенный признак активности.
  * **История сайта**: титул/описание домена в разные годы (проект переименовывался,
    менял тематику, был заброшен).

API (публичное, без ключей):
  * ``web.archive.org/cdx/search/cdx`` — список снимков (JSON),
  * ``web.archive.org/web/<таймстамп>id_/<url>`` — «сырой» снимок для разбора.

Важно: archive.org в некоторых странах/сетях блокируется. Тогда модуль честно
пишет ``blocked`` и подсказывает про прокси — а не «истории нет».
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from ..core.models import ModuleResult, SourceStatus
from .base import Context, Module, add_entity

CDX_API = "https://web.archive.org/cdx/search/cdx"
SNAPSHOT = "https://web.archive.org/web/{ts}id_/{url}"
OG_TITLE = re.compile(r'<meta property="og:title" content="([^"]*)"')
OG_DESC = re.compile(r'<meta property="og:description" content="([^"]*)"')
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL)
TG_EXTRA = re.compile(r'class="tgme_page_extra">([^<]*)<')


class WaybackModule(Module):
    name = "wayback"
    title = "Веб-архив: история страницы, прежние ники и описания"
    categories = ("archive",)
    target_types = ("username", "telegram", "email", "domain", "url", "person")

    async def run(self, ctx: Context, target: str, result: ModuleResult) -> None:
        target_type = str(ctx.options.get("target_type") or "")
        original = str(ctx.options.get("original_target") or target)
        urls = self._candidate_urls(target, target_type, original)
        if not urls:
            self.add_status(result, SourceStatus(
                source="wayback", category="archive", status="unsupported",
                detail="Для этого типа цели веб-архив нечего проверять: не известен URL профиля/сайта"))
            return

        seen_snapshots: dict[str, list[dict]] = {}
        for url in urls:
            snapshots = await self._cdx(ctx, url, result)
            if snapshots:
                seen_snapshots[url] = snapshots

        for url, snapshots in seen_snapshots.items():
            await self._compare(ctx, url, snapshots, result, target_type=target_type)

    # ─────────────────────────── вспомогательное ───────────────────────────
    @staticmethod
    def _candidate_urls(target: str, target_type: str, original: str) -> list[str]:
        """Какие URL цели имеет смысл искать в архиве."""
        urls: list[str] = []
        login = target.lstrip("@").strip()
        if target_type in ("username", "telegram"):
            if re.fullmatch(r"[A-Za-z0-9_]{3,64}", login):
                urls.append(f"t.me/{login}")
                urls.append(f"telegram.me/{login}")
        elif target_type == "person":
            return []                       # у ФИО нет URL, который можно проверить в архиве
        else:
            domain = original.split("@")[-1].strip().lower() if target_type == "email" else target.lower()
            if target.startswith("http"):
                parsed = urlparse(target)
                domain = parsed.netloc or parsed.path.split("/")[0]
            if domain and "." in domain and " " not in domain:
                urls.append(domain)
                if not domain.startswith("www."):
                    urls.append(f"www.{domain}")
        out: list[str] = []
        for url in urls:
            if url and url not in out:
                out.append(url)
        return out[:3]

    async def _cdx(self, ctx: Context, url: str, result: ModuleResult) -> list[dict]:
        """Список снимков страницы в архиве."""
        limit = 200 if ctx.deep else 60
        params = {"url": url, "output": "json", "fl": "timestamp,original,statuscode",
                  "filter": "statuscode:200", "collapse": "timestamp:6", "limit": str(limit)}
        resp = await ctx.http.get(CDX_API, params=params, retries=1, timeout=60)
        if resp.error or resp.looks_blocked():
            self.add_status(result, SourceStatus(
                source="wayback-cdx", category="archive",
                status="blocked" if resp.looks_blocked() else "error",
                url=resp.url, http_code=resp.status_code or None,
                error=resp.error or "архив вернул заглушку",
                detail="archive.org недоступен из вашей сети (в РФ он часто блокируется провайдером). "
                       "Прокси решит: OSINTX_PROXY=http://host:port"))
            return []
        if resp.status_code == 429:
            self.add_status(result, SourceStatus(
                source="wayback-cdx", category="archive", status="blocked", url=resp.url, http_code=429,
                detail="веб-архив ограничил частоту запросов (429) — повторите позже"))
            return []
        rows = resp.json()
        if not isinstance(rows, list) or len(rows) < 2:
            self.add_status(result, SourceStatus(
                source="wayback-cdx", category="archive", status="not_found", url=resp.url,
                http_code=resp.status_code, detail=f"в веб-архиве нет снимков {url}"))
            return []
        header = [str(c).lower() for c in rows[0]]
        snapshots: list[dict] = []
        for row in rows[1:]:
            item = dict(zip(header, [str(c) for c in row]))
            ts = item.get("timestamp", "")
            if not re.fullmatch(r"\d{14}", ts or ""):
                continue
            snapshots.append({"timestamp": ts, "url": item.get("original", url),
                              "status": item.get("statuscode", ""),
                              "archive_url": SNAPSHOT.format(ts=ts, url=item.get("original", url))})
        if not snapshots:
            self.add_status(result, SourceStatus(source="wayback-cdx", category="archive",
                                                 status="not_found", url=resp.url,
                                                 detail=f"снимки {url} есть, но ни один не с кодом 200"))
            return []
        first, last = snapshots[0], snapshots[-1]
        self.add_finding(
            result, source="wayback", category="archive", kind="history", confidence="high",
            title=(f"Веб-архив: {len(snapshots)} снимков {url} с "
                   f"{_human_date(first['timestamp'])} по {_human_date(last['timestamp'])}"),
            url=last["archive_url"], value=url,
            data={"snapshots": len(snapshots), "first_seen": _human_date(first["timestamp"]),
                  "last_snapshot": _human_date(last["timestamp"]),
                  "first_url": first["archive_url"], "last_url": last["archive_url"],
                  "years": sorted({s["timestamp"][:4] for s in snapshots}),
                  "timeline": [s["archive_url"] for s in snapshots[::max(1, len(snapshots) // 8)]][:8]},
            evidence=f"web.archive.org CDX для {url}: {len(snapshots)} снимков "
                     f"(самый старый {first['timestamp']}, самый новый {last['timestamp']})",
            http_code=resp.status_code, tags=["архив", "история"])
        self.add_status(result, SourceStatus(source="wayback-cdx", category="archive", status="found",
                                             url=resp.url, http_code=resp.status_code,
                                             detail=f"{len(snapshots)} снимков"))
        add_entity(result, "url", url, snapshots=len(snapshots), first=_human_date(first["timestamp"]),
                   last=_human_date(last["timestamp"]))
        return snapshots

    async def _compare(self, ctx: Context, url: str, snapshots: list[dict], result: ModuleResult,
                       *, target_type: str) -> None:
        """Сравнение старого и нового снимка: как менялись имя и описание."""
        picks: list[dict] = []
        if len(snapshots) == 1:
            picks = [snapshots[0]]
        else:
            middle = snapshots[len(snapshots) // 2]
            picks = [snapshots[0], middle, snapshots[-1]]
        observed: list[dict] = []
        for pick in picks:
            parsed = await self._fetch_snapshot(ctx, pick)
            if parsed:
                observed.append({**pick, **parsed})
        if not observed:
            self.add_status(result, SourceStatus(
                source=f"wayback-page:{url}", category="archive", status="error",
                detail="снимки есть, но содержимое не разобралось (архив отдал заглушку или таймаут)"))
            return

        for item in observed:
            label = " · ".join(x for x in (item.get("name"), item.get("bio")) if x)
            if not label:
                continue
            self.add_finding(
                result, source="wayback:snapshot", category="archive", kind="profile",
                confidence="high",
                title=f"Архивная копия {url} от {_human_date(item['timestamp'])}: {label[:180]}",
                url=item["archive_url"], value=url,
                data={"name": item.get("name"), "bio": item.get("bio"),
                      "display_name": item.get("name"), "description": item.get("bio"),
                      "snapshot_date": _human_date(item["timestamp"]), "timestamp": item["timestamp"]},
                evidence=f"снимок web.archive.org {item['timestamp']} → og:title={item.get('name')!r}, "
                         f"og:description={(item.get('bio') or '')[:120]!r}",
                http_code=200, tags=["архив", "профиль"])
            add_entity(result, "url", url, **{"last_name": item.get("name") or None})

        names = [i.get("name") for i in observed if i.get("name")]
        if len({n for n in names}) > 1:
            chain = " → ".join(
                f"{n} ({_human_date(i['timestamp'])})" for i, n in zip(observed, names))
            self.add_finding(
                result, source="wayback:changes", category="archive", kind="change", confidence="high",
                title=f"Имя/ник менялся в архиве: {chain[:220]}",
                url=observed[-1]["archive_url"], value=url,
                data={"history": [{"date": _human_date(i["timestamp"]), "name": i.get("name"),
                                   "url": i["archive_url"]} for i in observed],
                      "names": names},
                evidence="разные значения og:title в снимках веб-архива за разные годы — "
                         "подтверждённая смена имени/названия профиля",
                tags=["архив", "история", "ник"])
        bios = [i.get("bio") for i in observed if i.get("bio")]
        if len({b for b in bios}) > 1:
            self.add_finding(
                result, source="wayback:changes", category="archive", kind="change", confidence="high",
                title=f"Описание профиля менялось ({len(set(bios))} варианта за {len(observed)} снимка)",
                url=observed[-1]["archive_url"], value=url,
                data={"bio_history": [{"date": _human_date(i["timestamp"]), "bio": i.get("bio"),
                                       "url": i["archive_url"]} for i in observed if i.get("bio")]},
                evidence="разные og:description в снимках архива: "
                         + " | ".join(f"{_human_date(i['timestamp'])}: {(i.get('bio') or '')[:80]}"
                                      for i in observed if i.get("bio")),
                tags=["архив", "история", "био"])
        self.add_status(result, SourceStatus(
            source=f"wayback-page:{url}", category="archive", status="found",
            detail=f"разобрано снимков: {len(observed)}"))

    async def _fetch_snapshot(self, ctx: Context, pick: dict) -> dict:
        """Разбор архивного снимка: имя и описание страницы."""
        resp = await ctx.http.get(pick["archive_url"], retries=1, timeout=45)
        if resp.error or resp.status_code != 200 or resp.looks_blocked():
            return {}
        body = resp.text
        title = html.unescape(OG_TITLE.search(body).group(1)) if OG_TITLE.search(body) else ""
        desc = html.unescape(OG_DESC.search(body).group(1)) if OG_DESC.search(body) else ""
        if not title:
            raw_title = TITLE.search(body)
            title = html.unescape(re.sub(r"\s+", " ", raw_title.group(1))).strip() if raw_title else ""
        if title.startswith("Telegram: Contact @"):
            title = ""
        if not desc:
            extra = TG_EXTRA.search(body)
            desc = html.unescape(extra.group(1)).strip() if extra else ""
        # отсекаем страницы-заглушки самого архива
        if "Wayback Machine" in title and not desc:
            title = ""
        return {"name": title[:200], "bio": desc[:400]}

    @staticmethod
    def host_of(url: str) -> str:
        return urlparse(url).netloc


def _human_date(timestamp: str) -> str:
    """20170204045656 → 2017-02-04."""
    ts = (timestamp or "")[:8]
    if len(ts) == 8 and ts.isdigit():
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:]}"
    return timestamp or "?"
