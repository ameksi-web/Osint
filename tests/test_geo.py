"""Тесты гео-словаря, гео-модуля, инсайтов и веб-архива (без реальной сети)."""
from __future__ import annotations

import asyncio
import json

import pytest

from osintx.core import gazetteer as gz
from osintx.core.models import Finding, ModuleResult, Report
from osintx.core.store import Store


# ───────────────────────────── словарь стран/городов ─────────────────────────────
@pytest.mark.parametrize("text,country,city", [
    ("Portland, OR", "США", "Портленд"),
    ("Berlin, Germany", "Германия", "Берлин"),
    ("Munich, Bavaria, Germany", "Германия", "Мюнхен"),
    ("Toronto, ON, Canada", "Канада", "Торонто"),
    ("San Francisco, CA", "США", "Сан-Франциско"),
    ("Sydney, NSW", "Австралия", "Сидней"),
    ("Новосибирск, Россия", "Россия", "Новосибирск"),
    ("живу в Мюнхене, работаю в Берлине", "Германия", "Мюнхен"),
    ("Алматы, Казахстан", "Казахстан", "Алматы"),
    ("Tel Aviv, Israel", "Израиль", "Тель-Авив"),
])
def test_find_location(text, country, city):
    matches = gz.find_location(text)
    assert matches, f"не распознано: {text}"
    assert any(m.country == country and m.city == city for m in matches)


@pytest.mark.parametrize("text", ["Remote", "Earth", "Worldwide", "интернет", ""])
def test_blacklist_not_location(text):
    assert gz.find_location(text) == []


def test_no_false_positive_francisco_as_france():
    """«San Francisco» не должен превращаться во Францию (стемма franc)."""
    countries = {m.country for m in gz.find_location("San Francisco, CA")}
    assert "Франция" not in countries


def test_no_duplicate_country_when_city_known():
    matches = gz.find_location("Berlin, Germany")
    assert [m.country for m in matches] == ["Германия"]     # без «Германия вообще» второй раз


def test_country_from_phone():
    assert gz.country_from_phone("+4915112345678") == "DE"
    assert gz.country_from_phone("+79991234567") == "RU"
    assert gz.country_from_phone("") == ""


def test_country_name_and_cities():
    assert gz.country_name("DE") == "Германия"
    assert gz.country_name("de") == "Германия"
    assert "Мюнхен" in gz.cities_of("DE")


# ───────────────────────────── инсайты ─────────────────────────────
def _report_with_profiles():
    report = Report(target="ivanpetrov", target_type="username")
    module = ModuleResult(module="username", target="ivanpetrov")
    module.findings = [
        Finding(source="github-api", category="username", kind="profile",
                title="GitHub: Иван Петров (@ivanpetrov)", url="https://github.com/ivanpetrov",
                data={"name": "Иван Петров", "location": "Berlin, Germany",
                      "created_at": "2013-05-04T10:00:00Z", "public_repos": 42}),
        Finding(source="t.me", category="telegram", kind="profile",
                title="Telegram пользователь: Иван", url="https://t.me/ivanpetrov",
                data={"name": "Иван", "bio": "Живу в Мюнхене, пишу на Python"}),
        Finding(source="phone", category="phone", kind="profile", title="+49 30 1234567",
                value="+49301234567", data={"e164": "+49301234567", "region": "DE", "carrier": "Vodafone"}),
    ]
    report.merge(module)
    report.compute_summary()
    return report


def test_insights_location_and_names_and_timeline():
    from osintx import insights

    report = _report_with_profiles()
    insights.apply(report, store=None, record=False)

    geo = [f for f in report.findings if f.source == "insights:geo"]
    assert geo, "сводка по местоположению не собралась"
    assert "Германия" in geo[0].value
    assert report.meta["insights"]["location"].endswith("Германия")

    names = [f for f in report.findings if f.category == "identity" and f.kind == "name"]
    assert {"Иван Петров", "Иван"} <= {f.value for f in names}

    timeline = [f for f in report.findings if f.category == "timeline"]
    assert timeline and "2013" in timeline[0].value

    contacts = [f for f in report.findings if f.category == "contacts"]
    assert contacts and "phone" in contacts[0].title


def test_insights_records_history_and_reports_changes(tmp_path):
    from osintx import insights

    store = Store(tmp_path / "hist.db")
    report = _report_with_profiles()
    insights.apply(report, store=store)
    assert store.snapshot_stats("ivanpetrov")["total"] >= 4

    # второй поиск: имя в Telegram изменилось
    changed = _report_with_profiles()
    for finding in changed.findings:
        if finding.source == "t.me":
            finding.data["name"] = "Иван П."
    insights.apply(changed, store=store)

    changes = store.profile_changes("ivanpetrov")
    assert any(c["field"] == "name" and c["old"] == "Иван" and c["new"] == "Иван П." for c in changes)
    assert any(f.source == "insights:changes" for f in changed.findings)
    assert "Иван" in insights.format_changes(changes, "ivanpetrov")
    store.close()


def test_format_changes_empty():
    from osintx.insights import format_changes

    assert "пуста" in format_changes([], "x")


# ───────────────────────────── гео-модуль ─────────────────────────────
class FakeResponse:
    def __init__(self, payload=None, text="", status=200, url="https://example"):
        self._json = payload
        self.text = text
        self.status_code = status
        self.url = url
        self.error = ""
        self.headers = {}

    def json(self):
        return self._json

    def looks_blocked(self):
        return False

    def snippet(self, limit=300):
        return self.text[:limit]


class FakeHttp:
    """Подменяет HttpClient: отдаёт заранее заготовленные ответы по URL."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    async def get(self, url, **kw):
        self.seen.append(url)
        for needle, response in self.routes.items():
            if needle in url:
                return response
        return FakeResponse(payload=None, text="", status=404, url=url)


def _ctx(http, options=None):
    from osintx.config import get_settings
    from osintx.modules.base import Context

    return Context(settings=get_settings(), http=http, store=Store(":memory:"),
                   options=options or {})


def test_geo_module_gravatar_by_email():
    from osintx.modules.geo import GeoModule

    payload = {"entry": [{
        "displayName": "Ivan Petrov", "currentLocation": "Berlin, Germany",
        "aboutMe": "Backend developer", "profileUrl": "https://gravatar.com/ivanpetrov",
        "thumbnailUrl": "https://secure.gravatar.com/avatar/x",
        "accounts": [{"domain": "github.com", "url": "https://github.com/ivanpetrov", "verified": True}],
        "urls": [{"title": "site", "value": "https://ivan.example"}]}]}
    http = FakeHttp({"gravatar.com": FakeResponse(payload=payload, text=json.dumps(payload))})
    ctx = _ctx(http, {"target_type": "email", "original_target": "ivan@example.com"})
    result = ModuleResult(module="geo", target="ivan")
    asyncio.run(GeoModule().run(ctx, "ivan", result))

    gravatar = [f for f in result.findings if f.source == "gravatar"]
    assert gravatar, "Gravatar-профиль не разобран"
    assert gravatar[0].data["location"] == "Berlin, Germany"
    assert gravatar[0].data["country"] == "Германия"
    assert any("github.com" in (a.get("url") or "") for a in gravatar[0].data["accounts"])
    ctx.store.close()


def test_geo_module_steam_xml():
    from osintx.modules.geo import GeoModule

    xml = ("<profile><steamID64>7656119</steamID64><steamID>robot</steamID>"
           "<realname>Ivan Petrov</realname><summary><![CDATA[Hello]]></summary>"
           "<location>Munich, Germany</location><timecreated>2011-01-02T03:04:05Z</timecreated>"
           "<loccountrycode>DE</loccountrycode></profile>")
    http = FakeHttp({"/id/robot/?xml=1": FakeResponse(text=xml)})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="geo", target="robot")
    asyncio.run(GeoModule().run(ctx, "robot", result))

    steam = [f for f in result.findings if f.source == "steam-geo"]
    assert steam and steam[0].data["location"] == "Munich, Germany"
    assert steam[0].data["country"] == "Германия"
    assert steam[0].data["created_at"].startswith("2011-01-02")
    ctx.store.close()


def test_geo_module_steam_missing_profile():
    from osintx.modules.geo import GeoModule

    http = FakeHttp({"/id/nobody/?xml=1": FakeResponse(text="<response><error>The specified profile could not be found.</error></response>")})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="geo", target="nobody")
    asyncio.run(GeoModule().run(ctx, "nobody", result))
    assert not result.findings
    assert any(s.status == "not_found" for s in result.statuses)
    ctx.store.close()


def test_geo_module_phone_country():
    from osintx.modules.geo import GeoModule

    ctx = _ctx(FakeHttp({}), {"target_type": "phone"})
    result = ModuleResult(module="geo", target="+4915112345678")
    asyncio.run(GeoModule().run(ctx, "+4915112345678", result))
    assert result.findings and result.findings[0].data["country"] == "Германия"
    assert "страна номера — это НЕ доказательство проживания" in result.findings[0].data["note"]
    ctx.store.close()


# ───────────────────────────── веб-архив ─────────────────────────────
def test_wayback_candidate_urls():
    from osintx.modules.wayback import WaybackModule as W

    assert W._candidate_urls("ivanpetrov", "username", "ivanpetrov") == ["t.me/ivanpetrov", "telegram.me/ivanpetrov"]
    assert W._candidate_urls("ivan@example.com", "email", "ivan@example.com") == ["example.com", "www.example.com"]
    assert W._candidate_urls("Иван Петров", "person", "Иван Петров") == []


def test_wayback_history_and_name_change():
    from osintx.modules.wayback import WaybackModule

    cdx = json.dumps([["timestamp", "original", "statuscode"],
                      ["20140203040506", "t.me/ivanpetrov", "200"],
                      ["20180603040506", "t.me/ivanpetrov", "200"],
                      ["20250603040506", "t.me/ivanpetrov", "200"]])
    old_html = ('<meta property="og:title" content="Telegram: Contact @ivanpetrov">'
                '<meta property="og:description" content="Иван, 24, Москва">')
    new_html = ('<meta property="og:title" content="Иван Петров">'
                '<meta property="og:description" content="Backend-разработчик, Берлин">')
    routes = {
        "cdx/search/cdx": FakeResponse(payload=json.loads(cdx), text=cdx),
        "20140203040506": FakeResponse(text=old_html),
        "20180603040506": FakeResponse(text=old_html),
        "20250603040506": FakeResponse(text=new_html),
    }
    ctx = _ctx(FakeHttp(routes), {"target_type": "telegram", "original_target": "@ivanpetrov"})
    result = ModuleResult(module="wayback", target="ivanpetrov")
    asyncio.run(WaybackModule().run(ctx, "ivanpetrov", result))

    history = [f for f in result.findings if f.kind == "history"]
    assert history, "история снимков не собрана"
    assert history[0].data["snapshots"] == 3
    assert history[0].data["first_seen"] == "2014-02-03"

    changes = [f for f in result.findings if f.kind == "change"]
    assert changes, "смена описания/имени не обнаружена"
    assert any("Описание профиля менялось" in f.title for f in changes)
    ctx.store.close()


def test_wayback_blocked_archive_reports_blocked(monkeypatch):
    from osintx.modules.wayback import WaybackModule

    class BlockedResponse(FakeResponse):
        def looks_blocked(self):
            return True

    ctx = _ctx(FakeHttp({"cdx/search/cdx": BlockedResponse(text="captcha", status=403)}),
               {"target_type": "username"})
    result = ModuleResult(module="wayback", target="ivan")
    asyncio.run(WaybackModule().run(ctx, "ivan", result))
    assert not result.findings
    assert any(s.status == "blocked" and "archive.org" in s.detail for s in result.statuses)
    ctx.store.close()


def test_insights_apply_is_idempotent():
    """Повторный вызов (движок + CLI/бот) не должен дублировать выводы и «размножать» источники."""
    from osintx import insights

    report = _report_with_profiles()
    insights.apply(report, store=None, record=False)
    first = [f.title for f in report.findings if f.source == "insights:geo"]
    insights.apply(report, store=None, record=False)
    second = [f.title for f in report.findings if f.source == "insights:geo"]
    assert first == second
    assert len([m for m in report.modules if m.module == "insights"]) == 1


def test_snapshots_include_summary_counters():
    from osintx.insights import snapshots_from_report

    report = _report_with_profiles()
    fields = {item["field"] for item in snapshots_from_report(report)}
    assert {"находок всего", "источников ответило"} <= fields
    assert any(item["field"] == "location" and item["value"] == "Berlin, Germany"
               for item in snapshots_from_report(report))
