"""Тесты модулей VK, MAX, поиска «где писал» в Telegram и импорта датасетов площадок.

Сеть не используется: HTTP-клиент подменяется FakeHttp с готовыми ответами,
токены — заглушкой настроек.
"""
from __future__ import annotations

import asyncio
import json

from osintx.core.models import ModuleResult
from osintx.core.store import Store


# ───────────────────────────── общая обвязка ─────────────────────────────
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

    @property
    def ok(self):
        return 200 <= self.status_code < 400 and not self.error

    def looks_blocked(self):
        return False

    def snippet(self, limit=300):
        return self.text[:limit]


class FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    async def get(self, url, **kw):
        params = kw.get("params") or {}
        full = url + ("?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else "")
        self.seen.append(full)
        for needle, response in self.routes.items():
            if needle in url or needle in full:
                return response
        return FakeResponse(payload=None, text="", status=404, url=full)


class FakeSettings:
    def __init__(self, keys=None):
        self.keys = keys or {}

    def key(self, name):
        return self.keys.get(name, "")


def _ctx(http, options=None, keys=None):
    from osintx.modules.base import Context

    return Context(settings=FakeSettings(keys), http=http, store=Store(":memory:"),
                   options=options or {})


VK_HTML = """
<html><head><title>Pavel Durov | VK</title>
<meta property="og:description" content="Санкт-Петербург, Россия. 1,020 posts">
</head><body>
<a href="https://m.vk.ru/wall1_525">запись</a>
<a href="https://t.me/durov/525">ещё</a>
<div class="wall_post_text">Пишите мне на pavel@example.com, телефон +7 999 123-45-67,
сайт https://durov.example</div>
<span class="rel_date">8 May 2018</span>
<div class="wall_post_text">Вторая запись про Telegram</div>
<span class="rel_date">1 Apr 2018</span>
</body></html>
"""


# ───────────────────────────── VK без токена ─────────────────────────────
def test_vk_public_page_found_with_mentions():
    from osintx.modules.vk import VkModule

    http = FakeHttp({"m.vk.com/durov": FakeResponse(text=VK_HTML)})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="vk", target="durov")
    asyncio.run(VkModule().run(ctx, "durov", result))

    profiles = [f for f in result.findings if f.kind == "profile"]
    assert profiles and "Pavel Durov" in profiles[0].title
    assert profiles[0].data["location"], "город/страна не распознаны из og:description"
    statuses = {s.source: s.status for s in result.statuses}
    assert statuses.get("vk") == "found"
    ctx.store.close()


def test_vk_public_page_not_found():
    from osintx.modules.vk import VkModule

    http = FakeHttp({"m.vk.com/ghost": FakeResponse(text="<html>Страница не найдена</html>")})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="vk", target="ghost")
    asyncio.run(VkModule().run(ctx, "ghost", result))

    assert [s.status for s in result.statuses if s.source == "vk"] == ["not_found"]
    assert not result.findings
    ctx.store.close()


def test_vk_public_page_captcha_is_blocked_not_not_found():
    from osintx.modules.vk import VkModule

    http = FakeHttp({"m.vk.com/robot": FakeResponse(text="<html>Проверяем, что вы не робот</html>")})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="vk", target="robot")
    asyncio.run(VkModule().run(ctx, "robot", result))

    status = [s for s in result.statuses if s.source == "vk"][0]
    assert status.status == "blocked", "капча не должна превращаться в «не найден»"
    assert "VK_TOKEN" in status.detail
    ctx.store.close()


def test_vk_api_mode_uses_token():
    from osintx.modules.vk import VkModule

    routes = {
        "utils.resolveScreenName": FakeResponse(payload={"response": {"object_id": 1, "type": "user"}}),
        "users.get": FakeResponse(payload={"response": [{
            "id": 1, "first_name": "Pavel", "last_name": "Durov", "domain": "durov",
            "city": {"title": "Санкт-Петербург"}, "country": {"title": "Россия"},
            "followers_count": 1200000, "status": "Founder", "verified": 1,
        }]}),
        "wall.get": FakeResponse(payload={"response": {"count": 1, "items": [
            {"id": 525, "date": 1525780800, "text": "Почта: pavel@example.com",
             "likes": {"count": 10}, "views": {"count": 5000}},
        ]}}),
    }
    http = FakeHttp(routes)
    ctx = _ctx(http, {"target_type": "username"}, keys={"vk_token": "FAKE"})
    result = ModuleResult(module="vk", target="durov")
    asyncio.run(VkModule().run(ctx, "durov", result))

    profile = [f for f in result.findings if f.source == "vk-api"][0]
    assert profile.data["city"] == "Санкт-Петербург"
    assert profile.data["followers"] == 1200000
    posts = [f for f in result.findings if f.source == "vk:wall"][0]
    assert posts.data["mentions"]["emails"] == ["pavel@example.com"]
    assert any(f.source == "vk-api" for f in result.findings)
    ctx.store.close()


def test_vk_api_error_requires_token_reported():
    from osintx.modules.vk import VkModule

    routes = {"utils.resolveScreenName": FakeResponse(
        payload={"error": {"error_code": 15, "error_msg": "Access denied: token required"}})}
    http = FakeHttp(routes)
    ctx = _ctx(http, {"target_type": "username"}, keys={"vk_token": "BAD"})
    result = ModuleResult(module="vk", target="durov")
    asyncio.run(VkModule().run(ctx, "durov", result))

    status = [s for s in result.statuses if s.source == "vk-api"][0]
    assert status.status == "error" and "VK_TOKEN" in status.detail
    ctx.store.close()


def test_vk_phone_is_unsupported():
    from osintx.modules.vk import VkModule

    http = FakeHttp({"m.vk.com": FakeResponse(text=VK_HTML)})
    ctx = _ctx(http, {"target_type": "phone"})
    result = ModuleResult(module="vk", target="+79991234567")
    asyncio.run(VkModule().run(ctx, "+79991234567", result))

    assert any(s.status == "unsupported" for s in result.statuses)
    ctx.store.close()


def test_vk_mentions_extracts_contacts():
    from osintx.modules.vk import _mentions

    data = _mentions(["почта ivan@example.com и сайт https://ivan.example, тел. +79991234567",
                      "второй пост ivan@example.com"])
    assert data["emails"] == ["ivan@example.com"]
    assert any(link.startswith("https://ivan.example") for link in data["links"])
    assert data["phones"] and data["phones"][0].endswith("9991234567")


# ───────────────────────────── MAX ─────────────────────────────
def test_max_nick_found_as_channel_or_bot():
    from osintx.modules.max import MaxModule

    html = ('<html><head><title>Новости — MAX</title>'
            '<meta property="og:description" content="Официальный канал"></head></html>')
    http = FakeHttp({"max.ru/@news": FakeResponse(text=html)})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="max", target="news")
    asyncio.run(MaxModule().run(ctx, "news", result))

    finding = result.findings[0]
    assert finding.data["type"] == "channel_or_bot"
    assert "Новости" in finding.title
    assert finding.data["web_url"] == "https://web.max.ru/@news"
    assert any(s.status == "unsupported" for s in result.statuses), "честно про людей без @username"
    ctx.store.close()


def test_max_free_nick_is_not_found():
    from osintx.modules.max import MaxModule

    http = FakeHttp({"max.ru/@ghost": FakeResponse(text="<html>Не нашли чат по этой ссылке</html>")})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="max", target="ghost")
    asyncio.run(MaxModule().run(ctx, "ghost", result))

    assert [s.status for s in result.statuses if s.source == "max"] == ["not_found"]
    ctx.store.close()


def test_max_profile_link_is_checked():
    from osintx.modules.max import MaxModule

    html = '<html><head><title>Профиль</title><meta property="og:title" content="Иван"></head></html>'
    http = FakeHttp({"max.ru/u/abc123": FakeResponse(text=html)})
    ctx = _ctx(http, {"target_type": "url"})
    result = ModuleResult(module="max", target="max.ru/u/abc123")
    asyncio.run(MaxModule().run(ctx, "max.ru/u/abc123", result))

    assert any(f.source == "max:profile" for f in result.findings)
    ctx.store.close()


def test_max_phone_is_unsupported():
    from osintx.modules.max import MaxModule

    http = FakeHttp({"max.ru": FakeResponse(text="Не нашли чат по этой ссылке")})
    ctx = _ctx(http, {"target_type": "phone"})
    result = ModuleResult(module="max", target="+79991234567")
    asyncio.run(MaxModule().run(ctx, "+79991234567", result))

    statuses = {s.source: s.status for s in result.statuses}
    assert statuses.get("max:phone") == "unsupported"
    ctx.store.close()


# ───────────────────────────── Telegram: «где писал» ─────────────────────────────
def test_tg_post_links_and_oldest_id():
    from osintx.modules.telegram import _oldest_post_id, _post_links

    hrefs = ('<a href="https://t.me/durov/525">11</a><a href="https://t.me/durov/526">12</a>')
    assert _post_links(hrefs, "durov") == ["https://t.me/durov/525", "https://t.me/durov/526"]
    data_posts = '<div data-post="durov/527"></div><div data-post="durov/528"></div>'
    assert _post_links(data_posts, "durov") == ["https://t.me/durov/527", "https://t.me/durov/528"]
    assert _oldest_post_id(data_posts, "durov") == "527"
    assert _oldest_post_id(hrefs, "durov") == "525"   # запасной путь: без data-post
    assert _post_links("<a href='https://t.me/other/1'>x</a>", "durov") == []


def test_tg_activity_counts_period_and_frequency():
    from osintx.modules.telegram import TelegramModule

    posts = [{"date": "2024-01-10", "text": "a", "url": "https://t.me/x/2"},
             {"date": "2024-03-10", "text": "b", "url": "https://t.me/x/1"}]
    http = FakeHttp({})
    ctx = _ctx(http, {"target_type": "username"})
    result = ModuleResult(module="telegram", target="x")
    asyncio.run(TelegramModule()._activity(ctx, "x", posts, result))

    finding = [f for f in result.findings if f.source == "t.me:activity"][0]
    assert finding.data["first_post_date"] == "2024-01-10"
    assert finding.data["last_post_date"] == "2024-03-10"
    assert finding.data["posts_collected"] == 2 and finding.data["days_span"] == 60
    assert finding.data["recent"][0]["url"] == "https://t.me/x/2"
    ctx.store.close()


def test_tg_search_in_channel_builds_findings_with_urls():
    from osintx.modules.telegram import TelegramModule

    html = ('<div class="tgme_widget_message_text">написал про @durov и почту a@b.c</div>'
            '<div data-post="chan/42"></div>')
    http = FakeHttp({"t.me/s/chan": FakeResponse(text=html)})
    ctx = _ctx(http, {"target_type": "telegram"})
    result = ModuleResult(module="telegram", target="durov")
    posts = [{"date": "2024-01-01", "url": "https://t.me/chan/1",
              "text": "пишите на kontakt@example.com"}]
    asyncio.run(TelegramModule()._search_in_channel(ctx, "chan", posts, result))

    findings = [f for f in result.findings if f.kind == "messages"]
    finding = findings[0]
    assert finding.data["hits"] == ["https://t.me/chan/42"]
    assert finding.data["search_url"] == "https://t.me/s/chan?q=chan"
    assert any("durov" in text for text in finding.data["snippets"])
    assert any(f.data["query"] == "kontakt@example.com" for f in findings), "email из постов тоже ищется"
    assert any("?q=" in url for url in http.seen)
    ctx.store.close()


# ───────────────────────────── реестры и датасеты ─────────────────────────────
def test_builtin_registry_is_broad():
    from osintx.core.registry import count_sources, load_sites

    counts = count_sources()
    assert counts["username"] >= 200, "реестр площадок должен быть широким"
    assert counts["email"] >= 10 and counts["phone"] >= 2
    names = {s["name"] for s in load_sites("username", include_user=False)}
    for required in ("vk", "telegram", "github", "ok", "rutube", "masтодон", "boosty"):
        if required == "masтодон":
            required = "mastodon.social"
        assert required in names, f"нет площадки {required}"


def test_registry_has_no_duplicate_urls():
    from osintx.core.registry import load_sites

    urls = [s["url"] for s in load_sites("username", include_user=False)]
    assert len(urls) == len(set(urls)), "в реестре дублируются URL"


def test_wmn_converter_maps_strategies():
    from osintx.core import wmn

    payload = {"sites": [
        {"name": "A", "uri_check": "https://a.example/{account}", "e_code": 200,
         "e_string": "profile-page", "m_string": "not found", "m_code": 404, "cat": "social"},
        {"name": "B", "uri_check": "https://b.example/{account}", "e_code": 200, "cat": "tech"},
        {"name": "NSFW", "uri_check": "https://c.example/{account}", "e_code": 200, "cat": "xx NSFW xx"},
    ]}
    sites = wmn.convert_wmn(payload)
    assert [s["strategy"] for s in sites] == ["message_exclude", "status_code"]
    assert sites[0]["not_found_msgs"] == ["not found"]
    assert all(s["dataset"] == "wmn" for s in sites)
    assert all("{username}" in s["url"] for s in sites)
    assert len(wmn.convert_wmn(payload, include_nsfw=True)) == 3


def test_sherlock_converter():
    from osintx.core import wmn

    payload = {"Site": {"url": "https://s.example/{username}", "urlMain": "https://s.example",
                        "errorType": "message", "errorMsg": "No such user"},
               "Other": {"url": "https://o.example/{username}", "errorType": "status_code"}}
    sites = wmn.convert_sherlock(payload)
    by_name = {s["name"]: s for s in sites}
    assert by_name["sherlock:Site"]["strategy"] == "message_exclude"
    assert by_name["sherlock:Other"]["not_found_codes"] == [404, 410]


def test_dataset_merge_and_clear(tmp_path):
    from osintx.core import wmn

    path = tmp_path / "sites_user.json"
    sites = wmn.convert_wmn({"sites": [
        {"name": "X", "uri_check": "https://x.example/{account}", "e_code": 200, "cat": "social"}]})
    first = wmn.merge_username_sites(path, sites)
    assert first["added"] == 1
    second = wmn.merge_username_sites(path, sites)
    assert second["added"] == 1 and second["total_user"] == 1, "повторный импорт не должен дублировать"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["datasets"]["wmn"] == 1
    assert wmn.clear_datasets(path, {"wmn"}) == 1
    assert json.loads(path.read_text(encoding="utf-8"))["username"] == []


def test_user_registry_extends_builtin(tmp_path, monkeypatch):
    custom = tmp_path / "sites_user.json"
    custom.write_text(json.dumps({"username": [{"name": "my-site", "url": "https://my.example/{username}"}]}),
                      encoding="utf-8")

    class S:
        data_dir = tmp_path

    import osintx.core.registry as reg
    monkeypatch.setattr(reg, "get_settings", lambda: S())
    sites = reg.load_sites("username")
    assert any(s["name"] == "my-site" for s in sites)
    assert len(sites) > len(reg.load_sites("username", include_user=False))


def test_person_code_search_github_and_gitlab():
    from osintx.modules.person import PersonModule

    routes = {
        "api.github.com/search/users": FakeResponse(payload={"total_count": 1, "items": [
            {"login": "ivanpetrov", "html_url": "https://github.com/ivanpetrov",
             "score": 90.0, "type": "User"}]}),
        "gitlab.com/api/v4/users": FakeResponse(payload=[{
            "username": "ipetrov", "name": "Ivan Petrov", "web_url": "https://gitlab.com/ipetrov",
            "location": "Munich, Germany", "bio": "backend", "state": "active"}]),
    }
    http = FakeHttp(routes)
    ctx = _ctx(http, {"target_type": "person"})
    result = ModuleResult(module="person", target="Иван Петров")
    asyncio.run(PersonModule()._code_search(ctx, "Иван Петров", result))

    github = [f for f in result.findings if f.source == "github-search"]
    gitlab = [f for f in result.findings if f.source == "gitlab-search"]
    assert github and github[0].data["candidates"][0]["login"] == "ivanpetrov"
    assert github[0].data["logins"] == ["ivanpetrov"]
    assert gitlab and gitlab[0].data["candidates"][0]["location"] == "Munich, Germany"
    assert any(e["relation"] == "name_match_github" for e in result.meta["edges"])
    ctx.store.close()
