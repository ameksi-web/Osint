#!/usr/bin/env python3
"""Сборка реестра источников OsintX (osintx/data/sites_*.json).

Реестр — данные, а не код: правь списки ниже и запусти
    python tools/build_registry.py
чтобы пересобрать JSON. Пользовательские источники можно добавлять без правки
этого файла — в $OSINTX_DATA_DIR/sites_user.json (см. README).

Поля записи:
    name           — идентификатор источника (в отчёте)
    url            — шаблон, поддерживает {username} {email} {email_url} {email_hash}
                     {phone_digits} {domain} {ip} {query} {target}
    strategy       — status_code | message_exclude | message_include | json_path | regex | redirect
    method, params, payload, json_body — если проверка через API/POST
    found_codes / not_found_codes      — для strategy status_code
    not_found_msgs / found_msgs        — для message-стратегий
    json_found     — {"path": "data.exists", "op": "exists|equals|not_equals|contains|empty", "value": ...}
    confidence     — high | medium | low (насколько надёжен признак)
    kind           — profile | account | meta | ...
    tags           — теги для фильтрации (--tags)
    control_user   — существующий логин для калибровки (на нём источник должен дать «найден»)
    control_ghost  — несуществующий логин (источник должен дать «не найден»)
    extract_meta   — вытаскивать og:/title/description со страницы профиля
    disabled       — временно исключить источник
"""
from __future__ import annotations

import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "osintx" / "data"

# ─────────────────────────────── USERNAME ───────────────────────────────
# (имя, url, стратегия-параметры, confidence, kind, tags, контрольные)
U = []


def add(name, url, *, strategy="status_code", confidence="medium", kind="profile", tags=(),
        control=None, ghost=None, method="GET", params=None, payload=None, json_body=None,
        found_codes=None, not_found_codes=None, not_found_msgs=None, found_msgs=None,
        json_found=None, extract_meta=False, note="", follow_redirects=None, timeout=None,
        pattern=None, title=None, disabled=False, retries=None, store_body=False):
    entry = {"name": name, "url": url, "strategy": strategy, "confidence": confidence, "kind": kind,
             "tags": list(tags)}
    if control:
        entry["control_user"] = control
    if ghost:
        entry["control_ghost"] = ghost
    for key, val in (("method", method if method != "GET" else None), ("params", params),
                     ("payload", payload), ("json_body", json_body), ("found_codes", found_codes),
                     ("not_found_codes", not_found_codes), ("not_found_msgs", not_found_msgs),
                     ("found_msgs", found_msgs), ("json_found", json_found),
                     ("extract_meta", extract_meta or None), ("note", note or None),
                     ("follow_redirects", follow_redirects), ("timeout", timeout), ("pattern", pattern),
                     ("title", title or None), ("disabled", disabled or None), ("retries", retries),
                     ("store_body", store_body or None)):
        if val is not None:
            entry[key] = val
    U.append(entry)


# --- соцсети и мессенджеры ---
add("telegram", "https://t.me/{username}", control="durov", confidence="high", tags=["messenger", "ru"])
add("instagram", "https://www.instagram.com/{username}/", strategy="message_exclude",
    not_found_msgs=["Sorry, this page isn't available", "Page Not Found"],
    control="instagram", confidence="medium", tags=["social"], extract_meta=True,
    note="Instagram часто отдаёт заглушку для дата-центровых IP")
add("twitter", "https://x.com/{username}", strategy="message_exclude",
    not_found_msgs=["This account doesn’t exist", "This account doesn't exist", "Hmm...this page doesn’t exist"],
    confidence="low", tags=["social"], note="X/Twitter требует JS и часто отдаёт страницу входа")
add("tiktok", "https://www.tiktok.com/@{username}", strategy="message_exclude",
    not_found_msgs=["Couldn't find this account", "Couldn’t find this account"],
    control="tiktok", confidence="low", tags=["social"])
add("facebook", "https://www.facebook.com/{username}", strategy="message_exclude",
    not_found_msgs=["content isn't available", "This content isn't available right now", "Page Not Found"],
    confidence="low", tags=["social"], note="Facebook почти всегда требует вход")
add("linkedin", "https://www.linkedin.com/in/{username}", confidence="low", tags=["social", "work"],
    note="LinkedIn отдаёт HTTP 999 ботам")
add("reddit", "https://www.reddit.com/user/{username}/about.json", strategy="json_path",
    json_found={"path": "data.name", "op": "exists"}, control="reddit", confidence="high", tags=["social"])
add("vk", "https://vk.com/{username}", strategy="message_exclude",
    not_found_msgs=["Профиль не найден", "Page not found", "Такой страницы нет"],
    control="vk", confidence="medium", tags=["social", "ru"])
add("ok", "https://ok.ru/{username}", confidence="low", tags=["social", "ru"],
    note="OK.ru отдаёт 200 и для несуществующих страниц — нужна калибровка")
add("pinterest", "https://www.pinterest.com/{username}/", control="pinterest", confidence="high",
    tags=["social"])
add("youtube", "https://www.youtube.com/@{username}", control="YouTube", confidence="high", tags=["video"])
add("twitch", "https://www.twitch.tv/{username}", control="twitch", confidence="high", tags=["video"])
add("kick", "https://kick.com/{username}", control="kick", confidence="medium", tags=["video"])
add("vimeo", "https://vimeo.com/{username}", control="vimeo", confidence="high", tags=["video"])
add("dailymotion", "https://www.dailymotion.com/{username}", control="dailymotion", confidence="medium",
    tags=["video"])
add("rutube", "https://rutube.ru/channel/{username}/", confidence="low", tags=["video", "ru"])
add("soundcloud", "https://soundcloud.com/{username}", control="soundcloud", confidence="high", tags=["music"])
add("spotify", "https://open.spotify.com/user/{username}", control="spotify", confidence="medium", tags=["music"])
add("lastfm", "https://www.last.fm/user/{username}", control="RJ", confidence="high", tags=["music"])
add("bandcamp", "https://bandcamp.com/{username}", control="bandcamp", confidence="medium", tags=["music"])
add("mixcloud", "https://www.mixcloud.com/{username}/", confidence="medium", tags=["music"])
add("mastodon.social", "https://mastodon.social/@{username}", control="mastodon", confidence="high",
    tags=["social", "fediverse"])
add("bluesky", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile", method="GET",
    params={"actor": "{username}.bsky.social"}, strategy="json_path",
    json_found={"path": "did", "op": "exists" if False else "non_empty"}, control="bsky.app",
    confidence="high", tags=["social", "fediverse"], kind="profile",
    note="Bluesky: проверяется handle <логин>.bsky.social через публичный API")
add("tumblr", "https://{username}.tumblr.com/", confidence="medium", tags=["blog"], control="staff")
add("livejournal", "https://{username}.livejournal.com/", confidence="medium", tags=["blog", "ru"])
add("medium", "https://medium.com/@{username}", strategy="message_exclude",
    not_found_msgs=["Out of nothing, something", "404"], confidence="low", tags=["blog"])
add("substack", "https://{username}.substack.com/", confidence="medium", tags=["blog"])
add("hashnode", "https://hashnode.com/@{username}", control="hashnode", confidence="medium", tags=["blog", "dev"])
add("habr", "https://habr.com/ru/users/{username}/", control="habr", confidence="high", tags=["blog", "ru", "dev"])
add("pikabu", "https://pikabu.ru/@{username}", confidence="medium", tags=["blog", "ru"])
add("dzen", "https://dzen.ru/{username}", confidence="low", tags=["blog", "ru"])
add("disqus", "https://disqus.com/by/{username}/", control="disqus", confidence="high", tags=["social"])
add("gravatar", "https://gravatar.com/{username}.json", strategy="json_path",
    json_found={"path": "entry", "op": "non_empty"}, confidence="high", tags=["profile"])
add("aboutme", "https://about.me/{username}", confidence="medium", tags=["profile"])
add("linktree", "https://linktr.ee/{username}", control="linktree", confidence="high", tags=["profile"])
add("producthunt", "https://www.producthunt.com/@{username}", control="producthunt", confidence="medium",
    tags=["tech"])
add("foursquare", "https://foursquare.com/{username}", control="foursquare", confidence="medium", tags=["geo"])
add("untappd", "https://untappd.com/user/{username}", confidence="medium", tags=["social"])
add("letterboxd", "https://letterboxd.com/{username}/", control="letterboxd", confidence="high", tags=["media"])
add("trakt", "https://trakt.tv/users/{username}", control="trakt", confidence="high", tags=["media"])
add("myanimelist", "https://myanimelist.net/profile/{username}", confidence="medium", tags=["media"])
add("anilist", "https://anilist.co/user/{username}/", control="AniList", confidence="high", tags=["media"])
add("goodreads", "https://www.goodreads.com/{username}", confidence="low", tags=["media"])
add("genius", "https://genius.com/{username}", control="genius", confidence="medium", tags=["music"])
add("imgur", "https://imgur.com/user/{username}", control="imgur", confidence="high", tags=["media"])
add("9gag", "https://9gag.com/u/{username}", confidence="medium", tags=["media"])
add("deviantart", "https://www.deviantart.com/{username}", confidence="medium", tags=["art"])
add("artstation", "https://www.artstation.com/{username}", control="artstation", confidence="high", tags=["art"])
add("behance", "https://www.behance.net/{username}", control="behance", confidence="high", tags=["art"])
add("dribbble", "https://dribbble.com/{username}", control="dribbble", confidence="high", tags=["art"])
add("unsplash", "https://unsplash.com/@{username}", control="unsplash", confidence="high", tags=["art"])
add("flickr", "https://www.flickr.com/people/{username}", confidence="medium", tags=["art"])
add("500px", "https://500px.com/p/{username}", confidence="medium", tags=["art"])
add("patreon", "https://www.patreon.com/{username}", control="patreon", confidence="medium", tags=["money"])
add("buymeacoffee", "https://www.buymeacoffee.com/{username}", confidence="medium", tags=["money"])
add("kofi", "https://ko-fi.com/{username}", confidence="medium", tags=["money"])
add("ko-fi", "https://ko-fi.com/{username}", confidence="low", tags=["money"], disabled=True,
    note="дубль buymeacoffee-подобного сервиса, оставлен пример отключённого источника")
add("opensea", "https://opensea.io/{username}", control="opensea", confidence="medium", tags=["crypto"])
add("snapchat", "https://www.snapchat.com/add/{username}", confidence="low", tags=["social"])

# --- разработка ---
add("github", "https://github.com/{username}", control="torvalds", confidence="high", tags=["dev"],
    extract_meta=True)
add("gist", "https://gist.github.com/{username}", control="torvalds", confidence="high", tags=["dev"])
add("gitlab", "https://gitlab.com/{username}", control="gitlab", confidence="medium", tags=["dev"])
add("bitbucket", "https://bitbucket.org/{username}/", control="atlassian", confidence="medium", tags=["dev"])
add("sourceforge", "https://sourceforge.net/u/{username}/profile", control="sourceforge", confidence="medium",
    tags=["dev"])
add("launchpad", "https://launchpad.net/~{username}", control="ubuntu", confidence="medium", tags=["dev"])
add("codeberg", "https://codeberg.org/{username}", control="Codeberg", confidence="high", tags=["dev"])
add("huggingface", "https://huggingface.co/{username}", control="huggingface", confidence="high", tags=["dev", "ai"])
add("kaggle", "https://www.kaggle.com/{username}", control="kaggle", confidence="high", tags=["dev", "data"])
add("dockerhub", "https://hub.docker.com/v2/users/{username}/", strategy="json_path",
    json_found={"path": "username", "op": "exists"}, control="library", confidence="high", tags=["dev"])
add("npm", "https://registry.npmjs.org/-/user/org.couchdb.user:{username}", strategy="json_path",
    json_found={"path": "name", "op": "exists"}, control="npm", confidence="high", tags=["dev"])
add("pypi", "https://pypi.org/user/{username}/", control="kennethreitz", confidence="low", tags=["dev"],
    note="PyPI отдаёт страницу-челлендж (HTTP 200) для ботов: без калибровки возможен ложный «найден». "
         "Проверяй результат вручную по ссылке.")
add("rubygems", "https://rubygems.org/profiles/{username}", control="dhh", confidence="medium", tags=["dev"])
add("cratesio", "https://crates.io/api/v1/users/{username}", control="alexcrichton", confidence="high", tags=["dev"])
add("devto", "https://dev.to/api/users/by_username", params={"url": "{username}"}, strategy="json_path",
    json_found={"path": "username", "op": "exists"}, control="ben", confidence="high", tags=["dev"])
add("codepen", "https://codepen.io/{username}", control="codepen", confidence="high", tags=["dev"])
add("jsfiddle", "https://jsfiddle.net/user/{username}/", confidence="medium", tags=["dev"])
add("replit", "https://replit.com/@{username}", control="replit", confidence="medium", tags=["dev"])
add("glitch", "https://glitch.com/@{username}", control="glitch", confidence="medium", tags=["dev"])
add("vercel", "https://vercel.com/{username}", confidence="medium", tags=["dev"])
add("codesandbox", "https://codesandbox.io/u/{username}", confidence="medium", tags=["dev"])
add("stackblitz", "https://stackblitz.com/@{username}", confidence="low", tags=["dev"])
add("leetcode", "https://leetcode.com/{username}/", control="leetcode", confidence="high", tags=["dev", "ctf"])
add("codeforces", "https://codeforces.com/profile/{username}", control="tourist", confidence="high",
    tags=["dev", "ctf"])
add("codewars", "https://www.codewars.com/users/{username}", control="codewars", confidence="high",
    tags=["dev", "ctf"])
add("hackerrank", "https://www.hackerrank.com/{username}", control="hackerrank", confidence="medium",
    tags=["dev", "ctf"])
add("tryhackme", "https://tryhackme.com/p/{username}", confidence="medium", tags=["ctf", "security"])
add("hackerone", "https://hackerone.com/{username}", control="hackerone", confidence="high", tags=["security"])
add("bugcrowd", "https://bugcrowd.com/{username}", control="bugcrowd", confidence="medium", tags=["security"])
add("exercism", "https://exercism.org/profiles/{username}", control="exercism", confidence="high", tags=["dev"])
add("freecodecamp", "https://www.freecodecamp.org/{username}", control="quincy", confidence="medium", tags=["dev"])
add("replit-2", "https://replit.com/@{username}", confidence="low", tags=["dev"], disabled=True,
    note="пример отключённой записи")
add("qiita", "https://qiita.com/{username}", control="qiita", confidence="medium", tags=["dev", "jp"])
add("zenn", "https://zenn.dev/{username}", control="zenn", confidence="medium", tags=["dev", "jp"])
add("keybase", "https://keybase.io/{username}", control="chris", confidence="medium", tags=["dev", "crypto"])
add("keybase-json", "https://keybase.io/_/api/1.0/user/lookup.json", params={"username": "{username}"},
    strategy="json_path", json_found={"path": "them.0.id", "op": "exists"}, confidence="medium",
    tags=["dev"], disabled=True, note="keybase уже проверяется через API в коде модуля")
add("telegram-preview", "https://t.me/s/{username}", strategy="message_exclude",
    not_found_msgs=["If you have Telegram, you can contact", "Preview channel"], confidence="low",
    tags=["messenger"], disabled=True, note="отдельная проверка каналов делается Telegram-модулем")
add("soundbetter", "https://soundbetter.com/profiles/{username}", confidence="low", tags=["music"])
add("splice", "https://splice.com/{username}", confidence="low", tags=["music"])
add("roblox", "https://users.roblox.com/v1/usernames/users", method="POST",
    json_body={"usernames": ["{username}"], "excludeBypassDisplayNameChanges": True},
    strategy="json_path", json_found={"path": "data.0.id", "op": "exists"}, control="Roblox",
    confidence="high", tags=["games"])
add("namemc", "https://namemc.com/profile/{username}", control="Notch", confidence="medium", tags=["games"])
add("osu", "https://osu.ppy.sh/users/{username}", control="peppy", confidence="high", tags=["games"])
add("chesscom", "https://www.chess.com/member/{username}", control="hikaru", confidence="high", tags=["games"])
add("lichess", "https://lichess.org/@{username}", control="lichess", confidence="high", tags=["games"])
add("steam", "https://steamcommunity.com/id/{username}", strategy="message_exclude",
    not_found_msgs=["The specified profile could not be found"], confidence="high", tags=["games"])
add("steamid", "https://steamcommunity.com/search/users/#text={username}", strategy="message_exclude",
    not_found_msgs=[], confidence="low", tags=["games"], disabled=True,
    note="поиск по Steam — только через их API/поиск, оставлено как заглушка")

# --- торговля и сервисы ---
add("ebay", "https://www.ebay.com/usr/{username}", control="ebay", confidence="medium", tags=["market"])
add("etsy", "https://www.etsy.com/shop/{username}", control="etsy", confidence="medium", tags=["market"])
add("paypal", "https://www.paypal.me/{username}", strategy="message_exclude",
    not_found_msgs=["This profile doesn't exist", "We can't find this profile"], confidence="low",
    tags=["money"])
add("cashapp", "https://cash.app/${username}", confidence="low", tags=["money"])
add("venmo", "https://account.venmo.com/u/{username}", confidence="low", tags=["money"])
add("calendly", "https://calendly.com/{username}", confidence="medium", tags=["work"])
add("duolingo", "https://www.duolingo.com/profile/{username}", control="duolingo", confidence="medium",
    tags=["edu"])
add("trello", "https://trello.com/{username}", confidence="low", tags=["work"])
add("shopify", "https://{username}.myshopify.com/", confidence="low", tags=["market"])
add("wordpress", "https://{username}.wordpress.com/", confidence="medium", tags=["blog"])
add("blogspot", "https://{username}.blogspot.com/", confidence="medium", tags=["blog"])
add("teletype", "https://teletype.in/@{username}", confidence="low", tags=["blog", "ru"])
add("vcru", "https://vc.ru/u/{username}", confidence="medium", tags=["blog", "ru"])
add("tenchat", "https://tenchat.ru/{username}", confidence="low", tags=["social", "ru"])
add("myspace", "https://myspace.com/{username}", confidence="low", tags=["social"])
add("quora", "https://www.quora.com/profile/{username}", confidence="low", tags=["social"],
    note="Quora блокирует ботов (403) — результат помечается как blocked")
add("xing", "https://www.xing.com/profile/{username}", confidence="low", tags=["work"])
add("crunchbase", "https://www.crunchbase.com/person/{username}", confidence="low", tags=["work"])
add("angelco", "https://angel.co/u/{username}", confidence="low", tags=["work"])


# ─────────────────────────────── EMAIL ───────────────────────────────
E = []


def eadd(name, url, **kw):
    """Добавляет источник в реестр email (см. add())."""
    global U
    saved = U
    U = E
    try:
        add(name, url, **kw)
    finally:
        U = saved


# Проверки существования аккаунта по email — публичные API сервисов (та же логика, что в holehe)
eadd("mozilla", "https://api.accounts.firefox.com/v1/account/status", method="POST",
     json_body={"email": "{email}"}, strategy="json_path", json_found={"path": "exists", "op": "equals", "value": True},
     confidence="high", kind="account", tags=["api"],
     note="Firefox Accounts: POST /v1/account/status → exists=true, если аккаунт есть")
eadd("microsoft", "https://login.microsoftonline.com/common/GetCredentialType", method="POST",
     json_body={"Username": "{email}", "IsOtherIdpSupported": True, "CheckPhones": False},
     strategy="json_path", json_found={"path": "IfExistsResult", "op": "equals", "value": 0},
     confidence="high", kind="account", tags=["api"],
     note="Microsoft GetCredentialType: IfExistsResult=0 значит аккаунт существует (1/5/6 — нет)")
eadd("twitter-email", "https://api.twitter.com/i/users/email_available.json", params={"email": "{email}"},
     strategy="json_path", json_found={"path": "valid", "op": "equals", "value": False},
     confidence="medium", kind="account", tags=["api"],
     note="Twitter: valid=false означает, что email уже занят (аккаунт есть)")
eadd("instagram-email", "https://www.instagram.com/accounts/account_recovery_send_ajax/", method="POST",
     payload={"email_or_username": "{email}"}, strategy="message_include",
     found_msgs=["We sent an email to", "email_sent"], confidence="medium", kind="account", tags=["api"],
     note="Instagram: запрос восстановления → «We sent an email to», если аккаунт есть")
eadd("pinterest-email", "https://www.pinterest.com/resource/EmailExistsResource/get/",
     params={"source_url": "/password/reset/", "data": '{"options":{"email":"{email}"}}'},
     strategy="json_path", json_found={"path": "resource_response.data", "op": "equals", "value": True},
     confidence="medium", kind="account", tags=["api"],
     note="Pinterest: resource_response.data=true, если email занят")
eadd("protonmail", "https://api.protonmail.ch/pks/lookup", params={"op": "index", "search": "{email}"},
     strategy="status_code", found_codes=[200], not_found_codes=[404], confidence="high",
     kind="account", tags=["api"],
     note="Proton Mail: публичный PGP-сервер отдаёт ключ только для существующих адресов")
eadd("wordpress-email", "https://public-api.wordpress.com/rest/v1.1/users/email/exists",
     params={"email": "{email}"}, strategy="json_path", json_found={"path": "exists", "op": "equals", "value": True},
     confidence="medium", kind="account", tags=["api"],
     note="WordPress.com: /users/email/exists → exists=true")
eadd("discord-email", "https://discord.com/api/v9/auth/register", method="POST",
     json_body={"email": "{email}", "username": "osintxprobe1", "password": "Qwerty!23456",
                "consent": True, "date_of_birth": "1995-01-01"},
     strategy="message_include", found_msgs=["EMAIL_ALREADY_REGISTERED"], confidence="medium",
     kind="account", tags=["api"], timeout=12, retries=0,
     note="Discord: ответ EMAIL_ALREADY_REGISTERED означает, что аккаунт с таким email существует "
          "(Cloudflare может блокировать — тогда статус blocked)")
eadd("duolingo-email", "https://www.duolingo.com/2017-06-30/users", params={"email": "{email}"},
     strategy="json_path", json_found={"path": "users.0.username", "op": "exists"},
     confidence="medium", kind="account", tags=["api"],
     note="Duolingo: публичный список пользователей по email (так делает holehe)")
eadd("spotify-email", "https://www.spotify.com/api/signup/validate",
     params={"fields": "email", "email": "{email}", "validate": "1"}, strategy="json_path",
     json_found={"path": "email", "op": "equals", "value": True}, confidence="low", kind="account", tags=["api"],
     note="Spotify: validate=true означает, что email свободен → инвертируем через калибровку (низкое доверие)")
eadd("tumblr-email", "https://www.tumblr.com/svc/account/register", method="POST",
     payload={"email": "{email}", "password": "Qwerty!23456"}, strategy="message_include",
     found_msgs=["already", "уже"], confidence="low", kind="account", tags=["api"])
eadd("gravatar-email", "https://gravatar.com/{email_hash}.json", strategy="json_path",
     json_found={"path": "entry", "op": "non_empty"}, confidence="high", kind="profile", tags=["api"],
     note="Gravatar: профиль по MD5-хешу адреса (WordPress-аккаунт)")
eadd("hunter-verify", "https://api.hunter.io/v2/email-verifier", confidence="low", kind="meta",
     tags=["api"], strategy="unsupported", disabled=True,
     note="Hunter.io проверяется в коде модуля (нужен ключ)")
eadd("slack-check", "https://slack.com/api/users.admin.invite", confidence="low", kind="account",
     strategy="unsupported", disabled=True,
     note="Требует токен/workspace — публичной проверки нет, оставлено как пример")



# ─────────────────────────────── PHONE ───────────────────────────────
P = []


def padd(name, url, **kw):
    global U
    saved = U
    U = P
    try:
        add(name, url, **kw)
    finally:
        U = saved


padd("telegram-phone", "https://t.me/+{phone_digits}", strategy="message_include",
     found_msgs=['tgme_page_title', 'tgme_page_photo'], confidence="low", kind="account",
     tags=["messenger"],
     note="Публичная страница t.me/+номер: если номер привязан к Telegram-аккаунту, "
          "показывается карточка профиля. Иначе Telegram показывает заглушку.")
padd("whatsapp-wa", "https://wa.me/{phone_digits}", strategy="message_exclude",
     not_found_msgs=["this link is invalid", "phone number shared via url is invalid"],
     confidence="low", kind="account", tags=["messenger"],
     note="wa.me отдаёт страницу-переадресацию; отсутствие явной ошибки — слабый признак (низкое доверие)")
padd("phone-dorks", "https://www.google.com/search?q=%22{phone_e164}%22", strategy="unsupported",
     confidence="low", kind="link", tags=["dork"], disabled=True,
     note="поисковые ссылки по номеру формируются в коде модуля (kind=link)")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for filename, entries, title in (("sites_username.json", U, "username"),
                                     ("sites_email.json", E, "email"),
                                     ("sites_phone.json", P, "phone")):
        payload = {
            "title": f"Реестр источников OsintX: {title}",
            "updated": "2026-09-20",
            "sites": sorted(entries, key=lambda s: s["name"]),
        }
        path = DATA / filename
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        active = [s for s in entries if not s.get("disabled")]
        print(f"{path}: всего {len(entries)}, активных {len(active)}")


if __name__ == "__main__":
    main()
