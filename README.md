# 🔎 OsintX

**Реальный OSINT-комбайн по открытым источникам.** Ищет человека и его цифровые следы по email,
логину, телефону, Telegram, домену, IP, ФИО и криптоадресам. Каждая находка подтверждена
доказательством (URL, HTTP-код, фрагмент ответа). Никаких выдуманных данных.

Работает в трёх режимах:

| Режим | Команда | Что это |
|---|---|---|
| 🖥 **Web-приложение** | `osintx serve` | Форма поиска, живые результаты по SSE, отчёты, история, загрузка своих баз |
| ⌨️ **CLI** | `osintx search <цель>` | Полноценный терминальный поиск с прогрессом и отчётами в 8 форматах |
| 🤖 **Telegram-бот** | `osintx bot` | Поиск прямо в Telegram: `/search`, `/deep`, `/id`, файлы отчётов кнопками |

---

## ⚖️ Главный принцип: честность результата

Большинство «OSINT-ботов» и «пробивов» показывают выдуманные данные. OsintX так не делает:

* **Находка появляется только при положительном доказательстве** — код ответа, строка в теле,
  значение в JSON, запись в DNS. В отчёте рядом с каждой находкой стоит поле `доказательство`.
* **Недоступный источник — это `error`/`blocked`, а не «не найдено».** Отчёт всегда содержит
  блок покрытия: сколько источников проверено, сколько ответило, какой процент покрытия.
* **У каждой находки есть уровень достоверности** (`high`/`medium`/`low`) и, при калибровке,
  пометка «источник врёт → нужна ручная проверка».
* **Автоматическая калибровка источников.** Перед проверкой цели движок проверяет сам источник на
  заведомо существующем и заведомо несуществующем логине. Если сайт отвечает «найдено» на всё
  (типичный пример — PyPI, который отдаёт HTTP 200 с челленджем на любой адрес), источник
  помечается ненадёжным, и его результаты понижаются до `low`.
* **Ссылки на поисковики — это `link`, а не «находка».** Dorks (Google/Yandex с операторами) выводятся
  отдельным типом с `confidence=low` и честной пометкой «ручная проверка».

## 🧩 Что умеет поиск

| Тип цели | Модуль | Реальные проверки |
|---|---|---|
| **email** | `email` | синтаксис, MX/A/NS/SPF/DMARC/DKIM/DNSSEC, почтовый провайдер по MX, одноразовые домены, Gravatar (профиль+аватар), регистрации на сервисах (12 API-проверок: Mozilla, Microsoft, Twitter, Instagram, Pinterest, Proton, WordPress, Discord, Duolingo, Tumblr, Spotify, Gravatar), SMTP RCPT (опция `--smtp`), Hunter.io (с ключом), вариации адреса |
| **email** | `breach` | XposedOrNot (без ключа), HIBP, LeakCheck, DeHashed, IntelX (с ключами), поиск по **вашим локальным базам**, прямые ссылки на сервисы проверки утечек |
| **логин** | `username` | **119 площадок** из реестра с калибровкой + официальные API: GitHub (профиль, репозитории, языки, публичный email), GitLab, Keybase (криптоподтверждённые связи!), Reddit, Hacker News, StackOverflow; выгрузка og-метаданных профилей; проверка вариантов написания |
| **Telegram** | `telegram` | `t.me/<name>`: тип (юзер/канал/группа/бот), имя, bio, число подписчиков, признак верификации и скама, аватар; публичный превью канала `t.me/s/`: посты, даты, извлечение email/телефонов/ссылок из постов; fragment.com (занят/аукцион/цена); **MTProto** (Telethon, с TG_API_ID/HASH): числовой ID, access_hash, DC, premium, общие чаты, bio целиком, **глобальный поиск по сообщениям** |
| **телефон** | `phone` | libphonenumber (страна, регион, оператор, тип линии, часовые пояса, форматы E.164), Numverify/Veriphone (с ключами), реестр веб-проверок, ссылки на мессенджеры |
| **домен** | `domain` | DNS (A/AAAA/MX/NS/SOA/TXT/CAA/CNAME/DNSSEC), RDAP (регистратор, даты, статусы, abuse-контакт), **Certificate Transparency (crt.sh)** — все поддомены, HackerTarget hostsearch, urlscan.io, Wayback Machine, security.txt/robots.txt/sitemap.xml, HTTP-заголовки и определение технологий, поиск email/телефонов/соцсетей на сайте, **перебор поддоменов по словарю** (до 250 имён, в глубоком режиме — весь список) с реальным DNS-резолвом, попытка AXFR (передача зоны), обратный IP-поиск (соседи по хостингу), dorks |
| **IP** | `ip` | гео и ASN (ipwho.is + ipapi.co — два независимых источника), **Shodan InternetDB** (открытые порты, CVE, hostnames — без ключа), RDAP (владелец блока, abuse), RIPE Stat (whois RIR), BGPView (префиксы, RIR), PTR, **Tor Onionoo** (релей/exit-нода), StopForumSpam, обратный IP-поиск, Shodan/VirusTotal/ipinfo (с ключами) |
| **ФИО** | `person` | транслитерация и генерация логинов из ФИО, **реальная проверка этих логинов** по 22 ключевым площадкам, кандидаты email + реальная DNS-проверка MX, Wikidata, Wikipedia (ru/en), **OpenSanctions** (санкционные и PEP-списки), genderize/nationalize (честно помечены как догадка), ссылки на реестры юрлиц (ЕГРЮЛ, rusprofile) |
| **крипта** | `crypto` | Bitcoin: blockstream.info (баланс, транзакции, число UTXO), Blockchair; Ethereum: Blockchair dashboard, Ethplorer (токены, счётчики) |

**Движение по цепочке.** Поиск не заканчивается на одном модуле: из email автоматически
извлекается локальная часть — она проверяется как логин по всем 119 площадкам и как Telegram-профиль,
а домен адреса уходит в доменный модуль (DNS, MX, SPF/DMARC, поддомены). Найден домен — тянутся
поддомены, IP и опубликованные на сайте адреса; найден логин — проверяется Telegram и связанные адреса.

```
$ osintx search torvalds@gmail.com
  email     → torvalds@gmail.com   20 источников
  domain    → gmail.com            10 источников   (MX, SPF, DMARC, поддомены)
  telegram  → torvalds              4 источника
  username  → torvalds            169 источников   (GitHub API: реальный профиль)
```

**Связывание данных (граф).** Каждый поиск строит граф сущностей и связей
(`email → аккаунт`, `логин → криптоподтверждённый профиль`, `домен → IP`, `телефон → Telegram`).
Граф хранится в SQLite и экспортируется в Mermaid/DOT.

---

## 🚀 Установка

```bash
git clone <repo> && cd Osint
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt      # или: pip install -e .
cp .env.example .env                 # опционально: ключи API, токен бота
```

Минимум для работы: `httpx`, `phonenumbers`, `dnspython`, `rich`, `fastapi`, `uvicorn`, `jinja2`.
Telethon нужен только для MTProto-модуля Telegram, `python-telegram-bot` — только для бота.

Проверка окружения:

```bash
osintx doctor
```

Команда покажет, что установлено, какие ключи заданы и **какие источники реально доступны из вашей сети**.

---

## 🖥 Веб-приложение

```bash
osintx serve                 # http://0.0.0.0:8000
osintx serve --port 9000 --reload
```

Что внутри:

* форма поиска с примерами, режимами (глубокий / варианты / SMTP / API-ключи);
* **живой прогресс по SSE** — видно, как находятся данные в реальном времени;
* страница отчёта с находками, доказательствами, сущностями, связями и покрытием источников;
* скачивание отчёта в JSON / HTML / Markdown / CSV / TXT / Mermaid;
* история поисков из SQLite;
* **загрузка внешних баз** (CSV/JSON/TXT) прямо в браузере → они попадают в FTS-индекс и
  проверяются автоматически;
* реестр источников `/sources` и Swagger `/docs`.

API:

```
POST /api/search              {"target": "...", "deep": false, "variants": false}
GET  /api/stream/{job_id}     прогресс (SSE)
GET  /api/report/{job_id}     результат (JSON)
GET  /report/{search_id}      HTML-страница отчёта
GET  /report/{search_id}/download?fmt=json|html|md|csv|txt|mermaid|dot
GET  /api/history, /api/stats, /api/sources, /api/graph, /api/meta, /api/health
POST /api/datasets            загрузка базы (multipart)
GET  /api/datasets/search?value=...
```

---

## ⌨️ CLI

```bash
# базовый поиск
osintx search ivan.petrov@example.com

# глубокий поиск с вариантами и отчётами во всех форматах
osintx search torvalds --deep --variants --json-out r.json --html-out r.html --md-out r.md

# конкретные модули и подробный вывод по каждому источнику
osintx search example.com -m domain --verbose

# поиск по ФИО
osintx search "Иван Петров" -m person --deep

# сохранить и открыть HTML-отчёт
osintx search @durov --html-out durov.html

# проверка пароля по утечкам (k-anonymity: наружу уходят только 5 символов хеша)
osintx password 'qwerty123'

# свои базы данных: CSV/JSON/TXT → локальный FTS-индекс
osintx dataset-import dump.csv --name mydump
osintx dataset-search user@example.com
osintx dataset-list

# история и база
osintx history -n 20
osintx show --target ivan.petrov@example.com
osintx stats
osintx graph torvalds --format mermaid

# наблюдение за целью: ищем новые находки между запусками
osintx watch add ivan.petrov@example.com
osintx watch check

# реестр источников
osintx sources --category username --tags social
osintx sources --stats
```

Полезные флаги: `--deep` (больше источников), `--variants` (варианты написания),
`--smtp` (проверка существования ящика), `--no-keys` (без API-ключей),
`--no-calibrate` (быстрее, но возможны ложные срабатывания),
`--max-sites N`, `--timeout`, `--out FILE --format html`.

---

## 🤖 Telegram-бот

### 1. Получите токен
Напишите [@BotFather](https://t.me/BotFather) → `/newbot` → имя и юзернейм бота.
Токен выглядит так: `123456789:AAH...`.

### 2. Впишите настройки в `.env`

```ini
TELEGRAM_BOT_TOKEN=123456789:AAH...
TELEGRAM_ALLOWED_IDS=          # свой ID (узнать: напишите боту /start — он ответит),
                               # пусто = бот открыт для всех
WEB_PUBLIC_URL=https://ваш-домен   # необязательно: кнопка «Открыть веб-отчёт»
```

### 3. Проверьте и запустите

```bash
osintx bot --check      # реальная проверка токена через getMe + отчёт о настройках
osintx bot              # запуск (Ctrl+C — остановить)
```

Если `--check` пишет «Не удалось связаться с api.telegram.org» — сеть блокирует Telegram
(частая ситуация в корпоративных сетях и песочницах): запускайте бота на своей машине/VPS
или укажите прокси: `OSINTX_PROXY=socks5://user:pass@host:port`.

### 4. Что умеет бот

| Команда | Что делает |
|---|---|
| любой текст или `/search <цель>` | полный поиск (email, логин, @telegram, телефон, домен, IP, ФИО, крипта) |
| `/deep <цель>` | глубокий поиск: больше источников, варианты написания |
| `/id <@username\|телефон>` | Telegram-разведка: карточка t.me, подписчики, посты, fragment; с MTProto — ID, DC, общие чаты, поиск по сообщениям |
| `/password <пароль>` | проверка пароля по утечкам (k-anonymity — сам пароль никуда не уходит, сообщение удаляется) |
| `/watch add <цель>` / `list` / `check` / `rm` | наблюдение: бот сам сравнивает находки между запусками и показывает **только новые** |
| `/graph <цель>` | схема связей (mermaid) |
| `/history`, `/stats`, `/sources` | история поисков, статистика базы, количество источников |
| `/dataset-search <значение>` | поиск по загруженным внешним базам |

Результат приходит сводкой с уровнями достоверности, а файлы отчёта (HTML/JSON/CSV) —
кнопками под сообщением. В группах бот отвечает только на упоминание.

### 5. Держать бота запущенным постоянно

```bash
# systemd (рекомендуется)
sudo cp deploy/osintx-bot.service /etc/systemd/system/
sudo systemctl enable --now osintx-bot && journalctl -u osintx-bot -f

# Docker
cd deploy && docker compose up -d --build bot

# или просто screen/tmux
screen -S osintx-bot -d -m bash -c "cd $(pwd) && .venv/bin/osintx bot"
```

Подробности и варианты (включая веб-сервис и MTProto-вход) — в `deploy/README.md`.

### 6. MTProto: числовой ID, DC и глобальный поиск по сообщениям

```bash
# 1) api_id/api_hash на https://my.telegram.org → API development tools
# 2) в .env: TG_API_ID=..., TG_API_HASH=...
osintx tgauth        # одноразовый вход: номер + код из Telegram
osintx bot           # после входа /id начнёт отдавать ID, DC и поиск по сообщениям
```

Без MTProto **числовой ID не вычисляется**: публично его взять негде, «генераторы ID по
юзернейму» — обман. OsintX честно помечает такие пункты как `unsupported`.

### 7. Как доработать бота под себя

Весь бот — один файл `osintx/bot/run.py`, каждая команда это функция `async def cmd_*(update, context)`,
которая регистрируется в `main()`:

```python
async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Пассивный IP: адрес и ASN без полного поиска."""
    ip = " ".join(context.args).strip()
    if not ip:
        await update.message.reply_text("Использование: /ip 8.8.8.8")
        return
    await run_search(update, ip)          # та же механика, что у /search

# в main() рядом с остальными:
app.add_handler(CommandHandler("ip", cmd_ip))
```

Полезные точки расширения:

* `run_search()` — общая логика с прогрессом, клавиатурой и файлами отчётов;
* `_report_keyboard()` — добавьте свои кнопки в `cmd_callback` (обработчик `data.startswith(...)`);
* `Progress` — редактируемое сообщение прогресса (порог обновления 1.6 с, чтобы не упереться в лимиты Telegram);
* `Engine().search(..., on_event=...)` — любые свои события можно вешать на тот же поток.

Свой бот на другом фреймворке (aiogram и т.п.) — просто вызывайте движок напрямую:

```python
from osintx.report import to_html
from osintx.engine import Engine

report = await Engine().search(target, deep=True, on_event=my_progress)
open("report.html", "w").write(to_html(report))
```

Для кнопки «Открыть в веб-приложении» задайте `WEB_PUBLIC_URL` и добавьте инлайн-кнопку
`WebAppInfo(url=...)` — бот уже передаёт ваш ID в `settings.public_url`.

## 🔑 Ключи API (все опциональные)

Базовые проверки работают без ключей. Ключи расширяют покрытие:

| Переменная | Сервис | Что даёт |
|---|---|---|
| `HIBP_API_KEY` | haveibeenpwned.com | точный список утечек по email и домены |
| `LEAKCHECK_API_KEY` | leakcheck.io | источники утечек и поля записей |
| `DEHASHED_API_KEY` + `DEHASHED_EMAIL` | dehashed.com | поля записей из дампов |
| `INTELX_API_KEY` | intelx.io | поиск по дампам и paste-сайтам |
| `HUNTER_API_KEY` | hunter.io | верификация адреса, поиск связанных адресов домена |
| `SHODAN_API_KEY` | shodan.io | полный Shodan (ОС, сервисы, баннеры) |
| `VIRUSTOTAL_API_KEY` | virustotal.com | репутация IP и доменов |
| `IPINFO_TOKEN` | ipinfo.io | расширенное гео и ASN |
| `NUMVERIFY_API_KEY` / `VERIPHONE_API_KEY` | — | оператор и тип номера |
| `SERPAPI_KEY` / `SEARXNG_URL` | serpapi / SearXNG | реальная поисковая выдача программно |
| `OSINTX_PROXY` | — | работа через прокси (`http://user:pass@host:port`, `socks5://...`) |

---

## 🧱 Расширение без правки кода

**Свой источник** — файл `$OSINTX_DATA_DIR/sites_user.json`:

```json
{
  "username": [
    {"name": "my-forum", "url": "https://forum.example.com/u/{username}",
     "strategy": "status_code", "found_codes": [200], "not_found_codes": [404],
     "confidence": "medium", "kind": "profile", "tags": ["forum"]}
  ]
}
```

Пользовательские источники объединяются с базовыми (по имени) и проверяются в каждом поиске.

**Системный реестр** собирается скриптом — списки источников лежат прямо в нём:

```bash
python tools/build_registry.py     # пересобирает osintx/data/sites_*.json
```

Стратегии проверки: `status_code`, `message_exclude`, `message_include`, `json_path` (с операторами
`exists/equals/not_equals/contains/empty`), `regex`, `redirect`, `unsupported`.
Поддерживаются `params`, `payload`, `json_body`, свои заголовки, таймауты и ретраи.

**Своя база данных** — `osintx dataset-import <файл>`; принимает CSV с заголовками (колонка
определяется автоматически или флагом `--column`), JSON-массивы и простые списки. Импортированные
значения ищутся в каждом поиске (источник `local-datasets`) и вручную: `dataset-search`.

---

## 📂 Структура проекта

```
osintx/
├── cli.py            # CLI (argparse + rich)
├── engine.py         # планирование модулей, запуск, сборка графа, история
├── report.py         # отчёты: txt/json/csv/md/html/mermaid/dot
├── config.py         # .env + настройки (+ системные CA-сертификаты)
├── tg_auth.py        # авторизация MTProto
├── core/
│   ├── http.py       # async HTTP: ретраи, лимиты на хост, распознавание блокировок
│   ├── models.py     # Finding / SourceStatus / Entity / Edge / Report
│   ├── registry.py   # загрузка реестра источников + пользовательские
│   ├── store.py      # SQLite: история, граф, здоровье источников, датасеты, watchlist
│   ├── variants.py   # вариации email/логинов/ФИО
│   └── utils.py      # определение типа цели, транслит, маскирование
├── modules/
│   ├── base.py       # Context, Module, SiteChecker, стратегии проверки, калибровка
│   ├── email.py      # DNS/провайдер/disposable/Gravatar/SMTP/регистрации
│   ├── username.py   # реестр площадок + GitHub/GitLab/Keybase/Reddit/HN/StackOverflow
│   ├── phone.py      # libphonenumber + онлайн-API
│   ├── telegram.py   # t.me, fragment, MTProto (ID/DC/поиск по сообщениям)
│   ├── domain.py     # DNS, RDAP, crt.sh, поддомены, веб-разведка
│   ├── ip.py         # гео, ASN, Shodan InternetDB, Tor, RDAP, BGP
│   ├── person.py     # ФИО → логины/адреса, Wikidata, OpenSanctions
│   ├── breach.py     # утечки + k-anonymity проверка паролей
│   └── crypto.py     # Bitcoin / Ethereum
├── web/              # FastAPI: app.py + шаблоны (index/report/sources)
├── bot/              # Telegram-бот (python-telegram-bot v21)
└── data/             # реестры источников, список одноразовых доменов
tools/build_registry.py
tests/                # 29 тестов: типы целей, стратегии, калибровка, отчёты, БД, движок
examples/             # пример готового HTML-отчёта
```

## 🗄 Хранение данных

Всё складывается в `$OSINTX_DATA_DIR` (по умолчанию `.osintx-data/`):

* `osintx.db` — SQLite (WAL): поиски, находки, сущности, связи, здоровье источников, watchlist,
  импортированные базы (FTS5), кэш;
* `reports/` — сохранённые отчёты;
* `uploads/` — загруженные внешние базы;
* `*.session` — MTProto-сессия Telegram (не публикуйте её!).

## ⚠️ Ограничения — честно

* **Публичные источники и только они.** Никаких «пробивов» по закрытым базам, доступа к чужим
  аккаунтам, обхода авторизации или использования украденных данных. Это законно и осознанно.
* **Сайты блокируют ботов.** Instagram, Twitter/X, LinkedIn, Cloudflare-защищённые сайты часто
  отдают капчу или 403. OsintX показывает это как `blocked`, а не как «не найдено». Решение:
  запуск с домашнего/мобильного IP или через `OSINTX_PROXY`.
* **Совпадение ≠ личность.** Занятый логин `ivan` не значит, что это тот самый Иван. Именно поэтому
  у каждой находки есть уровень достоверности и пометки о необходимости ручной проверки.
* **Числовой Telegram ID без MTProto недоступен.** Точка.
* **Данные устаревают.** Провайдеры меняют ответы; реестр источников нужно периодически
  перепроверять (`osintx doctor`, калибровка в каждом поиске).

## 🛡 Этика и закон

Используйте инструмент только в законных целях: проверка собственной цифровой экспозиции,
due diligence, журналистские расследования, корпоративная безопасность, CTF/обучение.
Обработка персональных данных в большинстве юрисдикций регулируется законом (GDPR, 152-ФЗ и др.) —
ответственность за использование лежит на вас. Не преследуйте людей.

## 🗺 Что можно добавить дальше

* Подключение SearXNG/SerpAPI для реальной поисковой выдачи программно (сейчас — ссылки-dorks).
* Интеграция с коллекциями утечек через свой импорт (форматы already поддерживаются).
* Расширение реестра источников до 500+ площадок по регионам (СНГ, Азия, Латинская Америка).
* Разбор изображений (EXIF, reverse image search) и метаданных документов.
* Периодический watchlist с уведомлениями в Telegram при новых находках.
* Экспорт графа в Neo4j/Gephi.

## 📄 Лицензия

MIT.
