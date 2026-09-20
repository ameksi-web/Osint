# Быстрый запуск OsintX

Три сценария: **Telegram-бот**, **веб-приложение**, **поиск из терминала**.
Везде один движок и одни настройки (`.env`).

---

## 🤖 Telegram-бот

### Windows

```bat
:: 1. откройте папку проекта, дважды кликните start_bot.bat
::    (или в командной строке)
cd путь\к\Osint
start_bot.bat
```

При первом запуске скрипт сам создаст окружение, поставит зависимости и откроет мастер
настройки — вставьте токен бота и нажмите Enter.

### Linux / macOS

```bash
cd Osint
./start_bot.sh              # первый запуск: окружение + зависимости + мастер настройки
./start_bot.sh --check      # только проверить токен
./start_bot.sh --setup      # вернуться к мастеру (.env)

# или напрямую:
python bot.py --init        # мастер настройки
python bot.py               # запуск бота
python bot.py --check       # проверка токена
```

### Вручную (любая система)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # один раз
python bot.py --init               # мастер: токен бота, ключи, прокси → .env
python bot.py                      # запуск
```

Остановить: `Ctrl+C`.

### Где взять токен бота

1. Откройте Telegram → **@BotFather** → `/newbot`.
2. Имя бота (любое) и юзернейм (должен заканчиваться на `bot`, например `my_osint_x_bot`).
3. BotFather пришлёт строку вида `123456789:AAH...` — это `TELEGRAM_BOT_TOKEN`.
4. Напишите своему боту `/start` — он ответит вашим Telegram ID.
   Впишите его в `TELEGRAM_ALLOWED_IDS`, чтобы ботом не пользовались посторонние.

### Проверка, что всё в порядке

```bash
python bot.py --check      # или: osintx bot --check
```

* `✅ Токен рабочий. Бот: @...` — можно запускать `osintx bot`.
* `❌ Токен неверный или отозван` — скопируйте токен заново (без пробелов).
* `❌ Не удалось связаться с api.telegram.org` — сеть блокирует Telegram.
  Запускайте бота на своём компьютере/VPS или укажите прокси: `OSINTX_PROXY=socks5://user:pass@host:port` в `.env`.
  ⚠️ Из облачных песочниц с whitelist-прокси (только GitHub/PyPI) Telegram API недоступен —
  это нормально, бот должен работать на вашей машине.

### Чтобы бот не выключался

```bash
# Linux + systemd
sudo cp deploy/osintx-bot.service /etc/systemd/system/
sudo systemctl enable --now osintx-bot && journalctl -u osintx-bot -f

# Docker
cd deploy && docker compose up -d --build bot

# временно, без установки служб
screen -S osintx-bot -d -m bash -c "cd $(pwd) && .venv/bin/osintx bot"
```

---

## 🖥 Веб-приложение

```bash
osintx serve                 # http://localhost:8000
osintx serve --port 9000     # другой порт
```

На стартовой странице — форма поиска, живой прогресс, отчёты, история и загрузка своих баз.

## ⌨️ Поиск из терминала

```bash
osintx search ivan.petrov@example.com
osintx search torvalds --deep --variants --html-out torvalds.html
osintx search "Иван Петров" -m person --deep
osintx search example.com -m domain --verbose
osintx password 'qwerty123'          # проверка пароля по утечкам
osintx geo torvalds                   # где живёт: страна/город по публичным профилям
osintx changes torvalds               # как менялся ник/имя/био — с прошлых проверок
osintx usernames torvalds             # все ники цели: текущий и прежние (офлайн, из базы)
osintx search durov -m vk             # ВКонтакте: профиль, записи (+ VK_TOKEN для полного API)
osintx search durov -m max            # мессенджер MAX: канал/бот по нику
osintx sources --stats                # сколько площадок в реестре
osintx sources --import-wmn           # +≈700 площадок из WhatsMyName (доводит охват до ~1000)
osintx doctor                         # какие источники доступны из вашей сети
```

---

## Если что-то не работает

Первый шаг всегда один — диагностика сети:

```bash
python bot.py --net      # DNS, TCP, TLS для api.telegram.org, pypi.org, github.com + прокси
python bot.py --check    # реальная проверка токена через getMe
```


| Симптом | Причина и решение |
|---|---|
| `Не задан TELEGRAM_BOT_TOKEN` | запустите `osintx init` или впишите токен в `.env` вручную |
| Бот запустился, но не отвечает | напишите ему `/start`; проверьте, что запущен не второй экземпляр бота (два процесса с одним токеном конфликтуют) |
| `Unauthorized` в логах | токен неверный/отозван — перевыпустите у @BotFather (`/mybots` → API Token → Revoke) |
| `getaddrinfo failed`, «DNS» | не работает DNS: `python bot.py --net`, затем `nslookup api.telegram.org`, смена DNS на `8.8.8.8`/`1.1.1.1`, `ipconfig /flushdns` |
| `ConnectError` к api.telegram.org | DNS в порядке, но соединения блокируются: нужен прокси — `TELEGRAM_PROXY=socks5://127.0.0.1:1080` (и `pip install socksio`) |
| `pip` падает на `files.pythonhosted.org` | тот же DNS-сбой: смените DNS и повторите `pip install -r requirements.txt`; apscheduler для бота НЕ нужен |
| «Пробив» не находит данные | часть сайтов блокирует ботов: запустите с домашнего IP, добавьте прокси, смотрите блок «покрытие источников» в отчёте |
| Часть источников `error`/`blocked` | это не «не найдено», а отказ источника — так и должно быть видно в отчёте |
| Нужен числовой Telegram ID | заполните `TG_API_ID`/`TG_API_HASH` (my.telegram.org) и один раз выполните `osintx tgauth` |
| Не видно, в каких группах человек | это приватные данные Telegram: публично видны только чаты, где найдены его сообщения. Общие с вами группы покажет MTProto после `osintx tgauth` |
| Нужны прежние юзернеймы, а бот выключен | история лежит в локальной базе: `osintx usernames <цель>` (или `/usernames`), сеть не нужна |
| VK показывает капчу / «Проверяем, что вы не робот» | это `blocked`, а не «не найдено»: добавьте сервисный ключ `VK_TOKEN` в `.env` — модуль переключится на официальный API |
| `sources --import-wmn` не может скачать датасет | сеть блокирует raw.githubusercontent.com: скачайте `wmn-data.json` вручную и укажите путь — `osintx sources --import-wmn wmn-data.json` |
| Не находит людей в MAX | у личных профилей MAX нет публичных @username: модуль проверяет каналы/ботов и ссылки `max.ru/u/…`, остальное честно помечено `unsupported` |

## Что бот умеет после запуска

```
/search <цель>       полный поиск (email, логин, @telegram, телефон, домен, IP, ФИО, крипта)
/deep <цель>         глубокий поиск + варианты написания
/email /user /phone /tg /domain /ip /name <значение>   быстрый поиск одного типа
/geo <цель>          где живёт: страна/город по публичным профилям
/changes <цель>      как менялся ник/имя/био/город между проверками
/usernames <цель>    все юзернеймы цели: текущий и прежние (локальная база, офлайн)
/vk <ник>            ВКонтакте: профиль, город, записи, сообщества
/max <ник|ссылка>    мессенджер MAX: канал/бот по @нику, ссылка max.ru/u/…
/id <@user|телефон>  Telegram-разведка + «где писал»: активность, топ слов/хэштегов,
                     чаты с его сообщениями; с MTProto — общие группы (GetCommonChats)
/cancel              остановить текущий поиск
/watch add|list|check|rm <цель>   наблюдение: сообщает только о НОВЫХ находках
/settings /modules                настройки поиска и выбор модулей
/report <id>                      заново открыть отчёт из истории
/password <пароль>                проверка пароля по утечкам (k-anonymity)
/graph /history /stats /sources /dataset-search
```

Просто отправьте боту цель обычным сообщением — он начнёт поиск.

Кнопки под сводкой: **🔗 раскрутить дальше** (нажать найденную сущность и искать по ней),
**◀ ▶ листать находки**, **📄 HTML / 🧾 JSON / 📊 CSV**, **🧠 Глубже**, **📈 Граф**, **🌍 Веб-отчёт**.

Ограничения частоты — в `.env`: `TELEGRAM_SEARCH_COOLDOWN` (секунд между поисками),
`TELEGRAM_MAX_PER_HOUR` (поисков в час), `TELEGRAM_WATCH_INTERVAL` (часов между автопроверками
наблюдений, 0 — выключить).
