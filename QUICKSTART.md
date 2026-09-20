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
osintx doctor                        # какие источники доступны из вашей сети
```

---

## Если что-то не работает

| Симптом | Причина и решение |
|---|---|
| `Не задан TELEGRAM_BOT_TOKEN` | запустите `osintx init` или впишите токен в `.env` вручную |
| Бот запустился, но не отвечает | напишите ему `/start`; проверьте, что запущен не второй экземпляр бота (два процесса с одним токеном конфликтуют) |
| `Unauthorized` в логах | токен неверный/отозван — перевыпустите у @BotFather (`/mybots` → API Token → Revoke) |
| `ConnectError` к api.telegram.org | блокировка сети или нужен прокси в `OSINTX_PROXY` |
| «Пробив» не находит данные | часть сайтов блокирует ботов: запустите с домашнего IP, добавьте прокси, смотрите блок «покрытие источников» в отчёте |
| Часть источников `error`/`blocked` | это не «не найдено», а отказ источника — так и должно быть видно в отчёте |
| Нужен числовой Telegram ID | заполните `TG_API_ID`/`TG_API_HASH` (my.telegram.org) и один раз выполните `osintx tgauth` |

## Что бот умеет после запуска

```
/search <цель>       полный поиск (email, логин, @telegram, телефон, домен, IP, ФИО, крипта)
/deep <цель>         глубокий поиск + варианты написания
/email /user /phone /tg /domain /ip /name <значение>   быстрый поиск одного типа
/id <@user|телефон>  Telegram-разведка (с MTProto — ID, DC, поиск по сообщениям)
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
