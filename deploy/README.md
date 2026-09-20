# Развёртывание OsintX

## Вариант 1: systemd (Linux, без Docker)

```bash
sudo mkdir -p /opt/Osint && sudo chown "$USER" /opt/Osint
git clone <repo> /opt/Osint && cd /opt/Osint
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env && nano .env          # токен бота, ключи (опционально)

sudo cp deploy/osintx-bot.service /etc/systemd/system/
sudo cp deploy/osintx-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now osintx-bot osintx-web
journalctl -u osintx-bot -f                 # логи бота
```

Обновление: `cd /opt/Osint && git pull && .venv/bin/pip install -e . && sudo systemctl restart osintx-bot osintx-web`

## Вариант 2: Docker Compose

```bash
cd deploy
cp ../.env.example ../.env   # заполните токен бота
docker compose up -d --build web bot
docker compose logs -f bot
docker compose run --rm tgauth      # разовый вход в MTProto для /id
```

Данные (SQLite, отчёты, сессия Telegram, загруженные базы) живут в томе `osintx-data`.

## Вариант 3: быстрый «на час» — screen/tmux

```bash
screen -S osintx-bot -d -m bash -c "cd /opt/Osint && .venv/bin/osintx bot"
screen -S osintx-web -d -m bash -c "cd /opt/Osint && .venv/bin/osintx serve"
screen -ls
```

## Тонкости

* **Прокси.** Если сервер в стране, где часть источников недоступна, задайте `OSINTX_PROXY=socks5://user:pass@host:port` — трафик пойдёт через него.
* **Токен бота** — только в `.env` (файл в `.gitignore`), не коммитьте его.
* **MTProto-сессия** (`*.session`) равносильна входу в аккаунт: держите файл в закрытом каталоге и не публикуйте.
* **Доступ к боту.** Если бот публичный, обязательно заполните `TELEGRAM_ALLOWED_IDS` — иначе поиском сможет пользоваться любой.
