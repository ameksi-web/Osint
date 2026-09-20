#!/usr/bin/env bash
# OsintX — запуск Telegram-бота одной командой.
#
#   ./start_bot.sh              — установить зависимости (при необходимости) и запустить бота
#   ./start_bot.sh --check      — только проверить токен и настройки
#   ./start_bot.sh --setup      — открыть мастер настройки (.env)
#
# Работает на Linux и macOS. Для Windows используйте start_bot.bat
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "Не найден python3. Установите Python 3.10+ и повторите."; exit 1; }

if [ ! -d .venv ]; then
  echo "→ создаю виртуальное окружение .venv"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import telegram, httpx, fastapi" >/dev/null 2>&1; then
  echo "→ устанавливаю зависимости (первый запуск, ~1-2 минуты)"
  pip install -q --upgrade pip
  pip install -q -r requirements.txt
  pip install -q -e . >/dev/null 2>&1 || true
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "→ создан .env — сейчас поможем заполнить основные параметры"
  python bot.py --init || true
fi

case "${1:-}" in
  --setup) shift; exec python bot.py --init "$@" ;;
  --check) shift; exec python bot.py --check "$@" ;;
  *)       exec python bot.py "$@" ;;
esac
