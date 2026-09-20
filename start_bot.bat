@echo off
rem OsintX — запуск Telegram-бота одной командой (Windows).
rem   start_bot.bat            — установить зависимости (при необходимости) и запустить бота
rem   start_bot.bat --check    — только проверить токен и настройки
rem   start_bot.bat --setup    — открыть мастер настройки (.env)
setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Не найден python. Установите Python 3.10+ с python.org и включите "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist .venv (
  echo - создаю виртуальное окружение .venv
  python -m venv .venv || (echo Не удалось создать окружение & pause & exit /b 1)
)
call .venv\Scripts\activate.bat

python -c "import telegram, httpx, fastapi" >nul 2>&1
if errorlevel 1 (
  echo - устанавливаю зависимости ^(первый запуск^)
  python -m pip install -q --upgrade pip
  python -m pip install -q -r requirements.txt
)

if not exist .env (
  copy /y .env.example .env >nul
  echo - создан .env, запускаю мастер настройки
  python -m osintx.cli init
)

if "%~1"=="--setup" (
  python -m osintx.cli init %2 %3 %4 %5
  goto :done
)
if "%~1"=="--check" (
  python -m osintx.cli bot --check
  goto :done
)
python -m osintx.cli bot
:done
pause
