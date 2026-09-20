@echo off
rem OsintX — запуск без установки консольной команды в PATH.
rem
rem Примеры:
rem     osintx.bat search durov
rem     osintx.bat tgauth
rem     osintx.bat usernames durov
rem     osintx.bat sources --import-wmn
rem
rem Скрипт сам находит python из .venv рядом с проектом; если его нет — берёт
rem системный python/py. Это то же самое, что команда `osintx` или `python -m osintx`.
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"
if exist "%PY%" goto run
set "PY=python"
where py >nul 2>nul
if %errorlevel%==0 set "PY=py"
:run
"%PY%" -m osintx %*
