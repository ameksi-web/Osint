"""Запуск OsintX без установки консольной команды:  python -m osintx <команда>.

Полезно на Windows, когда после установки `osintx` не находится в PATH
(«osintx не является внутренней или внешней командой»): эта форма работает из
каталога проекта всегда, если активировано виртуальное окружение.

Примеры:
    python -m osintx search durov
    python -m osintx tgauth
    python -m osintx usernames durov
    python -m osintx sources --import-wmn
"""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
