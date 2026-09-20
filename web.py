#!/usr/bin/env python3
"""OsintX — запуск веб-интерфейса:  python web.py [--host 0.0.0.0] [--port 8000]

Открывает приложение FastAPI из osintx.web.app (форма поиска, живой прогресс,
отчёты, история, загрузка своих баз).

Примеры:
    python web.py                 # http://localhost:8000
    python web.py --port 9000
    python web.py --reload        # автоперезагрузка при правках (для разработки)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="web.py", description="OsintX Web UI")
    parser.add_argument("--host", help="адрес прослушивания (по умолчанию OSINTX_HOST или 0.0.0.0)")
    parser.add_argument("--port", type=int, help="порт (по умолчанию OSINTX_PORT или 8000)")
    parser.add_argument("--reload", action="store_true", help="автоперезагрузка (разработка)")
    args = parser.parse_args(argv)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("Не установлен uvicorn. Выполните:  pip install -r requirements.txt")
        return 1

    from osintx.config import get_settings
    settings = get_settings()
    host = args.host or settings.host
    port = args.port or settings.port
    print(f"OsintX Web UI: http://{host}:{port}  (Ctrl+C — остановить)")
    import uvicorn as _uvicorn
    _uvicorn.run("osintx.web.app:app", host=host, port=port, reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
