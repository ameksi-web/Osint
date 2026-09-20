# OsintX — образ для веб-интерфейса и бота
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OSINTX_DATA_DIR=/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md ./
COPY osintx ./osintx
COPY tools ./tools
RUN pip install -r requirements.txt && pip install -e .

VOLUME ["/data"]
EXPOSE 8000

# по умолчанию — веб-интерфейс; для бота: docker compose run --rm bot
CMD ["python", "-m", "uvicorn", "osintx.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
