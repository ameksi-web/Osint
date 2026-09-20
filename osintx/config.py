"""Конфигурация OsintX: .env + переменные окружения."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def clean_env_value(raw: str) -> str:
    """Разбирает значение из .env: кавычки и inline-комментарии.

    ``OSINTX_TIMEOUT=15   # таймаут`` → ``"15"``
    ``PROXY="socks5://user:pa#ss@host:1080"`` → значение целиком (решётка внутри кавычек)
    ``TOKEN=abc#def`` → ``"abc#def"`` (решётка без пробела перед ней — часть значения)
    """
    value = raw.strip()
    if not value or value.startswith("#"):
        return ""   # строка-подсказка из шаблона .env (например: "OSINTX_PROXY=   # http://...")
    if value[0] in "\"'":
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end != -1 else value[1:]
    for index, char in enumerate(value):
        if char == "#" and index > 0 and value[index - 1].isspace():
            return value[:index].strip()
    return value


def _load_dotenv(path: Path) -> None:
    """Минимальный парсер .env (без внешних зависимостей)."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw_value = line.partition("=")
        key, value = key.strip(), clean_env_value(raw_value)
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(PROJECT_ROOT / ".env")
_load_dotenv(Path.cwd() / ".env")


def _default_ca_bundle() -> str:
    """Системный набор корневых сертификатов.

    В корпоративных сетях и в песочницах TLS перехватывается прокси с собственным
    корневым сертификатом: он есть в системном бандле (как у curl), но отсутствует
    в certifi, который использует httpx по умолчанию. Поэтому, если системный
    бандл доступен, используем его — иначе поведение httpx по умолчанию.
    """
    env = os.environ.get("OSINTX_CA_BUNDLE", "").strip()
    if env:
        return env
    for candidate in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                      "/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem"):
        if Path(candidate).exists():
            return candidate
    return ""


def _resolve_data_dir() -> Path:
    """Каталог данных: абсолютный путь — как есть, относительный — от корня проекта."""
    raw = os.environ.get("OSINTX_DATA_DIR", "").strip()
    if not raw:
        return PROJECT_ROOT / ".osintx-data"
    path = Path(raw).expanduser()
    return path if path.is_absolute() else (PROJECT_ROOT / path)


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # общее
    data_dir: Path = field(default_factory=lambda: _resolve_data_dir())
    timeout: float = field(default_factory=lambda: float(os.environ.get("OSINTX_TIMEOUT", 15)))
    concurrency: int = field(default_factory=lambda: int(os.environ.get("OSINTX_CONCURRENCY", 40)))
    proxy: str = field(default_factory=lambda: os.environ.get("OSINTX_PROXY", "").strip())
    user_agent: str = field(default_factory=lambda: os.environ.get("OSINTX_USER_AGENT", "").strip())
    verify_tls: bool = field(default_factory=lambda: not _bool("OSINTX_INSECURE_TLS"))
    ca_bundle: str = field(default_factory=_default_ca_bundle)

    # web
    host: str = field(default_factory=lambda: os.environ.get("OSINTX_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.environ.get("OSINTX_PORT", 8000)))
    public_url: str = field(default_factory=lambda: os.environ.get("WEB_PUBLIC_URL", "").strip())

    # telegram bot
    bot_token: str = field(default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN", "").strip())
    allowed_ids: tuple[int, ...] = field(default_factory=lambda: tuple(
        int(x) for x in os.environ.get("TELEGRAM_ALLOWED_IDS", "").replace(" ", "").split(",") if x.strip().isdigit()))

    # telegram mtproto
    tg_api_id: int | None = field(default_factory=lambda: (
        int(os.environ["TG_API_ID"]) if os.environ.get("TG_API_ID", "").strip().isdigit() else None))
    tg_api_hash: str = field(default_factory=lambda: os.environ.get("TG_API_HASH", "").strip())
    tg_session: str = field(default_factory=lambda: os.environ.get("TG_SESSION", "osintx"))

    # ключи провайдеров
    keys: dict[str, str] = field(default_factory=lambda: {
        "hibp": os.environ.get("HIBP_API_KEY", "").strip(),
        "leakcheck": os.environ.get("LEAKCHECK_API_KEY", "").strip(),
        "dehashed": os.environ.get("DEHASHED_API_KEY", "").strip(),
        "dehashed_email": os.environ.get("DEHASHED_EMAIL", "").strip(),
        "intelx": os.environ.get("INTELX_API_KEY", "").strip(),
        "hunter": os.environ.get("HUNTER_API_KEY", "").strip(),
        "shodan": os.environ.get("SHODAN_API_KEY", "").strip(),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", "").strip(),
        "ipinfo": os.environ.get("IPINFO_TOKEN", "").strip(),
        "numverify": os.environ.get("NUMVERIFY_API_KEY", "").strip(),
        "veriphone": os.environ.get("VERIPHONE_API_KEY", "").strip(),
        "serpapi": os.environ.get("SERPAPI_KEY", "").strip(),
    })
    searxng_url: str = field(default_factory=lambda: os.environ.get("SEARXNG_URL", "").strip())

    def key(self, name: str) -> str:
        return self.keys.get(name, "")

    def has(self, name: str) -> bool:
        return bool(self.keys.get(name))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "osintx.db"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    def ensure_dirs(self) -> "Settings":
        for p in (self.data_dir, self.reports_dir, self.cache_dir):
            p.mkdir(parents=True, exist_ok=True)
        return self


_settings: Settings | None = None


def get_settings(reload: bool = False) -> Settings:
    global _settings
    if _settings is None or reload:
        _settings = Settings().ensure_dirs()
    return _settings
