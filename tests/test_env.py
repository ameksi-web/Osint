"""Тесты разбора .env, мастера настройки и настроек."""
from __future__ import annotations

from pathlib import Path

from osintx.config import clean_env_value


def test_inline_comments_are_stripped():
    assert clean_env_value("15                     # таймаут одного запроса, сек") == "15"
    assert clean_env_value("http://proxy:8080   # прокси") == "http://proxy:8080"
    assert clean_env_value("0.0.0.0") == "0.0.0.0"


def test_quoted_values_keep_special_chars():
    assert clean_env_value('"socks5://user:pa#ss@host:1080"') == "socks5://user:pa#ss@host:1080"
    assert clean_env_value("'abc # не комментарий'") == "abc # не комментарий"
    assert clean_env_value("abc#def") == "abc#def"          # без пробела — часть значения
    assert clean_env_value("") == ""
    assert clean_env_value("      # свой User-Agent") == ""      # подсказка из шаблона
    assert clean_env_value("OSINTX_USER_AGENT=   # подсказка".split("=", 1)[1]) == ""


def test_load_dotenv_tolerates_placeholder_lines(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# комментарий\n"
        "OSINTX_PORT=8123           # порт\n"
        "OSINTX_HOST=127.0.0.1\n"
        "TELEGRAM_BOT_TOKEN=          # токен от @BotFather\n",
        encoding="utf-8")
    for key in ("OSINTX_PORT", "OSINTX_HOST", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    from osintx.config import _load_dotenv
    _load_dotenv(env_file)
    import os
    assert os.environ["OSINTX_PORT"] == "8123"          # комментарий не попал в значение
    assert os.environ["OSINTX_HOST"] == "127.0.0.1"
    assert os.environ["TELEGRAM_BOT_TOKEN"] == ""       # пустая подсказка — пустое значение


def test_wizard_writes_only_given_values(tmp_path: Path, monkeypatch):
    from argparse import Namespace
    from osintx import wizard

    project = tmp_path
    (project / ".env.example").write_text(
        "# шаблон\nTELEGRAM_BOT_TOKEN=    # токен\nOSINTX_TIMEOUT=15   # таймаут\n", encoding="utf-8")
    monkeypatch.setattr(wizard, "ENV_PATH", project / ".env")
    monkeypatch.setattr(wizard, "ENV_EXAMPLE", project / ".env.example")
    # проверку токена не выполняем (сети нет)
    monkeypatch.setattr(wizard, "_check_token", lambda token: _fake_check())

    code = wizard.run_wizard(Namespace(token="", no_input=True))
    assert code == 0
    assert (project / ".env").exists()
    content = (project / ".env").read_text(encoding="utf-8")
    assert "OSINTX_TIMEOUT=15   # таймаут" in content     # строки шаблона сохранены
    assert "TELEGRAM_BOT_TOKEN=" not in content or "TELEGRAM_BOT_TOKEN=\n" not in content


async def _fake_check():
    return True, "✅ Тестовый токен принят"


def test_data_dir_is_absolute_and_project_relative(monkeypatch):
    from osintx.config import Settings
    monkeypatch.setenv("OSINTX_DATA_DIR", ".osintx-data")
    monkeypatch.delenv("OSINTX_TIMEOUT", raising=False)
    settings = Settings()
    assert settings.data_dir.is_absolute()
    assert str(settings.data_dir).endswith(".osintx-data")
    assert settings.timeout == 15.0
