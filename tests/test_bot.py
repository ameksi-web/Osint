"""Тесты Telegram-бота: регистрация команд и разбор аргументов (сеть не нужна)."""
from __future__ import annotations

import pytest

telegram = pytest.importorskip("telegram", reason="python-telegram-bot не установлен")

from osintx.bot.run import build_application, _report_keyboard  # noqa: E402


def test_build_application_registers_all_commands():
    app = build_application("123456:FAKE_TOKEN_FOR_TESTS")
    handlers = app.handlers[0]
    commands = set()
    for handler in handlers:
        if hasattr(handler, "commands"):
            commands |= set(handler.commands)
    assert {"start", "search", "deep", "id", "password", "history", "stats", "sources",
            "graph", "watch", "dataset_search"} <= commands


def test_report_keyboard_has_download_buttons():
    markup = _report_keyboard("abc123", "user@example.com", deep=False)
    labels = [btn.text for row in markup.inline_keyboard for btn in row]
    callbacks = [btn.callback_data for row in markup.inline_keyboard for btn in row]
    assert any("HTML" in label for label in labels)
    assert any(cb.startswith("dl:json:abc123") for cb in callbacks)
    assert any(cb.startswith("graph:") for cb in callbacks)
