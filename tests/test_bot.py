"""Тесты Telegram-бота: регистрация команд, клавиатуры, пивоты, пагинация, лимиты.

Сеть не используется: проверяем чистую логику UI-слоя и хранилища настроек.
"""
from __future__ import annotations

import json

import pytest

telegram = pytest.importorskip("telegram", reason="python-telegram-bot не установлен")

from osintx.bot import ui  # noqa: E402
from osintx.bot.limits import RateLimiter  # noqa: E402
from osintx.bot.run import build_application  # noqa: E402
from osintx.bot.watch import diff, fingerprint  # noqa: E402
from osintx.core.models import Finding, ModuleResult, Report, SourceStatus  # noqa: E402


def _report(findings: int = 20) -> Report:
    report = Report(target="ivan.petrov@example.com", target_type="email")
    module = ModuleResult(module="email", target=report.target, duration_ms=1500)
    module.statuses.append(SourceStatus(source="dns", category="email", status="found", http_code=200))
    module.statuses.append(SourceStatus(source="t.me", category="email", status="blocked"))
    categories = ["email", "username", "domain", "ip", "telegram", "breach"]
    for index in range(findings):
        module.findings.append(Finding(
            source=f"src{index}", category=categories[index % len(categories)], kind="profile",
            title=f"Находка номер {index}", value=f"value{index}.example.com",
            confidence=["high", "medium", "low"][index % 3], url=f"https://example.org/{index}"))
    report.merge(module)
    report.dedupe()
    report.compute_summary()
    return report


# ─────────────────────────── регистрация команд ───────────────────────────
def test_build_application_registers_all_commands():
    app = build_application("123456:FAKE_TOKEN_FOR_TESTS")
    handlers = app.handlers[0]
    commands = set()
    for handler in handlers:
        if hasattr(handler, "commands"):
            commands |= set(handler.commands)
    expected = {"start", "help", "search", "deep", "id", "password", "history", "stats", "sources",
                "graph", "watch", "dataset_search", "settings", "modules", "report", "cancel"}
    assert expected <= commands, expected - commands
    # быстрые команды по типам данных
    assert {"email", "user", "phone", "tg", "domain", "ip", "name"} <= commands


# ─────────────────────────── сводка и пагинация ───────────────────────────
def test_summary_pagination_splits_and_numbers_pages():
    report = _report(findings=20)
    text0, page0, pages = ui.summary_text(report, page=0, per_page=8)
    assert pages == 3 and page0 == 0
    assert "Страница 1/3" in text0
    assert "Находок: <b>20</b>" in text0
    text2, page2, _ = ui.summary_text(report, page=2, per_page=8)
    assert "Страница 3/3" in text2 and page2 == 2
    # выход за границы не роняет
    _, clamped, _ = ui.summary_text(report, page=99, per_page=8)
    assert clamped == 2


def test_summary_warns_when_coverage_is_low():
    report = _report(findings=1)              # 1 источник из 2 недоступен → покрытие ровно 50%
    text, _, _ = ui.summary_text(report)
    assert "недоступна из вашей сети" not in text  # порог строго ниже 50%

    for name in ("x", "y"):
        report.modules[0].statuses.append(SourceStatus(source=name, category="email", status="error"))
    report.compute_summary()                  # 3 из 4 недоступны → 25%
    text, _, _ = ui.summary_text(report)
    assert "недоступна из вашей сети" in text
    assert "результат неполный" in text


def test_empty_report_gives_explanation_not_silence():
    report = _report(findings=0)
    text, _, _ = ui.summary_text(report)
    assert "Находок нет" in text and "покрытие источников" in text


# ─────────────────────────── пивоты ───────────────────────────
def test_pivot_targets_uses_confirmed_findings_only():
    report = _report(findings=12)
    pivots = ui.pivot_targets(report)
    assert pivots, "должны быть кнопки продолжения поиска"
    assert len(pivots) <= 3
    for label, category, value in pivots:
        assert category in ui.PIVOT_PRIORITY
        assert value and len(value.encode()) <= ui.CALLBACK_VALUE_LIMIT


def test_pivot_masks_personal_data_in_labels():
    report = Report(target="ivan.petrov@example.com", target_type="email")
    module = ModuleResult(module="email", target=report.target)
    module.findings.append(Finding(source="hibp", category="email", kind="breach",
                                   title="Утечка", value="ivan.petrov@example.com", confidence="high"))
    module.statuses.append(SourceStatus(source="hibp", category="breach", status="found"))
    report.merge(module)
    report.compute_summary()
    label, category, value = ui.pivot_targets(report)[0]
    assert "***" in label                 # в кнопке адрес замаскирован
    assert value == "ivan.petrov@example.com"   # для поиска берём настоящее значение


def test_callback_data_fits_telegram_limit():
    report = Report(target="very.long.username.for.testing@subdomain.example.com", target_type="email")
    module = ModuleResult(module="email", target=report.target)
    module.findings.append(Finding(
        source="x", category="email", kind="breach", title="t",
        value="very.long.username.for.testing@subdomain.example.com", confidence="high"))
    report.merge(module)
    report.compute_summary()
    markup = ui.report_keyboard(report)
    for row in markup.inline_keyboard:
        for button in row:
            if button.callback_data:
                assert len(button.callback_data.encode("utf-8")) <= 64, button.callback_data


# ─────────────────────────── клавиатуры ───────────────────────────
def test_report_keyboard_has_downloads_pivots_and_pages():
    report = _report(findings=20)
    markup = ui.report_keyboard(report, page=0, pages=3, web_url="https://osint.example.com")
    callbacks = [b.callback_data for row in markup.inline_keyboard for b in row if b.callback_data]
    urls = [b.url for row in markup.inline_keyboard for b in row if b.url]
    assert any(c.startswith("dl:json:") for c in callbacks)
    assert any(c.startswith("dl:html:") for c in callbacks)
    assert any(c.startswith("pivot:") for c in callbacks)
    assert any(c.startswith("page:") for c in callbacks)
    assert any(c.startswith("deep:") for c in callbacks)
    assert any(c.startswith("graph:") for c in callbacks)
    assert any(url and "/report/" in url for url in urls)


def test_modules_keyboard_marks_selection():
    markup = ui.modules_keyboard(["email", "ip"])
    labels = [b.text for row in markup.inline_keyboard for b in row]
    assert any(label.startswith("✅") and "email" in label for label in labels)
    assert sum(1 for label in labels if label.startswith("✅")) == 2
    callbacks = [b.callback_data for row in markup.inline_keyboard for b in row if b.callback_data]
    assert "run_modules" in callbacks and "mod_reset" in callbacks


def test_settings_keyboard_reflects_prefs():
    prefs = {"deep": True, "variants": False, "save": True, "use_keys": False, "modules": ["ip"]}
    markup = ui.settings_keyboard(prefs)
    labels = [b.text for row in markup.inline_keyboard for b in row]
    assert any("✅ Глубокий" in label for label in labels)
    assert any("⬜️ Варианты" in label for label in labels)
    assert "Глубокий режим: вкл" in ui.prefs_text(prefs)
    assert "ip" in ui.prefs_text(prefs)


# ─────────────────────────── память отчётов ───────────────────────────
def test_reports_memory_roundtrip():
    report = _report(findings=2)
    search_id = ui.remember(report)
    assert ui.recall(search_id) is report
    assert ui.recall("нет-такого") is None


# ─────────────────────────── наблюдение ───────────────────────────
def test_watch_fingerprint_and_diff():
    from osintx.core.models import Finding as F

    before = [F(source="github", category="username", kind="profile", title="t", value="user")]
    after = before + [F(source="t.me", category="telegram", kind="profile", title="t", value="user2")]
    old = fingerprint(before)
    new = fingerprint(after)
    assert diff(old, new) == ["t.me:profile:user2"]
    assert diff(None, new) == []          # первая проверка — «новых» нет
    assert diff(old, old) == []
    assert json.loads(old) == sorted(json.loads(old))


# ─────────────────────────── лимиты ───────────────────────────
def test_rate_limiter_blocks_after_limit():
    limiter = RateLimiter(cooldown=0, per_hour=2)
    assert limiter.check(1)[0] is True
    limiter.register(1)
    limiter.register(1)
    ok, message = limiter.check(1)
    assert ok is False and "Лимит" in message


def test_rate_limiter_cooldown():
    limiter = RateLimiter(cooldown=100, per_hour=100)
    limiter.register(7)
    ok, message = limiter.check(7)
    assert ok is False and "часто" in message
    assert limiter.cooldown_left(7) > 0
    limiter.reset(7)
    assert limiter.check(7)[0] is True


# ─────────────────────────── предпочтения в БД ───────────────────────────
def test_prefs_and_watch_roundtrip(tmp_path):
    from osintx.core.store import Store

    store = Store(tmp_path / "bot.db")
    assert store.get_prefs(42)["deep"] is False
    store.set_prefs(42, deep=True, modules=["email", "ip"])
    prefs = store.get_prefs(42)
    assert prefs["deep"] is True and prefs["modules"] == ["email", "ip"]

    store.watch_add("user@example.com", "email", chat_id=555)
    rows = store.watch_list(chat_id=555)
    assert rows and rows[0]["chat_id"] == 555
    assert len(store.watch_due()) == 1              # ни разу не проверялась → пора
    store.watch_update("user@example.com", fingerprint([]))
    assert store.watch_due() == []
    store.watch_remove_target("user@example.com")
    assert store.watch_list(chat_id=555) == []

    store.log_search(42, "user@example.com")
    assert store.recent_searches(42, 3600) == 1
    store.close()
