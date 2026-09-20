"""Тесты диагностики сети и планировщика без apscheduler.

Все проверки офлайн: используем заведомо разрешимые/неразрешимые имена и
подставные объекты вместо реального Application.
"""
from __future__ import annotations

import pytest

from osintx import netcheck


# ─────────────────────────── netcheck ───────────────────────────
def test_check_host_ok_for_localhost():
    result = netcheck.check_host("localhost", "локальный хост", port=80, timeout=2)
    assert result.status in ("ok", "tcp-fail")     # DNS должен сработать
    assert result.ips, "localhost обязан разрешаться"
    assert not result.dns_error


def test_check_host_dns_failure_is_reported_not_raised():
    result = netcheck.check_host("this-host-must-not-exist-osintx.invalid", timeout=2)
    assert result.status == "dns-fail"
    assert result.dns_error
    assert result.ips == []


def test_diagnose_returns_text_and_flag():
    text, ok = netcheck.diagnose((("pypi.org", "проверка DNS"),))
    assert "Проверка сети OsintX" in text
    assert isinstance(ok, bool)
    assert "pypi.org" in text


def test_diagnose_explains_dns_failure():
    text, ok = netcheck.diagnose((("nope-osintx-does-not-exist.invalid", "тестовый хост"),))
    assert ok is False
    assert "DNS не работает вовсе" in text
    assert "8.8.8.8" in text and "ipconfig /flushdns" in text


def test_diagnose_suggests_proxy_when_host_is_blocked(monkeypatch):
    blocked = netcheck.Result(host="api.telegram.org", note="Telegram",
                              ips=["149.154.167.220"], tcp_ok=True, tls_ok=False,
                              tls_error="SSLError: connection reset")
    monkeypatch.setattr(netcheck, "check_host", lambda host, note="", **kw: blocked)
    text, ok = netcheck.diagnose((("api.telegram.org", "Telegram"),))
    assert ok is False
    assert "блокировка провайдера" in text
    assert "TELEGRAM_PROXY=socks5://127.0.0.1:1080" in text


def test_explain_network_error_for_dns_and_timeouts():
    dns_text = netcheck.explain_network_error(
        "httpx.ConnectError: [Errno 11002] getaddrinfo failed")
    assert "DNS" in dns_text and "python bot.py --net" in dns_text
    assert "TELEGRAM_PROXY" in dns_text and "socks5://" in dns_text

    timeout_text = netcheck.explain_network_error("ReadTimeout: server did not answer")
    assert "таймаут" in timeout_text.lower()

    auth_text = netcheck.explain_network_error("Unauthorized")
    assert "токен" in auth_text.lower()


def test_proxies_from_env(monkeypatch):
    monkeypatch.setenv("TELEGRAM_PROXY", "socks5://127.0.0.1:1080")
    monkeypatch.delenv("OSINTX_PROXY", raising=False)
    found = netcheck.proxies_from_env()
    assert found.get("TELEGRAM_PROXY") == "socks5://127.0.0.1:1080"


# ─────────────────────── планировщик наблюдений ───────────────────────
class FakeJobQueue:
    def __init__(self):
        self.calls = []

    def run_repeating(self, callback, interval=None, first=None, name=""):
        self.calls.append({"callback": callback, "interval": interval, "name": name})
        return object()


class FakeAppNoJobQueue:
    """Имитация сборки python-telegram-bot БЕЗ apscheduler: свойство job_queue кидает RuntimeError."""

    def __init__(self):
        self.tasks = []

    @property
    def job_queue(self):
        raise RuntimeError("To use JobQueue, PTB must be installed via pip install "
                           "python-telegram-bot[job-queue]")

    def create_task(self, coro, name=""):
        coro.close()          # не выполняем цикл, только фиксируем факт планирования
        self.tasks.append(name)
        return object()


class FakeAppWithJobQueue:
    def __init__(self):
        self._jq = FakeJobQueue()

    @property
    def job_queue(self):
        return self._jq


def test_scheduler_falls_back_to_task_without_apscheduler():
    from osintx.bot.run import setup_watch_scheduler

    app = FakeAppNoJobQueue()
    mode = setup_watch_scheduler(app, 6)
    assert mode == "task"
    assert app.tasks == ["osintx-watch"]


class FakeAppJobQueueNone:
    """PTB без apscheduler: job_queue просто None (плюс предупреждение)."""

    def __init__(self):
        self.tasks = []

    @property
    def job_queue(self):
        return None

    def create_task(self, coro, name=""):
        coro.close()
        self.tasks.append(name)
        return object()


def test_scheduler_handles_none_job_queue(monkeypatch):
    from osintx.bot import run as bot_run

    app = FakeAppJobQueueNone()
    monkeypatch.setattr(bot_run, "_job_queue", lambda _app: None)
    assert bot_run.setup_watch_scheduler(app, 6) == "task"
    assert app.tasks == ["osintx-watch"]


def test_job_queue_ignored_when_apscheduler_missing(monkeypatch):
    import builtins

    from osintx.bot import run as bot_run

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("apscheduler"):
            raise ImportError("нет apscheduler")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert bot_run._job_queue(FakeAppWithJobQueue()) is None


def test_scheduler_prefers_job_queue_when_available():
    from osintx.bot.run import setup_watch_scheduler

    app = FakeAppWithJobQueue()
    mode = setup_watch_scheduler(app, 3)
    assert mode == "job_queue"
    assert len(app.job_queue.calls) == 1
    assert app.job_queue.calls[0]["name"] == "osintx-watch"


def test_scheduler_off_when_interval_disabled():
    from osintx.bot.run import setup_watch_scheduler

    app = FakeAppNoJobQueue()
    assert setup_watch_scheduler(app, 0) == "off"
    assert app.tasks == []


@pytest.mark.asyncio
async def test_notify_watch_results_sends_only_new_data():
    from osintx.bot.run import notify_watch_results

    sent = []

    class FakeBot:
        async def send_message(self, chat_id, text, parse_mode=None):
            sent.append((chat_id, text))

    results = [
        {"target": "a@example.com", "chat_id": 1, "new": ["github:profile:a"], "findings": 5},
        {"target": "b@example.com", "chat_id": 2, "new": [], "findings": 3},          # без изменений
        {"target": "c@example.com", "chat_id": 3, "first_time": True, "new": []},     # первая проверка
        {"target": "d@example.com", "chat_id": None, "new": ["x"]},                   # без чата
        {"target": "e@example.com", "chat_id": 5, "new": ["x"], "error": "boom"},     # ошибка
    ]
    await notify_watch_results(FakeBot(), results)
    assert len(sent) == 1
    assert sent[0][0] == 1
    assert "github:profile:a" in sent[0][1]


@pytest.mark.asyncio
async def test_watch_cycle_without_targets_is_silent(tmp_path, monkeypatch):
    from osintx.bot import run as bot_run
    from osintx.core.store import Store

    store = Store(tmp_path / "watch.db")
    monkeypatch.setattr(bot_run, "get_store", lambda: store)

    class FakeBot:
        async def send_message(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("не должно быть сообщений")

    assert await bot_run.run_watch_cycle(FakeBot()) == []
    store.close()


# ─────────────────────── конфигурация прокси бота ───────────────────────
def test_telegram_proxy_defaults_to_osintx_proxy(monkeypatch):
    from osintx.config import Settings

    monkeypatch.delenv("TELEGRAM_PROXY", raising=False)
    monkeypatch.setenv("OSINTX_PROXY", "socks5://10.0.0.1:1080")
    assert Settings().telegram_proxy == "socks5://10.0.0.1:1080"

    monkeypatch.setenv("TELEGRAM_PROXY", "http://127.0.0.1:8080")
    assert Settings().telegram_proxy == "http://127.0.0.1:8080"


def test_application_builds_with_proxy_without_network():
    pytest.importorskip("telegram")
    from osintx.bot.run import _socks_support, build_application

    if not _socks_support():
        pytest.skip("socksio не установлен — для SOCKS-прокси он обязателен")
    app = build_application("123456:FAKE", proxy="socks5://127.0.0.1:1080")
    assert app.bot.token == "123456:FAKE"
    app2 = build_application("123456:FAKE", proxy="http://127.0.0.1:8080")
    assert app2.bot.token == "123456:FAKE"


def test_proxy_hint_validates_scheme_and_socks_dependency(monkeypatch):
    from osintx.bot import run as bot_run

    ok, hint = bot_run.proxy_hint("")
    assert ok and hint == ""
    ok, hint = bot_run.proxy_hint("127.0.0.1:1080")          # схема не указана
    assert not ok and "http://" in hint
    ok, _ = bot_run.proxy_hint("http://127.0.0.1:8080")
    assert ok
    monkeypatch.setattr(bot_run, "_socks_support", lambda: False)
    ok, hint = bot_run.proxy_hint("socks5://127.0.0.1:1080")
    assert not ok and "socksio" in hint
    with pytest.raises(RuntimeError, match="socksio"):
        bot_run.build_application("123456:FAKE", proxy="socks5://127.0.0.1:1080")
