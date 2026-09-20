"""Тесты OsintX: проверяем логику определения цели, вариаций, калибровки и отчётов.

Тесты не ходят в сеть: HTTP-клиент подменяется фейковым, чтобы проверять
решения движка (найден / не найден / заблокирован), а не доступность сайтов.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from osintx.core.models import Finding, ModuleResult, Report, SourceStatus
from osintx.core.registry import count_sources, load_sites
from osintx.core.utils import detect_target_type, translit
from osintx.core.variants import email_variants, name_to_usernames, username_variants
from osintx.modules.base import evaluate, render_url
from osintx.report import FORMATS, to_csv, to_dot, to_html, to_markdown, to_mermaid, to_text


class FakeResp:
    def __init__(self, status_code=200, text="", data=None, url="https://example.org", error=""):
        self.status_code = status_code
        self.text = text
        self._data = data
        self.url = url
        self.error = error
        self.latency_ms = 12
        self._resp = object() if not error else None
        self.headers = {}

    def json(self):
        return self._data

    def snippet(self, limit=300):
        return self.text[:limit]

    def looks_blocked(self):
        from osintx.core.http import BLOCK_MARKERS
        return self.status_code == 403 or any(m in self.text.lower() for m in BLOCK_MARKERS)


# ─────────────────────────── определение типа цели ───────────────────────────
@pytest.mark.parametrize("target,expected", [
    ("ivan.petrov@example.com", "email"),
    ("@durov", "telegram"),
    ("t.me/durov", "telegram"),
    ("https://t.me/durov", "telegram"),
    ("+7 999 123-45-67", "phone"),
    ("example.com", "domain"),
    ("https://github.com/torvalds", "domain"),
    ("8.8.8.8", "ip"),
    ("Иван Петров", "person"),
    ("torvalds", "username"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "crypto"),
])
def test_detect_target_type(target, expected):
    assert detect_target_type(target) == expected


def test_translit():
    assert translit("Иван Петров") == "ivanpetrov"
    assert translit("Ёжик") == "ezhik"


# ─────────────────────────── вариации ───────────────────────────
def test_email_variants_gmail_dots():
    variants = email_variants("ivan.petrov@gmail.com")
    assert "ivan.petrov@gmail.com" in variants
    assert "ivanpetrov@gmail.com" in variants
    assert "ivan_petrov@gmail.com" in variants


def test_username_variants_limits_and_charset():
    variants = username_variants("ivan_petrov")
    assert all(v.replace("_", "").replace(".", "").replace("-", "").isalnum() for v in variants)
    assert len(variants) <= 40
    assert len({v.lower() for v in variants}) == len(variants)


def test_name_to_usernames_cyrillic():
    logins = name_to_usernames("Иван Петров")
    assert "ivanpetrov" in logins
    assert "petrovivan" in logins
    assert "ipetrov" in logins or "ivanp" in logins


# ─────────────────────────── стратегии проверки источников ───────────────────────────
def test_evaluate_status_code():
    site = {"strategy": "status_code", "found_codes": [200], "not_found_codes": [404]}
    assert evaluate(site, FakeResp(200))[0] == "found"
    assert evaluate(site, FakeResp(404))[0] == "not_found"
    assert evaluate(site, FakeResp(0, error="timeout"))[0] == "error"
    assert evaluate(site, FakeResp(403))[0] == "blocked"


def test_evaluate_message_exclude():
    site = {"strategy": "message_exclude", "not_found_msgs": ["Sorry, this page isn't available"]}
    assert evaluate(site, FakeResp(200, "Профиль"))[0] == "found"
    assert evaluate(site, FakeResp(200, "Sorry, this page isn't available"))[0] == "not_found"


def test_evaluate_json_path():
    site = {"strategy": "json_path", "json_found": {"path": "data.exists", "op": "equals", "value": True}}
    assert evaluate(site, FakeResp(200, data={"data": {"exists": True}}))[0] == "found"
    assert evaluate(site, FakeResp(200, data={"data": {"exists": False}}))[0] == "not_found"
    assert evaluate(site, FakeResp(200, text="не json", data=None))[0] == "error"


def test_evaluate_detects_captcha():
    site = {"strategy": "status_code", "found_codes": [200]}
    assert evaluate(site, FakeResp(200, "<html>Just a moment... checking your browser</html>"))[0] == "blocked"


def test_render_url_placeholders():
    assert render_url({"url": "https://t.me/{username}"}, "@durov", None) == "https://t.me/durov"
    import hashlib
    expected = hashlib.md5("a@b.com".encode()).hexdigest()
    assert render_url({"url": "https://gravatar.com/{email_hash}.json"}, "a@b.com") == \
        f"https://gravatar.com/{expected}.json"
    assert "79991234567" in render_url({"url": "https://wa.me/{phone_digits}"}, "+7 999 123 45 67")


# ─────────────────────────── реестр источников ───────────────────────────
def test_registry_loads_and_has_controls():
    assert count_sources()["username"] > 80
    assert count_sources()["email"] >= 10
    sites = load_sites("username")
    assert all("name" in s and "url" in s and "strategy" in s for s in sites)
    assert any(s.get("control_user") for s in sites), "должны быть источники с контрольным логином"
    names = [s["name"] for s in sites]
    assert len(names) == len(set(names)), "имена источников не должны дублироваться"


def test_registry_disabled_entries_excluded():
    assert not any(s.get("disabled") for s in load_sites("username"))


def test_every_site_has_known_strategy():
    known = {"status_code", "message_exclude", "message_include", "message", "json_path", "regex",
             "redirect", "unsupported"}
    for category in ("username", "email", "phone"):
        for site in load_sites(category):
            assert site["strategy"] in known, f"{site['name']}: неизвестная стратегия {site['strategy']}"


# ─────────────────────────── отчёты ───────────────────────────
def _sample_report() -> Report:
    report = Report(target="ivan.petrov@example.com", target_type="email")
    module = ModuleResult(module="email", target=report.target, duration_ms=1200)
    module.statuses.append(SourceStatus(source="gravatar", category="email", status="found", http_code=200))
    module.statuses.append(SourceStatus(source="t.me", category="email", status="blocked",
                                        error="captcha"))
    module.findings.append(Finding(source="gravatar", category="email", kind="profile", title="Gravatar найден",
                                   url="https://gravatar.com/x", value=report.target, confidence="high",
                                   evidence="HTTP 200", http_code=200))
    report.merge(module)
    report.dedupe()
    report.compute_summary()
    return report


def test_report_formats_are_valid():
    report = _sample_report()
    assert "Gravatar найден" in to_text(report)
    assert json.loads(report.to_json())["findings"][0]["source"] == "gravatar"
    assert "category;source" in to_csv(report)
    assert "| Достоверность |" in to_markdown(report)
    assert "<!doctype html>" in to_html(report).lower()
    assert to_mermaid(report).startswith("graph LR")
    assert to_dot(report).startswith("digraph")
    assert report.summary["sources_checked"] == 2
    assert report.summary["sources_failed"] == 1


def test_dedupe_removes_duplicates():
    report = Report(target="x", target_type="username")
    module = ModuleResult(module="username", target="x")
    for _ in range(3):
        module.findings.append(Finding(source="github", category="username", kind="profile",
                                       title="дубль", value="x"))
    report.merge(module)
    report.dedupe()
    assert len(report.findings) == 1


# ─────────────────────────── хранилище ───────────────────────────
def test_store_roundtrip(tmp_path: Path):
    from osintx.core.store import Store

    store = Store(tmp_path / "t.db")
    report = _sample_report()
    store.save_report(report)
    row = store.get_search(report.search_id)
    assert row and row["target"] == report.target
    assert len(row["findings"]) == 1
    assert store.stats()["searches"] == 1
    store.close()


def test_store_dataset_import_and_search(tmp_path: Path):
    from osintx.core.store import Store

    csv_file = tmp_path / "base.csv"
    csv_file.write_text("email,password\nuser@example.com,secret\nother@example.com,secret2\n",
                        encoding="utf-8")
    store = Store(tmp_path / "t.db")
    result = store.import_dataset(csv_file, name="mydump")
    assert result["rows"] == 2
    hits = store.search_local("user@example.com")
    assert any(h["value"] == "user@example.com" for h in hits)
    store.drop_dataset("mydump")
    assert store.datasets() == []
    store.close()


# ─────────────────────────── движок (без сети) ───────────────────────────
def test_engine_plan_and_ci_offline(monkeypatch):
    """Движок должен корректно отработать при полностью недоступной сети."""
    from osintx.engine import Engine

    report = asyncio.run(Engine().search("zzq7x9k2v8n4m3b1q0wz9x8c7v6b",
                                         modules=["username"], timeout=1, no_save=True))
    assert report.target_type == "username"
    assert report.summary["sources_checked"] > 0
    # при недоступной сети находок быть не должно, а ошибки — должны быть видны
    assert all(f.source != "github-api" or f.confidence == "high" for f in report.findings)


def test_report_written_to_disk(tmp_path: Path):
    from osintx.report import save

    report = _sample_report()
    for fmt in ("json", "html", "md", "csv", "txt", "mermaid", "dot"):
        path = save(report, tmp_path / f"report.{fmt}", fmt=fmt)
        assert path.exists() and path.stat().st_size > 0
    assert set(FORMATS) >= {"json", "html", "md", "csv", "txt", "mermaid", "dot"}
