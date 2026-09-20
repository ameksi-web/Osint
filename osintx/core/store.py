"""Хранилище OsintX — SQLite: история поисков, находки, граф сущностей,
здоровье источников, watchlist, локальные наборы данных (внешние базы) и кэш.

Это и есть «своя база данных» проекта: каждый поиск навсегда остаётся в
SQLite, сущности связываются в граф, а внешние датасеты (CSV/JSON/TXT с
email, телефонами, логинами) можно загрузить в полнотекстовый индекс FTS5
и искать по ним офлайн.
"""
from __future__ import annotations

import csv
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from ..config import get_settings
from .models import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS searches (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    started_at TEXT,
    duration_ms INTEGER,
    findings INTEGER,
    coverage REAL,
    risk INTEGER,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id TEXT,
    source TEXT, category TEXT, kind TEXT, title TEXT, url TEXT, value TEXT,
    confidence TEXT, data_json TEXT, created_at TEXT,
    FOREIGN KEY(search_id) REFERENCES searches(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_search ON findings(search_id);
CREATE INDEX IF NOT EXISTS idx_findings_value ON findings(value);
CREATE TABLE IF NOT EXISTS entities (
    type TEXT, value TEXT, first_seen TEXT, last_seen TEXT, meta_json TEXT,
    PRIMARY KEY (type, value)
);
CREATE TABLE IF NOT EXISTS edges (
    src TEXT, dst TEXT, relation TEXT, weight REAL, evidence TEXT, created_at TEXT,
    PRIMARY KEY (src, dst, relation)
);
CREATE TABLE IF NOT EXISTS site_health (
    site TEXT, category TEXT, status TEXT, checked_at TEXT,
    http_code INTEGER, notes TEXT,
    PRIMARY KEY (site, category)
);
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT, target_type TEXT, created_at TEXT, last_check TEXT, last_fingerprint TEXT, note TEXT,
    UNIQUE(target, target_type)
);
CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE, kind TEXT, rows INTEGER, source TEXT, imported_at TEXT
);
CREATE TABLE IF NOT EXISTS index_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset TEXT, kind TEXT, value TEXT, extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_index_value ON index_entries(value);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY, value TEXT, created_at REAL, ttl REAL
);
CREATE TABLE IF NOT EXISTS profile_snapshots (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  target      TEXT NOT NULL,
  source      TEXT NOT NULL,
  field       TEXT NOT NULL,
  value       TEXT NOT NULL,
  url         TEXT DEFAULT '',
  search_id   TEXT,
  observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_target ON profile_snapshots(target, field, source);
CREATE TABLE IF NOT EXISTS user_prefs (
    user_id INTEGER PRIMARY KEY,
    deep INTEGER DEFAULT 0,
    variants INTEGER DEFAULT 0,
    save INTEGER DEFAULT 1,
    use_keys INTEGER DEFAULT 1,
    modules TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS search_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, target TEXT, at REAL
);
CREATE INDEX IF NOT EXISTS idx_activity_user ON search_activity(user_id, at);
CREATE VIRTUAL TABLE IF NOT EXISTS index_fts USING fts5(
    value, extra, dataset, kind, tokenize='unicode61'
);
"""


def _iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    def __init__(self, path: Path | str | None = None):
        settings = get_settings()
        self.path = Path(path) if path else settings.db_path
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:  # pragma: no cover - read-only fs
            pass
        self.conn.commit()

    def _migrate(self) -> None:
        """Догоняющие миграции для баз, созданных прошлыми версиями."""
        with self._lock:
            columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(watchlist)").fetchall()}
            for name, ddl in (("chat_id", "ALTER TABLE watchlist ADD COLUMN chat_id INTEGER"),
                              ("interval_hours", "ALTER TABLE watchlist ADD COLUMN interval_hours REAL")):
                if name not in columns:
                    try:
                        self.conn.execute(ddl)
                    except sqlite3.Error:  # pragma: no cover
                        pass
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ───────────────────────── поиски и находки ─────────────────────────
    def save_report(self, report: Report) -> str:
        report.compute_summary()
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO searches (id,target,target_type,started_at,duration_ms,findings,coverage,risk,summary_json)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (report.search_id, report.target, report.target_type, report.started_at, report.duration_ms,
                 len(report.findings), report.summary.get("coverage", 0), report.summary.get("risk_score", 0),
                 json.dumps(report.summary, ensure_ascii=False)),
            )
            self.conn.execute("DELETE FROM findings WHERE search_id=?", (report.search_id,))
            for f in report.findings:
                self.conn.execute(
                    "INSERT INTO findings (search_id,source,category,kind,title,url,value,confidence,data_json,created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (report.search_id, f.source, f.category, f.kind, f.title, f.url, f.value, f.confidence,
                     json.dumps(f.data, ensure_ascii=False), f.created_at))
            now = _iso()
            for e in report.entities:
                self.conn.execute(
                    "INSERT INTO entities (type,value,first_seen,last_seen,meta_json) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(type,value) DO UPDATE SET last_seen=excluded.last_seen,"
                    " meta_json=excluded.meta_json",
                    (e.type, e.value, now, now, json.dumps(e.meta, ensure_ascii=False)))
            for edge in report.edges:
                self.conn.execute(
                    "INSERT OR REPLACE INTO edges (src,dst,relation,weight,evidence,created_at) VALUES (?,?,?,?,?,?)",
                    (edge.src, edge.dst, edge.relation, edge.weight, edge.evidence, now))
            self.conn.commit()
        return report.search_id

    def history(self, limit: int = 50, target: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if target:
                rows = self.conn.execute(
                    "SELECT * FROM searches WHERE target LIKE ? ORDER BY started_at DESC LIMIT ?",
                    (f"%{target}%", limit)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM searches ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_search(self, search_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM searches WHERE id=?", (search_id,)).fetchone()
            if not row:
                return None
            findings = [dict(r) for r in self.conn.execute(
                "SELECT * FROM findings WHERE search_id=? ORDER BY confidence, category", (search_id,)).fetchall()]
        data = dict(row)
        data["findings"] = findings
        return data

    def get_search_by_target(self, target: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM searches WHERE target=? ORDER BY started_at DESC LIMIT 1", (target,)).fetchone()
        return self.get_search(row["id"]) if row else None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            searches = self.conn.execute("SELECT COUNT(*) c FROM searches").fetchone()["c"]
            findings = self.conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
            entities = self.conn.execute("SELECT COUNT(*) c FROM entities").fetchone()["c"]
            edges = self.conn.execute("SELECT COUNT(*) c FROM edges").fetchone()["c"]
            by_cat = {r["category"]: r["c"] for r in self.conn.execute(
                "SELECT category, COUNT(*) c FROM findings GROUP BY category").fetchall()}
            by_type = {r["type"]: r["c"] for r in self.conn.execute(
                "SELECT type, COUNT(*) c FROM entities GROUP BY type ORDER BY c DESC").fetchall()}
            datasets = [dict(r) for r in self.conn.execute("SELECT * FROM datasets ORDER BY imported_at DESC").fetchall()]
        return {"searches": searches, "findings": findings, "entities": entities, "edges": edges,
                "findings_by_category": by_cat, "entities_by_type": by_type, "datasets": datasets,
                "db_path": str(self.path)}

    # ───────────────────────── граф сущностей ─────────────────────────
    def entity_neighbours(self, etype: str, value: str, depth: int = 1) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        frontier = [f"{etype}:{value}"]
        seen = set(frontier)
        for _ in range(max(1, depth)):
            nxt: list[str] = []
            for node in frontier:
                with self._lock:
                    rows = self.conn.execute(
                        "SELECT * FROM edges WHERE src=? OR dst=?", (node, node)).fetchall()
                for r in rows:
                    edges.append(dict(r))
                    for other in (r["src"], r["dst"]):
                        if other not in seen:
                            seen.add(other)
                            nxt.append(other)
            frontier = nxt
        for node in seen:
            t, _, v = node.partition(":")
            nodes[node] = {"id": node, "type": t, "value": v}
        return {"nodes": list(nodes.values()), "edges": edges}

    def graph(self, limit: int = 400) -> dict[str, Any]:
        with self._lock:
            edges = [dict(r) for r in self.conn.execute(
                "SELECT * FROM edges ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]
            entities = [dict(r) for r in self.conn.execute(
                "SELECT * FROM entities ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()]
        return {"edges": edges, "entities": entities}

    # ───────────────────────── здоровье источников ─────────────────────────
    def save_site_health(self, site: str, category: str, status: str, http_code: int | None = None,
                         notes: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO site_health (site,category,status,checked_at,http_code,notes)"
                " VALUES (?,?,?,?,?,?)", (site, category, status, _iso(), http_code, notes))
            self.conn.commit()

    def site_health(self, category: str | None = None) -> dict[str, dict[str, Any]]:
        with self._lock:
            if category:
                rows = self.conn.execute("SELECT * FROM site_health WHERE category=?", (category,)).fetchall()
            else:
                rows = self.conn.execute("SELECT * FROM site_health").fetchall()
        return {f"{r['category']}:{r['site']}": dict(r) for r in rows}

    # ───────────────────────── watchlist ─────────────────────────
    def watch_add(self, target: str, target_type: str, note: str = "", chat_id: int | None = None,
                  interval_hours: float | None = None) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO watchlist (target,target_type,created_at,note,chat_id,interval_hours)"
                " VALUES (?,?,?,?,?,?) ON CONFLICT(target,target_type) DO UPDATE SET"
                " note=excluded.note, chat_id=COALESCE(excluded.chat_id, watchlist.chat_id),"
                " interval_hours=COALESCE(excluded.interval_hours, watchlist.interval_hours)",
                (target, target_type, _iso(), note, chat_id, interval_hours))
            self.conn.commit()
            return cur.lastrowid or 0

    def watch_list(self, chat_id: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if chat_id is None:
                rows = self.conn.execute("SELECT * FROM watchlist ORDER BY created_at DESC").fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM watchlist WHERE chat_id=? OR chat_id IS NULL ORDER BY created_at DESC",
                    (chat_id,)).fetchall()
        return [dict(r) for r in rows]

    def watch_remove_target(self, target: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM watchlist WHERE target=?", (target,))
            self.conn.commit()

    def watch_due(self, now: float | None = None) -> list[dict[str, Any]]:
        """Цели, которые пора перепроверить (по интервалу из записи)."""
        import calendar
        import time as _time
        now = now or _time.time()
        out = []
        for row in self.watch_list():
            interval = row.get("interval_hours") or 24.0
            last = row.get("last_check")
            if not last:
                out.append(row)
                continue
            try:
                stamp = calendar.timegm(_time.strptime(last, "%Y-%m-%dT%H:%M:%SZ"))
            except ValueError:
                out.append(row)
                continue
            if now - stamp >= interval * 3600:
                out.append(row)
        return out

    # ───────────────────────── предпочтения пользователей ─────────────────────────
    def get_prefs(self, user_id: int) -> dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM user_prefs WHERE user_id=?", (user_id,)).fetchone()
        prefs = {"deep": False, "variants": False, "save": True, "use_keys": True, "modules": None}
        if row:
            prefs.update({"deep": bool(row["deep"]), "variants": bool(row["variants"]),
                          "save": bool(row["save"]), "use_keys": bool(row["use_keys"]),
                          "modules": json.loads(row["modules"]) if row["modules"] else None})
        return prefs

    def set_prefs(self, user_id: int, **changes: Any) -> dict[str, Any]:
        prefs = self.get_prefs(user_id)
        prefs.update({k: v for k, v in changes.items() if k in prefs})
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO user_prefs (user_id,deep,variants,save,use_keys,modules,updated_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (user_id, int(prefs["deep"]), int(prefs["variants"]), int(prefs["save"]),
                 int(prefs["use_keys"]),
                 json.dumps(prefs["modules"], ensure_ascii=False) if prefs["modules"] else None, _iso()))
            self.conn.commit()
        return prefs

    # ───────────────────────── активность и квоты ─────────────────────────
    def log_search(self, user_id: int, target: str) -> None:
        import time as _time
        with self._lock:
            self.conn.execute("INSERT INTO search_activity (user_id,target,at) VALUES (?,?,?)",
                              (user_id, target, _time.time()))
            self.conn.commit()

    def recent_searches(self, user_id: int, seconds: float) -> int:
        import time as _time
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) c FROM search_activity WHERE user_id=? AND at>=?",
                                    (user_id, _time.time() - seconds)).fetchone()
        return int(row["c"]) if row else 0

    def top_targets(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT user_id, target, COUNT(*) c FROM search_activity GROUP BY target ORDER BY c DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def watch_update(self, target: str, fingerprint: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE watchlist SET last_check=?, last_fingerprint=? WHERE target=?",
                              (_iso(), fingerprint, target))
            self.conn.commit()

    def watch_remove(self, target: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM watchlist WHERE target=?", (target,))
            self.conn.commit()

    # ───────────────────────── история изменений профиля ─────────────────────────
    def record_snapshots(self, target: str, snapshots: list[dict[str, str]],
                         search_id: str | None = None) -> int:
        """Запоминает текущие значения публичных полей цели.

        Дубликаты не пишутся: новая запись появляется только если значение изменилось
        (или это первое наблюдение). Так накапливается реальная история изменений.
        """
        written = 0
        with self._lock:
            for item in snapshots:
                source = str(item.get("source") or "?")[:80]
                field_name = str(item.get("field") or "?")[:40]
                value = str(item.get("value") or "").strip()
                if not value:
                    continue
                row = self.conn.execute(
                    "SELECT value FROM profile_snapshots WHERE target=? AND source=? AND field=?"
                    " ORDER BY id DESC LIMIT 1", (target, source, field_name)).fetchone()
                if row and row["value"] == value:
                    continue
                self.conn.execute(
                    "INSERT INTO profile_snapshots (target,source,field,value,url,search_id,observed_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (target, source, field_name, value[:1000], str(item.get("url") or "")[:500],
                     search_id, _iso()))
                written += 1
            self.conn.commit()
        return written

    def profile_changes(self, target: str, limit: int = 50) -> list[dict[str, Any]]:
        """История изменений: что и когда менялось у цели (ник, имя, био, город...)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT source,field,value,url,observed_at FROM profile_snapshots"
                " WHERE target=? ORDER BY id", (target,)).fetchall()
        previous: dict[tuple[str, str], dict[str, Any]] = {}
        changes: list[dict[str, Any]] = []
        for row in rows:
            key = (row["source"], row["field"])
            old = previous.get(key)
            if old and old["value"] != row["value"]:
                changes.append({"source": row["source"], "field": row["field"],
                                "old": old["value"], "new": row["value"],
                                "changed_at": row["observed_at"], "url": row["url"]})
            previous[key] = {"value": row["value"], "url": row["url"], "at": row["observed_at"]}
        return changes[-limit:][::-1]

    def snapshot_stats(self, target: str) -> dict[str, Any]:
        """Сколько наблюдений и по каким полям накоплено по цели."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT source,field,COUNT(*) c,MIN(observed_at) first,MAX(observed_at) last"
                " FROM profile_snapshots WHERE target=? GROUP BY source,field", (target,)).fetchall()
        return {"fields": [dict(r) for r in rows], "total": sum(int(r["c"]) for r in rows)}

    def latest_snapshots(self, target: str) -> dict[str, str]:
        """Последние известные значения полей цели: {source.field: value}."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT source,field,value FROM profile_snapshots WHERE target=? ORDER BY id", (target,)).fetchall()
        out: dict[str, str] = {}
        for row in rows:
            out[f"{row['source']}.{row['field']}"] = row["value"]
        return out

    # ───────────────────────── внешние базы (датасеты) ─────────────────────────
    def import_dataset(self, path: Path | str, name: str | None = None, kind: str = "auto",
                       value_column: str | None = None) -> dict[str, Any]:
        """Импорт внешней базы (CSV/JSON/TXT) в локальный FTS-индекс.

        Понимает: CSV с заголовками (колонки email/phone/username/логин/пароль
        определяются автоматически или задаются value_column), JSON-массив
        объектов, простой список строк.
        """
        path = Path(path)
        name = name or path.stem
        rows = list(self._read_dataset(path, value_column=value_column))
        with self._lock:
            self.conn.execute("DELETE FROM index_entries WHERE dataset=?", (name,))
            self.conn.execute("DELETE FROM index_fts WHERE dataset=?", (name,))
            self.conn.executemany(
                "INSERT INTO index_entries (dataset,kind,value,extra) VALUES (?,?,?,?)",
                [(name, r["kind"], r["value"], r["extra"]) for r in rows])
            self.conn.executemany(
                "INSERT INTO index_fts (value,extra,dataset,kind) VALUES (?,?,?,?)",
                [(r["value"], r["extra"], name, r["kind"]) for r in rows])
            self.conn.execute(
                "INSERT OR REPLACE INTO datasets (name,kind,rows,source,imported_at) VALUES (?,?,?,?,?)",
                (name, kind, len(rows), str(path), _iso()))
            self.conn.commit()
        return {"dataset": name, "rows": len(rows), "path": str(path),
                "kinds": sorted({r["kind"] for r in rows})}

    @staticmethod
    def _read_dataset(path: Path, value_column: str | None = None) -> Iterable[dict[str, str]]:
        def classify(value: str) -> str:
            import re
            if re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", value):
                return "email"
            if re.match(r"^\+?\d{7,15}$", value):
                return "phone"
            return "string"

        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, dict):
                data = data.get("data", data.get("items", [data]))
            for item in data:
                if isinstance(item, dict):
                    value = str(item.get(value_column) if value_column else
                                next((v for k, v in item.items()
                                      if k.lower() in {"email", "mail", "phone", "phone_number", "username",
                                                       "login", "user", "value", "target"}), "")).strip()
                    extra = json.dumps({k: v for k, v in item.items() if str(v) != value}, ensure_ascii=False)[:500]
                else:
                    value, extra = str(item).strip(), ""
                if value:
                    yield {"value": value, "kind": classify(value), "extra": extra}
            return

        text = path.read_text(encoding="utf-8", errors="ignore")
        first = text.split("\n", 1)[0]
        delimiter = max([";", ",", "\t", "|"], key=lambda d: first.count(d))
        if first.count(delimiter) >= 1 and any(w in first.lower() for w in
                                               ("email", "mail", "phone", "user", "login", "pass", "value", "target")):
            reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
            fields = [f.lower() for f in (reader.fieldnames or [])]
            col = value_column
            if not col:
                for want in ("email", "mail", "phone", "phone_number", "username", "user", "login", "value", "target"):
                    if want in fields:
                        col = reader.fieldnames[fields.index(want)]  # type: ignore[index]
                        break
            for row in reader:
                raw = row.get(col) if col else None
                if not raw:
                    continue
                value = str(raw).strip()
                if not value:
                    continue
                extra = json.dumps({k: v for k, v in row.items() if k != col}, ensure_ascii=False)[:500]
                yield {"value": value, "kind": classify(value), "extra": extra}
            return

        for line in text.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            parts = [p.strip() for p in value.replace(";", ":").replace(",", ":").split(":")]
            if len(parts) >= 2 and classify(parts[0]) != "string":
                yield {"value": parts[0], "kind": classify(parts[0]),
                       "extra": json.dumps({"rest": ":".join(parts[1:])}, ensure_ascii=False)[:500]}
            else:
                yield {"value": value, "kind": classify(value), "extra": ""}

    def search_local(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Поиск по загруженным внешним базам (точный + префиксный + FTS)."""
        q = query.strip()
        with self._lock:
            exact = [dict(r) for r in self.conn.execute(
                "SELECT * FROM index_entries WHERE value = ? COLLATE NOCASE LIMIT ?", (q, limit)).fetchall()]
            if len(exact) < limit:
                prefix = [dict(r) for r in self.conn.execute(
                    "SELECT * FROM index_entries WHERE value LIKE ? COLLATE NOCASE LIMIT ?",
                    (f"%{q}%", limit)).fetchall()]
            else:
                prefix = []
            try:
                fts = [dict(r) for r in self.conn.execute(
                    "SELECT dataset, kind, value, extra FROM index_fts WHERE index_fts MATCH ? LIMIT ?",
                    (f'"{q}"', limit)).fetchall()]
            except sqlite3.Error:
                fts = []
        merged: dict[tuple, dict] = {}
        for row in exact + prefix + fts:
            merged[(row.get("dataset"), row.get("value"), row.get("extra", ""))] = row
        return list(merged.values())[:limit]

    def datasets(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM datasets ORDER BY imported_at DESC").fetchall()]

    def drop_dataset(self, name: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM index_entries WHERE dataset=?", (name,))
            self.conn.execute("DELETE FROM index_fts WHERE dataset=?", (name,))
            self.conn.execute("DELETE FROM datasets WHERE name=?", (name,))
            self.conn.commit()

    # ───────────────────────── кэш ─────────────────────────
    def cache_get(self, key: str) -> Any | None:
        with self._lock:
            row = self.conn.execute("SELECT value, created_at, ttl FROM cache WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        if row["ttl"] and time.time() - row["created_at"] > row["ttl"]:
            return None
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return None

    def cache_set(self, key: str, value: Any, ttl: float = 3600) -> None:
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO cache (key,value,created_at,ttl) VALUES (?,?,?,?)",
                              (key, json.dumps(value, ensure_ascii=False), time.time(), ttl))
            self.conn.commit()

    def cache_clear(self) -> int:
        with self._lock:
            cur = self.conn.execute("DELETE FROM cache")
            self.conn.commit()
            return cur.rowcount or 0


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store
