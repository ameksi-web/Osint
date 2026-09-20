"""Модели данных OsintX.

Философия: находка (Finding) существует только тогда, когда есть
положительное доказательство от источника — код ответа, строка в теле,
значение в JSON. Ошибка сети/блокировка попадает в SourceStatus, а НЕ в находки.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Confidence = Literal["high", "medium", "low"]
Status = Literal["found", "not_found", "error", "blocked", "unsupported", "skipped"]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Finding:
    """Одна подтверждённая единица информации из источника."""
    source: str                       # имя источника, напр. "github"
    category: str                     # email | username | phone | telegram | domain | ip | person | breach | crypto
    kind: str                         # account | profile | breach | dns | rdap | leak | meta | link
    title: str                        # человекочитаемый заголовок
    url: str = ""                     # ссылка на первоисточник
    value: str = ""                   # ключевое значение (логин, email, телефон...)
    data: dict[str, Any] = field(default_factory=dict)   # структурированные детали
    confidence: Confidence = "medium"
    evidence: str = ""                # чем подтверждено (код/строка/значение)
    http_code: int | None = None
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def one_line(self) -> str:
        return f"[{self.confidence}] {self.source}: {self.title}" + (f" — {self.url}" if self.url else "")


@dataclass
class SourceStatus:
    """Результат проверки конкретного источника (включая ошибки)."""
    source: str
    category: str
    status: Status
    url: str = ""
    http_code: int | None = None
    latency_ms: int | None = None
    error: str = ""
    detail: str = ""
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def checked(self) -> int:
        return len(self.statuses)

    @property
    def found(self) -> int:
        return sum(1 for s in self.statuses if s.status == "found")

    @property
    def failed(self) -> int:
        return sum(1 for s in self.statuses if s.status in {"error", "blocked"})

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "checked": self.checked,
            "found": self.found,
            "failed": self.failed,
            "duration_ms": self.duration_ms,
            "errors": self.errors,
            "meta": self.meta,
            "statuses": [s.to_dict() for s in self.statuses],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Entity:
    type: str        # email | username | phone | domain | ip | person | telegram | url | crypto
    value: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    src: str          # "type:value"
    dst: str
    relation: str     # "registered_on" | "same_person_hint" | "resolves_to" | "variant_of" ...
    weight: float = 1.0
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    target: str
    target_type: str
    search_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    started_at: str = field(default_factory=now_iso)
    duration_ms: int = 0
    modules: list[ModuleResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    # ---------- агрегаты ----------
    def compute_summary(self) -> dict[str, Any]:
        total_checked = sum(m.checked for m in self.modules)
        total_failed = sum(m.failed for m in self.modules)
        by_category: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for f in self.findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_conf[f.confidence] = by_conf.get(f.confidence, 0) + 1
        self.summary = {
            "findings": len(self.findings),
            "sources_checked": total_checked,
            "sources_failed": total_failed,
            "sources_ok": total_checked - total_failed,
            "coverage": round((total_checked - total_failed) / total_checked * 100, 1) if total_checked else 0.0,
            "by_category": by_category,
            "by_confidence": by_conf,
            "modules": {m.module: {"checked": m.checked, "found": m.found, "failed": m.failed,
                                   "duration_ms": m.duration_ms} for m in self.modules},
            "risk_score": self.risk_score(),
        }
        return self.summary

    def risk_score(self) -> int:
        """Оценка цифровой экспозиции 0..100 (для владельца аккаунта — насколько он заметен)."""
        score = 0.0
        for f in self.findings:
            score += {"high": 2.0, "medium": 1.0, "low": 0.5}.get(f.confidence, 0.5)
            if f.kind == "breach":
                score += 6.0
            if f.category == "phone":
                score += 0.5
        return int(min(100, round(score * 1.6)))

    def merge(self, other: ModuleResult) -> None:
        self.modules.append(other)
        self.findings.extend(other.findings)

    def dedupe(self) -> None:
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for f in self.findings:
            key = (f.source, f.kind, f.value or f.url or f.title)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        order = {"high": 0, "medium": 1, "low": 2}
        unique.sort(key=lambda f: (order.get(f.confidence, 3), f.category, f.source))
        self.findings = unique

    # ---------- сериализация ----------
    def to_dict(self) -> dict[str, Any]:
        self.compute_summary()
        return {
            "search_id": self.search_id,
            "target": self.target,
            "target_type": self.target_type,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "entities": [e.to_dict() for e in self.entities],
            "edges": [e.to_dict() for e in self.edges],
            "modules": [m.to_dict() for m in self.modules],
            "warnings": self.warnings,
            "meta": self.meta,
            "tool": "OsintX",
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
