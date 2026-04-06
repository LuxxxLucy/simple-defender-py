from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
import re

RiskLevel = Literal["low", "medium", "high", "critical"]

PatternCategory = Literal[
    "role_marker",
    "instruction_override",
    "role_assumption",
    "security_bypass",
    "command_execution",
    "encoding_suspicious",
    "structural",
]


@dataclass
class PatternDefinition:
    id: str
    pattern: re.Pattern
    category: PatternCategory
    severity: Literal["low", "medium", "high"]
    description: str


@dataclass
class PatternMatch:
    id: str
    category: PatternCategory
    severity: Literal["low", "medium", "high"]
    matched: str
    position: int


@dataclass
class StructuralFlag:
    type: str  # "high_entropy" | "excessive_length" | "suspicious_formatting" | "nested_markers"
    details: str
    severity: Literal["low", "medium", "high"]


@dataclass
class Tier1Result:
    matches: list[PatternMatch] = field(default_factory=list)
    structural_flags: list[StructuralFlag] = field(default_factory=list)
    has_detections: bool = False
    suggested_risk: RiskLevel = "low"
    latency_ms: float = 0.0


@dataclass
class Tier2Result:
    score: float = 0.0
    confidence: float = 0.0
    risk_level: RiskLevel = "low"
    skipped: bool = False
    skip_reason: str | None = None
    max_sentence: str | None = None
    sentence_scores: list[dict] | None = None
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    is_injection: bool = False
    risk_level: RiskLevel = "low"
    score: float | None = None
    pattern_matches: list[PatternMatch] = field(default_factory=list)
    max_sentence: str | None = None
    fields_scanned: list[str] = field(default_factory=list)
    latency_ms: float = 0.0


@dataclass
class ExtractedField:
    field_name: str
    path: str
    text: str
