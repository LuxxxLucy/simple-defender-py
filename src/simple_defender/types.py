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
    sanitized: str | None = None


@dataclass
class ScanInput:
    value: str | dict | list
    tool_name: str | None = None
    sanitize: bool | None = None


@dataclass
class ExtractedField:
    field_name: str
    path: str
    text: str


# ---------------------------------------------------------------------------
# Sanitization types (Stage 2)
# ---------------------------------------------------------------------------

@dataclass
class DataBoundary:
    id: str
    start_tag: str
    end_tag: str


SanitizationMethod = Literal[
    "unicode_normalization",
    "role_stripping",
    "pattern_removal",
    "encoding_detection",
    "boundary_annotation",
]


@dataclass
class PatternRemovalResult:
    text: str
    patterns_removed: list[str] = field(default_factory=list)
    replacement_count: int = 0


@dataclass
class EncodingDetection:
    type: str  # "base64" | "url" | "hex" | "unicode_escape"
    original: str
    decoded: str | None = None
    position: int = 0
    length: int = 0
    suspicious: bool = False


@dataclass
class EncodingDetectionResult:
    has_encoding: bool = False
    encoding_types: list[str] = field(default_factory=list)
    detections: list[EncodingDetection] = field(default_factory=list)
    processed_text: str | None = None


@dataclass
class FieldSanitizationResult:
    sanitized: str = ""
    methods_applied: list[str] = field(default_factory=list)
    patterns_removed: list[str] = field(default_factory=list)
    risk_level: RiskLevel = "low"


@dataclass
class SanitizationMetadata:
    fields_sanitized: list[str] = field(default_factory=list)
    methods_by_field: dict[str, list[str]] = field(default_factory=dict)
    overall_risk_level: RiskLevel = "low"
