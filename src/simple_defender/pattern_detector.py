"""
Tier 1: Pattern Detection

Fast, regex-based detection of known injection patterns.
Ported from defender-ref/src/classifiers/pattern-detector.ts
"""

from __future__ import annotations

import math
import re
import time

from .patterns import ALL_PATTERNS, contains_filter_keywords
from .types import PatternDefinition, PatternMatch, RiskLevel, StructuralFlag, Tier1Result


class PatternDetector:
    """Pattern detector for Tier 1 classification."""

    def __init__(
        self,
        *,
        use_fast_filter: bool = True,
        max_analysis_length: int = 50_000,
        entropy_threshold: float = 4.5,
        entropy_min_length: int = 50,
        max_field_length: int = 100_000,
        custom_patterns: list[PatternDefinition] | None = None,
    ) -> None:
        self.use_fast_filter = use_fast_filter
        self.max_analysis_length = max_analysis_length
        self.entropy_threshold = entropy_threshold
        self.entropy_min_length = entropy_min_length
        self.max_field_length = max_field_length
        self._patterns: list[PatternDefinition] = list(ALL_PATTERNS)
        self._has_custom_patterns = False
        if custom_patterns:
            self._patterns.extend(custom_patterns)
            self._has_custom_patterns = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, text: str) -> Tier1Result:
        start = time.perf_counter()

        if not text or len(text) < 3:
            return self._empty_result(start)

        original_length = len(text)

        analysis_text = text[: self.max_analysis_length] if len(text) > self.max_analysis_length else text

        # Fast filter: skip regex when no keywords found (unless custom patterns)
        should_use_fast_filter = self.use_fast_filter and not self._has_custom_patterns
        if should_use_fast_filter and not contains_filter_keywords(analysis_text):
            flags = self._detect_structural_issues(analysis_text, original_length)
            return self._create_result([], flags, start)

        matches = self._detect_patterns(analysis_text)
        flags = self._detect_structural_issues(analysis_text, original_length)
        return self._create_result(matches, flags, start)

    def add_pattern(self, pattern: PatternDefinition) -> None:
        self._patterns.append(pattern)

    def get_patterns(self) -> list[PatternDefinition]:
        return list(self._patterns)

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def _detect_patterns(self, text: str) -> list[PatternMatch]:
        matches: list[PatternMatch] = []
        for defn in self._patterns:
            for m in defn.pattern.finditer(text):
                matches.append(
                    PatternMatch(
                        id=defn.id,
                        matched=m.group(0),
                        position=m.start(),
                        category=defn.category,
                        severity=defn.severity,
                    )
                )
        return matches

    # ------------------------------------------------------------------
    # Structural issue detection
    # ------------------------------------------------------------------

    def _detect_structural_issues(self, text: str, original_length: int) -> list[StructuralFlag]:
        flags: list[StructuralFlag] = []

        # Excessive length
        if original_length > self.max_field_length:
            flags.append(
                StructuralFlag(
                    type="excessive_length",
                    details=f"Field length {original_length} exceeds maximum {self.max_field_length}",
                    severity="medium",
                )
            )

        # High entropy
        if len(text) >= self.entropy_min_length:
            entropy = self._calculate_entropy(text)
            if entropy > self.entropy_threshold:
                flags.append(
                    StructuralFlag(
                        type="high_entropy",
                        details=f"Entropy {entropy:.2f} exceeds threshold {self.entropy_threshold}",
                        severity="medium",
                    )
                )

        # Nested markers
        if self._has_nested_markers(text):
            flags.append(
                StructuralFlag(
                    type="nested_markers",
                    details="Suspicious nested XML tags or bracket patterns detected",
                    severity="medium",
                )
            )

        # Suspicious formatting
        if self._has_suspicious_formatting(text):
            flags.append(
                StructuralFlag(
                    type="suspicious_formatting",
                    details="Unusual formatting patterns detected",
                    severity="low",
                )
            )

        return flags

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _has_nested_markers(text: str) -> bool:
        suspicious_xml = re.findall(
            r"</?(?:system|user|assistant|instruction|prompt|admin|developer)[^>]*>",
            text,
            re.IGNORECASE,
        )
        if len(suspicious_xml) >= 2:
            return True

        xml_tags = re.findall(r"<[a-zA-Z][^>]*>", text)
        if xml_tags and len(xml_tags) > 4:
            marker_tags = [t for t in xml_tags if re.search(r"system|user|assistant|instruction|prompt", t, re.IGNORECASE)]
            if marker_tags:
                return True

        if re.search(r"\[\[.*?(system|instruction|ignore).*?\]\]", text, re.IGNORECASE):
            return True

        return False

    @staticmethod
    def _has_suspicious_formatting(text: str) -> bool:
        if re.search(r"\n{3,}(system|instruction|ignore|forget)", text, re.IGNORECASE):
            return True
        if re.search(r"^#{1,3}\s*(system|instruction|new rules)", text, re.IGNORECASE | re.MULTILINE):
            return True
        if re.search(r"[-=]{3,}\s*\n\s*(system|instruction|ignore)", text, re.IGNORECASE):
            return True
        return False

    def _calculate_suggested_risk(
        self, matches: list[PatternMatch], flags: list[StructuralFlag]
    ) -> RiskLevel:
        high_matches = sum(1 for m in matches if m.severity == "high")
        medium_matches = sum(1 for m in matches if m.severity == "medium")
        high_flags = sum(1 for f in flags if f.severity == "high")
        medium_flags = sum(1 for f in flags if f.severity == "medium")

        if high_matches >= 2 or (high_matches >= 1 and high_flags >= 1):
            return "critical"
        if high_matches >= 1 or medium_matches >= 3 or (medium_matches >= 2 and medium_flags >= 1):
            return "high"
        if medium_matches >= 1 or high_flags >= 1 or medium_flags >= 2:
            return "medium"
        return "low"

    def _create_result(
        self,
        matches: list[PatternMatch],
        flags: list[StructuralFlag],
        start: float,
    ) -> Tier1Result:
        has_detections = len(matches) > 0 or len(flags) > 0
        return Tier1Result(
            matches=matches,
            structural_flags=flags,
            has_detections=has_detections,
            suggested_risk=self._calculate_suggested_risk(matches, flags),
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _empty_result(self, start: float) -> Tier1Result:
        return Tier1Result(
            matches=[],
            structural_flags=[],
            has_detections=False,
            suggested_risk="low",
            latency_ms=(time.perf_counter() - start) * 1000,
        )
