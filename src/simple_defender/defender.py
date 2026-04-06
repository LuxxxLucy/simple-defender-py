"""Defender: unified prompt injection detection interface."""

from __future__ import annotations

import os
import time

from .config import HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD
from .field_extractor import FieldExtractor
from .pattern_detector import PatternDetector
from .tier2_classifier import Tier2Classifier
from .types import PatternMatch, RiskLevel, ScanResult, Tier1Result

_RISK_ORDER: list[RiskLevel] = ["low", "medium", "high", "critical"]


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return _RISK_ORDER[max(_RISK_ORDER.index(a), _RISK_ORDER.index(b))]


class Defender:
    """Simple unified interface for prompt injection detection.

    Combines Tier 1 (pattern detection) and Tier 2 (ML classification).
    """

    def __init__(
        self,
        enable_tier1: bool = True,
        enable_tier2: bool = True,
        model_path: str | None = None,
    ) -> None:
        self._enable_tier1 = enable_tier1
        self._enable_tier2 = enable_tier2

        self._pattern_detector = PatternDetector() if enable_tier1 else None
        self._field_extractor = FieldExtractor()

        if enable_tier2:
            if model_path is None:
                model_path = os.path.join(
                    os.path.dirname(__file__), "..", "..", "models", "minilm-full-aug"
                )
            self._tier2 = Tier2Classifier(model_path)
        else:
            self._tier2 = None

    def scan(
        self,
        value: str | dict | list,
        tool_name: str | None = None,
    ) -> ScanResult:
        """Main entry point for scanning text or structured data."""
        start = time.perf_counter()

        # 1. Extract text fields
        fields = self._field_extractor.extract(value, tool_name)
        fields_scanned = [f.field_name for f in fields]

        # 2. Tier 1: pattern detection on each field
        all_matches: list[PatternMatch] = []
        tier1_risk: RiskLevel = "low"
        if self._pattern_detector and fields:
            for ef in fields:
                result = self._pattern_detector.analyze(ef.text)
                all_matches.extend(result.matches)
                tier1_risk = _max_risk(tier1_risk, result.suggested_risk)

        # 3. Tier 2: ML classification on concatenated text
        tier2_score: float | None = None
        tier2_risk: RiskLevel = "low"
        max_sentence: str | None = None
        if self._tier2 and fields:
            combined = "\n\n".join(ef.text for ef in fields)
            if len(combined) >= 10:  # min_text_length
                t2 = self._tier2.classify_by_sentence(combined)
                if not t2.skipped:
                    tier2_score = t2.score
                    tier2_risk = t2.risk_level
                    max_sentence = t2.max_sentence

        # 4. Merge results
        final_risk = _max_risk(tier1_risk, tier2_risk)

        # is_injection: any high-severity pattern OR tier2 score >= high threshold
        has_high_pattern = any(m.severity == "high" for m in all_matches)
        has_high_tier2 = tier2_score is not None and tier2_score >= HIGH_RISK_THRESHOLD
        is_injection = has_high_pattern or has_high_tier2

        latency_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            is_injection=is_injection,
            risk_level=final_risk,
            score=tier2_score,
            pattern_matches=all_matches,
            max_sentence=max_sentence,
            fields_scanned=fields_scanned,
            latency_ms=latency_ms,
        )

    def warmup(self) -> None:
        """Preload Tier 2 ONNX model."""
        if self._tier2:
            self._tier2.warmup()

    def analyze(self, text: str) -> Tier1Result:
        """Tier 1 only — convenience/debug method."""
        if self._pattern_detector is None:
            return Tier1Result()
        return self._pattern_detector.analyze(text)
