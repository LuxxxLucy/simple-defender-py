"""Defender: unified prompt injection detection interface."""

from __future__ import annotations

import os
import time

import math

from .config import HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD
from .field_extractor import FieldExtractor
from .pattern_detector import PatternDetector
from .sanitizers.sanitizer import Sanitizer
from .tier2_classifier import Tier2Classifier
from .types import PatternMatch, RiskLevel, ScanInput, ScanResult, Tier1Result

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
        sanitize: bool = False,
    ) -> None:
        self._enable_tier1 = enable_tier1
        self._enable_tier2 = enable_tier2
        self._sanitize = sanitize

        self._pattern_detector = PatternDetector() if enable_tier1 else None
        self._field_extractor = FieldExtractor()
        self._sanitizer = Sanitizer() if sanitize else None

        if enable_tier2:
            if model_path is None:
                model_path = self._find_model_path()
            if model_path is not None:
                self._tier2 = Tier2Classifier(model_path)
            else:
                self._tier2 = None
        else:
            self._tier2 = None

    @property
    def tier1_enabled(self) -> bool:
        return self._enable_tier1

    @property
    def tier2_enabled(self) -> bool:
        return self._enable_tier2

    @property
    def model_loaded(self) -> bool:
        return self._tier2 is not None and self._tier2.is_ready()

    @staticmethod
    def _find_model_path() -> str | None:
        """Search common locations for the ONNX model."""
        candidates = [
            # Relative to package source (dev layout)
            os.path.join(os.path.dirname(__file__), "..", "..", "models", "minilm-full-aug"),
            # Relative to cwd
            os.path.join("models", "minilm-full-aug"),
        ]
        for p in candidates:
            if os.path.isfile(os.path.join(p, "model_quantized.onnx")):
                return os.path.abspath(p)
        return None

    def scan(
        self,
        value: str | dict | list,
        tool_name: str | None = None,
        sanitize: bool | None = None,
    ) -> ScanResult:
        """Main entry point for scanning text or structured data.

        Args:
            value: Text string, dict, or list to scan.
            tool_name: Optional tool name for field extraction rules.
            sanitize: Override instance-level sanitize setting for this call.
        """
        start = time.perf_counter()
        do_sanitize = sanitize if sanitize is not None else self._sanitize

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

        # 5. Sanitize if requested
        sanitized_text: str | None = None
        if do_sanitize:
            sanitizer = self._sanitizer or Sanitizer()
            combined_text = "\n\n".join(ef.text for ef in fields) if fields else ""
            if combined_text:
                sr = sanitizer.sanitize(combined_text, risk_level=final_risk)
                sanitized_text = sr.sanitized

        latency_ms = (time.perf_counter() - start) * 1000

        return ScanResult(
            is_injection=is_injection,
            risk_level=final_risk,
            score=tier2_score,
            pattern_matches=all_matches,
            max_sentence=max_sentence,
            fields_scanned=fields_scanned,
            latency_ms=latency_ms,
            sanitized=sanitized_text,
        )

    def scan_batch(self, items: list[ScanInput | dict]) -> list[ScanResult]:
        """Batch scan multiple items with a single ONNX inference call.

        Accepts both ScanInput dataclass instances and plain dicts
        (with keys ``value``, ``tool_name``, ``sanitize``).
        """
        if not items:
            return []

        start = time.perf_counter()

        # 1. Normalize to ScanInput
        normalized: list[ScanInput] = []
        for item in items:
            if isinstance(item, ScanInput):
                normalized.append(item)
            elif isinstance(item, dict):
                normalized.append(ScanInput(
                    value=item.get("value", ""),
                    tool_name=item.get("tool_name"),
                    sanitize=item.get("sanitize"),
                ))
            else:
                raise TypeError(f"Expected ScanInput or dict, got {type(item)}")

        # 2. Extract fields per item
        per_item_fields = [
            self._field_extractor.extract(si.value, si.tool_name)
            for si in normalized
        ]

        # 3. Tier 1: pattern detection per item (fast, no batching)
        per_item_matches: list[list[PatternMatch]] = []
        per_item_tier1_risk: list[RiskLevel] = []
        for fields in per_item_fields:
            matches: list[PatternMatch] = []
            risk: RiskLevel = "low"
            if self._pattern_detector and fields:
                for ef in fields:
                    result = self._pattern_detector.analyze(ef.text)
                    matches.extend(result.matches)
                    risk = _max_risk(risk, result.suggested_risk)
            per_item_matches.append(matches)
            per_item_tier1_risk.append(risk)

        # 4. Tier 2: collect ALL sentences across ALL items → single batch call
        # Track which sentences belong to which item
        per_item_tier2_score: list[float | None] = [None] * len(normalized)
        per_item_tier2_risk: list[RiskLevel] = ["low"] * len(normalized)
        per_item_max_sentence: list[str | None] = [None] * len(normalized)

        if self._tier2:
            all_sentences: list[str] = []
            sentence_item_map: list[int] = []  # sentence index -> item index
            sentence_originals: list[str] = []  # original (untrimmed) text

            for idx, fields in enumerate(per_item_fields):
                if not fields:
                    continue
                combined = "\n\n".join(ef.text for ef in fields)
                if len(combined) < 10:  # min_text_length
                    continue
                sentences = self._tier2.split_into_sentences(combined)
                for s in sentences:
                    if len(s) < self._tier2.min_text_length:
                        continue
                    original = s
                    truncated = (
                        s[: self._tier2.max_text_length]
                        if len(s) > self._tier2.max_text_length
                        else s
                    )
                    all_sentences.append(truncated)
                    sentence_originals.append(original)
                    sentence_item_map.append(idx)

            if all_sentences:
                try:
                    scores = self._tier2._classifier.classify_batch(all_sentences)
                except Exception:
                    scores = [0.0] * len(all_sentences)

                # Redistribute scores back to per-item
                # For each item, find the max sentence score
                item_max_scores: dict[int, float] = {}
                item_max_sentences: dict[int, str] = {}

                for i, raw_score in enumerate(scores):
                    sc = (
                        raw_score
                        if isinstance(raw_score, (int, float)) and math.isfinite(raw_score)
                        else 0.0
                    )
                    item_idx = sentence_item_map[i]
                    if item_idx not in item_max_scores or sc > item_max_scores[item_idx]:
                        item_max_scores[item_idx] = sc
                        item_max_sentences[item_idx] = sentence_originals[i]

                for item_idx, max_score in item_max_scores.items():
                    per_item_tier2_score[item_idx] = max_score
                    per_item_tier2_risk[item_idx] = self._tier2.get_risk_level(max_score)
                    per_item_max_sentence[item_idx] = item_max_sentences[item_idx]

        # 5. Merge per item and build results
        results: list[ScanResult] = []
        for idx, si in enumerate(normalized):
            item_start = time.perf_counter()
            all_item_matches = per_item_matches[idx]
            tier1_risk = per_item_tier1_risk[idx]
            tier2_score = per_item_tier2_score[idx]
            tier2_risk = per_item_tier2_risk[idx]
            max_sentence = per_item_max_sentence[idx]

            final_risk = _max_risk(tier1_risk, tier2_risk)
            has_high_pattern = any(m.severity == "high" for m in all_item_matches)
            has_high_tier2 = tier2_score is not None and tier2_score >= HIGH_RISK_THRESHOLD
            is_injection = has_high_pattern or has_high_tier2

            fields_scanned = [f.field_name for f in per_item_fields[idx]]

            # Sanitize if requested
            do_sanitize = si.sanitize if si.sanitize is not None else self._sanitize
            sanitized_text: str | None = None
            if do_sanitize:
                sanitizer = self._sanitizer or Sanitizer()
                combined_text = (
                    "\n\n".join(ef.text for ef in per_item_fields[idx])
                    if per_item_fields[idx]
                    else ""
                )
                if combined_text:
                    sr = sanitizer.sanitize(combined_text, risk_level=final_risk)
                    sanitized_text = sr.sanitized

            latency_ms = (time.perf_counter() - start) * 1000

            results.append(ScanResult(
                is_injection=is_injection,
                risk_level=final_risk,
                score=tier2_score,
                pattern_matches=all_item_matches,
                max_sentence=max_sentence,
                fields_scanned=fields_scanned,
                latency_ms=latency_ms,
                sanitized=sanitized_text,
            ))

        return results

    def warmup(self) -> None:
        """Preload Tier 2 ONNX model."""
        if self._tier2:
            self._tier2.warmup()

    def analyze(self, text: str) -> Tier1Result:
        """Tier 1 only — convenience/debug method."""
        if self._pattern_detector is None:
            return Tier1Result()
        return self._pattern_detector.analyze(text)
