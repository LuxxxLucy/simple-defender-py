"""Tier 2 Classifier: ML-based prompt injection detection."""

from __future__ import annotations

import math
import re
import time

from simple_defender.onnx_classifier import OnnxClassifier
from simple_defender.types import RiskLevel, Tier2Result

_SENTENCE_SPLIT_RE = re.compile(
    r"(?<=[.!?])\s+|\n\n+|\n(?=[A-Z0-9#\-*])|(?<=:)\s*\n"
)


class Tier2Classifier:
    """Tier 2 classifier using fine-tuned ONNX MiniLM model."""

    def __init__(
        self,
        model_path: str,
        high_risk_threshold: float = 0.8,
        medium_risk_threshold: float = 0.5,
        min_text_length: int = 10,
        max_text_length: int = 10000,
    ) -> None:
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold
        self.min_text_length = min_text_length
        self.max_text_length = max_text_length
        self._classifier = OnnxClassifier(model_path)

    def classify(self, text: str) -> Tier2Result:
        """Classify a single text for prompt injection."""
        start = time.perf_counter()

        if len(text) < self.min_text_length:
            return Tier2Result(
                skipped=True,
                skip_reason=f"Text too short ({len(text)} < {self.min_text_length})",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        analysis_text = (
            text[: self.max_text_length] if len(text) > self.max_text_length else text
        )

        try:
            score = self._classifier.classify(analysis_text)
        except Exception as e:
            return Tier2Result(
                skipped=True,
                skip_reason=f"Classification error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        confidence = abs(score - 0.5) * 2
        return Tier2Result(
            score=score,
            confidence=confidence,
            risk_level=self.get_risk_level(score),
            skipped=False,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def classify_by_sentence(self, text: str) -> Tier2Result:
        """Classify text by splitting into sentences, returning max score."""
        start = time.perf_counter()

        sentences = self.split_into_sentences(text)
        if not sentences:
            return Tier2Result(
                skipped=True,
                skip_reason="No sentences found",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        classifiable: list[str] = []
        originals: list[str] = []
        for s in sentences:
            if len(s) < self.min_text_length:
                continue
            originals.append(s)
            classifiable.append(
                s[: self.max_text_length] if len(s) > self.max_text_length else s
            )

        if not classifiable:
            return Tier2Result(
                skipped=True,
                skip_reason="No classifiable sentences",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        try:
            scores = self._classifier.classify_batch(classifiable)
        except Exception as e:
            return Tier2Result(
                skipped=True,
                skip_reason=f"Classification error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        sentence_scores: list[dict] = []
        max_score = 0.0
        max_sentence = ""

        for i, raw_score in enumerate(scores):
            sc = raw_score if isinstance(raw_score, (int, float)) and math.isfinite(raw_score) else 0.0
            sentence = originals[i]
            sentence_scores.append({"sentence": sentence, "score": sc})
            if sc > max_score:
                max_score = sc
                max_sentence = sentence

        confidence = abs(max_score - 0.5) * 2

        return Tier2Result(
            score=max_score,
            confidence=confidence,
            risk_level=self.get_risk_level(max_score),
            skipped=False,
            max_sentence=max_sentence,
            sentence_scores=sentence_scores,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def split_into_sentences(self, text: str) -> list[str]:
        """Split text into sentences for granular analysis."""
        chunks = _SENTENCE_SPLIT_RE.split(text)
        sentences: list[str] = []
        for chunk in chunks:
            trimmed = chunk.strip()
            if not trimmed:
                continue
            if len(trimmed) > 200 and "\n" in trimmed:
                for sub in trimmed.split("\n"):
                    sub = sub.strip()
                    if sub:
                        sentences.append(sub)
            else:
                sentences.append(trimmed)
        return sentences

    def get_risk_level(self, score: float) -> RiskLevel:
        """Get risk level based on score."""
        if score >= self.high_risk_threshold:
            return "high"
        if score >= self.medium_risk_threshold:
            return "medium"
        return "low"

    def warmup(self) -> None:
        """Pre-load the ONNX model and tokenizer."""
        self._classifier.warmup()

    def is_ready(self) -> bool:
        """Check if the classifier is ready for inference."""
        return self._classifier.is_loaded()

    def get_config(self) -> dict:
        """Get current configuration."""
        return {
            "highRiskThreshold": self.high_risk_threshold,
            "mediumRiskThreshold": self.medium_risk_threshold,
            "minTextLength": self.min_text_length,
            "maxTextLength": self.max_text_length,
        }
