"""ONNX classifier for fine-tuned MiniLM prompt injection detection."""

from __future__ import annotations

import os

import numpy as np
import onnxruntime
from tokenizers import Tokenizer

_session_cache: dict[str, dict] = {}


class OnnxClassifier:
    """ONNX-based text classifier using a fine-tuned MiniLM model."""

    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self._session: onnxruntime.InferenceSession | None = None
        self._tokenizer: Tokenizer | None = None
        self._max_length = 256

    def load_model(self) -> None:
        """Load the ONNX model and tokenizer (uses module-level cache)."""
        if self._session is not None and self._tokenizer is not None:
            return

        cached = _session_cache.get(self.model_path)
        if cached:
            self._session = cached["session"]
            self._tokenizer = cached["tokenizer"]
            return

        tokenizer = Tokenizer.from_file(
            os.path.join(self.model_path, "tokenizer.json")
        )
        session = onnxruntime.InferenceSession(
            os.path.join(self.model_path, "model_quantized.onnx")
        )
        _session_cache[self.model_path] = {
            "session": session,
            "tokenizer": tokenizer,
        }
        self._session = session
        self._tokenizer = tokenizer

    def classify(self, text: str) -> float:
        """Classify a single text, returning a sigmoid score in [0, 1]."""
        self._ensure_loaded()
        assert self._tokenizer is not None
        assert self._session is not None

        self._tokenizer.enable_truncation(max_length=self._max_length)
        self._tokenizer.no_padding()
        encoded = self._tokenizer.encode(text)

        input_ids = np.array([encoded.ids], dtype=np.int64)
        attention_mask = np.array([encoded.attention_mask], dtype=np.int64)

        results = self._session.run(
            None, {"input_ids": input_ids, "attention_mask": attention_mask}
        )
        logit = results[0][0][0]
        return float(1.0 / (1.0 + np.exp(-logit)))

    def classify_batch(self, texts: list[str]) -> list[float]:
        """Classify multiple texts in a single batched inference call."""
        if not texts:
            return []

        self._ensure_loaded()
        assert self._tokenizer is not None
        assert self._session is not None

        self._tokenizer.enable_truncation(max_length=self._max_length)
        self._tokenizer.no_padding()
        encodings = [self._tokenizer.encode(t) for t in texts]

        max_len = max(len(e.ids) for e in encodings)
        batch_size = len(texts)
        batch_ids = np.zeros((batch_size, max_len), dtype=np.int64)
        batch_mask = np.zeros((batch_size, max_len), dtype=np.int64)

        for i, enc in enumerate(encodings):
            seq_len = len(enc.ids)
            batch_ids[i, :seq_len] = enc.ids
            batch_mask[i, :seq_len] = enc.attention_mask

        results = self._session.run(
            None, {"input_ids": batch_ids, "attention_mask": batch_mask}
        )

        scores: list[float] = []
        for i in range(batch_size):
            logit = results[0][i][0]
            scores.append(float(1.0 / (1.0 + np.exp(-logit))))
        return scores

    def warmup(self) -> None:
        """Pre-load the model."""
        self.load_model()

    def is_loaded(self) -> bool:
        """Check if the model is loaded and ready for inference."""
        return self._session is not None and self._tokenizer is not None

    def _ensure_loaded(self) -> None:
        if not self.is_loaded():
            self.load_model()
