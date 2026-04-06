"""Encoding detection for hidden injection attempts.

Ported from defender-ref/src/sanitizers/encoding-detector.ts
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass

from ..types import EncodingDetection, EncodingDetectionResult

_SUSPICIOUS_RE = re.compile(
    r"system|ignore|instruction|assistant|bypass|override", re.IGNORECASE
)


@dataclass
class EncodingDetectorConfig:
    min_base64_length: int = 20
    decode_base64: bool = True
    decode_url: bool = True
    action: str = "flag"  # "flag" | "decode" | "redact"
    redact_replacement: str = "[ENCODED DATA DETECTED]"


def detect_encoding(
    text: str,
    config: EncodingDetectorConfig | None = None,
) -> EncodingDetectionResult:
    """Detect encoded content in text."""
    if not text:
        return EncodingDetectionResult()

    cfg = config or EncodingDetectorConfig()
    detections: list[EncodingDetection] = []

    if cfg.decode_base64:
        detections.extend(_detect_base64(text, cfg.min_base64_length))

    if cfg.decode_url:
        detections.extend(_detect_url_encoding(text))

    detections.extend(_detect_hex_encoding(text))
    detections.extend(_detect_unicode_escapes(text))

    encoding_types = list(dict.fromkeys(d.type for d in detections))

    result = EncodingDetectionResult(
        has_encoding=len(detections) > 0,
        encoding_types=encoding_types,
        detections=detections,
    )

    if detections and cfg.action in ("decode", "redact"):
        result.processed_text = _process_encoded_content(text, detections, cfg)

    return result


def _detect_base64(text: str, min_length: int) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        candidate = m.group(0)
        if len(candidate) < min_length:
            continue
        try:
            decoded_bytes = base64.b64decode(candidate)
            decoded = decoded_bytes.decode("ascii", errors="strict")
            is_printable = all(0x20 <= ord(c) <= 0x7E or c in "\t\n\r" for c in decoded)
            is_suspicious = is_printable and bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(
                EncodingDetection(
                    type="base64",
                    original=candidate,
                    decoded=decoded if is_printable else None,
                    position=m.start(),
                    length=len(candidate),
                    suspicious=is_suspicious,
                )
            )
        except Exception:
            pass
    return detections


def _detect_url_encoding(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(%[0-9A-Fa-f]{2}){3,}", text):
        candidate = m.group(0)
        try:
            decoded = urllib.parse.unquote(candidate)
            if decoded != candidate:
                is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
                detections.append(
                    EncodingDetection(
                        type="url",
                        original=candidate,
                        decoded=decoded,
                        position=m.start(),
                        length=len(candidate),
                        suspicious=is_suspicious,
                    )
                )
        except Exception:
            pass
    return detections


def _detect_hex_encoding(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(\\x[0-9A-Fa-f]{2}){4,}", text):
        candidate = m.group(0)
        try:
            decoded = re.sub(
                r"\\x([0-9A-Fa-f]{2})",
                lambda hm: chr(int(hm.group(1), 16)),
                candidate,
            )
            is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(
                EncodingDetection(
                    type="hex",
                    original=candidate,
                    decoded=decoded,
                    position=m.start(),
                    length=len(candidate),
                    suspicious=is_suspicious,
                )
            )
        except Exception:
            pass
    return detections


def _detect_unicode_escapes(text: str) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    for m in re.finditer(r"(\\u[0-9A-Fa-f]{4}){3,}", text):
        candidate = m.group(0)
        try:
            decoded = re.sub(
                r"\\u([0-9A-Fa-f]{4})",
                lambda um: chr(int(um.group(1), 16)),
                candidate,
            )
            is_suspicious = bool(_SUSPICIOUS_RE.search(decoded))
            detections.append(
                EncodingDetection(
                    type="unicode_escape",
                    original=candidate,
                    decoded=decoded,
                    position=m.start(),
                    length=len(candidate),
                    suspicious=is_suspicious,
                )
            )
        except Exception:
            pass
    return detections


def _process_encoded_content(
    text: str,
    detections: list[EncodingDetection],
    config: EncodingDetectorConfig,
) -> str:
    result = text
    # Process from end to start to preserve positions
    for det in sorted(detections, key=lambda d: d.position, reverse=True):
        if config.action == "redact":
            replacement = config.redact_replacement
        else:
            replacement = det.decoded if det.decoded else det.original
        result = result[: det.position] + replacement + result[det.position + det.length :]
    return result


# Convenience functions

def contains_encoded_content(text: str) -> bool:
    return detect_encoding(text).has_encoding


def contains_suspicious_encoding(text: str) -> bool:
    return any(d.suspicious for d in detect_encoding(text).detections)


def decode_all_encoding(text: str) -> str:
    result = detect_encoding(text, EncodingDetectorConfig(action="decode"))
    return result.processed_text if result.processed_text is not None else text


def redact_all_encoding(
    text: str, replacement: str = "[ENCODED DATA DETECTED]"
) -> str:
    result = detect_encoding(
        text,
        EncodingDetectorConfig(action="redact", redact_replacement=replacement),
    )
    return result.processed_text if result.processed_text is not None else text
