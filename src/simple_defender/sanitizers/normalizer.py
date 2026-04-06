"""Unicode normalization to prevent bypass attacks.

Ported from defender-ref/src/sanitizers/normalizer.ts
"""

from __future__ import annotations

import re
import unicodedata


# Zero-width characters
_ZERO_WIDTH_RE = re.compile("[\u200b-\u200d\ufeff]")

# Cyrillic homoglyphs -> ASCII
_HOMOGLYPHS: list[tuple[re.Pattern, str]] = [
    (re.compile("[\u0430]"), "a"),
    (re.compile("[\u0435]"), "e"),
    (re.compile("[\u043e]"), "o"),
    (re.compile("[\u0440]"), "p"),
    (re.compile("[\u0441]"), "c"),
    (re.compile("[\u0443]"), "y"),
    (re.compile("[\u0445]"), "x"),
    (re.compile("[\u0456]"), "i"),
]

# Quote/dash normalizations
_SPECIAL_CHARS: list[tuple[re.Pattern, str]] = [
    (re.compile("[\u2018\u2019\u201b\u0060\u00b4]"), "'"),
    (re.compile("[\u201c\u201d\u201e\u201f]"), '"'),
    (re.compile("[\u2010-\u2015\u2212]"), "-"),
    (re.compile("[\u2024]"), "."),
    (re.compile("[\u2026]"), "..."),
    (re.compile("[\u02d0]"), ":"),
    (re.compile("[\ua789]"), ":"),
]


def normalize_unicode(text: str) -> str:
    """Apply NFKC normalization and special character cleanup."""
    if not text:
        return text

    result = unicodedata.normalize("NFKC", text)
    result = _normalize_special_characters(result)
    return result


def _normalize_special_characters(text: str) -> str:
    result = _ZERO_WIDTH_RE.sub("", text)

    for pattern, replacement in _HOMOGLYPHS:
        result = pattern.sub(replacement, result)

    for pattern, replacement in _SPECIAL_CHARS:
        result = pattern.sub(replacement, result)

    return result


def contains_suspicious_unicode(text: str) -> bool:
    """Check for zero-width chars, mixed scripts, math symbols, fullwidth."""
    if not text:
        return False

    if _ZERO_WIDTH_RE.search(text):
        return True

    has_cyrillic = bool(re.search("[\u0400-\u04ff]", text))
    has_latin = bool(re.search("[a-zA-Z]", text))
    if has_cyrillic and has_latin:
        return True

    if bool(re.search("[\U0001d400-\U0001d7ff]", text)):
        return True

    if bool(re.search("[\uff00-\uffef]", text)):
        return True

    return False


def analyze_suspicious_unicode(text: str) -> dict[str, bool]:
    """Return detailed analysis of suspicious Unicode."""
    return {
        "has_suspicious": contains_suspicious_unicode(text),
        "zero_width": bool(_ZERO_WIDTH_RE.search(text)) if text else False,
        "mixed_script": (
            bool(re.search("[\u0400-\u04ff]", text))
            and bool(re.search("[a-zA-Z]", text))
        )
        if text
        else False,
        "math_symbols": bool(re.search("[\U0001d400-\U0001d7ff]", text))
        if text
        else False,
        "fullwidth": bool(re.search("[\uff00-\uffef]", text)) if text else False,
    }
