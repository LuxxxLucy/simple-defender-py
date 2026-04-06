"""Role marker stripping.

Ported from defender-ref/src/sanitizers/role-stripper.ts
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class RoleStripperConfig:
    start_only: bool = False
    strip_xml_tags: bool = True
    strip_bracket_markers: bool = True
    custom_markers: list[re.Pattern] = field(default_factory=list)


# Role markers (match at line start, multiline + case-insensitive)
_ROLE_MARKERS = [
    re.compile(r"^SYSTEM:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^ASSISTANT:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^USER:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^DEVELOPER:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^ADMIN(ISTRATOR)?:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^INSTRUCTION(S)?:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^HUMAN:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^AI:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^BOT:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^CLAUDE:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^GPT:\s*", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^CHATGPT:\s*", re.IGNORECASE | re.MULTILINE),
]

# Inline markers (not anchored to line start)
_INLINE_ROLE_MARKERS = [
    re.compile(r"\bSYSTEM:\s*", re.IGNORECASE),
    re.compile(r"\bASSISTANT:\s*", re.IGNORECASE),
    re.compile(r"\bINSTRUCTION(S)?:\s*", re.IGNORECASE),
]

# XML-style tags
_XML_ROLE_TAGS = [
    re.compile(r"</?system>", re.IGNORECASE),
    re.compile(r"</?assistant>", re.IGNORECASE),
    re.compile(r"</?user>", re.IGNORECASE),
    re.compile(r"</?instruction>", re.IGNORECASE),
    re.compile(r"</?prompt>", re.IGNORECASE),
    re.compile(r"</?admin>", re.IGNORECASE),
    re.compile(r"</?developer>", re.IGNORECASE),
]

# Bracket-style markers
_BRACKET_MARKERS = [
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"\[/SYSTEM\]", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"\[INSTRUCTION\]", re.IGNORECASE),
    re.compile(r"\[/INSTRUCTION\]", re.IGNORECASE),
    re.compile(r"\[\[SYSTEM\]\]", re.IGNORECASE),
    re.compile(r"\[\[/SYSTEM\]\]", re.IGNORECASE),
]


def strip_role_markers(text: str, config: RoleStripperConfig | None = None) -> str:
    """Strip role markers from text."""
    if not text:
        return text

    cfg = config or RoleStripperConfig()
    result = text

    for p in _ROLE_MARKERS:
        result = p.sub("", result)

    if not cfg.start_only:
        for p in _INLINE_ROLE_MARKERS:
            result = p.sub("", result)

    if cfg.strip_xml_tags:
        for p in _XML_ROLE_TAGS:
            result = p.sub("", result)

    if cfg.strip_bracket_markers:
        for p in _BRACKET_MARKERS:
            result = p.sub("", result)

    for p in cfg.custom_markers:
        result = p.sub("", result)

    # Clean up double spaces and trim
    result = re.sub(r"\s{2,}", " ", result).strip()
    return result


def contains_role_markers(text: str) -> bool:
    """Check if text contains any role markers."""
    if not text:
        return False

    for patterns in (_ROLE_MARKERS, _INLINE_ROLE_MARKERS, _XML_ROLE_TAGS, _BRACKET_MARKERS):
        for p in patterns:
            if p.search(text):
                return True
    return False


def find_role_markers(text: str) -> list[str]:
    """Find all unique role markers in text."""
    if not text:
        return []

    found: list[str] = []
    all_patterns = [*_ROLE_MARKERS, *_INLINE_ROLE_MARKERS, *_XML_ROLE_TAGS, *_BRACKET_MARKERS]

    for p in all_patterns:
        for m in p.finditer(text):
            marker = m.group(0).strip()
            if marker and marker not in found:
                found.append(marker)

    return found
