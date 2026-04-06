"""Pattern removal / redaction.

Ported from defender-ref/src/sanitizers/pattern-remover.ts
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..patterns import (
    ALL_PATTERNS,
    COMMAND_EXECUTION_PATTERNS,
    INSTRUCTION_OVERRIDE_PATTERNS,
    ROLE_ASSUMPTION_PATTERNS,
    SECURITY_BYPASS_PATTERNS,
)
from ..types import PatternDefinition, PatternRemovalResult


@dataclass
class PatternRemoverConfig:
    replacement: str = "[REDACTED]"
    preserve_length: bool = False
    preserve_char: str = "\u2588"  # █
    high_severity_only: bool = False
    categories: list[str] | None = None
    custom_patterns: list[re.Pattern] | None = None


def remove_patterns(
    text: str,
    config: PatternRemoverConfig | None = None,
) -> PatternRemovalResult:
    """Remove injection patterns from text."""
    if not text:
        return PatternRemovalResult(text=text)

    cfg = config or PatternRemoverConfig()
    result = text
    patterns_removed: list[str] = []
    replacement_count = 0

    patterns_to_use = _get_patterns_by_config(cfg)

    for defn in patterns_to_use:
        pattern = re.compile(defn.pattern.pattern, defn.pattern.flags)
        matches = pattern.findall(result)
        if matches:
            def _make_replacer(defn_id: str):
                def replacer(m: re.Match) -> str:
                    nonlocal replacement_count
                    replacement_count += 1
                    if defn_id not in patterns_removed:
                        patterns_removed.append(defn_id)
                    if cfg.preserve_length:
                        return cfg.preserve_char * len(m.group(0))
                    return cfg.replacement
                return replacer

            result = pattern.sub(_make_replacer(defn.id), result)

    if cfg.custom_patterns:
        for custom in cfg.custom_patterns:
            pattern = re.compile(custom.pattern, custom.flags)
            if pattern.search(result):
                def _custom_replacer(m: re.Match) -> str:
                    nonlocal replacement_count
                    replacement_count += 1
                    if "custom" not in patterns_removed:
                        patterns_removed.append("custom")
                    if cfg.preserve_length:
                        return cfg.preserve_char * len(m.group(0))
                    return cfg.replacement

                result = pattern.sub(_custom_replacer, result)

    return PatternRemovalResult(
        text=result,
        patterns_removed=patterns_removed,
        replacement_count=replacement_count,
    )


def _get_patterns_by_config(config: PatternRemoverConfig) -> list[PatternDefinition]:
    patterns = list(ALL_PATTERNS)

    if config.high_severity_only:
        patterns = [p for p in patterns if p.severity == "high"]

    if config.categories:
        patterns = [p for p in patterns if p.category in config.categories]

    return patterns


def remove_instruction_overrides(
    text: str, replacement: str = "[REDACTED]"
) -> PatternRemovalResult:
    """Remove only instruction override patterns."""
    return _remove_category(text, INSTRUCTION_OVERRIDE_PATTERNS, replacement)


def remove_role_assumptions(
    text: str, replacement: str = "[REDACTED]"
) -> PatternRemovalResult:
    """Remove only role assumption patterns."""
    return _remove_category(text, ROLE_ASSUMPTION_PATTERNS, replacement)


def remove_security_bypasses(
    text: str, replacement: str = "[REDACTED]"
) -> PatternRemovalResult:
    """Remove only security bypass patterns."""
    return _remove_category(text, SECURITY_BYPASS_PATTERNS, replacement)


def remove_command_executions(
    text: str, replacement: str = "[REDACTED]"
) -> PatternRemovalResult:
    """Remove only command execution patterns."""
    return _remove_category(text, COMMAND_EXECUTION_PATTERNS, replacement)


def _remove_category(
    text: str,
    definitions: list[PatternDefinition],
    replacement: str,
) -> PatternRemovalResult:
    if not text:
        return PatternRemovalResult(text=text)

    result = text
    patterns_removed: list[str] = []
    replacement_count = 0

    for defn in definitions:
        pattern = re.compile(defn.pattern.pattern, defn.pattern.flags)
        if pattern.search(result):
            def _make_replacer(defn_id: str):
                def replacer(m: re.Match) -> str:
                    nonlocal replacement_count
                    replacement_count += 1
                    if defn_id not in patterns_removed:
                        patterns_removed.append(defn_id)
                    return replacement
                return replacer

            result = pattern.sub(_make_replacer(defn.id), result)

    return PatternRemovalResult(
        text=result,
        patterns_removed=patterns_removed,
        replacement_count=replacement_count,
    )
