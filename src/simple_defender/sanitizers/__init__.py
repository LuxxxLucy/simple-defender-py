"""Sanitization pipeline — Stage 2."""

from .encoding_detector import (
    EncodingDetectorConfig,
    contains_encoded_content,
    contains_suspicious_encoding,
    decode_all_encoding,
    detect_encoding,
    redact_all_encoding,
)
from .normalizer import (
    analyze_suspicious_unicode,
    contains_suspicious_unicode,
    normalize_unicode,
)
from .pattern_remover import (
    PatternRemoverConfig,
    remove_command_executions,
    remove_instruction_overrides,
    remove_patterns,
    remove_role_assumptions,
    remove_security_bypasses,
)
from .role_stripper import (
    RoleStripperConfig,
    contains_role_markers,
    find_role_markers,
    strip_role_markers,
)
from .sanitizer import (
    Sanitizer,
    create_sanitizer,
    generate_data_boundary,
    sanitize_text,
    suggest_risk_level,
    wrap_with_boundary,
)

__all__ = [
    # normalizer
    "normalize_unicode",
    "contains_suspicious_unicode",
    "analyze_suspicious_unicode",
    # role_stripper
    "strip_role_markers",
    "contains_role_markers",
    "find_role_markers",
    "RoleStripperConfig",
    # pattern_remover
    "remove_patterns",
    "remove_instruction_overrides",
    "remove_role_assumptions",
    "remove_security_bypasses",
    "remove_command_executions",
    "PatternRemoverConfig",
    # encoding_detector
    "detect_encoding",
    "contains_encoded_content",
    "contains_suspicious_encoding",
    "decode_all_encoding",
    "redact_all_encoding",
    "EncodingDetectorConfig",
    # sanitizer
    "Sanitizer",
    "create_sanitizer",
    "sanitize_text",
    "suggest_risk_level",
    "generate_data_boundary",
    "wrap_with_boundary",
]
