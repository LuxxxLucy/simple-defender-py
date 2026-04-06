"""
Shared injection pattern definitions.

Ported from defender-ref/src/classifiers/patterns.ts
"""

from __future__ import annotations

import re

from .types import PatternDefinition

# ---------------------------------------------------------------------------
# Role markers
# ---------------------------------------------------------------------------
ROLE_MARKER_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="role_system",
        pattern=re.compile(r"^SYSTEM:\s*", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="System role marker at start of text",
    ),
    PatternDefinition(
        id="role_assistant",
        pattern=re.compile(r"^ASSISTANT:\s*", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Assistant role marker at start of text",
    ),
    PatternDefinition(
        id="role_user",
        pattern=re.compile(r"^USER:\s*", re.IGNORECASE),
        category="role_marker",
        severity="medium",
        description="User role marker at start of text",
    ),
    PatternDefinition(
        id="role_developer",
        pattern=re.compile(r"^DEVELOPER:\s*", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Developer role marker at start of text",
    ),
    PatternDefinition(
        id="role_admin",
        pattern=re.compile(r"^ADMIN(ISTRATOR)?:\s*", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Admin role marker at start of text",
    ),
    PatternDefinition(
        id="role_instruction",
        pattern=re.compile(r"^INSTRUCTION(S)?:\s*", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Instruction marker at start of text",
    ),
    PatternDefinition(
        id="role_human",
        pattern=re.compile(r"^HUMAN:\s*", re.IGNORECASE),
        category="role_marker",
        severity="medium",
        description="Human role marker at start of text",
    ),
    PatternDefinition(
        id="role_ai",
        pattern=re.compile(r"^AI:\s*", re.IGNORECASE),
        category="role_marker",
        severity="medium",
        description="AI role marker at start of text",
    ),
    # Bracketed variants
    PatternDefinition(
        id="role_system_bracket",
        pattern=re.compile(r"^\[SYSTEM\]", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Bracketed system role marker",
    ),
    PatternDefinition(
        id="role_inst_bracket",
        pattern=re.compile(r"^\[INST\]", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="Bracketed instruction marker (Llama format)",
    ),
    # XML-style variants
    PatternDefinition(
        id="role_system_xml",
        pattern=re.compile(r"<system>", re.IGNORECASE),
        category="role_marker",
        severity="high",
        description="XML-style system tag",
    ),
    PatternDefinition(
        id="role_assistant_xml",
        pattern=re.compile(r"<assistant>", re.IGNORECASE),
        category="role_marker",
        severity="medium",
        description="XML-style assistant tag",
    ),
]

# ---------------------------------------------------------------------------
# Instruction override patterns
# ---------------------------------------------------------------------------
INSTRUCTION_OVERRIDE_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="ignore_previous",
        pattern=re.compile(
            r"ignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|rules?|guidelines?|directions?)",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to ignore previous instructions",
    ),
    PatternDefinition(
        id="forget_previous",
        pattern=re.compile(
            r"forget\s+(?:all\s+)?(?:(?:previous|prior|earlier|above)\s+)?(instructions?|prompts?|rules?|context|guidelines?)",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to make AI forget instructions",
    ),
    PatternDefinition(
        id="disregard_previous",
        pattern=re.compile(
            r"disregard\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|rules?)",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to disregard instructions",
    ),
    PatternDefinition(
        id="override_instructions",
        pattern=re.compile(
            r"override\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="high",
        description="Direct override attempt",
    ),
    PatternDefinition(
        id="new_instructions",
        pattern=re.compile(r"new\s+instructions?:\s*", re.IGNORECASE),
        category="instruction_override",
        severity="high",
        description="Attempt to inject new instructions",
    ),
    PatternDefinition(
        id="updated_instructions",
        pattern=re.compile(r"(updated?|revised?|changed?)\s+instructions?:\s*", re.IGNORECASE),
        category="instruction_override",
        severity="high",
        description="Attempt to update instructions",
    ),
    PatternDefinition(
        id="stop_being",
        pattern=re.compile(
            r"stop\s+being\s+(a\s+)?(helpful|assistant|ai|chatbot)", re.IGNORECASE
        ),
        category="instruction_override",
        severity="medium",
        description="Attempt to change AI behavior",
    ),
    PatternDefinition(
        id="from_now_on",
        pattern=re.compile(
            r"from\s+now\s+on,?\s+(you\s+)?(will|must|should|are)", re.IGNORECASE
        ),
        category="instruction_override",
        severity="medium",
        description="Attempt to set new behavior",
    ),
]

# ---------------------------------------------------------------------------
# Role assumption patterns
# ---------------------------------------------------------------------------
ROLE_ASSUMPTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="you_are_now",
        pattern=re.compile(
            r"you\s+are\s+now\s+(a\s+)?(different|new|the|my)?", re.IGNORECASE
        ),
        category="role_assumption",
        severity="high",
        description="Attempt to assign new role",
    ),
    PatternDefinition(
        id="act_as",
        pattern=re.compile(
            r"act\s+(as|like)\s+(a\s+)?(system|admin|developer|root|superuser)",
            re.IGNORECASE,
        ),
        category="role_assumption",
        severity="high",
        description="Attempt to make AI act as privileged role",
    ),
    PatternDefinition(
        id="pretend_to_be",
        pattern=re.compile(r"pretend\s+(to\s+be|you\s+are)\s+(a\s+)?", re.IGNORECASE),
        category="role_assumption",
        severity="medium",
        description="Attempt to make AI pretend",
    ),
    PatternDefinition(
        id="roleplay_as",
        pattern=re.compile(r"roleplay\s+(as|like)\s+(a\s+)?", re.IGNORECASE),
        category="role_assumption",
        severity="low",
        description="Roleplay request (lower severity)",
    ),
    PatternDefinition(
        id="imagine_you_are",
        pattern=re.compile(
            r"imagine\s+(that\s+)?you\s+are\s+(a\s+)?", re.IGNORECASE
        ),
        category="role_assumption",
        severity="low",
        description="Imagination prompt (lower severity)",
    ),
    PatternDefinition(
        id="jailbreak_dan",
        pattern=re.compile(r"\bDAN\b.*?(do\s+anything|jailbreak)", re.IGNORECASE),
        category="role_assumption",
        severity="high",
        description="DAN jailbreak attempt",
    ),
    PatternDefinition(
        id="developer_mode",
        pattern=re.compile(
            r"developer\s+mode\s+(is\s+)?(now\s+)?(enabled?|activated?|on)",
            re.IGNORECASE,
        ),
        category="role_assumption",
        severity="high",
        description="Developer mode activation attempt",
    ),
]

# ---------------------------------------------------------------------------
# Security bypass patterns
# ---------------------------------------------------------------------------
SECURITY_BYPASS_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="bypass_security",
        pattern=re.compile(
            r"bypass\s+(the\s+)?(security|safety|guardrails?|filters?|restrictions?)",
            re.IGNORECASE,
        ),
        category="security_bypass",
        severity="high",
        description="Direct security bypass attempt",
    ),
    PatternDefinition(
        id="disable_safety",
        pattern=re.compile(
            r"disable\s+(the\s+)?(safety|security|guardrails?|filters?|restrictions?)",
            re.IGNORECASE,
        ),
        category="security_bypass",
        severity="high",
        description="Attempt to disable safety features",
    ),
    PatternDefinition(
        id="ignore_safety",
        pattern=re.compile(
            r"ignore\s+(the\s+)?(safety|security|ethical)\s+(guidelines?|rules?|restrictions?)",
            re.IGNORECASE,
        ),
        category="security_bypass",
        severity="high",
        description="Attempt to ignore safety guidelines",
    ),
    PatternDefinition(
        id="no_restrictions",
        pattern=re.compile(
            r"(without|no)\s+(any\s+)?(restrictions?|limitations?|guardrails?|filters?)",
            re.IGNORECASE,
        ),
        category="security_bypass",
        severity="medium",
        description="Request for unrestricted response",
    ),
    PatternDefinition(
        id="uncensored",
        pattern=re.compile(
            r"(uncensored|unfiltered|unrestricted)\s*(mode|response|output|version)?",
            re.IGNORECASE,
        ),
        category="security_bypass",
        severity="high",
        description="Request for uncensored mode",
    ),
]

# ---------------------------------------------------------------------------
# Command execution patterns
# ---------------------------------------------------------------------------
COMMAND_EXECUTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="execute_command",
        pattern=re.compile(
            r"execute\s+(the\s+)?(following|this|these)\s+(command|instruction|code)",
            re.IGNORECASE,
        ),
        category="command_execution",
        severity="high",
        description="Command execution instruction",
    ),
    PatternDefinition(
        id="run_code",
        pattern=re.compile(
            r"run\s+(the\s+)?(following|this|these)\s+(code|script|command)",
            re.IGNORECASE,
        ),
        category="command_execution",
        severity="high",
        description="Code execution instruction",
    ),
    PatternDefinition(
        id="eval_expression",
        pattern=re.compile(r"eval(uate)?\s*\(", re.IGNORECASE),
        category="command_execution",
        severity="medium",
        description="Eval function pattern",
    ),
    PatternDefinition(
        id="shell_command",
        pattern=re.compile(r"\$\([^)]+\)|`[^`]+`"),
        category="command_execution",
        severity="medium",
        description="Shell command substitution",
    ),
]

# ---------------------------------------------------------------------------
# Encoding suspicious patterns
# ---------------------------------------------------------------------------
ENCODING_SUSPICIOUS_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="base64_instruction",
        pattern=re.compile(
            r"(?:decode|base64)\s*[:(]\s*[A-Za-z0-9+/=]{20,}", re.IGNORECASE
        ),
        category="encoding_suspicious",
        severity="high",
        description="Base64 encoded content with decode instruction",
    ),
    PatternDefinition(
        id="hex_escape_sequence",
        pattern=re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"),
        category="encoding_suspicious",
        severity="medium",
        description="Hex escape sequence (potential obfuscation)",
    ),
    PatternDefinition(
        id="unicode_escape_sequence",
        pattern=re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
        category="encoding_suspicious",
        severity="medium",
        description="Unicode escape sequence (potential obfuscation)",
    ),
    PatternDefinition(
        id="html_entity_abuse",
        pattern=re.compile(
            r"(?:&#\d{2,4};){4,}|(?:&#x[0-9a-fA-F]{2,4};){4,}", re.IGNORECASE
        ),
        category="encoding_suspicious",
        severity="medium",
        description="HTML entity encoding (potential obfuscation)",
    ),
    PatternDefinition(
        id="rot13_mention",
        pattern=re.compile(r"rot13|caesar\s+cipher|decode\s+this", re.IGNORECASE),
        category="encoding_suspicious",
        severity="low",
        description="Mention of simple encoding schemes",
    ),
    PatternDefinition(
        id="leetspeak_injection",
        pattern=re.compile(r"1gn0r3|f0rg3t|byp4ss|syst3m|4dm1n|h4ck", re.IGNORECASE),
        category="encoding_suspicious",
        severity="medium",
        description="Leetspeak obfuscation of injection keywords",
    ),
]

# ---------------------------------------------------------------------------
# Prompt leaking patterns
# ---------------------------------------------------------------------------
PROMPT_LEAKING_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="reveal_system_prompt",
        pattern=re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
        category="instruction_override",
        severity="high",
        description="Attempt to reveal system prompt",
    ),
    PatternDefinition(
        id="show_instructions",
        pattern=re.compile(
            r"show\s+(?:me\s+)?(?:your\s+)?(?:(?:initial|original|system|hidden)\s+)?instructions?",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to show hidden instructions",
    ),
    PatternDefinition(
        id="print_above",
        pattern=re.compile(
            r"print\s+(everything|all|text)\s+(above|before)", re.IGNORECASE
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to print content above current context",
    ),
    PatternDefinition(
        id="repeat_back",
        pattern=re.compile(
            r"repeat\s+(back\s+)?(everything|all|your\s+instructions?)", re.IGNORECASE
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to make AI repeat instructions",
    ),
    PatternDefinition(
        id="what_are_your_instructions",
        pattern=re.compile(
            r"what\s+(are|were)\s+(your|the)\s+(?:(?:initial|original|system)\s+)?instructions?",
            re.IGNORECASE,
        ),
        category="instruction_override",
        severity="medium",
        description="Question about system instructions",
    ),
    PatternDefinition(
        id="output_initialization",
        pattern=re.compile(
            r"output\s+(your\s+)?(initialization|init|startup|boot)", re.IGNORECASE
        ),
        category="instruction_override",
        severity="high",
        description="Attempt to output initialization content",
    ),
]

# ---------------------------------------------------------------------------
# Indirect injection patterns
# ---------------------------------------------------------------------------
INDIRECT_INJECTION_PATTERNS: list[PatternDefinition] = [
    PatternDefinition(
        id="markdown_hidden_instruction",
        pattern=re.compile(
            r"\[.*?\]\(.*?(?:ignore|forget|system|instruction).*?\)", re.IGNORECASE
        ),
        category="structural",
        severity="high",
        description="Markdown link with hidden injection",
    ),
    PatternDefinition(
        id="html_comment_injection",
        pattern=re.compile(
            r"<!--\s*(?:system|ignore|instruction|prompt).*?-->", re.IGNORECASE
        ),
        category="structural",
        severity="high",
        description="HTML comment containing injection keywords",
    ),
    PatternDefinition(
        id="invisible_unicode",
        pattern=re.compile(r"[\u200B-\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064]"),
        category="encoding_suspicious",
        severity="medium",
        description="Invisible Unicode characters (zero-width, etc.)",
    ),
    PatternDefinition(
        id="text_direction_override",
        pattern=re.compile(r"[\u202A-\u202E\u2066-\u2069]"),
        category="encoding_suspicious",
        severity="medium",
        description="Text direction override characters",
    ),
    PatternDefinition(
        id="confusable_homoglyphs",
        pattern=re.compile(r"[\u13A0-\u13F4]|[\u1D00-\u1D2B]|[\u0400-\u04FF]"),
        category="encoding_suspicious",
        severity="medium",
        description="Unicode homoglyph characters (Cherokee, Small Caps, Cyrillic)",
    ),
    PatternDefinition(
        id="separator_injection",
        pattern=re.compile(
            r"[-=]{10,}[^-=\n]*(?:system|instruction|ignore)", re.IGNORECASE
        ),
        category="structural",
        severity="medium",
        description="Separator followed by injection attempt",
    ),
    PatternDefinition(
        id="json_injection",
        pattern=re.compile(
            r'"(?:system|role|instruction|prompt)"\s*:\s*"', re.IGNORECASE
        ),
        category="structural",
        severity="medium",
        description="JSON-style role/instruction injection",
    ),
]

# ---------------------------------------------------------------------------
# All patterns combined
# ---------------------------------------------------------------------------
ALL_PATTERNS: list[PatternDefinition] = [
    *ROLE_MARKER_PATTERNS,
    *INSTRUCTION_OVERRIDE_PATTERNS,
    *ROLE_ASSUMPTION_PATTERNS,
    *SECURITY_BYPASS_PATTERNS,
    *COMMAND_EXECUTION_PATTERNS,
    *ENCODING_SUSPICIOUS_PATTERNS,
    *PROMPT_LEAKING_PATTERNS,
    *INDIRECT_INJECTION_PATTERNS,
]

# ---------------------------------------------------------------------------
# Fast filter keywords
# ---------------------------------------------------------------------------
FAST_FILTER_KEYWORDS: list[str] = [
    # Role markers
    "system:",
    "assistant:",
    "user:",
    "developer:",
    "admin:",
    "instruction",
    "[system]",
    "[inst]",
    "<system>",
    "<assistant>",
    # Override keywords
    "ignore",
    "forget",
    "disregard",
    "override",
    "bypass",
    "disable",
    "stop being",
    "from now on",
    # Role assumption
    "you are now",
    "act as",
    "pretend",
    "roleplay",
    "jailbreak",
    "dan",
    "developer mode",
    "imagine you",
    # Security bypass
    "uncensored",
    "unfiltered",
    "unrestricted",
    "no restrictions",
    "without restrictions",
    # Commands
    "execute",
    "eval(",
    "$(",
    "run the",
    # Encoding/obfuscation
    "base64",
    "decode",
    "\\x",
    "\\u",
    "&#",
    "rot13",
    "1gn0r3",
    "f0rg3t",
    "byp4ss",
    # Prompt leaking
    "reveal",
    "show me your",
    "print everything",
    "print above",
    "repeat back",
    "what are your instructions",
    "output initialization",
    # Indirect injection
    "<!--",
    '"system"',
    '"role"',
    '"instruction"',
]


def contains_filter_keywords(text: str) -> bool:
    """Check if text contains any fast filter keywords (case-insensitive)."""
    lower_text = text.lower()
    return any(kw.lower() in lower_text for kw in FAST_FILTER_KEYWORDS)
