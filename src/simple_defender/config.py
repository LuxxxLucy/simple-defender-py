import re

# Tier 2 thresholds
HIGH_RISK_THRESHOLD = 0.8
MEDIUM_RISK_THRESHOLD = 0.5
SKIP_BELOW_SIZE = 50

# Traversal limits
MAX_DEPTH = 10
MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LARGE_ARRAY_THRESHOLD = 1000

# Risky field names (exact match)
DEFAULT_RISKY_FIELDS: list[str] = [
    "name", "description", "content", "title", "notes",
    "summary", "bio", "body", "text", "message", "comment", "subject",
]

# Risky field patterns (suffix match)
DEFAULT_RISKY_FIELD_PATTERNS: list[re.Pattern] = [
    re.compile(r"_name$"),
    re.compile(r"_description$"),
    re.compile(r"_content$"),
    re.compile(r"_body$"),
    re.compile(r"_notes$"),
    re.compile(r"_summary$"),
    re.compile(r"_bio$"),
    re.compile(r"_text$"),
    re.compile(r"_message$"),
    re.compile(r"_title$"),
]

# Tool-specific field overrides (glob pattern -> risky field list)
TOOL_FIELD_OVERRIDES: dict[str, list[str]] = {
    "documents_*": ["name", "description", "content", "title"],
    "hris_*": ["name", "notes", "bio", "description"],
    "ats_*": ["name", "notes", "description", "summary"],
    "crm_*": ["name", "description", "notes", "content"],
    "gmail_*": ["subject", "body", "snippet", "content"],
    "email_*": ["subject", "body", "snippet", "content"],
    "github_*": ["name", "description", "body", "content", "message", "title"],
}

# Tool-specific skip fields
TOOL_SKIP_FIELDS: dict[str, list[str]] = {
    "documents_*": ["id", "url", "size", "created_at", "updated_at", "mime_type"],
    "hris_*": ["id", "employee_id", "created_at", "updated_at"],
    "ats_*": ["id", "candidate_id", "application_id", "created_at", "updated_at"],
    "crm_*": ["id", "contact_id", "account_id", "created_at", "updated_at"],
    "gmail_*": ["id", "thread_id", "message_id", "date"],
    "email_*": ["id", "thread_id", "message_id", "date"],
    "github_*": ["id", "sha", "url", "html_url", "created_at", "updated_at"],
}
