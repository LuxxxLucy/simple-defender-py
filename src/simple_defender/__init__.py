from simple_defender.defender import Defender
from simple_defender.types import (
    ScanResult,
    PatternMatch,
    Tier1Result,
    Tier2Result,
    ExtractedField,
    DataBoundary,
    FieldSanitizationResult,
    SanitizationMetadata,
)
from simple_defender.config import HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD
from simple_defender.sanitizers import (
    contains_boundary_patterns,
    generate_boundary_instructions,
    generate_xml_boundary,
)

__all__ = [
    "Defender",
    "ScanResult",
    "PatternMatch",
    "Tier1Result",
    "Tier2Result",
    "ExtractedField",
    "DataBoundary",
    "FieldSanitizationResult",
    "SanitizationMetadata",
    "HIGH_RISK_THRESHOLD",
    "MEDIUM_RISK_THRESHOLD",
    "generate_xml_boundary",
    "contains_boundary_patterns",
    "generate_boundary_instructions",
]
