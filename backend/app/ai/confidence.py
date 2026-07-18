"""
False-positive-aware confidence scoring for Reconix Scan Engine.

Each scanner module already assigns an initial confidence score based
on the strength of its own detection signal. This module applies a
cross-cutting adjustment pass -- boosting confidence when multiple
independent modules corroborate the same endpoint/parameter -- then
classifies findings into a reviewer-facing confidence band.
"""

from dataclasses import dataclass
from enum import Enum

from app.scanner.base import ScanFinding

_LOW_CONFIDENCE_THRESHOLD = 0.35
_HIGH_CONFIDENCE_THRESHOLD = 0.7

_CORROBORATION_BOOST = 0.15
_MAX_CONFIDENCE = 0.98


class ConfidenceBand(str, Enum):
    """Human-facing confidence classification for a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ConfidenceAssessment:
    """Result of the confidence adjustment pass for a single finding."""

    adjusted_confidence: float
    band: ConfidenceBand
    likely_false_positive: bool
    rationale: str


def _band_for(confidence: float) -> ConfidenceBand:
    if confidence >= _HIGH_CONFIDENCE_THRESHOLD:
        return ConfidenceBand.HIGH
    if confidence >= _LOW_CONFIDENCE_THRESHOLD:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


def assess_confidence(finding: ScanFinding, all_findings_for_endpoint: list[ScanFinding]) -> ConfidenceAssessment:
    """
    Recompute a finding's confidence, boosting it slightly when other
    findings on the SAME url+parameter corroborate a related issue.
    """
    corroborating = [
        f for f in all_findings_for_endpoint
        if f is not finding
        and f.url == finding.url
        and f.parameter == finding.parameter
        and f.vulnerability_type != finding.vulnerability_type
    ]

    adjusted = finding.confidence
    rationale_parts = [f"Base confidence from '{finding.vulnerability_type}' module: {finding.confidence:.2f}."]

    if corroborating:
        boost = min(_CORROBORATION_BOOST * len(corroborating), 0.3)
        adjusted = min(adjusted + boost, _MAX_CONFIDENCE)
        rationale_parts.append(
            f"Boosted by {boost:.2f} due to {len(corroborating)} corroborating finding(s) "
            f"on the same endpoint/parameter."
        )

    band = _band_for(adjusted)
    likely_false_positive = band == ConfidenceBand.LOW

    if likely_false_positive:
        rationale_parts.append("Confidence below the low-confidence threshold; recommend manual verification.")

    return ConfidenceAssessment(
        adjusted_confidence=round(adjusted, 3),
        band=band,
        likely_false_positive=likely_false_positive,
        rationale=" ".join(rationale_parts),
    )


def assess_all(findings: list[ScanFinding]) -> dict[int, ConfidenceAssessment]:
    """Run confidence assessment across a full findings list, grouped implicitly by endpoint."""
    assessments: dict[int, ConfidenceAssessment] = {}
    for finding in findings:
        same_endpoint = [f for f in findings if f.url == finding.url]
        assessments[id(finding)] = assess_confidence(finding, same_endpoint)
    return assessments