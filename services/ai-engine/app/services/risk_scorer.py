"""
Risk Scorer — Heuristic-based vulnerability risk assessment
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Severity base weights (0-100 scale)
SEVERITY_WEIGHTS = {
    "CRITICAL": 40.0,
    "HIGH":     25.0,
    "MEDIUM":   10.0,
    "LOW":       2.0,
    "UNKNOWN":   5.0,
}


@dataclass
class VulnInput:
    """Input for risk scoring"""
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None  # 0.0-1.0; probability of exploit in 30 days
    has_public_exploit: bool = False
    is_in_kev: bool = False  # CISA Known Exploited Vulnerabilities


def score_vulnerability(vuln: VulnInput) -> float:
    """
    Risk score formula:
    score = base (severity)
           + cvss contribution (0-30 points)
           + epss contribution (0-20 points)
           + exploit bonus (5 points if public exploit)
           + KEV bonus (10 points if actively exploited)
    
    All clamped to [0, 100].
    """
    base = SEVERITY_WEIGHTS.get(vuln.severity.upper(), 5.0)

    # CVSS contributes up to 30 points (score/10 * 30)
    cvss_contrib = (vuln.cvss_score / 10.0 * 30.0) if vuln.cvss_score else 0.0
    cvss_contrib = min(cvss_contrib, 30.0)

    # EPSS contributes up to 20 points (probability * 20)
    epss_contrib = (vuln.epss_score * 20.0) if vuln.epss_score else 0.0
    epss_contrib = min(epss_contrib, 20.0)

    # Public exploit available: +5
    exploit_bonus = 5.0 if vuln.has_public_exploit else 0.0

    # In CISA KEV (actively exploited): +10
    kev_bonus = 10.0 if vuln.is_in_kev else 0.0

    raw_score = base + cvss_contrib + epss_contrib + exploit_bonus + kev_bonus
    final_score = min(round(raw_score, 2), 100.0)

    logger.debug(
        "Scored %s (%s): base=%.1f + cvss=%.1f + epss=%.1f + exploit=%.1f + kev=%.1f = %.2f",
        vuln.cve_id, vuln.severity, base, cvss_contrib, epss_contrib, exploit_bonus, kev_bonus, final_score
    )

    return final_score


def score_scan(vulns: list[VulnInput]) -> float:
    """
    Aggregate scan risk score.
    Uses weighted sum biased toward highest individual scores.
    
    Strategy:
    - Top 3 critical findings dominate (80% weight)
    - Remaining findings (20% weight)
    """
    if not vulns:
        return 0.0

    individual_scores = [score_vulnerability(v) for v in vulns]
    individual_scores.sort(reverse=True)

    # Top 3 findings
    top = individual_scores[:3]
    rest = individual_scores[3:]

    top_avg  = sum(top) / len(top) if top else 0.0
    rest_avg = sum(rest) / len(rest) if rest else 0.0

    final_score = top_avg * 0.8 + rest_avg * 0.2
    final_score = min(round(final_score, 2), 100.0)

    logger.info("Scan risk score: %.2f (from %d vulns, top 3 avg: %.2f)", final_score, len(vulns), top_avg)
    return final_score
