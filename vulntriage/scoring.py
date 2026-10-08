"""Deterministic, explainable triage scoring.

The priority score (0-100) is an additive model: the CVSS base contributes the
technical severity, exploit maturity and asset context add environmental weight,
and each contribution is recorded as a :class:`Factor` so a score is always the
sum of named reasons. The total maps to a P1-P4 priority with an SLA. The model
is rule-based, not learned — vulnerability prioritisation must be auditable and
defensible to the teams that act on it.
"""

from __future__ import annotations

from .models import (
    AssetContext,
    Criticality,
    DataSensitivity,
    ExploitMaturity,
    Factor,
    Finding,
    Priority,
)

_EXPLOIT_POINTS = {
    ExploitMaturity.NONE: 0.0,
    ExploitMaturity.POC: 8.0,
    ExploitMaturity.FUNCTIONAL: 16.0,
    ExploitMaturity.WEAPONIZED: 24.0,
}
_CRITICALITY_POINTS = {
    Criticality.LOW: 0.0,
    Criticality.MEDIUM: 8.0,
    Criticality.HIGH: 18.0,
}
_DATA_POINTS = {
    DataSensitivity.NONE: 0.0,
    DataSensitivity.INTERNAL: 4.0,
    DataSensitivity.SENSITIVE: 12.0,
}

# (minimum score, priority, SLA days)
_LEVELS = [
    (70.0, Priority.P1, 7),
    (45.0, Priority.P2, 30),
    (25.0, Priority.P3, 90),
    (0.0, Priority.P4, 180),
]


def _priority(score: float) -> tuple[Priority, int]:
    for threshold, priority, sla in _LEVELS:
        if score >= threshold:
            return priority, sla
    return Priority.P4, 180


def score_factors(finding: Finding) -> list[Factor]:
    asset: AssetContext = finding.asset
    factors = [
        Factor("cvss", round(finding.cvss_base * 4.0, 1),
               f"CVSS base {finding.cvss_base} (×4)"),
        Factor("exploit_maturity", _EXPLOIT_POINTS[finding.exploit_maturity],
               f"exploit maturity: {finding.exploit_maturity.value}"),
        Factor("criticality", _CRITICALITY_POINTS[asset.criticality],
               f"asset criticality: {asset.criticality.value}"),
        Factor("data_sensitivity", _DATA_POINTS[asset.data_sensitivity],
               f"data sensitivity: {asset.data_sensitivity.value}"),
    ]
    if asset.internet_facing:
        factors.append(Factor("exposure", 15.0, "asset is internet-facing"))
    return [f for f in factors if f.points > 0]


def score(finding: Finding) -> tuple[float, Priority, int, list[Factor]]:
    factors = score_factors(finding)
    total = min(100.0, round(sum(f.points for f in factors), 1))
    priority, sla = _priority(total)
    return total, priority, sla, factors
