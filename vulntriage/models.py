"""The vulnerability and triage data model.

A finding pairs a technical severity (its CVSS base score and how mature the
exploit is) with the *context* of the asset it affects (internet-facing,
business-critical, holding sensitive data). Priority comes from combining the two
— a medium CVSS on an internet-facing crown-jewel outranks a high CVSS on an
isolated test box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ExploitMaturity(StrEnum):
    NONE = "none"
    POC = "poc"
    FUNCTIONAL = "functional"
    WEAPONIZED = "weaponized"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DataSensitivity(StrEnum):
    NONE = "none"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"  # PII / PHI / financial


class Priority(StrEnum):
    P1 = "P1"  # critical
    P2 = "P2"  # high
    P3 = "P3"  # medium
    P4 = "P4"  # low


@dataclass(frozen=True)
class AssetContext:
    name: str
    internet_facing: bool = False
    criticality: Criticality = Criticality.LOW
    data_sensitivity: DataSensitivity = DataSensitivity.NONE


@dataclass(frozen=True)
class Finding:
    id: str
    cve: str
    title: str
    cvss_base: float  # 0.0 - 10.0
    exploit_maturity: ExploitMaturity
    asset: AssetContext


@dataclass
class Factor:
    name: str
    points: float
    detail: str


@dataclass
class TriageResult:
    finding_id: str
    cve: str
    score: float  # 0 - 100
    priority: Priority
    sla_days: int
    factors: list[Factor] = field(default_factory=list)
    recommendation: str = ""
    note_source: str = ""  # "llm" or "heuristic"
