"""A synthetic vulnerability backlog for the demo and the tests."""

from __future__ import annotations

from .models import (
    AssetContext,
    Criticality,
    DataSensitivity,
    ExploitMaturity,
    Finding,
)

SAMPLE_BACKLOG: list[Finding] = [
    Finding(
        "F-001",
        "CVE-2021-44228",
        "Log4Shell RCE",
        10.0,
        ExploitMaturity.WEAPONIZED,
        AssetContext(
            "payments-api",
            internet_facing=True,
            criticality=Criticality.HIGH,
            data_sensitivity=DataSensitivity.SENSITIVE,
        ),
    ),
    Finding(
        "F-002",
        "CVE-2023-1234",
        "Reflected XSS",
        6.1,
        ExploitMaturity.POC,
        AssetContext(
            "marketing-site",
            internet_facing=True,
            criticality=Criticality.LOW,
            data_sensitivity=DataSensitivity.NONE,
        ),
    ),
    Finding(
        "F-003",
        "CVE-2022-22965",
        "Spring4Shell RCE",
        9.8,
        ExploitMaturity.FUNCTIONAL,
        AssetContext(
            "internal-reports",
            internet_facing=False,
            criticality=Criticality.MEDIUM,
            data_sensitivity=DataSensitivity.INTERNAL,
        ),
    ),
    Finding(
        "F-004",
        "CVE-2020-0001",
        "Local privilege escalation",
        7.8,
        ExploitMaturity.NONE,
        AssetContext(
            "build-agent",
            internet_facing=False,
            criticality=Criticality.LOW,
            data_sensitivity=DataSensitivity.NONE,
        ),
    ),
    Finding(
        "F-005",
        "CVE-2024-3400",
        "Auth bypass",
        9.3,
        ExploitMaturity.FUNCTIONAL,
        AssetContext(
            "vpn-gateway",
            internet_facing=True,
            criticality=Criticality.HIGH,
            data_sensitivity=DataSensitivity.INTERNAL,
        ),
    ),
]
