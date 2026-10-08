from __future__ import annotations

from vulntriage.models import (
    AssetContext,
    Criticality,
    DataSensitivity,
    ExploitMaturity,
    Finding,
    Priority,
)
from vulntriage.scoring import score


def _finding(cvss, maturity, internet, crit, data):
    return Finding(
        "F",
        "CVE-X",
        "t",
        cvss,
        maturity,
        AssetContext("a", internet_facing=internet, criticality=crit, data_sensitivity=data),
    )


def test_weaponized_internet_crown_jewel_is_p1():
    total, priority, sla, _ = score(
        _finding(
            10.0, ExploitMaturity.WEAPONIZED, True, Criticality.HIGH, DataSensitivity.SENSITIVE
        )
    )
    assert priority is Priority.P1
    assert sla == 7
    assert total == 100.0  # capped


def test_context_outranks_raw_cvss():
    # A lower-CVSS internet-facing finding outranks a higher-CVSS isolated one.
    exposed = score(
        _finding(6.1, ExploitMaturity.POC, True, Criticality.LOW, DataSensitivity.NONE)
    )[0]
    isolated = score(
        _finding(7.8, ExploitMaturity.NONE, False, Criticality.LOW, DataSensitivity.NONE)
    )[0]
    assert exposed > isolated


def test_low_severity_isolated_is_p4():
    total, priority, _, _ = score(
        _finding(3.0, ExploitMaturity.NONE, False, Criticality.LOW, DataSensitivity.NONE)
    )
    assert priority is Priority.P4
    assert total == 12.0  # 3.0 * 4 only


def test_factors_are_decomposable_and_sum_to_score():
    total, _, _, factors = score(
        _finding(
            9.0, ExploitMaturity.FUNCTIONAL, True, Criticality.MEDIUM, DataSensitivity.INTERNAL
        )
    )
    assert round(sum(f.points for f in factors), 1) == total
    names = {f.name for f in factors}
    assert {"cvss", "exploit_maturity", "criticality", "data_sensitivity", "exposure"} == names
