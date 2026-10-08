from __future__ import annotations

from vulntriage.llm.fake import FailingLLM, FakeLLM
from vulntriage.models import (
    AssetContext,
    Criticality,
    DataSensitivity,
    ExploitMaturity,
    Finding,
    Priority,
)
from vulntriage.notes import RemediationAdvisor
from vulntriage.samples import SAMPLE_BACKLOG
from vulntriage.service import TriageService


def _finding():
    return Finding(
        "F",
        "CVE-2021-44228",
        "Log4Shell",
        10.0,
        ExploitMaturity.WEAPONIZED,
        AssetContext(
            "api",
            internet_facing=True,
            criticality=Criticality.HIGH,
            data_sensitivity=DataSensitivity.SENSITIVE,
        ),
    )


def test_llm_note_used_when_available():
    advisor = RemediationAdvisor(llm=FakeLLM("Upgrade log4j to 2.17.1 and restrict egress."))
    text, source = advisor.note(_finding(), Priority.P1, 7)
    assert source == "llm"
    assert "log4j" in text


def test_heuristic_note_when_llm_unavailable():
    advisor = RemediationAdvisor(llm=FailingLLM())
    text, source = advisor.note(_finding(), Priority.P1, 7)
    assert source == "heuristic"
    assert "CVE-2021-44228" in text
    assert "7 days" in text
    assert "exposure" in text.lower()


def test_service_triage_orders_by_score():
    service = TriageService(llm=FailingLLM())  # offline -> heuristic notes
    results = service.triage(SAMPLE_BACKLOG)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)
    assert results[0].cve == "CVE-2021-44228"  # Log4Shell first
    assert results[0].priority is Priority.P1
    assert all(r.note_source == "heuristic" for r in results)


def test_as_dict_shape():
    service = TriageService(llm=FailingLLM())
    d = service.as_dict(service.triage_one(_finding()))
    assert d["priority"] == "P1" and d["sla_days"] == 7
    assert d["factors"] and "recommendation" in d
