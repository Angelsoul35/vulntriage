from __future__ import annotations

from fastapi.testclient import TestClient

from vulntriage import cli
from vulntriage.llm.fake import FailingLLM
from vulntriage.service import TriageService


def _client():
    import vulntriage.main as main

    main._service = TriageService(llm=FailingLLM())
    return TestClient(main.app)


def test_api_triage_ranks():
    client = _client()
    assert client.get("/health").json() == {"status": "ok"}

    resp = client.post(
        "/triage",
        json=[
            {"id": "A", "cve": "CVE-1", "cvss_base": 10.0, "exploit_maturity": "weaponized",
             "asset_name": "api", "internet_facing": True, "criticality": "high",
             "data_sensitivity": "sensitive"},
            {"id": "B", "cve": "CVE-2", "cvss_base": 4.0, "exploit_maturity": "none",
             "asset_name": "lab", "internet_facing": False, "criticality": "low",
             "data_sensitivity": "none"},
        ],
    )
    assert resp.status_code == 200
    worklist = resp.json()["worklist"]
    assert worklist[0]["cve"] == "CVE-1"
    assert worklist[0]["priority"] == "P1"


def test_api_empty_and_bad_enum():
    client = _client()
    assert client.post("/triage", json=[]).status_code == 422
    bad = client.post(
        "/triage",
        json=[{"id": "A", "cve": "C", "cvss_base": 5.0, "exploit_maturity": "nope",
               "asset_name": "x", "criticality": "low", "data_sensitivity": "none"}],
    )
    assert bad.status_code == 422


def test_cli_demo_runs(capsys):
    cli.demo()
    out = capsys.readouterr().out
    assert "Prioritised worklist" in out
    assert "P1" in out
    assert "CVE-2021-44228" in out


def test_cli_main_dispatch(monkeypatch):
    called = {"demo": False}
    monkeypatch.setattr(cli, "demo", lambda: called.__setitem__("demo", True))
    monkeypatch.setattr("sys.argv", ["vulntriage", "demo"])
    cli.main()
    assert called["demo"] is True
