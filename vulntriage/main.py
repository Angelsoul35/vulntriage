"""vulntriage HTTP API."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .models import (
    AssetContext,
    Criticality,
    DataSensitivity,
    ExploitMaturity,
    Finding,
)
from .service import TriageService

app = FastAPI(
    title="vulntriage",
    version="1.0.0",
    summary="Risk-based vulnerability prioritization with remediation notes.",
)

_service: TriageService | None = None


def get_service() -> TriageService:
    global _service
    if _service is None:
        _service = TriageService()
    return _service


class FindingRequest(BaseModel):
    id: str
    cve: str
    title: str = ""
    cvss_base: float = Field(ge=0.0, le=10.0)
    exploit_maturity: str = "none"
    asset_name: str
    internet_facing: bool = False
    criticality: str = "low"
    data_sensitivity: str = "none"


def _to_finding(r: FindingRequest) -> Finding:
    try:
        return Finding(
            id=r.id, cve=r.cve, title=r.title, cvss_base=r.cvss_base,
            exploit_maturity=ExploitMaturity(r.exploit_maturity),
            asset=AssetContext(
                name=r.asset_name,
                internet_facing=r.internet_facing,
                criticality=Criticality(r.criticality),
                data_sensitivity=DataSensitivity(r.data_sensitivity),
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/triage", tags=["triage"])
def triage(findings: list[FindingRequest]) -> dict:
    if not findings:
        raise HTTPException(status_code=422, detail="no findings provided")
    service = get_service()
    results = service.triage([_to_finding(f) for f in findings])
    return {"worklist": [service.as_dict(r) for r in results]}
