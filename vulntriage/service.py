"""Triage findings: score, prioritise, order the worklist, and annotate."""

from __future__ import annotations

from .config import Settings, get_settings
from .llm.base import LLMClient
from .llm.factory import build_llm
from .models import Finding, TriageResult
from .notes import RemediationAdvisor
from .scoring import score


class TriageService:
    def __init__(
        self,
        settings: Settings | None = None,
        llm: LLMClient | None = None,
        advisor: RemediationAdvisor | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.llm = llm if llm is not None else build_llm(self.settings.llm_spec)
        self.advisor = advisor or RemediationAdvisor(
            llm=self.llm, max_tokens=self.settings.llm_max_tokens
        )

    def triage_one(self, finding: Finding) -> TriageResult:
        total, priority, sla, factors = score(finding)
        note, source = self.advisor.note(finding, priority, sla)
        return TriageResult(
            finding_id=finding.id,
            cve=finding.cve,
            score=total,
            priority=priority,
            sla_days=sla,
            factors=factors,
            recommendation=note,
            note_source=source,
        )

    def triage(self, findings: list[Finding]) -> list[TriageResult]:
        """Return the findings as a worklist ordered by priority score (desc)."""
        results = [self.triage_one(f) for f in findings]
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    @staticmethod
    def as_dict(result: TriageResult) -> dict:
        return {
            "finding_id": result.finding_id,
            "cve": result.cve,
            "score": result.score,
            "priority": result.priority.value,
            "sla_days": result.sla_days,
            "factors": [
                {"name": f.name, "points": f.points, "detail": f.detail}
                for f in result.factors
            ],
            "recommendation": result.recommendation,
            "note_source": result.note_source,
        }
