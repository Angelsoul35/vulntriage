"""Remediation notes: LLM-assisted, with a deterministic fallback.

The priority and SLA are decided by the scoring rules; this layer only writes the
human-readable *recommendation* that accompanies them. An LLM (via the provider
cascade) turns the finding and its context into a concrete sentence; when no
provider is reachable, a templated note assembled from the same facts is used, so
a recommendation is always produced.
"""

from __future__ import annotations

from .llm.base import LLMClient, LLMError
from .models import ExploitMaturity, Finding, Priority

_SYSTEM = (
    "You are a vulnerability remediation advisor. Given a finding and the context "
    "of the affected asset, write ONE concrete, actionable remediation sentence. "
    "Be specific and brief."
)


def _heuristic_note(finding: Finding, priority: Priority, sla_days: int) -> str:
    parts = [f"Patch {finding.cve} on {finding.asset.name}."]
    if finding.asset.internet_facing:
        parts.append(
            "Reduce external exposure (gateway/WAF or remove from the internet) meanwhile."
        )
    if finding.exploit_maturity in (ExploitMaturity.FUNCTIONAL, ExploitMaturity.WEAPONIZED):
        parts.append("Public exploit code exists — treat as actively exploitable.")
    if finding.asset.data_sensitivity.value == "sensitive":
        parts.append("Asset holds sensitive data; verify no compromise.")
    parts.append(f"Remediate within {sla_days} days ({priority.value}).")
    return " ".join(parts)


class RemediationAdvisor:
    def __init__(self, llm: LLMClient | None = None, max_tokens: int = 200) -> None:
        self.llm = llm
        self.max_tokens = max_tokens

    def note(self, finding: Finding, priority: Priority, sla_days: int) -> tuple[str, str]:
        if self.llm is not None:
            prompt = (
                f"Finding: {finding.cve} - {finding.title}\n"
                f"CVSS base: {finding.cvss_base}; exploit maturity: "
                f"{finding.exploit_maturity.value}\n"
                f"Asset: {finding.asset.name}; internet-facing: "
                f"{finding.asset.internet_facing}; criticality: "
                f"{finding.asset.criticality.value}; data: "
                f"{finding.asset.data_sensitivity.value}\n"
                f"Assigned priority: {priority.value} (SLA {sla_days} days)."
            )
            try:
                result = self.llm.complete(_SYSTEM, prompt, max_tokens=self.max_tokens)
                text = result.text.strip()
                if text:
                    return text, "llm"
            except LLMError:
                pass
        return _heuristic_note(finding, priority, sla_days), "heuristic"
