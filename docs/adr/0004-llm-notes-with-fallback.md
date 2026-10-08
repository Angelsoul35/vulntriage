# ADR 0004: LLM only for the note, always with a fallback

## Status

Accepted.

## Context

A remediation recommendation reads better when written in fluent prose tailored to
the finding — a good fit for an LLM. But the *priority* must be deterministic and
offline-capable, and the tool cannot become unusable when no LLM is reachable.

## Decision

Confine the LLM to the **recommendation sentence** only. The priority, SLA and
factors are always the deterministic rules'. The advisor asks the provider cascade
for a concrete remediation note; if every provider fails, it returns a templated
note assembled from the same facts. Each note records its `source`.

## Consequences

- **The decision stays deterministic.** The LLM never influences priority — only
  how the recommendation is phrased — so results are reproducible and the ranking
  is stable regardless of provider availability.
- **Always offline-capable.** The templated fallback means the full pipeline runs
  with no API key and no network, which is how the demo and tests run.
- **Transparent.** The `source` field shows whether a note is model-written or
  templated.
- **Trade-off.** The templated note is blunter than an LLM's. That is acceptable:
  it still names the CVE, the asset, the exposure, the exploit status and the SLA —
  everything needed to act — and the LLM is a readability upgrade, not a crutch.
