# vulntriage

Risk-based triage for a vulnerability backlog. It takes findings — each a CVE with
a CVSS base score, an exploit-maturity level, and the context of the asset it
affects — and produces a **prioritised worklist**: a 0-100 score decomposed into
named factors, a P1-P4 priority with an SLA, and an LLM-assisted remediation note.
The point is to rank by *real* risk, not by raw CVSS.

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why raw CVSS is not a priority

A CVSS base score measures a vulnerability's technical severity in isolation. It
says nothing about whether the affected asset is internet-facing, business
critical, or holds sensitive data, nor whether a working exploit exists. Triaging
by CVSS alone sends teams to patch a 9.8 on an isolated lab box before a 6.1 on an
internet-facing system that processes payments. vulntriage fixes the ordering by
combining severity with context — the same idea behind modern frameworks like
FIRST's SSVC and EPSS-informed prioritisation.

The sample backlog makes it concrete: a CVSS **6.1** XSS on an internet-facing
site outranks a CVSS **7.8** local privilege-escalation on an isolated,
exploit-free build agent; a CVSS **9.8** RCE on an internal host sits *below* two
internet-facing P1s.

## The scoring model

The priority score (0-100, capped) is an **additive** model so it is always the
sum of named, auditable factors:

| Factor            | Contribution                                                   |
| ----------------- | -------------------------------------------------------------- |
| CVSS base         | `cvss × 4`  (0-40)                                             |
| Exploit maturity  | none 0 · PoC +8 · functional +16 · weaponized +24              |
| Asset criticality | low 0 · medium +8 · high +18                                   |
| Data sensitivity  | none 0 · internal +4 · sensitive (PII/PHI/financial) +12       |
| Internet-facing   | +15                                                            |

Priority and SLA by score: `≥70 → P1 / 7 days`, `≥45 → P2 / 30 days`,
`≥25 → P3 / 90 days`, else `P4 / 180 days`. Every `TriageResult` lists the factors
that produced its score, so a priority can always be explained and challenged.

The model is **rule-based, not learned**. Prioritisation drives where limited
remediation effort goes and must be defensible to the teams it tasks — an
auditable, tunable rule set beats an opaque model, and there is no labelled
"correct priority" dataset to learn from anyway.

## Remediation notes: LLM-assisted, with a fallback

The priority and SLA are decided by the rules; the LLM only writes the
human-readable recommendation. The advisor sends the finding and its context to
the provider cascade (Anthropic → OpenAI → Gemini → DeepSeek → Ollama) for a
concrete remediation sentence. When no provider is reachable, a templated note
assembled from the same facts is used, so a recommendation is always produced and
the pipeline runs fully offline. Each note records its `source` (`llm` or
`heuristic`).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m vulntriage.cli demo        # triage a sample backlog, offline
uvicorn vulntriage.main:app --reload # HTTP API
```

```bash
curl -s -X POST localhost:8000/triage -H 'content-type: application/json' -d '[
  {"id":"F-1","cve":"CVE-2021-44228","cvss_base":10.0,"exploit_maturity":"weaponized",
   "asset_name":"payments-api","internet_facing":true,"criticality":"high",
   "data_sensitivity":"sensitive"}
]'
```

## Configuration

| Variable            | Default                                   | Meaning                        |
| ------------------- | ----------------------------------------- | ------------------------------ |
| `VT_LLM_SPEC`       | `anthropic,openai,gemini,deepseek,ollama` | Provider cascade for notes     |
| `VT_LLM_MAX_TOKENS` | `200`                                     | Max tokens per remediation note|

Provider API keys come from their own environment variables; with none set, the
templated note is used.

## Testing

```bash
ruff check vulntriage tests
pytest --cov=vulntriage --cov-report=term-missing --cov-fail-under=80
```

Covers the scoring model (factor decomposition, the context-beats-CVSS property,
level thresholds, the 100 cap), the remediation notes (LLM path and heuristic
fallback), the service (ranking), the HTTP API (ranking, empty, bad enum), and the
CLI. Nothing in the tests touches a network.

## Documentation

- `docs/architecture.md` — the scoring model, the notes layer, and the data flow.
- `docs/adr/` — the main design decisions and their trade-offs.
- `docs/estudio/` — a study guide in Spanish.

## License

MIT. See [LICENSE](LICENSE).
