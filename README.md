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

Prioritisation is **rule-based, not learned**, and deliberately so: it drives
where limited remediation effort goes and must be defensible to the teams it tasks,
so an auditable, tunable rule set is the right tool, and *priority is a policy
choice* with no ground-truth dataset to learn from. **Severity is different** — it
is a *fact* the NVD publishes as a CVSS vector — so vulntriage learns it: see
*Learned severity from a description* below.

## Remediation notes: LLM-assisted, with a fallback

The priority and SLA are decided by the rules; the LLM only writes the
human-readable recommendation. The advisor sends the finding and its context to
the provider cascade (Anthropic → OpenAI → Gemini → DeepSeek → Ollama) for a
concrete remediation sentence. When no provider is reachable, a templated note
assembled from the same facts is used, so a recommendation is always produced and
the pipeline runs fully offline. Each note records its `source` (`llm` or
`heuristic`).

## Learned severity from a description

A finding often arrives as prose — a vendor advisory, a bug-tracker note, a
scanner blurb — before anyone has hand-assigned a CVSS vector. `SeverityClassifier`
(`vulntriage/severity_classifier.py`) estimates the CVSS severity band (LOW /
MEDIUM / HIGH / CRITICAL) directly from that description, so the finding can be
placed on the same severity scale the rule-based score expects. It is a transparent,
linear model in the same spirit as the rest of the design: two TF-IDF views (word
unigrams/bigrams for phrasing, character n-grams for the terse, abbreviation-heavy
style of advisories) feeding a regularised multinomial logistic regression, so the
terms behind a prediction can be read off directly.

This is the counterpart to the rule-based scorer, not a replacement: *priority*
stays an explicit policy decision, while *severity* — a published fact — is
learned and measured.

### Validated on real CVE data

The classifier is trained and measured on **real** vulnerabilities: a balanced
2,800-CVE subset of the public `harinpurumandla/cve-severity-dataset` (descriptions
from the NIST National Vulnerability Database, labelled with the severity band
derived from each CVE's official CVSS v3.1 vector), vendored under
[`datasets/`](datasets/) with full provenance. Run `python -m vulntriage.real_benchmark`:

```
CVEs: 2800 balanced across 4 bands (LOW 700 / MEDIUM 700 / HIGH 700 / CRITICAL 700)
baseline (four-class chance): 0.250

CV accuracy    : 0.757 +/- 0.009
CV macro-F1    : 0.755
CV weighted-F1 : 0.755
train / test   : 0.880 / 0.753  (gap 0.127)   -> well-fit

confusion matrix (held-out; rows = actual, cols = predicted):
                   LOW    MEDIUM      HIGH  CRITICAL
       LOW         138        22         7         8
    MEDIUM          29       123        14         9
      HIGH          13        10       119        33
  CRITICAL          13         4        11       147
```

Two things are worth noting:

* **0.76 accuracy is three times the 0.25 four-class baseline**, cross-validated
  with a small train/test gap — strong and well-fit, not a memorised 1.0. The
  subset is balanced across the four bands on purpose, so the number is measured
  against a clean chance baseline and cannot be inflated by a dominant class.
* **The errors are between neighbouring bands.** Almost all confusion is HIGH↔CRITICAL
  or LOW↔MEDIUM — the model rarely calls a LOW a CRITICAL — which is exactly the
  behaviour a severity estimate should have, since the boundaries are a continuous
  CVSS score cut into bands.

Shuffling the labels collapses accuracy back toward the 0.25 baseline, which the
test suite asserts — the measured score reflects learned structure in the
descriptions, not leakage.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m vulntriage.cli demo          # triage a sample backlog, offline
python -m vulntriage.real_benchmark    # train & measure the severity model on real CVEs
uvicorn vulntriage.main:app --reload   # HTTP API
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
fallback), the service (ranking), the HTTP API (ranking, empty, bad enum), the CLI,
and the **real-data severity benchmark** (the NVD-derived CVSS v3.1 label equations
against published reference scores, the well-fit check on real CVEs, a
shuffled-label collapse to the four-class baseline, the verdict branches, and the
fetch path). The new benchmark modules are at 100% line coverage. Nothing in the
tests touches a network.

## Documentation

- `docs/architecture.md` — the scoring model, the severity classifier, the notes
  layer, and the data flow.
- `docs/adr/` — the main design decisions and their trade-offs.
- `docs/estudio/` — a study guide in Spanish, including the real-data benchmark.
- `datasets/` — the vendored real CVE-severity subset and its provenance.

## License

[MIT](LICENSE) © Angelo David Padilla Romero
