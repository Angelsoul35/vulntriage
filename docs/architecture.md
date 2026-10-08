# Architecture

vulntriage turns a backlog of vulnerability findings into a prioritised,
explained worklist. This document describes the pieces, the scoring model, and
the data flow.

## The pieces

| Layer         | Module                  | Responsibility                                       |
| ------------- | ----------------------- | ---------------------------------------------------- |
| Model         | `vulntriage/models.py`  | Findings, asset context, factors, triage result      |
| Scoring       | `vulntriage/scoring.py` | Additive, decomposable priority score + P1-P4 + SLA  |
| Notes         | `vulntriage/notes.py`   | LLM remediation note with a templated fallback       |
| LLM           | `vulntriage/llm/`       | Provider-agnostic client with a fallback cascade     |
| Orchestration | `vulntriage/service.py` | Score, prioritise, rank, annotate                    |
| Data          | `vulntriage/samples.py` | A synthetic backlog for the demo and tests           |
| HTTP API      | `vulntriage/main.py`    | `/triage` over REST                                  |
| CLI           | `vulntriage/cli.py`     | Demo                                                 |

## Data flow

```mermaid
flowchart LR
    A[Backlog] --> B["triage()"]
    B --> C[Finding]
    C --> D["score()"]
    D -->|"score, priority, SLA, factors"| E["advisor.note()"]
    E --> F[TriageResult]
    F -->|sort by score desc| G[Worklist]
```

## Severity is not priority

The central idea is the separation of **technical severity** (the CVSS base score,
raised by exploit maturity) from **environmental risk** (is the asset
internet-facing, business critical, holding sensitive data). CVSS answers "how bad
is this vulnerability in the abstract?"; triage must answer "which one do we fix
first given our estate?". Combining the two is what reorders the backlog so an
internet-facing, exploited, crown-jewel finding outranks a higher-CVSS but
isolated and exploit-free one.

## The additive model, and why additive

`score_factors` emits one `Factor` per contributing dimension; the score is their
sum, capped at 100, and mapped to a priority/SLA by fixed thresholds. Additivity
is a deliberate choice: it keeps the score **decomposable** — a result carries the
exact list of points and reasons that produced it — so a priority can be explained
to the owner who must act on it and challenged if a factor is wrong. A
multiplicative or learned score would be harder to justify line by line, which
matters more here than squeezing out marginal ranking accuracy.

## Why rules, not a learned model

Three reasons: prioritisation decisions must be **auditable and tunable** by
security teams to their own risk appetite; the factors (exploit maturity, asset
criticality) encode durable domain knowledge that does not drift; and there is no
ground-truth "correct priority" dataset to train on — priority is a policy choice,
not a fact to be predicted. This is the same learning-vs-policy split used across
the portfolio: the judgement with consequences stays explicit.

## The notes layer

Scoring decides priority; the notes layer only writes the prose recommendation.
It is the one place an LLM is used, via the provider cascade, and it degrades to a
templated note built from the same facts when no provider is reachable — so the
LLM improves readability without becoming a dependency, and the recommendation is
always present and offline-capable. Each note records whether it came from the LLM
or the fallback.

## Extension points

- **Factors and weights.** `_EXPLOIT_POINTS`, `_CRITICALITY_POINTS`,
  `_DATA_POINTS`, the CVSS multiplier and the level thresholds are plain data.
- **New signals.** An EPSS probability or a known-exploited-vulnerabilities flag
  is a new `Factor`; the additive model absorbs it without restructuring.
- **Notes.** The prompt and the templated fallback live in one module.
