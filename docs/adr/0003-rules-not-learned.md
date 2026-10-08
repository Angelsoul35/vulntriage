# ADR 0003: Rule-based scoring, not a learned model

## Status

Accepted.

## Context

Could the priority be learned from historical triage decisions? In principle, but
three things argue against it here, as they did for pqrs-router and reconforge.

## Decision

Score with an explicit, weighted **rule set**, not a machine-learned model.

## Consequences

- **Auditable and tunable.** Security teams must be able to inspect and adjust how
  priority is computed to match their own risk appetite; a rule set makes that a
  config change, a model makes it a retraining project.
- **No drift, durable knowledge.** The factors (exploit maturity, asset
  criticality) encode stable domain knowledge that does not degrade as data shifts.
- **No ground truth to learn from.** Priority is a *policy choice*, not an
  objective fact to predict; there is no unambiguous labelled dataset of "correct"
  priorities, so supervised learning would just encode one team's past habits,
  biases included.
- **Trade-off.** Rules will not discover a non-obvious predictor the way a model
  might. For a decision that must be defended to the people it tasks, explicit and
  defensible beats clever and opaque; a discovered signal can always be promoted to
  an explicit factor after review.
