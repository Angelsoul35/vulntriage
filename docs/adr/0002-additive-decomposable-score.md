# ADR 0002: An additive, decomposable score

## Status

Accepted.

## Context

The priority score drives where limited remediation effort goes, so when an owner
is told "patch this in 7 days" they will — and should — ask "why is this a P1?".
A score they cannot decompose is a score they cannot trust or challenge.

## Decision

Make the score **additive**: each dimension (CVSS, exploit maturity, criticality,
data sensitivity, internet exposure) contributes a `Factor` with points and a
reason, the score is their sum (capped at 100), and the `TriageResult` carries the
full factor list. Priority and SLA follow from fixed score thresholds.

## Consequences

- **Every priority is explainable.** The result literally lists the points and the
  reason for each — "CVSS 9.8 ×4 = 39.2, weaponized +24, internet-facing +15".
- **Challengeable.** If a factor is wrong (the asset is not actually
  internet-facing), the owner can point to it and the score recomputes transparently.
- **Easy to tune.** Weights are plain data, adjusted to an organisation's risk
  appetite without touching logic.
- **Trade-off.** An additive model cannot express interaction effects (e.g.
  "internet-facing *and* weaponized" being worse than the sum). The gain in
  transparency is worth it; a genuine interaction can be added as its own explicit
  factor rather than hidden in a multiplication.
