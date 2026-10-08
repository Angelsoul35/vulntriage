# ADR 0001: Priority from severity and context, not CVSS alone

## Status

Accepted.

## Context

The obvious way to triage a vulnerability backlog is to sort by CVSS base score.
But CVSS measures a vulnerability's severity *in the abstract* — it deliberately
excludes environmental factors. Sorting by it alone sends a team to patch a 9.8 on
an isolated lab box before a 6.1 on an internet-facing system that processes
payments. The ordering is wrong where it matters most.

## Decision

Compute priority from **both** technical severity (CVSS base, raised by exploit
maturity) **and** environmental risk (internet-facing, asset criticality, data
sensitivity). The combined score reorders the backlog so exposure and impact count,
mirroring modern frameworks (FIRST SSVC, EPSS-informed prioritisation).

## Consequences

- **Correct ordering.** An exploited, internet-facing, crown-jewel finding
  outranks a higher-CVSS but isolated one — demonstrated by the sample backlog.
- **Actionable.** The output is a worklist a team can follow top to bottom, with
  an SLA per item.
- **Needs asset context.** The model requires each finding to carry its asset's
  context; a deployment must feed that from a CMDB or asset inventory. That input
  requirement is explicit and is where the value comes from.
- **Trade-off.** The context dimensions are coarse (three levels each). Coarse,
  well-understood buckets are easier to populate accurately and to defend than a
  finer scale that invites false precision.
