"""vulntriage command-line demo."""

from __future__ import annotations

import argparse

from .samples import SAMPLE_BACKLOG
from .service import TriageService


def demo() -> None:
    print("1) Triaging a sample vulnerability backlog ...")
    service = TriageService()
    print(f"   (remediation notes via {service.llm.model}, offline fallback if unreachable)\n")

    results = service.triage(SAMPLE_BACKLOG)
    print("2) Prioritised worklist (highest risk first):")
    for r in results:
        print(f"   [{r.priority.value}] score {r.score:>5}  SLA {r.sla_days:>3}d  "
              f"{r.cve}  ({r.finding_id})")
        drivers = ", ".join(f"{f.name}+{f.points:g}" for f in r.factors)
        print(f"        drivers: {drivers}")
        print(f"        fix [{r.note_source}]: {r.recommendation}")


def main() -> None:
    parser = argparse.ArgumentParser(description="vulntriage CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="triage a built-in sample backlog")
    args = parser.parse_args()
    if args.command == "demo":
        demo()


if __name__ == "__main__":
    main()
