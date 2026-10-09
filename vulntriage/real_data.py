"""Load the real ``harinpurumandla/cve-severity-dataset`` of CVE descriptions.

vulntriage prioritises findings with a deterministic, auditable rule set, because
*priority* is a policy choice with no ground truth to learn (see
``docs/adr/0003-rules-not-learned.md``). *Severity*, by contrast, **is** a fact: the
NVD assigns every CVE a CVSS vector, and the CVSS v3.1 base score maps to a
qualitative band (LOW / MEDIUM / HIGH / CRITICAL). That band can be recovered from
the free-text description alone, which is exactly what this real-data benchmark
measures — so when a finding arrives as prose with no score attached yet, the
learned severity model can estimate the band that feeds the rule-based CVSS factor.

This module loads a **real**, public dataset of CVE descriptions paired with their
official CVSS v3.1 vector (``harinpurumandla/cve-severity-dataset`` on Hugging Face,
built from the National Vulnerability Database). The label is derived from the
vector with the canonical CVSS v3.1 base-score equations, so the ground truth is
the authoritative NVD severity, not a guess.

A balanced, representative subset is **vendored** under ``datasets/`` (see
``datasets/README.md`` for provenance) so the benchmark and its tests run offline
and deterministically. :func:`fetch` refreshes that subset from the Hugging Face
datasets-server.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DATASET_PATH = _REPO_ROOT / "datasets" / "cve_severity_real.jsonl"
_HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows?dataset=harinpurumandla%2F"
    "cve-severity-dataset&config=default&split=train&offset={offset}&length=100"
)

# The qualitative severity bands we model, in increasing order. NONE (base score 0)
# does not occur for real published CVEs and is excluded.
SEVERITIES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# CVSS v3.1 base-metric weights (from the first.org specification).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup: round to one decimal, always up at the hundredths place."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_base_score(vector: str) -> float | None:
    """Return the CVSS v3.1 base score for a base-metric ``vector``, or ``None``.

    Implements the canonical CVSS v3.1 equations so the severity label is the
    authoritative NVD score, not an approximation. Returns ``None`` for a vector
    that is missing a required base metric or uses an unknown metric value.
    """
    metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        conf, integ, avail = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_band(score: float) -> str:
    """Map a CVSS base score to its NVD qualitative band (CVSS v3.1 rating scale)."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def load_cve_severity(path: str | Path | None = None) -> tuple[list[str], list[str]]:
    """Return ``(descriptions, severities)`` from the vendored real CVE subset.

    Raises :class:`FileNotFoundError` if the vendored file is missing, so a broken
    checkout fails loudly instead of silently training on nothing.
    """
    p = Path(path) if path is not None else _DATASET_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"Vendored CVE severity data not found at {p}. Run "
            "`python -c 'from vulntriage.real_data import fetch; fetch()'` to download it."
        )
    descriptions: list[str] = []
    severities: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        descriptions.append(str(row["description"]))
        severities.append(str(row["severity"]))
    return descriptions, severities


def _is_usable(description: str) -> bool:
    text = description.strip()
    if len(text) < 40:
        return False
    low = text.lower()
    return not (low.startswith("rejected reason") or "** rejected" in low or "** disputed" in low)


def fetch(
    dest: str | Path | None = None,
    per_class: int = 700,
    max_rows_scanned: int = 60000,
) -> int:
    """Download a class-balanced CVE-severity subset into ``datasets/``.

    Scans the Hugging Face datasets-server, derives each CVE's severity band from
    its official CVSS v3.1 vector, de-duplicates descriptions (so no near-identical
    advisory leaks between train and test), and keeps up to ``per_class`` examples
    of each band. Needs network access; only used to create or refresh the vendored
    file. Returns the number of rows written.
    """
    import time
    import urllib.request

    target = Path(dest) if dest is not None else _DATASET_PATH
    collected: dict[str, list[dict]] = {s: [] for s in SEVERITIES}
    seen: set[str] = set()
    offset = 0
    while offset < max_rows_scanned and any(len(v) < per_class for v in collected.values()):
        url = _HF_ROWS_URL.format(offset=offset)
        payload = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed URL
                    payload = json.load(resp)
                break
            except Exception:  # noqa: BLE001 - retry transient gaps before giving up
                if attempt == 3:
                    payload = None
                    break
                time.sleep(1.5 * (attempt + 1))
        if payload is None:
            break
        batch = payload.get("rows", [])
        if not batch:
            break
        for item in batch:
            row = item["row"]
            description = str(row.get("description", ""))
            score = cvss_base_score(str(row.get("vector", "")))
            if score is None or not _is_usable(description):
                continue
            band = severity_band(score)
            if band not in collected or len(collected[band]) >= per_class:
                continue
            key = " ".join(description.lower().split())
            if key in seen:
                continue
            seen.add(key)
            collected[band].append(
                {
                    "cve_id": str(row.get("cve_id", "")),
                    "description": description.strip(),
                    "severity": band,
                    "cvss": score,
                }
            )
        offset += 100

    rows: list[dict] = []
    for band in SEVERITIES:
        rows.extend(collected[band])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
    )
    return len(rows)
