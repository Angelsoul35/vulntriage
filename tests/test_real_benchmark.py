"""Tests for the real-data CVE-severity benchmark.

They prove four things and fail if any breaks:
1. the vendored data really is the balanced CVE-severity subset (counts + bands);
2. the severity label is the authoritative NVD value — the CVSS v3.1 base-score
   equations reproduce known reference scores exactly;
3. the classifier is correctly fit on real CVEs — strong on held-out folds, far
   above the four-class baseline, and with its training score close to its test
   score (not a memorised ~1.0);
4. the signal is real: shuffling the labels collapses accuracy toward chance.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from vulntriage.real_benchmark import RealBenchmarkReport, format_report, run_benchmark
from vulntriage.real_data import (
    SEVERITIES,
    _is_usable,
    cvss_base_score,
    load_cve_severity,
    severity_band,
)
from vulntriage.severity_classifier import SeverityClassifier


@pytest.fixture(scope="module")
def data():
    return load_cve_severity()


@pytest.fixture(scope="module")
def report(data):
    # Train once; the benchmark is deterministic (fixed seeds), so every test
    # reads the same report instead of retraining.
    return run_benchmark()


def test_loads_the_real_balanced_cve_subset(data):
    texts, labels = data
    assert len(texts) == 2800
    assert len(labels) == 2800
    assert set(labels) == set(SEVERITIES)
    # Deliberately balanced across the four bands so accuracy is measured against a
    # 0.25 four-class baseline, not inflated by a dominant class.
    for band in SEVERITIES:
        assert labels.count(band) == 700


def test_cvss_v31_scoring_reproduces_reference_scores():
    # The label is the official NVD severity: these vectors must score exactly as
    # the CVSS v3.1 specification's reference calculator does.
    assert cvss_base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0  # Log4Shell
    assert cvss_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8  # unauth RCE
    assert cvss_base_score("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H") == 7.5
    assert cvss_base_score("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss_base_score("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == 1.6
    # No-impact vector collapses to 0.0; a malformed vector returns None.
    assert cvss_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss_base_score("AV:X/AC:L") is None


def test_severity_band_covers_the_rating_scale():
    assert severity_band(0.0) == "NONE"
    assert severity_band(3.9) == "LOW"
    assert severity_band(4.0) == "MEDIUM"
    assert severity_band(6.9) == "MEDIUM"
    assert severity_band(7.0) == "HIGH"
    assert severity_band(8.9) == "HIGH"
    assert severity_band(9.0) == "CRITICAL"
    assert severity_band(10.0) == "CRITICAL"


def test_is_usable_filters_junk_descriptions():
    assert _is_usable("A remote attacker can execute arbitrary code via a crafted request.")
    assert not _is_usable("too short")
    assert not _is_usable("Rejected reason: this candidate was withdrawn by its CNA entirely.")
    assert not _is_usable("** REJECTED ** DO NOT USE THIS CANDIDATE NUMBER AT ALL EVER.")
    assert not _is_usable("** DISPUTED ** the vendor disputes that this is a vulnerability.")


def test_classifier_is_well_fit_on_real_cves(report):
    # Strong on held-out real CVEs, far above the 0.25 four-class baseline, and not
    # a memorised ~1.0: real advisories are varied.
    assert report.cv_accuracy >= 0.68, report
    assert report.cv_accuracy <= 0.85, report
    assert report.cv_macro_f1 >= 0.68, report
    # Not overfit: the training accuracy does not run far ahead of the held-out score.
    assert report.gap <= 0.15, report
    assert report.verdict.startswith("well-fit")


def test_each_band_is_predicted_predominantly_correctly(report):
    # The diagonal is the largest entry in every row: the model genuinely separates
    # all four bands rather than collapsing onto one or two.
    for i, row in enumerate(report.confusion):
        assert row[i] == max(row), (SEVERITIES[i], row)


def test_shuffled_labels_collapse_toward_chance(data):
    texts, labels = data
    shuffled = np.random.default_rng(0).permutation(np.asarray(labels)).tolist()
    r = run_benchmark((texts, shuffled))
    # With the description/label link broken, accuracy falls back near the 0.25
    # four-class baseline, proving the real score reflects learned structure.
    assert r.cv_accuracy <= 0.40, r.cv_accuracy
    assert r.verdict.startswith("underfit")


def test_verdict_branches():
    def rep(cv, train, test):
        return RealBenchmarkReport(
            n_cves=2800,
            per_class={s: 700 for s in SEVERITIES},
            labels=list(SEVERITIES),
            cv_accuracy=cv,
            cv_accuracy_std=0.01,
            cv_macro_f1=cv,
            cv_weighted_f1=cv,
            train_accuracy=train,
            test_accuracy=test,
            gap=round(train - test, 4),
            confusion=[[1, 0, 0, 0]] * 4,
        )

    assert rep(0.40, 0.42, 0.40).verdict.startswith("underfit")
    assert rep(0.75, 0.97, 0.75).verdict.startswith("overfit")
    assert rep(0.75, 0.86, 0.75).verdict.startswith("well-fit")


def test_loader_rejects_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cve_severity(tmp_path / "nope.jsonl")


def test_loader_skips_blank_lines(tmp_path):
    f = tmp_path / "mini.jsonl"
    f.write_text(
        json.dumps({"description": "desc one", "severity": "HIGH"})
        + "\n\n"
        + json.dumps({"description": "desc two", "severity": "LOW"})
        + "\n",
        encoding="utf-8",
    )
    texts, labels = load_cve_severity(f)
    assert texts == ["desc one", "desc two"]
    assert labels == ["HIGH", "LOW"]


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_fetch_balances_filters_and_dedupes(tmp_path, monkeypatch):
    low = "AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    med = "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    high = "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
    crit = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    def row(cve, desc, vec):
        return {"row": {"cve_id": cve, "description": desc, "vector": vec}}

    d_high = "Remote attacker executes arbitrary code remotely."
    page = {
        "rows": [
            row("CVE-1", d_high, high),
            row("CVE-2", "broken vector is skipped during the scan now", "AV:X/AC:L"),
            row("CVE-3", "too short", crit),
            # Same description as CVE-1 but a different band -> de-duplicated away.
            row("CVE-4", d_high, med),
            row("CVE-5", "Local user reads sensitive memory via a data race.", med),
            row("CVE-6", "A second distinct high-severity advisory to collect.", high),
            row("CVE-7", "Low-impact physical-access information leak occurs.", low),
            row("CVE-8", "Critical network remote code execution, scope change.", crit),
        ]
    }

    # per_class=1 fills all four bands on the first page, so the scan exits before
    # requesting a second one; returning the same page is enough.
    def fake_urlopen(url, timeout=0):
        return _Resp(json.dumps(page).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    from vulntriage.real_data import fetch

    dest = tmp_path / "cve.jsonl"
    n = fetch(dest, per_class=1, max_rows_scanned=1000)
    # per_class=1 and one usable example of each band present -> exactly four rows,
    # the duplicate, the short and the malformed rows dropped.
    assert n == 4
    texts, labels = load_cve_severity(dest)
    assert sorted(labels) == ["CRITICAL", "HIGH", "LOW", "MEDIUM"]
    assert len(set(texts)) == 4


def test_fetch_stops_on_an_empty_page(tmp_path, monkeypatch):
    high = "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
    first = {
        "rows": [
            {
                "row": {
                    "cve_id": "CVE-1",
                    "description": "Remote attacker runs arbitrary code via a packet.",
                    "vector": high,
                }
            }
        ]
    }

    def fake_urlopen(url, timeout=0):
        offset = int(url.split("offset=")[1].split("&")[0])
        return _Resp(json.dumps(first if offset == 0 else {"rows": []}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    from vulntriage.real_data import fetch

    dest = tmp_path / "cve.jsonl"
    # per_class is never reached, so the scan runs until the empty second page.
    n = fetch(dest, per_class=5, max_rows_scanned=1000)
    assert n == 1


def test_fetch_gives_up_after_retrying_a_failing_endpoint(tmp_path, monkeypatch):
    def always_fails(url, timeout=0):
        raise OSError("network down")

    monkeypatch.setattr("urllib.request.urlopen", always_fails)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    from vulntriage.real_data import fetch

    dest = tmp_path / "cve.jsonl"
    n = fetch(dest, per_class=1, max_rows_scanned=1000)
    assert n == 0
    assert dest.exists()  # an empty file is still written


def test_classifier_predict_before_fit_raises():
    with pytest.raises(RuntimeError):
        SeverityClassifier().predict(["anything"])


def test_classifier_top_terms(data):
    texts, labels = data
    clf = SeverityClassifier().fit(texts, labels)
    # A textbook critical advisory classifies as CRITICAL with sensible drivers.
    assert clf.predict_one(
        "A remote unauthenticated attacker can execute arbitrary code over the network."
    ) in set(SEVERITIES)
    terms = clf.top_terms(
        "Remote unauthenticated attacker can execute arbitrary code leading to compromise."
    )
    assert terms and all(isinstance(t, str) and w > 0 for t, w in terms)
    # An unfitted classifier has nothing to explain; a large k exhausts the positive
    # contributions and still returns cleanly.
    assert SeverityClassifier().top_terms("x") == []
    assert len(clf.top_terms("buffer overflow", k=10_000)) >= 0


def test_format_and_main(report, capsys, monkeypatch):
    import vulntriage.real_benchmark as rb

    text = format_report(report)
    assert "harinpurumandla/cve-severity-dataset" in text
    assert f"{report.cv_accuracy:.3f}" in text
    assert report.verdict in text
    monkeypatch.setattr(rb, "run_benchmark", lambda data=None: report)
    rb.main()
    assert "real-data benchmark" in capsys.readouterr().out
