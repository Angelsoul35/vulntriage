"""Benchmark the severity classifier on REAL CVE descriptions.

Trains the project's own :class:`~vulntriage.severity_classifier.SeverityClassifier`
on a balanced subset of the real ``harinpurumandla/cve-severity-dataset`` (CVE
descriptions from the National Vulnerability Database, labelled with the severity
band derived from each CVE's official CVSS v3.1 vector) and reports whether the
model is correctly fit: cross-validated accuracy and macro/weighted F1, the
train/test gap, the confusion matrix, and a plain verdict.

The subset is balanced across the four bands, so the no-information baseline is the
0.25 chance of a four-way guess; the classifier is measured against that floor, not
a flattering accuracy inflated by a dominant class.

Run it with ``python -m vulntriage.real_benchmark``.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, train_test_split

from .real_data import SEVERITIES, load_cve_severity
from .severity_classifier import SeverityClassifier

_SEED = 42
_N_SPLITS = 5
# A balanced four-class problem: a no-information guess is right one time in four.
_BASELINE = 0.25
# Verdict thresholds. The floor sits well above the 0.25 chance baseline; the gap
# bound flags a model whose training score has run away from its held-out score.
_SIGNAL_FLOOR = 0.55
_GAP_LIMIT = 0.15


@dataclass
class RealBenchmarkReport:
    n_cves: int
    per_class: dict[str, int]
    labels: list[str]
    cv_accuracy: float
    cv_accuracy_std: float
    cv_macro_f1: float
    cv_weighted_f1: float
    train_accuracy: float
    test_accuracy: float
    gap: float
    confusion: list[list[int]]

    @property
    def verdict(self) -> str:
        if self.cv_accuracy < _SIGNAL_FLOOR:
            return "underfit: cross-validated accuracy is close to the four-class baseline"
        if self.gap > _GAP_LIMIT:
            return "overfit: training accuracy runs well ahead of held-out accuracy"
        return "well-fit: strong on held-out CVEs with training and test accuracy close"


def _cv_scores(texts: list[str], labels: list[str]) -> tuple[float, float, float, float]:
    """Out-of-fold accuracy (mean, std), macro-F1 and weighted-F1 on real CVEs."""
    y = np.asarray(labels)
    cv = StratifiedKFold(n_splits=_N_SPLITS, shuffle=True, random_state=_SEED)
    fold_acc: list[float] = []
    oof_true: list[str] = []
    oof_pred: list[str] = []
    for train_idx, test_idx in cv.split(texts, y):
        clf = SeverityClassifier().fit([texts[i] for i in train_idx], [y[i] for i in train_idx])
        pred = clf.predict([texts[i] for i in test_idx])
        truth = [y[i] for i in test_idx]
        fold_acc.append(accuracy_score(truth, pred))
        oof_true.extend(truth)
        oof_pred.extend(pred)
    macro = f1_score(oof_true, oof_pred, labels=list(SEVERITIES), average="macro", zero_division=0)
    weighted = f1_score(
        oof_true, oof_pred, labels=list(SEVERITIES), average="weighted", zero_division=0
    )
    return float(np.mean(fold_acc)), float(np.std(fold_acc)), float(macro), float(weighted)


def run_benchmark(data: tuple[list[str], list[str]] | None = None) -> RealBenchmarkReport:
    texts, labels = data if data is not None else load_cve_severity()
    cv_acc, cv_acc_std, cv_macro, cv_weighted = _cv_scores(texts, labels)

    y = np.asarray(labels)
    idx = np.arange(len(texts))
    train_idx, test_idx = train_test_split(idx, test_size=0.25, stratify=y, random_state=_SEED)
    clf = SeverityClassifier().fit([texts[i] for i in train_idx], [y[i] for i in train_idx])
    train_pred = clf.predict([texts[i] for i in train_idx])
    test_pred = clf.predict([texts[i] for i in test_idx])
    train_acc = accuracy_score([y[i] for i in train_idx], train_pred)
    test_acc = accuracy_score([y[i] for i in test_idx], test_pred)
    cm = confusion_matrix([y[i] for i in test_idx], test_pred, labels=list(SEVERITIES)).tolist()

    per_class = {s: int((y == s).sum()) for s in SEVERITIES}
    return RealBenchmarkReport(
        n_cves=len(texts),
        per_class=per_class,
        labels=list(SEVERITIES),
        cv_accuracy=round(cv_acc, 4),
        cv_accuracy_std=round(cv_acc_std, 4),
        cv_macro_f1=round(cv_macro, 4),
        cv_weighted_f1=round(cv_weighted, 4),
        train_accuracy=round(float(train_acc), 4),
        test_accuracy=round(float(test_acc), 4),
        gap=round(float(train_acc - test_acc), 4),
        confusion=cm,
    )


def format_report(r: RealBenchmarkReport) -> str:
    counts = " / ".join(f"{s} {r.per_class[s]}" for s in r.labels)
    lines = [
        "vulntriage — real-data benchmark (harinpurumandla/cve-severity-dataset)",
        "=" * 70,
        f"CVEs: {r.n_cves} balanced across {len(r.labels)} bands ({counts})",
        f"baseline (four-class chance): {_BASELINE:.3f}",
        "",
        f"CV accuracy    : {r.cv_accuracy:.3f} +/- {r.cv_accuracy_std:.3f}",
        f"CV macro-F1    : {r.cv_macro_f1:.3f}",
        f"CV weighted-F1 : {r.cv_weighted_f1:.3f}",
        f"train / test   : {r.train_accuracy:.3f} / {r.test_accuracy:.3f}  (gap {r.gap:.3f})",
        "",
        "confusion matrix (held-out; rows = actual, cols = predicted):",
        "            " + "".join(f"{s:>10}" for s in r.labels),
    ]
    for name, row in zip(r.labels, r.confusion, strict=True):
        lines.append(f"{name:>10}  " + "".join(f"{v:>10}" for v in row))
    lines += ["", f"verdict: {r.verdict}"]
    return "\n".join(lines)


def main() -> None:
    print(format_report(run_benchmark()))


if __name__ == "__main__":  # pragma: no cover
    main()
