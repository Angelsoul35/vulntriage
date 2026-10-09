"""A learned severity classifier for CVE descriptions.

vulntriage decides *priority* with an auditable rule set, because priority is a
policy choice with no ground truth. *Severity* is different: it is a fact the NVD
publishes as a CVSS vector, and the base score maps to a qualitative band
(LOW / MEDIUM / HIGH / CRITICAL). This classifier learns that band from the CVE's
free-text description, so a finding that arrives as prose — a vendor advisory, a
bug-tracker note — can be placed on the same severity scale the rule-based score
expects, before anyone has hand-assigned a CVSS vector.

The approach mirrors the rest of the design: a transparent, linear model. Two
TF-IDF views are combined — word unigrams/bigrams capture phrasing ("remote
attacker", "arbitrary code"), character n-grams (``char_wb``, 3-5) capture
sub-word cues and survive the terse, abbreviation-heavy style of advisories. A
multinomial, class-weight-balanced :class:`LogisticRegression` on top keeps every
decision a weighted sum of features, so the terms driving a prediction can be
read off directly.
"""

from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion


def _build_features() -> FeatureUnion:
    # The ``min_df`` floors drop once-off tokens (version strings, product names)
    # that otherwise let the model memorise individual advisories; this is the
    # regularisation on the feature side that keeps training and held-out accuracy
    # close (see ``vulntriage.real_benchmark`` and the study guide).
    return FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=4, sublinear_tf=True),
            ),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=8)),
        ]
    )


class SeverityClassifier:
    """Predict a CVE's severity band (LOW/MEDIUM/HIGH/CRITICAL) from its description.

    ``C`` defaults to ``0.4`` — the regularisation strength that reaches the data's
    attainable signal on real CVEs with the training and held-out accuracy closest
    together (a less regularised model memorises advisory wording; a more
    regularised one starts shedding cross-validated accuracy).
    """

    def __init__(self, C: float = 0.4) -> None:
        self._features = _build_features()
        self._model = LogisticRegression(max_iter=2000, C=C, class_weight="balanced")
        self._fitted = False

    def fit(self, texts: list[str], labels: list[str]) -> SeverityClassifier:
        x = self._features.fit_transform(texts)
        self._model.fit(x, labels)
        self._fitted = True
        return self

    def predict(self, texts: list[str]) -> list[str]:
        if not self._fitted:
            raise RuntimeError("Classifier is not fitted. Call fit() first.")
        x = self._features.transform(texts)
        return [str(p) for p in self._model.predict(x)]

    def predict_one(self, text: str) -> str:
        """Return the predicted severity band for a single description."""
        return self.predict([text])[0]

    def top_terms(self, text: str, k: int = 4) -> list[tuple[str, float]]:
        """The readable word features pushing hardest toward the predicted band."""
        if not self._fitted:
            return []
        x = self._features.transform([text])
        label = self._model.predict(x)[0]
        row = int(np.where(self._model.classes_ == label)[0][0])
        contributions = x.toarray().ravel() * self._model.coef_[row]
        names = self._features.get_feature_names_out()
        order = np.argsort(contributions)[::-1]
        out: list[tuple[str, float]] = []
        for i in order:
            if contributions[i] <= 0:
                break
            name = names[i]
            if name.startswith("word__"):
                out.append((name.removeprefix("word__"), round(float(contributions[i]), 4)))
            if len(out) >= k:
                break
        return out
