# Datasets — real CVE severity data

## `cve_severity_real.jsonl` — harinpurumandla/cve-severity-dataset

A **real**, public dataset of CVE descriptions paired with their official CVSS v3.1
vector, used to validate the severity model on real vulnerabilities (not only the
synthetic sample backlog). It is built from the National Vulnerability Database, the
authoritative U.S. government catalogue of disclosed vulnerabilities.

| | |
|---|---|
| **Origin** | `harinpurumandla/cve-severity-dataset` (Hugging Face), built from the NIST National Vulnerability Database |
| **Vendored subset** | 2,800 CVEs, balanced 700 per band, one JSON object per line: `{"cve_id", "description", "severity", "cvss"}` |
| **Label** | `severity` ∈ {LOW, MEDIUM, HIGH, CRITICAL}, derived from the CVE's CVSS v3.1 base score (the NVD qualitative rating scale) |
| **Retrieved** | 2026-10-09, via the Hugging Face datasets-server |
| **License** | dataset card: `other`; the underlying CVE/NVD records are public-domain U.S. government data (CVE List is CC0 by MITRE) |

### How the label is derived

The source carries each CVE's CVSS v3.1 base-metric vector (e.g.
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). `vulntriage.real_data.cvss_base_score`
implements the canonical CVSS v3.1 base-score equations, and `severity_band` maps
the score to the NVD qualitative rating (`0.1–3.9` LOW, `4.0–6.9` MEDIUM, `7.0–8.9`
HIGH, `9.0–10.0` CRITICAL). The label is therefore the authoritative NVD severity,
reproduced exactly (the test suite checks the equations against published reference
scores such as Log4Shell = 10.0).

### Why a balanced subset

The full NVD skews heavily toward HIGH and MEDIUM. The vendored subset takes an
equal 700 examples per band and de-duplicates descriptions, so the benchmark is
measured against a clean 0.25 four-class baseline and never inflated by a dominant
class or by near-identical advisories leaking between train and test.

### How it is used

`python -m vulntriage.real_benchmark` trains the project's own
`SeverityClassifier` (word + character TF-IDF with a regularised multinomial
logistic regression) on this data and reports cross-validated accuracy, macro/
weighted F1, the train/test gap and the confusion matrix. Measured result:
**0.757 accuracy / 0.755 macro-F1**, cross-validated, train/test `0.880 / 0.753`
(gap `0.127`) — strong and well-fit, three times the four-class baseline, not a
memorised 1.0.

The file is **vendored** (committed) so the benchmark and its tests run offline and
deterministically.

### Refreshing the file

```bash
python -c "from vulntriage.real_data import fetch; fetch()"   # re-downloads a balanced subset
```
