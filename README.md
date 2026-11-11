# shapetrap

A command-line toolkit that audits lightweight web-injection detectors across datasets. It answers one question: **does a detector learn the attack, or the shape of the input?**

The *shape* of an input is the container it arrives in, regardless of what it carries: `q=laptop` (key-value), `laptop` (bare), `{"q": "laptop"}` (JSON), `/a/b` (path), or empty. Many public datasets put benign inputs in one container and attacks in another, so a classifier can score above 99% on its own test split without looking at the payload at all.

shapetrap trains TF-IDF detectors on one public dataset, tests them on all the others and on honeypot logs, changes only the container of the test inputs to see which decisions flip, and compares everything with the real OWASP Core Rule Set.

Everything runs on a CPU. No GPU, no containers, no network traffic is generated.

## Features

- **Cross-dataset transfer matrix.** Train on one source, test on every source, with family-grouped splits, a leakage purge per cell, and several seeds.
- **Six learners on the same features.** Logistic regression, naive Bayes, linear SVM, random forest, LightGBM, and a one-hidden-layer MLP.
- **Shape-only interventions.** The same test inputs are re-sent as bare values, as `key=value`, and as JSON. A decision that changes can only be caused by the container.
- **Integrity audit.** Overlap between sources at string, normalized-string, and value level, to find benchmarks that share one origin.
- **Container canonicalization.** Two preprocessing modes that remove the container before classification (`cstrip`, `vmil`).
- **Real OWASP CRS baseline.** Every string is scored by the Core Rule Set through libmodsecurity at paranoia levels 1 and 2.
- **Held-out sources.** Payload lists and SSH/web honeypot logs that are never trained on, with attempted credentials as a non-injection control.
- **Statistics included.** Wilson intervals, exact McNemar tests with Holm correction, exact Wilcoxon signed-rank tests, and source-level bootstrap intervals.
- **One report.** All tables end up in `out/REPORT.md`, with the raw numbers as CSV next to it.

## Install

Requires Python 3.11 or newer and git. The CRS baseline is optional and also needs a C compiler and libmodsecurity 3.

```bash
# Arch Linux
sudo pacman -S --needed python git gcc libmodsecurity

# Debian / Ubuntu
sudo apt install python3 python3-venv git gcc libmodsecurity-dev

git clone https://github.com/1337strike/shapetrap.git
cd shapetrap
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Without `gcc` or libmodsecurity the `crs` step is skipped with a message, and the local signature set is used as the reference instead.

## Quick start

```bash
shapetrap fetch      # download the 14 public source repositories into data/raw (about 950 MB)
shapetrap anchor     # sanity check against previously published numbers
shapetrap all        # build -> audit -> crs -> run -> probe -> explain -> report
pytest               # 48 tests
```

The result is `out/REPORT.md`. A full run takes about two hours on a laptop CPU (measured on an Intel Core i7-10610U with 16 GB RAM); the `run` step is most of it.

`fetch` checks out every repository at a pinned commit and, for large repositories, only the folders that are used.

## Commands

| Command | What it does | Main output |
|---|---|---|
| `fetch` | Download every source at its pinned commit | `data/raw/` |
| `build` | Clean, de-duplicate, drop label conflicts, cap per class | `out/corpus/` |
| `audit` | Overlap between sources at string, normalized-string, and value level | `audit_overlap.csv` |
| `crs` | Score every string with the OWASP CRS through libmodsecurity, paranoia levels 1 and 2 | `out/crs/` |
| `run` | Transfer matrix, shape interventions, held-out evaluation | `transfer_cells.csv`, `transfer_summary.csv`, `interventions.csv` |
| `render` | Rebuild report sections 3, 4, 6, 7, 8 from the CSV files of the last `run`, without retraining | `section_*.md` |
| `probe` | Model-free indicators: container per class, accuracy from the container alone, separability | `probe.csv` |
| `explain` | Logistic-regression coefficients: strongest cues, container tokens, features whose sign flips | `explain_*.csv` |
| `report` | Merge all sections into one report | `REPORT.md` |
| `all` | Every step above except `fetch` | |
| `anchor` | Re-derive the HttpParamsDataset result of an earlier study (see [Related publication](#related-publication)) | terminal |

Options: `--config PATH` (default `shapetrap.toml`) and `--out DIR`.

## How it works

1. **Two kinds of sources.** *Benchmark* sources have a benign class and an attack class, so they are used for training and testing. *Held-out* sources (`role = "test"`) are never trained on.
2. **Splits.** Each benchmark source is split 75/25 by payload *family*, stratified by class, once per seed. A family groups strings that differ only in numbers, quoted literals, whitespace, or case, so near-duplicates never straddle the split.
3. **Transfer.** A model is trained on the training split of source A and tested on the test split of every source. Before cell A→B is scored, test strings whose normalized form occurs in A's training split are removed.
4. **Metric.** An input counts as *flagged* when the prediction is anything other than `benign`. This keeps sources with untyped attacks comparable.
5. **Shape interventions.** Each test set is scored again with only the container changed: `bare` (keys removed), `kv` (wrapped as `key=value`), `json`. Tested with exact McNemar tests and Holm correction.
6. **Preprocessing modes.**
   - `raw`: the input as sent.
   - `canon`: percent-decoding (up to three rounds), HTML entities, `\uXXXX` escapes, SQL comment removal, whitespace and case normalization.
   - `cstrip`: keys, separators, and JSON structure are removed; every value is canonicalized and the values are joined. `id=5&q=x`, `{"id":"5","q":"x"}`, and `5 x` become the same text.
   - `vmil`: one decision per value; an input is flagged when any value is flagged. Training is multiple-instance, because in an attack request it is not known which value is malicious.

   A key is dropped only when it is a plain identifier. Anything else in key position is kept as a value, so a payload cannot hide in a parameter name.
7. **Shape augmentation.** Each learned detector is also trained in a `+aug` variant that sees every training string in the other containers with the same label.
8. **CRS baseline.** Each string is placed in an HTTP request that matches its container (key-value as query string, path as request target, JSON as body, anything else as the value of one parameter) and evaluated by libmodsecurity with the CRS rules. Nothing is sent over a network; the request only exists as arguments to the library.
9. **Uncertainty.** Wilson intervals per cell, 10,000 bootstrap resamples over training sources for cross-dataset means, and exact Wilcoxon signed-rank tests for remedy comparisons.

### Reading honeypot sources

- The **attack class** of a honeypot source means *input received from the wild*: shell commands typed after login, or request parameters sent to an exposed server. It is hostile traffic, but not confirmed injection. The number reported is the share that is flagged, not recall.
- The **control class** is the usernames and passwords that were tried. They come from hostile clients but are not injection payloads, so an injection detector has no reason to flag them.
- **Distinct and events.** Each distinct string carries a weight, the number of events it was seen in. The report shows both views.
- **Syntax reference.** There is no ground truth, so the report splits the strings into those the CRS blocks and those it does not, and shows how many of each the model flags.

Log contents are only ever read as text. Nothing in them is executed.

## Data sources

The default configuration uses 16 sources: 8 benchmark sources (191,020 strings used, out of 2.1 million raw) and 8 held-out sources (90,843 strings used). The cap is 20,000 strings per class and source after de-duplication.

### Benchmark sources (trained and tested)

| Name | Origin | Year | Dominant container | License in the repository |
|---|---|---|---|---|
| `paper1x` | Payload corpus of [1337strike/sqlixss-detector](https://github.com/1337strike/sqlixss-detector) plus command-injection and traversal lists from InfoSecWarrior/Offensive-Payloads | 2026 | benign kv, attacks bare | no license file in Offensive-Payloads |
| `hpd` | Morzeux/HttpParamsDataset | 2020 | bare | MIT |
| `csic` | CSIC 2010 (msudol mirror), query string or body | 2010 | kv | mirror is GPL-3.0; check the terms of the original dataset |
| `ecml` | ECML/PKDD 2007 learning set (msudol mirror) | 2007 | kv | as above |
| `gran` | grananqvist/Machine-Learning-Web-Application-Firewall-and-Dataset | 2018 | bare | MIT |
| `fwaf` | faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall | 2017 | path | no license file |
| `modsec` | pralab/modsec-learn-dataset: legitimate queries from real traffic plus SQLi | 2024 | kv | no license file; citation requested |
| `crs` | OWASP Core Rule Set regression tests: attacks per rule family plus hard negatives written by the rule authors | 2026 | kv | Apache-2.0 |

### Held-out sources (tested only)

| Name | Origin | Period | Content | License |
|---|---|---|---|---|
| `patt` | swisskyrepo/PayloadsAllTheThings (Intruder lists) | list as of Oct 2026 | 24,312 payloads | MIT |
| `shell21` | zyw-286/shell-attack-evolution-dataset, Cowrie | 2021–2022 | 12,923 distinct commands, 65,317 events | data CC BY 4.0 |
| `shell24` | same | 2024 | 4,236 distinct commands, 33,259 events | data CC BY 4.0 |
| `copot_ssh` | ymlwww/Conpot2025 (Copot-2025), Cowrie on AWS | Apr–Jul 2025 | 190 distinct command sequences, 348,226 events; credentials as control | no explicit license; citation requested |
| `tpot25` | samdavi/SSH-Honeypot-Dataset, T-Pot | Nov 2025 | 1,835 distinct commands; usernames as control | no license file |
| `copot_web` | Copot-2025, Tanner and h0neytr4p web honeypots | 2025 | 2,232 distinct parameter strings, 11,538 events | as `copot_ssh` |
| `finch` | 0x4D31/honeypot-data, Finch reverse proxy | Jul–Nov 2025 | 273 distinct queries or bodies, 1,755 events | CC BY 4.0 |
| `vps` | masafykun/vps-attack-dataset, production VPS | Jun–Oct 2026 | 2,761 distinct parameter strings, 13,087 events; SSH usernames as control | CC BY 4.0 |

**No dataset is included in this repository.** `shapetrap fetch` downloads them from their original locations. Check each license before redistributing, and cite each source you use.

## Using your own data

Add a section to `shapetrap.toml`. A CSV file with a text column and a label column:

```toml
[datasets.mine]
loader = "csv"
path = "data/raw/mine.csv"
text_column = "payload"
label_column = "label"
label_map = { normal = "benign", SQLi = "sqli" }
```

Labels must map onto `benign`, `sqli`, `xss`, `cmdi`, `traversal`, `shell`, `other`, or `attack`.

Your own Cowrie honeypot log (one JSONL file or a folder of them), evaluated as a held-out source:

```toml
[datasets.mylog]
loader = "cowrie"
path = "data/honeypot"
role = "test"
group = "wild-ssh"
period = "2026"
```

Seeds, the cap per class, the tokenizer, the number of features, and the list of detectors and preprocessing modes are set at the top of the same file.

## Output

| File | Content |
|---|---|
| `out/REPORT.md` | All sections in one document |
| `out/transfer_cells.csv` | One row per seed, training source, test source, and configuration, with counts and Wilson intervals |
| `out/transfer_summary.csv` | The same cells averaged over seeds, with standard deviations |
| `out/interventions.csv` | Decisions under each container variant, with McNemar tests |
| `out/audit_overlap.csv` | Pairwise overlap between sources |
| `out/probe.csv` | Model-free indicators per source |
| `out/explain_*.csv` | Feature margins of the logistic model |

## Example results

The `out/` folder in this repository holds a complete run of version 0.5.1 with the default configuration: seeds 42, 43, 44; 31 detector configurations; Python 3.12.10, scikit-learn 1.9.1, NumPy 2.5.4, SciPy 1.18.1, LightGBM 4.7.0, libmodsecurity 3.0.17, CRS at commit `e587261`.

**Performance collapses across datasets.** Logistic regression on raw input, mean over the eight benchmark sources:

| Metric | In-distribution | Cross-dataset |
|---|---|---|
| Benign inputs flagged (FPR) | 8.6% | 47.2% |
| Attack inputs flagged | 97.1% | 67.0% |
| Balanced accuracy | 94.2% | 59.9% |

All six learners behave the same way:

| Learner (raw input) | FPR in-distribution | FPR cross-dataset | Gap [95% bootstrap] |
|---|---|---|---|
| Logistic regression | 8.6% | 47.2% | 38.6 [19.0, 57.5] |
| Naive Bayes | 13.6% | 42.4% | 28.8 [15.1, 45.2] |
| Linear SVM | 8.8% | 50.5% | 41.7 [20.8, 60.3] |
| Random forest | 10.5% | 52.8% | 42.3 [20.3, 64.6] |
| LightGBM | 8.3% | 55.4% | 47.1 [22.0, 70.7] |
| MLP | 10.2% | 42.8% | 32.6 [12.2, 53.2] |

**Changing only the container flips decisions.** On each model's own test split: benign `paper1x` inputs are flagged 0.0% as collected, 33.6% with keys removed, and 100.0% as JSON. Benign `hpd` inputs go from 0.0% to 42.4% when wrapped as `key=value`, and benign `fwaf` inputs from 0.5% to 87.5%. Of 264 benign cells, 132 change significantly after Holm correction.

**The `=` token changes sign between sources.** It is evidence for *benign* in five sources (`paper1x`, `csic`, `ecml`, `modsec`, `crs`) and evidence for an *attack* in three (`hpd`, `gran`, `fwaf`). In total 164 features flip sign.

**Three benchmarks share one benign origin.** 90.5% of the benign values of `hpd` occur in CSIC 2010 parameters, and 99.5% of the smaller set between `csic` and `gran`, at 0.0% string-level overlap. `hpd`, `csic`, and `gran` are the same application's traffic in different containers.

**Removing the container helps.** Logistic regression, cross-dataset mean:

| Preprocessing | FPR | Attacks flagged | Balanced accuracy |
|---|---|---|---|
| `raw` | 47.2% | 67.0% | 59.9% |
| `canon` | 49.7% | 79.2% | 64.8% |
| `canon` + shape augmentation | 39.3% | 78.5% | 69.6% |
| `cstrip` | 28.8% | 76.6% | 73.9% |
| `vmil` | 24.4% | 72.1% | 73.8% |

Against `canon`, with the training source as the unit (n = 8): `cstrip` lowers FPR by 20.8 points (better on 7 of 8 sources, Holm-adjusted p = 0.031) and `vmil` by 25.2 points (8 of 8, p = 0.023). The number of benign decisions that change when an input is wrapped as JSON drops from 20,090 to 51 out of 27,763. A gap remains: the cross-dataset FPR is still 24–29%.

**The real CRS beats every learned detector under this protocol.**

| Detector | FPR | Attacks flagged | Balanced accuracy |
|---|---|---|---|
| OWASP CRS, paranoia level 1 | 5.9% | 75.4% | 84.8% |
| OWASP CRS, paranoia level 2 | 19.8% | 87.0% | 83.6% |
| Best learned detector, cross-dataset (`svm-vmil`) | 25.7% | 73.4% | 73.9% |
| `lr-raw`, in-distribution | 8.6% | 97.1% | 94.2% |

**Repackaging alone works as evasion.** With the payload unchanged, detection of `lr-raw` drops significantly in 15 of 56 cross-dataset cells when the payload is wrapped as `key=value` and in 8 of 56 as JSON (largest drop 49.4 points). Shape augmentation makes this worse for JSON (28 of 56 cells). With `cstrip`, no cell drops significantly for logistic regression.

**On honeypot data the outcome depends on the training source, not on the input.** Share of distinct inputs flagged by `lr-raw`:

| Trained on | `shell21` | `shell24` | `copot_ssh` | `tpot25` | `copot_web` | `finch` | `vps` | Control (three sources) |
|---|---|---|---|---|---|---|---|---|
| `paper1x` | 100.0 | 99.9 | 100.0 | 100.0 | 55.8 | 35.4 | 4.9 | 99.7–99.9 |
| `csic` | 100.0 | 99.9 | 99.3 | 100.0 | 99.9 | 100.0 | 100.0 | 100.0 |
| `crs` | 98.5 | 99.2 | 89.8 | 99.6 | 73.5 | 64.1 | 12.8 | 98.2–99.5 |
| `fwaf` | 95.0 | 87.2 | 61.2 | 98.7 | 92.0 | 68.3 | 91.7 | 0.2–0.9 |
| `gran` | 87.5 | 76.2 | 48.4 | 92.9 | 89.5 | 59.3 | 90.6 | 0.0–0.1 |
| `hpd` | 37.0 | 92.0 | 39.3 | 27.5 | 77.6 | 55.2 | 66.9 | 0.0–0.2 |
| `ecml` | 5.4 | 10.6 | 37.5 | 8.4 | 19.1 | 2.9 | 3.0 | 0.2–0.5 |
| `modsec` | 0.0 | 0.0 | 0.0 | 0.0 | 1.2 | 0.2 | 0.1 | 0.0 |

Three training sources make the detector flag almost every username and password. With container canonicalization the mean share of control strings flagged drops from 37.5% (`canon`) to 12.8% (`cstrip`) and 0.3% (`vmil`).

The full tables are in [`out/REPORT.md`](out/REPORT.md).

## Reproducibility

- Linear models are trained to full convergence (`tol=1e-8`). With scikit-learn's default tolerance, in-distribution scores are unaffected, but single cross-dataset cells can differ by tens of points between machines.
- A second run of the same version on different hardware gave the same conclusions and the same p-values for the main tests. Individual logistic-regression cells differed by at most 0.6 points, caused by ties at the 4,000-feature vocabulary cut-off, which NumPy breaks differently on different CPUs. Averages of the random forest, LightGBM, and MLP differed by at most 1.8 points.
- CRS verdicts depend slightly on the libmodsecurity version: out of 272,242 strings, level 1 blocked 105,062 with 3.0.17 and 105,129 with 3.0.12.
- Report numbers from a single run, and record the library versions printed at the top of `REPORT.md`.

## Limitations

- All six learners use the same TF-IDF token features. Character-level models and transformers are not covered.
- The CRS runs outside a web server, on synthetic requests with minimal headers. This approximates a real deployment; it does not equal one.
- Interventions and the evasion test run on the first seed only, and move the payload between containers without mutating it.
- Container parsing knows key-value, JSON, and path with query string. Multipart, XML, and nested containers are not handled.
- Container canonicalization does not help evenly. Two training sources barely improve with `cstrip` (`paper1x` 53.5% → 48.5%, `csic` 100.0% → 94.6%), and `vmil` costs 7.0 points of detection.
- Remedy tests use n = 8 training sources, so the smallest possible p-value is 0.008. Read them together with the bootstrap intervals.
- Seed-to-seed variation is small in the median (1.2 points) but large in a few cells: 4 of 64 exceed 10 points, and one reaches 25.0 (`hpd` → `csic`).
- `csic` and `crs` are weak training sources: their own in-distribution FPR is 27.7% and 40.2%.
- The attack class of web honeypot sources is not confirmed injection, and SSH honeypots record shell commands typed after login, not command-injection payloads in web parameters.
- Five benchmark sources date from 2020 or earlier.
- The local signature set is small. The serious rule-based baseline is `crs-pl1` and `crs-pl2`.

## Roadmap

- Character-level and small transformer models.
- Interventions and evasion on all seeds.
- Deterministic tie-breaking at the vocabulary cut-off.
- More containers: multipart, XML, nested.
- Loaders for CyberLab honeynet, COW160x4, and SR-BH 2020.

## Related publication

shapetrap builds on the canonicalization and payload-family split introduced in:

> Khawarizmi and Prayudi, "Evaluating Input Canonicalization for SQLi and XSS Detection Using Lightweight Machine Learning."

`shapetrap anchor` re-derives that study's HttpParamsDataset result with its original settings (97.03% of benign inputs flagged by logistic regression on raw input; 97.53% with canonicalization) and with fully converged models (97.14% and 97.68%).
