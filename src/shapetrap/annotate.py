"""Manual labels for held-out sources.

Honeypot and log sources come without confirmed injection labels, so on them
the tool can only report how often a detector flags something.  This module
draws a fixed random sample, lets two people label it independently, measures
their agreement, and then scores every detector on the agreed labels.

Workflow:
  shapetrap label-sample   -> out/labels/sample.csv + out/labels/GUIDE.md
  (two people fill label_a and label_b; disagreements get label_final)
  shapetrap label-score    -> agreement and detector scores in out/labels/
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

LABELS = ("benign", "sqli", "xss", "cmdi", "traversal", "other_malicious", "unclear")
INJECTION = ("sqli", "xss", "cmdi", "traversal")

GUIDE = """# Labeling guide

Label every row in `sample.csv` on your own, without looking at the other
column, at the source name, or at any detector output. Write one label per row.

| Label | Use it when the input |
|---|---|
| `benign` | is ordinary data: a search term, an ID, a username or password attempt, a normal command a user would type |
| `sqli` | tries to change an SQL query: a quote or number followed by SQL syntax (`' or 1=1`, `union select`, `sleep(`, `--` to cut the query) |
| `xss` | tries to inject HTML or JavaScript: tags, event handlers (`onerror=`), `javascript:` URLs |
| `cmdi` | tries to run a shell command through a parameter: `;`, `|`, `&&`, backticks or `$( )` followed by a command |
| `traversal` | tries to read files outside the web root: `../`, `/etc/passwd`, `file://` |
| `other_malicious` | is clearly hostile but not one of the four injection types: malware download and execution, reconnaissance after a break-in, exploit strings for one product, scanner probes |
| `unclear` | cannot be decided from the string alone |

Notes:

- Shell commands typed in an SSH session are not injection: label them
  `benign` if a normal user could type them, `other_malicious` if they download,
  run, or hide malware, add keys, or change accounts.
- Judge the intent of the string, not whether it would work.
- If an input contains several things, use the most specific injection label.
- Use `note` for anything worth discussing later.

When both columns are filled, run `shapetrap label-score`. Rows where the two
labels differ are listed in `disagreements.csv`; settle them together and write
the result in `label_final`, then run `label-score` again.
"""


def draw_sample(corpus: dict[str, list[dict]], sources: list[str], n: int, seed: int) -> list[dict]:
    """Random sample of distinct strings, stratified by source and recorded
    class.  Every stratum gets an equal share (a small stratum gives its
    unused share to the others), so rare web attacks are not swamped by
    credential lists.  ``weight`` is the stratum size divided by the number
    drawn from it, for estimates that stand for the whole source."""
    rng = np.random.default_rng(seed)
    strata: dict[tuple[str, str], list[dict]] = {}
    for s in sources:
        seen = set()
        for r in corpus[s]:
            if r["text"] not in seen:
                seen.add(r["text"])
                strata.setdefault((s, r.get("y", "")), []).append(r)
    if not strata:
        return []
    # Equal allocation with redistribution ("water filling").
    want = dict.fromkeys(strata, 0)
    left = n
    open_ = list(strata)
    while left > 0 and open_:
        share = max(1, left // len(open_))
        for k in list(open_):
            take = min(share, len(strata[k]) - want[k], left)
            want[k] += take
            left -= take
            if want[k] >= len(strata[k]):
                open_.remove(k)
            if left == 0:
                break
    out = []
    for (s, y), pool in strata.items():
        size = want[(s, y)]
        if not size:
            continue
        idx = rng.choice(len(pool), size=size, replace=False)
        for i in sorted(idx):
            out.append(
                {
                    "source": s,
                    "text": pool[i]["text"],
                    "recorded_class": y,
                    "weight": round(len(pool) / size, 4),
                }
            )
    order = rng.permutation(len(out))  # mixed order, so sources are not labeled in blocks
    sample = []
    for j, i in enumerate(order):
        row = out[i]
        sample.append(
            {
                "id": f"L{j + 1:04d}",
                "text": row["text"],
                "label_a": "",
                "label_b": "",
                "label_final": "",
                "note": "",
                "source": row["source"],
                "recorded_class": row["recorded_class"],
                "weight": row["weight"],
            }
        )
    return sample


SAMPLE_FIELDS = [
    "id",
    "text",
    "label_a",
    "label_b",
    "label_final",
    "note",
    "source",
    "recorded_class",
    "weight",
]


def write_sample(sample: list[dict], folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "sample.csv"
    if path.exists():
        raise SystemExit(f"{path} exists already; move it away to draw a new sample")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, SAMPLE_FIELDS)
        w.writeheader()
        w.writerows(sample)
    # A copy without source and recorded class, for labeling blind.
    with open(folder / "sample_blind.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, SAMPLE_FIELDS[:6])
        w.writeheader()
        w.writerows([{k: r[k] for k in SAMPLE_FIELDS[:6]} for r in sample])
    (folder / "GUIDE.md").write_text(GUIDE, encoding="utf-8")
    return path


def read_labels(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    bad = []
    for r in rows:
        for col in ("label_a", "label_b", "label_final"):
            v = r.get(col, "").strip().lower()
            r[col] = v
            if v and v not in LABELS:
                bad.append(f"{r['id']} {col}={v!r}")
    if bad:
        raise SystemExit(
            "unknown labels: " + ", ".join(bad[:10]) + f" (allowed: {', '.join(LABELS)})"
        )
    return rows


def cohen_kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    if n == 0:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def agreement(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Kappa overall and per source, and the rows the two labels disagree on."""
    both = [r for r in rows if r["label_a"] and r["label_b"]]
    table = []
    by = defaultdict(list)
    for r in both:
        by[r["source"]].append(r)
    for name, rs in [("all", both)] + sorted(by.items()):
        a, b = [r["label_a"] for r in rs], [r["label_b"] for r in rs]
        inj_a = ["inj" if x in INJECTION else "no" for x in a]
        inj_b = ["inj" if x in INJECTION else "no" for x in b]
        table.append(
            {
                "source": name,
                "n": len(rs),
                "agree": round(sum(x == y for x, y in zip(a, b)) / len(rs), 4) if rs else "",
                "kappa": round(cohen_kappa(a, b), 4) if rs else "",
                "kappa_injection_vs_rest": round(cohen_kappa(inj_a, inj_b), 4) if rs else "",
            }
        )
    disagree = [r for r in both if r["label_a"] != r["label_b"]]
    return table, disagree


def final_label(r: dict) -> str:
    """The agreed label, or the settled one; empty while still open."""
    if r["label_final"]:
        return r["label_final"]
    if r["label_a"] and r["label_a"] == r["label_b"]:
        return r["label_a"]
    return ""


def score_flags(labels: list[str], flags: np.ndarray) -> dict:
    """Detection on injection, false positives on benign, and the share
    flagged among other malicious inputs (reported apart: no detector here is
    built for them)."""
    lab = np.array(labels, dtype=object)
    out: dict[str, int | float | str] = {}
    for name, mask in (
        ("injection", np.isin(lab, INJECTION)),
        ("benign", lab == "benign"),
        ("other_malicious", lab == "other_malicious"),
    ):
        k = int(mask.sum())
        out[f"n_{name}"] = k
        out[f"flagged_{name}"] = round(float(flags[mask].mean()), 4) if k else ""
    return out
