"""Model-free indicators computed from each source alone.

* Shape composition: what share of each class arrives in each container.
* Shape-only accuracy: how well benign/attack can be told apart from the
  container alone (no content at all), next to the majority-class rate.
* Separability: 5-fold AUC of a character n-gram logistic probe, i.e. how
  easy the source is to fit in-distribution.

Given transfer results, the probes are rank-correlated with each source's
mean cross-dataset performance (exact permutation p).
"""

from __future__ import annotations

import math
import random
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold, cross_val_score
from sklearn.pipeline import make_pipeline

from .datasets import held_out_sources
from .shapes import SHAPES, shape_features
from .stats import spearman_exact
from .tables import fmt, md_table, pct, write_csv


def _sample(rows: list[dict], cap: int, seed: int) -> list[dict]:
    if len(rows) <= cap:
        return rows
    return random.Random(seed).sample(rows, cap)


def probe_source(name: str, rows: list[dict], seed: int, cap: int = 20000,
                 composition_only: bool = False) -> dict:
    y = np.array([r["y"] == "attack" for r in rows])
    out = {"source": name, "n": len(rows), "attack_share": float(y.mean())}
    out["majority"] = max(out["attack_share"], 1 - out["attack_share"])
    for cls, mask in (("benign", ~y), ("attack", y)):
        counts = Counter(r["shape"] for r, m in zip(rows, mask) if m)
        total = max(1, int(mask.sum()))
        for s in SHAPES:
            out[f"{cls}_{s}"] = counts.get(s, 0) / total

    # Best rule that looks only at the dominant container of the benign class.
    dom = max(SHAPES, key=lambda s: out[f"benign_{s}"])
    bit = np.array([r["shape"] == dom for r in rows])
    acc = float(((bit & ~y) | (~bit & y)).mean())
    out["benign_shape"], out["one_bit_acc"] = dom, max(acc, 1 - acc)

    sub = _sample(rows, cap, seed)
    ys = np.array([r["y"] == "attack" for r in sub])
    groups = np.array([r["family"] for r in sub], dtype=object)
    if composition_only or ys.min() == ys.max() or min(ys.sum(), (~ys).sum()) < 5:
        out["shape_only_acc"] = out["separability_auc"] = float("nan")
        return out
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    xs = np.array([shape_features(r["text"]) for r in sub])
    out["shape_only_acc"] = float(cross_val_score(
        LogisticRegression(max_iter=1000), xs, ys, cv=cv, groups=groups).mean())
    probe = make_pipeline(
        TfidfVectorizer(analyzer="char", ngram_range=(2, 4), max_features=50000, sublinear_tf=True),
        LogisticRegression(max_iter=1000))
    out["separability_auc"] = float(cross_val_score(
        probe, [r["text"] for r in sub], ys, cv=cv, groups=groups, scoring="roc_auc").mean())
    return out


def run_probe(cfg: dict, corpus: dict[str, list[dict]], out_dir: Path, per_source_rows=None) -> str:
    held = held_out_sources(cfg)
    probes = [probe_source(n, rows, cfg["seed"], composition_only=n in held)
              for n, rows in corpus.items()]
    write_csv(probes, out_dir / "probe.csv")

    md = "## 2. What each source looks like before any detector is trained\n\n"
    md += "**Container of each class (% of the class)**\n\n"
    rows = []
    for p in probes:
        for cls in ("benign", "attack"):
            if sum(p[f"{cls}_{s}"] for s in SHAPES) == 0:
                continue  # the source has no string of this class
            label = "control" if (cls == "benign" and p["source"] in held) else cls
            rows.append([p["source"], label] + [pct(p[f"{cls}_{s}"]) for s in SHAPES])
    md += md_table(["source", "class"] + list(SHAPES), rows)
    md += "\n**How far the container alone separates the classes (benchmark sources)**\n\n"
    md += md_table(
        ["source", "majority rate (%)", "one-bit rule (%)", "shape-only probe (%)", "separability AUC"],
        [[p["source"], pct(p["majority"]), f"{pct(p['one_bit_acc'])} (is `{p['benign_shape']}`)",
          pct(p["shape_only_acc"]), fmt(p["separability_auc"], 4)] for p in probes
         if p["source"] not in held])
    md += ("\nThe one-bit rule predicts benign from a single fact: whether the input has the "
           "container most common among that source's benign inputs. The shape-only probe is a "
           "logistic model on container features only (grouped 5-fold accuracy).\n")

    if per_source_rows:
        by = {r["source"]: r for r in per_source_rows}
        common = [p for p in probes if p["source"] in by
                  and not math.isnan(p["separability_auc"])]
        if 3 <= len(common) <= 9:
            md += "\n**Rank association with mean cross-dataset performance**\n\n"
            lines = []
            for label, key in (("separability AUC", "separability_auc"),
                               ("shape-only probe", "shape_only_acc"),
                               ("one-bit rule", "one_bit_acc")):
                for mlabel, mkey in (("bal. acc. out", "out_bal_acc"), ("FPR out", "out_fpr")):
                    x = [p[key] for p in common]
                    yv = [by[p["source"]][mkey] for p in common]
                    if any(math.isnan(v) for v in x + yv):
                        continue
                    rho, pval = spearman_exact(x, yv)
                    lines.append([label, mlabel, fmt(rho), fmt(pval)])
            md += md_table(["probe", "transfer metric", "Spearman rho", "exact p"], lines)
            md += (f"\nn = {len(common)} sources. With so few points every p-value is coarse; "
                   "read the direction, not the significance.\n")
    return md
