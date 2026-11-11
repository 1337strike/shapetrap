"""Exact explanations from the linear model itself.

A TF-IDF logistic regression is its own explanation: every feature has one
weight per class.  For each source we report the *benign margin* of a feature,

    margin(t) = w_benign(t) - mean over attack classes of w_c(t)

so positive means "evidence for benign" and negative "evidence for an attack".
No gradient-based attribution and no GPU are needed.

Three outputs:

* the strongest cues per source,
* the weight of container tokens (``=``, ``&``, ``{`` ...) per source,
* features whose sign flips between sources.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from .datasets import held_out_sources, split_rows
from .models import make_detector
from .tables import fmt, md_table, write_csv

CONTAINER_TOKENS = ["=", "&", "{", "}", ":", "/", "."]


def benign_margin(clf) -> np.ndarray:
    classes = list(clf.classes_)
    W = clf.coef_
    if W.shape[0] == 1:
        return W[0] if classes[1] == "benign" else -W[0]
    b = classes.index("benign")
    others = [i for i in range(len(classes)) if i != b]
    return W[b] - W[others].mean(axis=0)


def run_explain(cfg: dict, corpus: dict[str, list[dict]], out_dir: Path, prep: str = "raw",
                top_k: int = 12, min_abs: float = 1.0) -> str:
    seed = cfg["seeds"][0]
    margins: dict[str, dict[str, float]] = {}
    empties = []
    held = held_out_sources(cfg)
    for name, rows in corpus.items():
        if name in held:
            continue
        train, _ = split_rows(rows, seed, cfg["test_size"])
        if len({r["y"] for r in train}) < 2:
            continue
        xtr, ytr = [r["text"] for r in train], [r["atype"] for r in train]
        det = make_detector("lr", prep, cfg, seed=seed).fit(xtr, ytr)
        m = benign_margin(det.clf)
        vocab = det.vec.get_feature_names_out()
        margins[name] = dict(zip(vocab, (float(v) for v in m)))
        row = {"source": name, "lr": det.empty_prediction()}
        for kind in ("mnb", "svm"):
            row[kind] = make_detector(kind, prep, cfg, seed=seed).fit(xtr, ytr).empty_prediction()
        empties.append(row)

    names = list(margins)
    cue_rows = []
    for name in names:
        ranked = sorted(margins[name].items(), key=lambda kv: kv[1])
        for rank, (tok, w) in enumerate(reversed(ranked[-top_k:]), 1):
            cue_rows.append({"source": name, "side": "benign", "rank": rank, "feature": tok, "margin": w})
        for rank, (tok, w) in enumerate(ranked[:top_k], 1):
            cue_rows.append({"source": name, "side": "attack", "rank": rank, "feature": tok, "margin": w})
    write_csv(cue_rows, out_dir / f"explain_cues_{prep}.csv")

    flips = []
    all_feats = set().union(*(set(m) for m in margins.values())) if margins else set()
    for tok in all_feats:
        vals = {n: margins[n][tok] for n in names if tok in margins[n] and abs(margins[n][tok]) >= min_abs}
        pos = [n for n, v in vals.items() if v > 0]
        neg = [n for n, v in vals.items() if v < 0]
        if pos and neg:
            flips.append({"feature": tok, "benign_cue_in": " ".join(pos), "attack_cue_in": " ".join(neg),
                          "spread": max(vals.values()) - min(vals.values()),
                          **{f"margin_{n}": margins[n].get(tok, float("nan")) for n in names}})
    flips.sort(key=lambda r: -r["spread"])
    write_csv(flips, out_dir / f"explain_sign_flips_{prep}.csv")

    md = f"## 5. What the logistic model learned (`lr-{prep}`)\n\n"
    md += ("Benign margin of each feature: positive is evidence for benign, negative for an "
           "attack. Read directly from the coefficients.\n\n")
    md += "**Container tokens**\n\n"
    md += md_table(["token"] + names,
                   [[f"`{t}`"] + [fmt(margins[n].get(t), 2) if t in margins[n] else "-" for n in names]
                    for t in CONTAINER_TOKENS])
    md += "\n**Strongest benign cues per source**\n\n"
    md += md_table(["source", "features (margin)"],
                   [[n, ", ".join(f"`{r['feature']}` ({r['margin']:+.1f})" for r in cue_rows
                                  if r["source"] == n and r["side"] == "benign" and r["rank"] <= 6)]
                    for n in names])
    md += (f"\n**Features whose sign flips between sources** (|margin| >= {min_abs} on both sides): "
           f"{len(flips)}. Largest spreads:\n\n")
    md += md_table(["feature", "benign cue in", "attack cue in", "spread"],
                   [[f"`{r['feature']}`", r["benign_cue_in"], r["attack_cue_in"], fmt(r["spread"], 1)]
                    for r in flips[:12]])
    md += "\n**Decision on an input with no known feature (empty or out of vocabulary)**\n\n"
    md += md_table(["source", "LR", "MNB", "SVM"], [[e["source"], e["lr"], e["mnb"], e["svm"]] for e in empties])
    write_csv(empties, out_dir / f"explain_empty_input_{prep}.csv")
    return md
