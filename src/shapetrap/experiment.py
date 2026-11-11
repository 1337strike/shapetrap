"""Cross-dataset transfer matrix and shape-only interventions.

For every seed, source and detector configuration one model is fitted on the
source's training split and evaluated on every source's test split.  Before a
cross-source cell is scored, test strings whose normalized key occurs in the
training split are removed, so the cell cannot be credited for memorization.

A sample counts as *flagged* when the predicted label is anything other than
benign; which attack label it got does not matter for these metrics.
"""

from __future__ import annotations

import math
import time
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np

from .datasets import held_out_sources, split_all
from .models import (CONTAINER_FREE, SIGNATURE_PREPS, Features, Signature, ValueSpace,
                     config_name, make_clf)
from .shapes import INTERVENTIONS
from .stats import bootstrap_mean, holm, mcnemar_exact, mean_sd, wilcoxon_exact, wilson
from .tables import md_table, pct, write_csv

TYPED = ("sqli", "xss", "cmdi", "traversal")


def _rate(k: int, n: int) -> float:
    return k / n if n else float("nan")


def _wrate(mask: np.ndarray, base: np.ndarray, weights: np.ndarray) -> float:
    total = float(weights[base].sum())
    return float(weights[mask & base].sum()) / total if total else float("nan")


def _score(flag: np.ndarray, is_attack: np.ndarray, atypes: np.ndarray, known: np.ndarray,
           weights: np.ndarray, ref: np.ndarray | None = None) -> dict:
    ben, att = ~is_attack, is_attack
    n_b, n_a = int(ben.sum()), int(att.sum())
    fp, tp = int((flag & ben).sum()), int((flag & att).sum())
    fpr, det = _rate(fp, n_b), _rate(tp, n_a)
    abst = flag & known  # abstain-on-unknown: no evidence -> let it through
    lo, hi = wilson(fp, n_b)
    dlo, dhi = wilson(tp, n_a)
    out = {"n_benign": n_b, "n_attack": n_a, "fp": fp, "tp": tp,
           "fpr": fpr, "fpr_lo": lo, "fpr_hi": hi, "det": det, "det_lo": dlo, "det_hi": dhi,
           "bal_acc": (det + (1 - fpr)) / 2 if n_b and n_a else float("nan"),
           "fpr_abstain": _rate(int((abst & ben).sum()), n_b),
           "det_abstain": _rate(int((abst & att).sum()), n_a),
           "no_evidence_benign": _rate(int((~known & ben).sum()), n_b),
           "no_evidence_attack": _rate(int((~known & att).sum()), n_a),
           # Weighted by how often each distinct string was observed (1 for
           # sources that do not record frequency).
           "fpr_w": _wrate(flag, ben, weights), "det_w": _wrate(flag, att, weights),
           "events_benign": float(weights[ben].sum()), "events_attack": float(weights[att].sum())}
    for t in TYPED:
        m = atypes == t
        out[f"det_{t}"] = _rate(int((flag & m).sum()), int(m.sum()))
    if ref is not None:
        # Attack-class strings split by whether the canonicalized local
        # signatures fire, i.e. whether they show explicit injection syntax.
        pos, neg = att & ref, att & ~ref
        out["n_ref_pos"], out["n_ref_neg"] = int(pos.sum()), int(neg.sum())
        out["det_ref_pos"] = _rate(int((flag & pos).sum()), int(pos.sum()))
        out["det_ref_neg"] = _rate(int((flag & neg).sum()), int(neg.sum()))
    return out


def _intervene(rows_out, flag, vflags, changed, is_attack, meta):
    for vname, vflag in vflags.items():
        for cls, mask in (("benign", ~is_attack), ("attack", is_attack)):
            n = int(mask.sum())
            if not n:
                continue
            became = int((~flag & vflag & mask).sum())
            cleared = int((flag & ~vflag & mask).sum())
            rows_out.append({**meta, "variant": vname, "class": cls, "n": n,
                             "n_changed": int((changed[vname] & mask).sum()),
                             "flagged_native": _rate(int((flag & mask).sum()), n),
                             "flagged_variant": _rate(int((vflag & mask).sum()), n),
                             "became_flagged": became, "became_clear": cleared,
                             "p_mcnemar": mcnemar_exact(became, cleared)})


def run_experiment(cfg: dict, corpus: dict[str, list[dict]], out_dir: Path, log=print):
    names = list(corpus)
    held = held_out_sources(cfg)
    kinds = [k for k in cfg["detectors"] if k not in ("sig", "crs")]
    nl_kinds = list(cfg.get("nonlinear_detectors", []))
    nl_preps = set(cfg.get("nonlinear_preprocess", []))
    # Real CRS verdicts, when `shapetrap crs` has produced them, are both a
    # detector of their own and the reference for explicit injection syntax.
    has_crs = all("crs1" in r for rows in corpus.values() for r in rows[:1])
    augs = [False, True] if cfg.get("shape_augment", False) else [False]
    do_iv = cfg.get("interventions", True)
    iv_kinds = set(cfg.get("intervention_detectors", ["lr"]))
    cells, interventions = [], []
    t0 = time.time()
    # The MLP is stopped early by design, and LightGBM is given unnamed sparse
    # columns; neither message is informative here.
    warnings.filterwarnings("ignore", message=".*(Maximum iterations|valid feature names).*")
    for si, seed in enumerate(cfg["seeds"]):
        splits = split_all(cfg, corpus, seed)
        # Signatures need no training, so their verdict on every test string
        # is computed once per seed.  The canonicalized verdict doubles as a
        # reference: does a string show explicit injection syntax or not?
        sig = {}
        for tgt in names:
            texts = [r["text"] for r in splits[tgt][1]]
            sig[tgt] = {prep: Signature(prep).predict(texts) != "benign" for prep in ("raw", "canon")}
        for src in names:
            train, _ = splits[src]
            if src in held:
                continue
            if len({r["y"] for r in train}) < 2:
                log(f"  skip {src}: training split lacks one of the two classes")
                continue
            train_keys = {r["key"] for r in train}
            xtr = [r["text"] for r in train]
            ytr = [r["atype"] for r in train]

            # Test view of every source for this training source: strings that
            # also occur in the training split are purged.
            view = {}
            for tgt in names:
                test = splits[tgt][1]
                keep = np.array([tgt == src or r["key"] not in train_keys for r in test], dtype=bool)
                rows = [r for r, k in zip(test, keep) if k]
                texts = [r["text"] for r in rows]
                v = {"keep": keep, "texts": texts, "purged": int((~keep).sum()),
                     "is_attack": np.array([r["y"] == "attack" for r in rows], dtype=bool),
                     "atypes": np.array([r["atype"] for r in rows], dtype=object),
                     "weights": np.array([float(r.get("weight", 1)) for r in rows]),
                     "ref": (np.array([r["crs1"] for r in rows], dtype=bool) if has_crs
                             else sig[tgt]["canon"][keep])}
                if has_crs:
                    v["crs"] = {lvl: np.array([r[f"crs{lvl}"] for r in rows], dtype=bool)
                                for lvl in (1, 2)}
                if si == 0 and do_iv:
                    v["vtexts"] = {name: [fn(t, seed) for t in texts] for name, fn in INTERVENTIONS.items()}
                    v["changed"] = {name: np.array([a != b for a, b in zip(texts, vt)], dtype=bool)
                                    for name, vt in v["vtexts"].items()}
                view[tgt] = v

            def record(name, tgt, flag, known):
                v = view[tgt]
                row = {"seed": seed, "source": src, "target": tgt, "config": name,
                       "n_train": len(train), "purged": v["purged"]}
                row.update(_score(flag, v["is_attack"], v["atypes"], known, v["weights"], v["ref"]))
                cells.append(row)

            if "sig" in cfg["detectors"]:
                for prep in [p for p in cfg["preprocess"] if p in SIGNATURE_PREPS]:
                    for tgt in names:
                        flag = sig[tgt][prep][view[tgt]["keep"]]
                        record(config_name("sig", prep, False), tgt, flag, np.ones(len(flag), dtype=bool))

            if has_crs and "crs" in cfg["detectors"]:
                for lvl in (1, 2):
                    for tgt in names:
                        flag = view[tgt]["crs"][lvl]
                        record(f"crs-pl{lvl}", tgt, flag, np.ones(len(flag), dtype=bool))

            want_iv = si == 0 and do_iv and any(k in iv_kinds for k in kinds + nl_kinds)
            if "vmil" in cfg["preprocess"]:
                space = ValueSpace(cfg.get("tokenizer", "web"), cfg.get("max_features", 4000),
                                   rounds=cfg.get("mil_rounds", 2))
                space.fit_transform(xtr, ytr)
                B = {tgt: space.transform(view[tgt]["texts"]) for tgt in names}
                BV = ({(tgt, name): space.transform(vt) for tgt in names
                       for name, vt in view[tgt]["vtexts"].items()} if want_iv else {})
                for kind in kinds:
                    clf = space.fit_clf(kind)
                    name = config_name(kind, "vmil", False)
                    for tgt in names:
                        flag, known = space.flags(clf, *B[tgt])
                        record(name, tgt, flag, known)
                        if want_iv and kind in iv_kinds:
                            vflags = {vn: space.flags(clf, *BV[(tgt, vn)])[0] for vn in INTERVENTIONS}
                            _intervene(interventions, flag, vflags, view[tgt]["changed"],
                                       view[tgt]["is_attack"],
                                       {"seed": seed, "source": src, "target": tgt, "config": name})

            for prep in [p for p in cfg["preprocess"] if p != "vmil"]:
                for aug in ([False] if prep in CONTAINER_FREE else augs):
                    feats = Features(prep, cfg.get("tokenizer", "web"), cfg.get("max_features", 4000),
                                     augment=aug, seed=seed)
                    X_train, y_train = feats.fit_transform(xtr, ytr)
                    X = {tgt: feats.transform(view[tgt]["texts"]) for tgt in names}
                    XV = ({(tgt, name): feats.transform(vt) for tgt in names
                           for name, vt in view[tgt]["vtexts"].items()} if want_iv else {})
                    extra = nl_kinds if (not aug and prep in nl_preps) else []
                    for kind in kinds + extra:
                        clf = make_clf(kind, seed).fit(X_train, y_train)
                        name = config_name(kind, prep, aug)
                        for tgt in names:
                            flag = np.asarray(clf.predict(X[tgt]), dtype=object) != "benign"
                            known = np.asarray(X[tgt].getnnz(axis=1) > 0)
                            record(name, tgt, flag, known)
                            if want_iv and kind in iv_kinds:
                                vflags = {vn: np.asarray(clf.predict(XV[(tgt, vn)]), dtype=object) != "benign"
                                          for vn in INTERVENTIONS}
                                _intervene(interventions, flag, vflags, view[tgt]["changed"],
                                           view[tgt]["is_attack"],
                                           {"seed": seed, "source": src, "target": tgt, "config": name})
            log(f"  seed {seed} source {src}: done ({time.time() - t0:.0f}s)")

    # Holm adjustment within each configuration and class.
    groups = defaultdict(list)
    for i, r in enumerate(interventions):
        groups[(r["config"], r["class"])].append(i)
    for idx in groups.values():
        for i, p in zip(idx, holm([interventions[i]["p_mcnemar"] for i in idx])):
            interventions[i]["p_holm"] = p
    for r in interventions:
        r["delta"] = r["flagged_variant"] - r["flagged_native"]

    write_csv(cells, out_dir / "transfer_cells.csv")
    if interventions:
        write_csv(interventions, out_dir / "interventions.csv")
    summary = summarize(cells)
    write_csv(summary, out_dir / "transfer_summary.csv")
    return cells, summary, interventions


def summarize(cells: list[dict]) -> list[dict]:
    """Mean and SD over seeds for every (source, target, config) cell."""
    groups = defaultdict(list)
    for r in cells:
        groups[(r["source"], r["target"], r["config"])].append(r)
    out = []
    metrics = ["fpr", "det", "bal_acc", "fpr_abstain", "det_abstain", "fpr_w", "det_w",
               "no_evidence_benign", "no_evidence_attack", "det_ref_pos", "det_ref_neg"] + \
              [f"det_{t}" for t in TYPED]
    for (src, tgt, config), rs in groups.items():
        row = {"source": src, "target": tgt, "config": config, "seeds": len(rs),
               "n_benign": rs[0]["n_benign"], "n_attack": rs[0]["n_attack"],
               "events_benign": rs[0]["events_benign"], "events_attack": rs[0]["events_attack"],
               "n_ref_pos": rs[0].get("n_ref_pos", 0), "n_ref_neg": rs[0].get("n_ref_neg", 0),
               "purged": rs[0]["purged"]}
        for m in metrics:
            row[m], row[m + "_sd"] = mean_sd([float(r[m]) for r in rs])
        out.append(row)
    return out


def _lookup(summary: list[dict], config: str) -> dict:
    return {(r["source"], r["target"]): r for r in summary if r["config"] == config}


def _offdiag_mean(table: dict, src: str, names: list[str], metric: str) -> float:
    vals = [float(table[(src, t)][metric]) for t in names if t != src and (src, t) in table]
    vals = [v for v in vals if not math.isnan(v)]
    return sum(vals) / len(vals) if vals else float("nan")


def per_source(summary: list[dict], config: str, names: list[str]) -> list[dict]:
    table = _lookup(summary, config)
    out = []
    for src in names:
        if (src, src) not in table:
            continue
        d = table[(src, src)]
        out.append({"source": src, "config": config,
                    "in_fpr": float(d["fpr"]), "in_det": float(d["det"]),
                    "in_bal_acc": float(d["bal_acc"]),
                    "out_fpr": _offdiag_mean(table, src, names, "fpr"),
                    "out_det": _offdiag_mean(table, src, names, "det"),
                    "out_bal_acc": _offdiag_mean(table, src, names, "bal_acc"),
                    "out_fpr_abstain": _offdiag_mean(table, src, names, "fpr_abstain"),
                    "out_det_abstain": _offdiag_mean(table, src, names, "det_abstain")})
    return out


def report_transfer(summary: list[dict], names: list[str], headline: str, configs: list[str],
                    held: set[str] = frozenset()) -> str:
    # Held-out (test-only) sources get their own section; the matrices and
    # cross-dataset means here cover the two-class benchmark sources only.
    names = [n for n in names if n not in held]
    table = {k: v for k, v in _lookup(summary, headline).items() if k[1] not in held}
    trained = [n for n in names if (n, n) in table]

    def cell(metric):
        def f(a, b):
            r = table.get((a, b))
            if r is None:
                return "-"
            return f"{pct(float(r[metric]))}"
        return f

    md = "## 3. Cross-dataset transfer\n\n"
    md += (f"Headline configuration: `{headline}`. Rows are the training source, columns the "
           "test source; the diagonal is in-distribution. Means over seeds.\n\n")
    md += "**Benign inputs flagged (false-positive rate, %)**\n\n"
    md += md_table(["train \\ test"] + names, [[a] + [cell("fpr")(a, b) for b in names] for a in trained])
    md += "\n**Attack inputs flagged (detection rate, %)**\n\n"
    md += md_table(["train \\ test"] + names, [[a] + [cell("det")(a, b) for b in names] for a in trained])
    md += "\n**Balanced accuracy (%)**\n\n"
    md += md_table(["train \\ test"] + names, [[a] + [cell("bal_acc")(a, b) for b in names] for a in trained])

    sds = [float(r[m + "_sd"]) for r in table.values() for m in ("fpr", "det")
           if not math.isnan(float(r[m + "_sd"]))]
    seeds = max(int(r["seeds"]) for r in table.values())
    purged = max(table.values(), key=lambda r: int(r["purged"]))
    md += (f"\n{seeds} seed(s); the largest standard deviation across seeds in the two rate "
           f"matrices is {100 * max(sds):.1f} points. Leakage purge: at most {purged['purged']} test "
           f"strings removed from a cell ({purged['source']} -> {purged['target']}).\n")

    md += f"\n**Per training source (`{headline}`): in-distribution versus mean of the other sources**\n\n"
    md += md_table(["source", "FPR in", "FPR out", "det in", "det out", "bal.acc in", "bal.acc out"],
                   [[p["source"], pct(p["in_fpr"]), pct(p["out_fpr"]), pct(p["in_det"]),
                     pct(p["out_det"]), pct(p["in_bal_acc"]), pct(p["out_bal_acc"])]
                    for p in per_source(summary, headline, names)])

    md += f"\n**Detection by attack type (`{headline}`, %, mean over cells whose test source labels the type)**\n\n"
    type_rows = []
    for t in TYPED:
        ins = [float(r[f"det_{t}"]) for (a, b), r in table.items() if a == b]
        outs = [float(r[f"det_{t}"]) for (a, b), r in table.items() if a != b]
        ins = [v for v in ins if not math.isnan(v)]
        outs = [v for v in outs if not math.isnan(v)]
        if outs:
            type_rows.append([t, pct(sum(ins) / len(ins)) if ins else "-", len(ins),
                              pct(sum(outs) / len(outs)), len(outs)])
    md += md_table(["type", "in-distribution", "cells", "cross-dataset", "cells"], type_rows)

    md += "\n**In-distribution versus mean cross-dataset, per configuration**\n\n"
    rows = []
    for config in configs:
        ps = per_source(summary, config, names)
        if not ps:
            continue
        avg = lambda k: sum(p[k] for p in ps if not math.isnan(p[k])) / max(1, sum(not math.isnan(p[k]) for p in ps))
        rows.append([f"`{config}`", pct(avg("in_fpr")), pct(avg("out_fpr")),
                     pct(avg("in_det")), pct(avg("out_det")),
                     pct(avg("in_bal_acc")), pct(avg("out_bal_acc")),
                     pct(avg("out_fpr_abstain")), pct(avg("out_det_abstain"))])
    md += md_table(["config", "FPR in", "FPR out", "det in", "det out", "bal.acc in",
                    "bal.acc out", "FPR out (abstain)", "det out (abstain)"], rows)
    md += ("\n\"Abstain\" lets an input through when it shares no feature with the model's "
           "vocabulary, instead of deciding from the intercept or prior.\n")

    md += "\n**Consistency across learners (raw input)**\n\n"
    family = {"lr": "linear (logistic regression)", "mnb": "linear (naive Bayes)",
              "svm": "linear (SVM)", "rf": "bagged trees (random forest)",
              "gbm": "boosted trees (LightGBM)", "mlp": "neural network (one hidden layer)"}
    rows = []
    for kind, label in family.items():
        ps = per_source(summary, f"{kind}-raw", names)
        if not ps:
            continue
        worse = sum(p["out_fpr"] > p["in_fpr"] for p in ps)
        rows.append([f"`{kind}-raw`", label, pct(_mean(p["in_fpr"] for p in ps)),
                     pct(_mean(p["out_fpr"] for p in ps)), pct(_mean(p["in_bal_acc"] for p in ps)),
                     pct(_mean(p["out_bal_acc"] for p in ps)), f"{worse}/{len(ps)}"])
    md += md_table(["config", "learner", "FPR in", "FPR out", "bal.acc in", "bal.acc out",
                    "sources with higher FPR out than in"], rows)

    md += ("\n**Source-level bootstrap, 95% interval** (10,000 resamples of the training "
           "sources; `gap` is cross-dataset minus in-distribution)\n\n")
    picks = [c for c in configs if c.endswith("-raw") or c in
             ("lr-canon", "lr-cstrip", "lr-vmil", "sig-canon", "crs-pl1", "crs-pl2")]
    rows = []
    for config in picks:
        ps = per_source(summary, config, names)
        if not ps:
            continue
        ci = lambda vals: "{} [{}, {}]".format(*(pct(v) for v in bootstrap_mean(list(vals))))
        # Signatures and the CRS are not trained, so they have no
        # in-distribution/cross-dataset gap to estimate.
        trained = not config.startswith(("sig-", "crs-"))
        rows.append([f"`{config}`", ci(p["out_fpr"] for p in ps),
                     ci(p["out_fpr"] - p["in_fpr"] for p in ps) if trained else "-",
                     ci(p["out_bal_acc"] for p in ps),
                     ci(p["out_bal_acc"] - p["in_bal_acc"] for p in ps) if trained else "-"])
    md += md_table(["config", "FPR out", "FPR gap", "bal.acc out", "bal.acc gap"], rows)
    return md


def report_interventions(interventions: list[dict], names: list[str], headline: str) -> str:
    if not interventions:
        return ""
    md = "## 4. Shape-only interventions\n\n"
    md += (f"Configuration `{headline}`, first seed. Each model is tested on its **own** source's "
           "test split, first as collected and then with only the container changed "
           "(`bare`: keys removed; `kv`: wrapped as key=value; `json`: flat JSON object). "
           "Content is identical, so any change is caused by shape.\n\n")
    rows = []
    for src in names:
        for cls in ("benign", "attack"):
            base = None
            line = [src, cls]
            for v in INTERVENTIONS:
                r = next((x for x in interventions if x["config"] == headline and x["source"] == src
                          and x["target"] == src and x["variant"] == v and x["class"] == cls), None)
                if r is None:
                    line.append("-")
                    continue
                base = r["flagged_native"]
                star = "*" if r["p_holm"] < 0.05 else ""
                line.append(f"{pct(r['flagged_variant'])}{star}")
            if base is None:
                continue
            rows.append(line[:2] + [pct(base)] + line[2:])
    md += md_table(["source", "class", "flagged as collected (%)"] +
                   [f"as {v} (%)" for v in INTERVENTIONS], rows)
    md += "\n`*` Holm-adjusted exact McNemar p < 0.05 within this configuration and class.\n"

    md += ("\n**Benign decisions changed by the container alone, per configuration** "
           "(own test split, summed over sources)\n\n")
    rows = []
    for config in sorted({r["config"] for r in interventions}):
        own = [r for r in interventions if r["config"] == config and r["source"] == r["target"]
               and r["class"] == "benign" and r["source"] in names]
        if not own:
            continue
        line = [f"`{config}`", sum(r["n"] for r in own if r["variant"] == "kv")]
        for v in INTERVENTIONS:
            vs = [r for r in own if r["variant"] == v]
            line.append(sum(r["became_flagged"] + r["became_clear"] for r in vs))
        rows.append(line)
    md += md_table(["config", "benign strings"] + [f"changed as {v}" for v in INTERVENTIONS], rows)

    sel = [r for r in interventions if r["config"] == headline]
    for cls in ("benign", "attack"):
        sub = [r for r in sel if r["class"] == cls]
        sig = sum(r["p_holm"] < 0.05 for r in sub)
        big = max(sub, key=lambda r: abs(r["delta"]))
        md += (f"\nAcross all {len(sub)} train/test/variant cells for the {cls} class, {sig} change "
               f"significantly after Holm adjustment; the largest shift is "
               f"{100 * big['delta']:+.1f} points ({big['source']} -> {big['target']}, as {big['variant']}).\n")
    return md


GROUPS = {"wild-ssh": "SSH/Telnet honeypots (shell commands typed after login)",
          "wild-web": "Web honeypots and exposed servers (request parameters)",
          "curated": "Curated payload lists (attack strings only)"}


def _mean(values) -> float:
    vals = [float(v) for v in values if v is not None and not math.isnan(float(v))]
    return sum(vals) / len(vals) if vals else float("nan")


def report_held_out(summary: list[dict], interventions: list[dict], names: list[str],
                    held: set[str], headline: str, configs: list[str], cfg: dict,
                    corpus: dict[str, list[dict]], reference: str = "sig") -> str:
    """Section for test-only sources: honeypot logs and curated lists."""
    held_names = [n for n in names if n in held]
    if not held_names:
        return ""
    bench = [n for n in names if n not in held]
    entry = cfg["datasets"]
    group_of = {n: entry[n].get("group", "wild") for n in held_names}
    table = _lookup(summary, headline)
    trained = [b for b in bench if any((b, h) in table for h in held_names)]

    md = "## 6. Held-out evidence\n\n"
    md += ("These sources are never trained on; every detector fitted on a benchmark source is "
           "applied to them unchanged. *Distinct* counts each different string once; *events* "
           "weights a string by how often it was observed. For honeypot sources the attack class "
           "means *input received from the wild*: it is hostile traffic, not traffic confirmed "
           "to be an injection. The control class (tried usernames and passwords) is hostile "
           "input that is not an injection payload.\n\n")

    inv = []
    for h in held_names:
        rows = corpus[h]
        att = [r for r in rows if r["y"] == "attack"]
        ctl = [r for r in rows if r["y"] == "benign"]
        w = lambda rs: int(sum(float(r.get("weight", 1)) for r in rs))
        inv.append([h, group_of[h], entry[h].get("period", "-"), len(att), w(att),
                    len(ctl) or "-", w(ctl) if ctl else "-"])
    md += "**Held-out sources as used**\n\n"
    md += md_table(["source", "group", "period", "attack-class strings", "events",
                    "control strings", "events"], inv)

    def matrix(metric, cols, title):
        if not cols:
            return ""
        body = [[b] + [pct(float(table[(b, h)][metric])) if (b, h) in table else "-" for h in cols]
                for b in trained]
        body.append(["**mean**"] + [pct(_mean(table[(b, h)][metric] for b in trained if (b, h) in table))
                                    for h in cols])
        return f"\n**{title} (`{headline}`, %)**\n\n" + md_table(["trained on"] + cols, body)

    with_control = [h for h in held_names if any(r["y"] == "benign" for r in corpus[h])]
    md += matrix("det", held_names, "Attack-class strings flagged, distinct")
    md += matrix("det_w", held_names, "Attack-class strings flagged, weighted by events")
    md += matrix("fpr", with_control, "Control strings flagged, distinct")

    md += f"\n**Explicit injection syntax or not (`{headline}`, mean over training sources)**\n\n"
    rows = []
    for h in held_names:
        cells = [table[(b, h)] for b in trained if (b, h) in table]
        pos, neg = _mean(c["n_ref_pos"] for c in cells), _mean(c["n_ref_neg"] for c in cells)
        share = pos / (pos + neg) if pos + neg else float("nan")
        rows.append([h, pct(share), pct(_mean(c["det_ref_pos"] for c in cells)),
                     pct(_mean(c["det_ref_neg"] for c in cells))])
    ref_name = ("the OWASP CRS (paranoia level 1) blocks" if reference == "crs"
                else "the local signatures fire")
    md += md_table(["source", f"strings where {ref_name} (%)",
                    "of those, flagged by the model (%)", "of the rest, flagged by the model (%)"], rows)
    md += ("\nThe reference is " + ("the real OWASP Core Rule Set run through libmodsecurity"
                                    if reference == "crs" else "the canonicalized local signatures")
           + ". It marks explicit injection syntax; it is not ground truth.\n")

    md += "\n**Per configuration: mean over training sources and over the sources of each group (%)**\n\n"
    groups = [g for g in GROUPS if g in group_of.values()] + \
             sorted(set(group_of.values()) - set(GROUPS))
    header = ["config"]
    for g in groups:
        header += [f"{g}: attack flagged", f"{g}: control flagged"]
    rows = []
    for config in configs:
        t = _lookup(summary, config)
        line = [f"`{config}`"]
        for g in groups:
            members = [h for h in held_names if group_of[h] == g]
            cells = [t[(b, h)] for h in members for b in bench if (b, h) in t]
            line += [pct(_mean(c["det"] for c in cells)), pct(_mean(c["fpr"] for c in cells))]
        rows.append(line)
    md += md_table(header, rows)
    for g in groups:
        md += f"\n`{g}`: {GROUPS.get(g, g)}: " + ", ".join(h for h in held_names if group_of[h] == g) + "."
    md += "\n"

    sel = [r for r in interventions if r["config"] == headline and r["target"] in held]
    if sel:
        rows = []
        for h in held_names:
            for cls, label in (("attack", "attack class"), ("benign", "control")):
                sub = [r for r in sel if r["target"] == h and r["class"] == cls]
                if not sub:
                    continue
                line = [h, label, pct(_mean(r["flagged_native"] for r in sub))]
                for v in INTERVENTIONS:
                    vs = [r for r in sub if r["variant"] == v]
                    sig = sum(r["p_holm"] < 0.05 for r in vs)
                    line.append(f"{pct(_mean(r['flagged_variant'] for r in vs))} ({sig}/{len(vs)})")
                rows.append(line)
        md += (f"\n**Same strings, container changed (`{headline}`, first seed, distinct, %, mean over "
               "training sources)**\n\n")
        md += md_table(["source", "class", "as observed"] + [f"as {v}" for v in INTERVENTIONS], rows)
        md += ("\nIn brackets: training sources for which the change is significant "
               "(Holm-adjusted exact McNemar p < 0.05).\n")
    return md


REMEDIES = (("canon+aug", "shape augmentation"), ("cstrip", "container removed"),
            ("vmil", "container removed, one decision per value"))


def report_remedies(summary: list[dict], cells: list[dict], names: list[str], held: set[str],
                    cfg: dict, corpus: dict[str, list[dict]]) -> str:
    """Paired comparison of each remedy with plain canonicalization.

    The unit is the training source: for every source, the mean over the other
    benchmark sources (and over seeds).  The three LR comparisons form the
    pre-specified family that is Holm-adjusted; MNB and SVM are shown to check
    that the direction does not depend on the classifier.
    """
    bench = [n for n in names if n not in held]
    kinds = [k for k in cfg["detectors"] if k not in ("sig", "crs")] + \
            list(cfg.get("nonlinear_detectors", []))
    have = {r["config"] for r in summary}
    with_control = [h for h in names if h in held and any(r["y"] == "benign" for r in corpus[h])]
    wild = [h for h in names if h in held and cfg["datasets"][h].get("group", "").startswith("wild")]

    def per_source_metric(config, metric, targets, same=False):
        t = _lookup(summary, config)
        out = {}
        for src in bench:
            vals = [float(t[(src, tg)][metric]) for tg in targets
                    if (src, tg) in t and (same or tg != src)]
            vals = [v for v in vals if not math.isnan(v)]
            if vals:
                out[src] = sum(vals) / len(vals)
        return out

    views = [("FPR, other benchmark sources", "fpr", bench, -1),
             ("attacks flagged, other benchmark sources", "det", bench, +1),
             ("balanced accuracy, other benchmark sources", "bal_acc", bench, +1),
             ("FPR, own source (in-distribution)", "fpr", None, -1),
             ("control flagged, honeypot sources", "fpr", with_control, -1),
             ("attack class flagged, honeypot sources", "det", wild, 0)]

    md = "## 7. Remedies compared with plain canonicalization\n\n"
    md += ("Unit of analysis: the training source (n = " + str(len(bench)) + "). Each value is that "
           "source's mean over the listed test sources and over seeds. `better` counts sources "
           "where the remedy moves the metric in the desired direction. p: exact two-sided "
           "Wilcoxon signed-rank test; the three LR rows of each block are Holm-adjusted "
           "together.\n")
    for title, metric, targets, direction in views:
        if targets is not None and not targets:
            continue
        rows, lr_idx, lr_p = [], [], []
        for kind in kinds:
            base = f"{kind}-canon"
            if base not in have:
                continue
            for suffix, label in REMEDIES:
                treat = f"{kind}-{suffix}"
                if treat not in have:
                    continue
                if targets is None:
                    b = {s_: float(_lookup(summary, base)[(s_, s_)][metric]) for s_ in bench
                         if (s_, s_) in _lookup(summary, base)}
                    t = {s_: float(_lookup(summary, treat)[(s_, s_)][metric]) for s_ in bench
                         if (s_, s_) in _lookup(summary, treat)}
                else:
                    b = per_source_metric(base, metric, targets)
                    t = per_source_metric(treat, metric, targets)
                common = [s_ for s_ in bench if s_ in b and s_ in t]
                diffs = [t[s_] - b[s_] for s_ in common]
                if not diffs:
                    continue
                _, pval, _ = wilcoxon_exact(diffs)
                better = (sum(d * direction > 0 for d in diffs) if direction else "-")
                _, lo, hi = bootstrap_mean(diffs)
                rows.append([f"`{treat}`", label, pct(_mean(b[s_] for s_ in common)),
                             pct(_mean(t[s_] for s_ in common)),
                             f"{100 * sum(diffs) / len(diffs):+.1f} [{100 * lo:+.1f}, {100 * hi:+.1f}]",
                             f"{better}/{len(diffs)}" if direction else "-", pval, ""])
                if kind == "lr":
                    lr_idx.append(len(rows) - 1)
                    lr_p.append(pval)
        for i, adj in zip(lr_idx, holm(lr_p)):
            rows[i][7] = f"{adj:.3f}"
        for r in rows:
            r[6] = f"{r[6]:.3f}"
        md += f"\n**{title} (%)**\n\n"
        md += md_table(["configuration", "remedy", "canon", "remedy",
                        "difference, points [95% bootstrap]", "better", "p", "p (Holm, LR)"], rows)

    # Robustness of the headline comparison across seeds and cells.
    if "lr-canon" in have and "lr-cstrip" in have:
        md += "\n**`lr-cstrip` against `lr-canon`: FPR on the other benchmark sources, per seed**\n\n"
        by = defaultdict(dict)
        for r in cells:
            if r["config"] in ("lr-canon", "lr-cstrip") and r["source"] != r["target"] \
                    and r["target"] in bench and r["source"] in bench:
                by[(r["seed"], r["source"], r["target"])][r["config"]] = float(r["fpr"])
        rows = []
        for seed in sorted({k[0] for k in by}):
            pairs = [v for k, v in by.items() if k[0] == seed and len(v) == 2]
            lower = sum(v["lr-cstrip"] < v["lr-canon"] for v in pairs)
            higher = sum(v["lr-cstrip"] > v["lr-canon"] for v in pairs)
            rows.append([seed, pct(_mean(v["lr-canon"] for v in pairs)),
                         pct(_mean(v["lr-cstrip"] for v in pairs)),
                         f"{lower}/{len(pairs)}", f"{higher}/{len(pairs)}"])
        md += md_table(["seed", "canon", "cstrip", "cells with lower FPR", "cells with higher FPR"], rows)
    return md


def report_evasion(interventions: list[dict], names: list[str], held: set[str]) -> str:
    """How far an attacker gets by changing only where a payload sits.

    The payload itself is untouched: it is moved into a key=value pair or a
    JSON object.  That costs an attacker nothing, and for key=value it is
    simply how a payload normally reaches an application.  (The `bare`
    variant, which removes a container, is in interventions.csv.)
    """
    bench = [n for n in names if n not in held]
    sel = [r for r in interventions if r["class"] == "attack" and r["source"] in bench
           and r["target"] in bench]
    if not sel:
        return ""
    variants = [v for v in ("kv", "json") if v in INTERVENTIONS]
    md = "## 8. Container change as an evasion vector\n\n"
    md += ("Attack strings of each test split, re-sent with only the container changed (first "
           "seed). `missed` counts attacks that were flagged as collected and are no longer "
           "flagged. `significant drops` counts train/test cells where detection falls "
           "(Holm-adjusted exact McNemar p < 0.05 within the configuration).\n")
    for title, same in (("Own source (in-distribution)", True), ("Other benchmark sources", False)):
        rows = []
        for config in sorted({r["config"] for r in sel}):
            sub = [r for r in sel if r["config"] == config and (r["source"] == r["target"]) == same]
            if not sub:
                continue
            total = sum(r["n"] for r in sub if r["variant"] == variants[0])
            line = [f"`{config}`", total, pct(_mean(r["flagged_native"] for r in sub
                                                    if r["variant"] == variants[0]))]
            drops = []
            for v in variants:
                vs = [r for r in sub if r["variant"] == v]
                worst = min(vs, key=lambda r: r["delta"])
                where = worst["source"] + ("" if same else f" -> {worst['target']}")
                line += [pct(_mean(r["flagged_variant"] for r in vs)),
                         sum(r["became_clear"] for r in vs),
                         f"{100 * worst['delta']:+.1f} ({where})"]
                drops.append(f"{sum(r['p_holm'] < 0.05 and r['delta'] < 0 for r in vs)}/{len(vs)}")
            rows.append(line + [" , ".join(drops)])
        header = ["config", "attack strings", "flagged as collected (%)"]
        for v in variants:
            header += [f"as {v} (%)", f"missed ({v})", f"largest drop, points ({v})"]
        header.append("significant drops (" + " , ".join(variants) + ")")
        md += f"\n**{title}**\n\n" + md_table(header, rows)
    md += ("\nA drop means the detector can be evaded by repackaging alone. A rise means it was "
           "reacting to the container rather than to the payload.\n")
    return md
