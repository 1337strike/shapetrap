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
from typing import Any

import numpy as np
from scipy.stats import rankdata

from .datasets import held_out_sources, split_all
from .models import (
    CONTAINER_FREE,
    SIGNATURE_PREPS,
    Features,
    Signature,
    ValueSpace,
    attack_score,
    config_name,
    make_clf,
    preprocess,
)
from .shapes import INTERVENTIONS, shape_features
from .shapes import interventions as rewrites_for
from .stats import holm, mcnemar_exact, mean_sd, wilson
from .tables import write_csv

TYPED = ("sqli", "xss", "cmdi", "traversal")
FIXED_FPR = ((0.01, "det_at_fpr1"), (0.05, "det_at_fpr5"))


def _rate(k: int, n: int) -> float:
    return k / n if n else float("nan")


def _wrate(mask: np.ndarray, base: np.ndarray, weights: np.ndarray) -> float:
    total = float(weights[base].sum())
    return float(weights[mask & base].sum()) / total if total else float("nan")


def _ranked(score: np.ndarray | None, is_attack: np.ndarray) -> dict:
    """Threshold-free view of a scoring detector on one cell.

    ``auc`` is the probability that a random attack string scores above a
    random benign one (ties count half).  ``det_at_fpr1`` and ``det_at_fpr5``
    are the shares of attack strings flagged when the threshold is set on this
    cell's own benign strings so that at most 1% or 5% of them are flagged.
    That threshold uses the test labels, so these are best-case operating
    points; they make detectors comparable at the same false-positive rate.
    """
    out = {"auc": float("nan")} | {key: float("nan") for _, key in FIXED_FPR}
    if score is None:
        return out
    a, b = score[is_attack], score[~is_attack]
    if not len(a) or not len(b):
        return out
    ranks = rankdata(np.concatenate([a, b]))
    out["auc"] = float((ranks[: len(a)].sum() - len(a) * (len(a) + 1) / 2) / (len(a) * len(b)))
    desc = np.sort(b)[::-1]
    for share, key in FIXED_FPR:
        allowed = math.floor(share * len(b))
        threshold = desc[allowed] if allowed < len(desc) else -np.inf
        out[key] = float((a > threshold).mean())
    return out


def _score(
    flag: np.ndarray,
    is_attack: np.ndarray,
    atypes: np.ndarray,
    known: np.ndarray,
    weights: np.ndarray,
    ref: np.ndarray | None = None,
    score: np.ndarray | None = None,
    overlap: np.ndarray | None = None,
) -> dict:
    ben, att = ~is_attack, is_attack
    n_b, n_a = int(ben.sum()), int(att.sum())
    fp, tp = int((flag & ben).sum()), int((flag & att).sum())
    fpr, det = _rate(fp, n_b), _rate(tp, n_a)
    abst = flag & known  # abstain-on-unknown: no evidence -> let it through
    lo, hi = wilson(fp, n_b)
    dlo, dhi = wilson(tp, n_a)
    out = {
        "n_benign": n_b,
        "n_attack": n_a,
        "fp": fp,
        "tp": tp,
        "fpr": fpr,
        "fpr_lo": lo,
        "fpr_hi": hi,
        "det": det,
        "det_lo": dlo,
        "det_hi": dhi,
        "bal_acc": (det + (1 - fpr)) / 2 if n_b and n_a else float("nan"),
        "fpr_abstain": _rate(int((abst & ben).sum()), n_b),
        "det_abstain": _rate(int((abst & att).sum()), n_a),
        "no_evidence_benign": _rate(int((~known & ben).sum()), n_b),
        "no_evidence_attack": _rate(int((~known & att).sum()), n_a),
        # Weighted by how often each distinct string was observed (1 for
        # sources that do not record frequency).
        "fpr_w": _wrate(flag, ben, weights),
        "det_w": _wrate(flag, att, weights),
        "events_benign": float(weights[ben].sum()),
        "events_attack": float(weights[att].sum()),
    }
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
    out.update(_ranked(score, is_attack))
    if overlap is not None:
        # Strings whose container-free form also occurs in the training split.
        rest = ~overlap
        out["overlap_cstrip"] = _rate(int(overlap.sum()), len(overlap))
        out["fpr_novl"] = _rate(int((flag & ben & rest).sum()), int((ben & rest).sum()))
        out["det_novl"] = _rate(int((flag & att & rest).sum()), int((att & rest).sum()))
    return out


def _intervene(rows_out, flag, vflags, changed, is_attack, meta):
    for vname, vflag in vflags.items():
        for cls, mask in (("benign", ~is_attack), ("attack", is_attack)):
            n = int(mask.sum())
            if not n:
                continue
            became = int((~flag & vflag & mask).sum())
            cleared = int((flag & ~vflag & mask).sum())
            rows_out.append(
                {
                    **meta,
                    "variant": vname,
                    "class": cls,
                    "n": n,
                    "n_changed": int((changed[vname] & mask).sum()),
                    "flagged_native": _rate(int((flag & mask).sum()), n),
                    "flagged_variant": _rate(int((vflag & mask).sum()), n),
                    "became_flagged": became,
                    "became_clear": cleared,
                    "p_mcnemar": mcnemar_exact(became, cleared),
                }
            )


def run_experiment(cfg: dict, corpus: dict[str, list[dict]], out_dir: Path, log=print):
    names = list(corpus)
    held = held_out_sources(cfg)
    kinds = [k for k in cfg["detectors"] if k not in ("sig", "crs")]
    nl_kinds = list(cfg.get("nonlinear_detectors", []))
    nl_preps = set(cfg.get("nonlinear_preprocess", []))
    nn_kinds = list(cfg.get("neural_detectors", []))
    nn_preps = [p for p in cfg.get("neural_preprocess", ["raw", "canon", "cstrip"]) if p != "vmil"]
    # Real CRS verdicts, when `shapetrap crs` has produced them, are both a
    # detector of their own and the reference for explicit injection syntax.
    has_crs = all("crs1" in r for rows in corpus.values() for r in rows[:1])
    augs = [False, True] if cfg.get("shape_augment", False) else [False]
    do_iv = cfg.get("interventions", True)
    iv_kinds = set(cfg.get("intervention_detectors", ["lr"]))
    iv_seeds = cfg.get("intervention_seeds", "all")
    iv_seeds = (
        set(cfg["seeds"])
        if iv_seeds == "all"
        else {cfg["seeds"][0]}
        if iv_seeds == "first"
        else {int(s) for s in iv_seeds}
    )
    shape_base = cfg.get("shape_baseline", False)
    rewrite_fns = rewrites_for(cfg)
    cells: list[dict] = []
    interventions: list[dict] = []
    t0 = time.time()
    # The MLP is stopped early by design, and LightGBM is given unnamed sparse
    # columns; neither message is informative here.
    warnings.filterwarnings("ignore", message=".*(Maximum iterations|valid feature names).*")
    for si, seed in enumerate(cfg["seeds"]):
        splits = split_all(cfg, corpus, seed)
        iv_here = do_iv and seed in iv_seeds
        # Container-free form of every test string, for the overlap check.
        cs_test = {tgt: [preprocess(r["text"], "cstrip") for r in splits[tgt][1]] for tgt in names}
        # Signatures need no training, so their verdict on every test string
        # is computed once per seed.  The canonicalized verdict doubles as a
        # reference: does a string show explicit injection syntax or not?
        sig = {}
        for tgt in names:
            texts = [r["text"] for r in splits[tgt][1]]
            sig[tgt] = {
                prep: Signature(prep).predict(texts) != "benign" for prep in ("raw", "canon")
            }
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
            train_cs = {preprocess(x, "cstrip") for x in xtr}
            train_cs.discard("")

            # Test view of every source for this training source: strings that
            # also occur in the training split are purged.
            view = {}
            for tgt in names:
                test = splits[tgt][1]
                keep = np.array(
                    [tgt == src or r["key"] not in train_keys for r in test], dtype=bool
                )
                rows = [r for r, k in zip(test, keep) if k]
                texts = [r["text"] for r in rows]
                v: dict[str, Any] = {
                    "keep": keep,
                    "texts": texts,
                    "purged": int((~keep).sum()),
                    "overlap": np.array(
                        [c in train_cs for c, k in zip(cs_test[tgt], keep) if k], dtype=bool
                    ),
                    "is_attack": np.array([r["y"] == "attack" for r in rows], dtype=bool),
                    "atypes": np.array([r["atype"] for r in rows], dtype=object),
                    "weights": np.array([float(r.get("weight", 1)) for r in rows]),
                    "ref": (
                        np.array([r["crs1"] for r in rows], dtype=bool)
                        if has_crs
                        else sig[tgt]["canon"][keep]
                    ),
                }
                if has_crs:
                    v["crs"] = {
                        lvl: np.array([r[f"crs{lvl}"] for r in rows], dtype=bool) for lvl in (1, 2)
                    }
                if iv_here:
                    v["vtexts"] = {
                        name: [fn(t, seed) for t in texts] for name, fn in rewrite_fns.items()
                    }
                    v["changed"] = {
                        name: np.array([a != b for a, b in zip(texts, vt)], dtype=bool)
                        for name, vt in v["vtexts"].items()
                    }
                view[tgt] = v

            def record(
                name, tgt, flag, known, score=None, view=view, seed=seed, src=src, train=train
            ):
                v = view[tgt]
                row = {
                    "seed": seed,
                    "source": src,
                    "target": tgt,
                    "config": name,
                    "n_train": len(train),
                    "purged": v["purged"],
                }
                row.update(
                    _score(
                        flag,
                        v["is_attack"],
                        v["atypes"],
                        known,
                        v["weights"],
                        v["ref"],
                        score,
                        v["overlap"],
                    )
                )
                cells.append(row)

            if "sig" in cfg["detectors"]:
                for prep in [p for p in cfg["preprocess"] if p in SIGNATURE_PREPS]:
                    for tgt in names:
                        flag = sig[tgt][prep][view[tgt]["keep"]]
                        record(
                            config_name("sig", prep, False),
                            tgt,
                            flag,
                            np.ones(len(flag), dtype=bool),
                        )

            if has_crs and "crs" in cfg["detectors"]:
                for lvl in (1, 2):
                    for tgt in names:
                        flag = view[tgt]["crs"][lvl]
                        record(f"crs-pl{lvl}", tgt, flag, np.ones(len(flag), dtype=bool))

            want_iv = iv_here and any(k in iv_kinds for k in kinds + nl_kinds + nn_kinds)
            if "vmil" in cfg["preprocess"]:
                space = ValueSpace(
                    cfg.get("tokenizer", "web"),
                    cfg.get("max_features", 4000),
                    rounds=cfg.get("mil_rounds", 2),
                )
                space.fit_transform(xtr, ytr)
                B = {tgt: space.transform(view[tgt]["texts"]) for tgt in names}
                BV = (
                    {
                        (tgt, name): space.transform(vt)
                        for tgt in names
                        for name, vt in view[tgt]["vtexts"].items()
                    }
                    if want_iv
                    else {}
                )
                for kind in kinds:
                    clf = space.fit_clf(kind)
                    name = config_name(kind, "vmil", False)
                    for tgt in names:
                        flag, known = space.flags(clf, *B[tgt])
                        record(name, tgt, flag, known, space.scores(clf, *B[tgt]))
                        if want_iv and kind in iv_kinds:
                            vflags = {
                                vn: space.flags(clf, *BV[(tgt, vn)])[0] for vn in INTERVENTIONS
                            }
                            _intervene(
                                interventions,
                                flag,
                                vflags,
                                view[tgt]["changed"],
                                view[tgt]["is_attack"],
                                {"seed": seed, "source": src, "target": tgt, "config": name},
                            )

            for prep in [p for p in cfg["preprocess"] if p != "vmil"]:
                for aug in [False] if prep in CONTAINER_FREE else augs:
                    feats = Features(
                        prep,
                        cfg.get("tokenizer", "web"),
                        cfg.get("max_features", 4000),
                        augment=aug,
                        seed=seed,
                    )
                    X_train, y_train = feats.fit_transform(xtr, ytr)
                    X = {tgt: feats.transform(view[tgt]["texts"]) for tgt in names}
                    XV = (
                        {
                            (tgt, name): feats.transform(vt)
                            for tgt in names
                            for name, vt in view[tgt]["vtexts"].items()
                        }
                        if want_iv
                        else {}
                    )
                    extra = nl_kinds if (not aug and prep in nl_preps) else []
                    for kind in kinds + extra:
                        clf = make_clf(kind, seed).fit(X_train, y_train)
                        name = config_name(kind, prep, aug)
                        for tgt in names:
                            flag = np.asarray(clf.predict(X[tgt]), dtype=object) != "benign"
                            known = np.asarray(X[tgt].getnnz(axis=1) > 0)
                            record(name, tgt, flag, known, attack_score(clf, X[tgt]))
                            if want_iv and kind in iv_kinds:
                                vflags = {
                                    vn: np.asarray(clf.predict(XV[(tgt, vn)]), dtype=object)
                                    != "benign"
                                    for vn in INTERVENTIONS
                                }
                                _intervene(
                                    interventions,
                                    flag,
                                    vflags,
                                    view[tgt]["changed"],
                                    view[tgt]["is_attack"],
                                    {"seed": seed, "source": src, "target": tgt, "config": name},
                                )
            if nn_kinds:
                from .neural import make_neural

                for kind in nn_kinds:
                    for prep in nn_preps:
                        det = make_neural(kind, prep, cfg, seed).fit(xtr, ytr)
                        name = config_name(kind, prep, False)
                        log(f"    {name}: trained in {det.train_seconds:.0f}s")
                        for tgt in names:
                            texts = view[tgt]["texts"]
                            pred, score = det.predict_and_score(texts)
                            flag = pred != "benign"
                            record(name, tgt, flag, det.known_mask(texts), score)
                            if want_iv and kind in iv_kinds:
                                vflags = {
                                    vn: det.predict(view[tgt]["vtexts"][vn]) != "benign"
                                    for vn in INTERVENTIONS
                                }
                                _intervene(
                                    interventions,
                                    flag,
                                    vflags,
                                    view[tgt]["changed"],
                                    view[tgt]["is_attack"],
                                    {"seed": seed, "source": src, "target": tgt, "config": name},
                                )
            if shape_base:
                # Baseline that sees only the container: one-hot shape and the
                # number of key=value pairs, nothing of the content.
                shp = lambda texts: (
                    np.array([shape_features(x) for x in texts]) if texts else np.zeros((0, 6))
                )
                clf = make_clf("lr", seed).fit(shp(xtr), ytr)
                for tgt in names:
                    Xs = shp(view[tgt]["texts"])
                    if not len(Xs):
                        continue
                    flag = np.asarray(clf.predict(Xs), dtype=object) != "benign"
                    record(
                        config_name("shape", "lr", False),
                        tgt,
                        flag,
                        np.ones(len(flag), dtype=bool),
                        attack_score(clf, Xs),
                    )
            log(f"  seed {seed} source {src}: done ({time.time() - t0:.0f}s)")

    # Holm adjustment within each seed, configuration and class.
    groups = defaultdict(list)
    for i, r in enumerate(interventions):
        groups[(r["seed"], r["config"], r["class"])].append(i)
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
    metrics = (
        [
            "fpr",
            "det",
            "bal_acc",
            "fpr_abstain",
            "det_abstain",
            "fpr_w",
            "det_w",
            "no_evidence_benign",
            "no_evidence_attack",
            "det_ref_pos",
            "det_ref_neg",
            "auc",
            "overlap_cstrip",
            "fpr_novl",
            "det_novl",
        ]
        + [key for _, key in FIXED_FPR]
        + [f"det_{t}" for t in TYPED]
    )
    for (src, tgt, config), rs in groups.items():
        row = {
            "source": src,
            "target": tgt,
            "config": config,
            "seeds": len(rs),
            "n_benign": rs[0]["n_benign"],
            "n_attack": rs[0]["n_attack"],
            "events_benign": rs[0]["events_benign"],
            "events_attack": rs[0]["events_attack"],
            "n_ref_pos": rs[0].get("n_ref_pos", 0),
            "n_ref_neg": rs[0].get("n_ref_neg", 0),
            "purged": rs[0]["purged"],
        }
        for m in metrics:
            row[m], row[m + "_sd"] = mean_sd([float(r.get(m, float("nan"))) for r in rs])
        out.append(row)
    return out
