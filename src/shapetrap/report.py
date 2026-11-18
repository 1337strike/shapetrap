"""Markdown sections of the report, built from the CSV files of a run.

Nothing here trains a model: every function reads the rows written by
``experiment.run_experiment`` (or loaded back from disk by ``shapetrap render``)
and returns markdown.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Collection
from typing import Any

from .experiment import (
    TYPED,
)
from .shapes import INTERVENTIONS
from .stats import bootstrap_mean, holm, wilcoxon_exact
from .tables import md_table, pct


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
        out.append(
            {
                "source": src,
                "config": config,
                "in_fpr": float(d["fpr"]),
                "in_det": float(d["det"]),
                "in_bal_acc": float(d["bal_acc"]),
                "out_fpr": _offdiag_mean(table, src, names, "fpr"),
                "out_det": _offdiag_mean(table, src, names, "det"),
                "out_bal_acc": _offdiag_mean(table, src, names, "bal_acc"),
                "out_fpr_abstain": _offdiag_mean(table, src, names, "fpr_abstain"),
                "out_det_abstain": _offdiag_mean(table, src, names, "det_abstain"),
            }
        )
    return out


def pool_seeds(interventions: list[dict]) -> list[dict]:
    """One row per train/test/config/variant/class, pooled over seeds.

    Rates are averaged.  ``p_holm`` becomes the largest per-seed value, so a
    pooled row counts as significant only if the change is significant in
    every seed; ``sig_seeds`` says in how many seeds it was.
    """
    groups = defaultdict(list)
    for r in interventions:
        groups[(r["source"], r["target"], r["config"], r["variant"], r["class"])].append(r)
    out = []
    for (src, tgt, config, variant, cls), rs in groups.items():
        mean = lambda k, rs=rs: sum(float(r[k]) for r in rs) / len(rs)
        out.append(
            {
                "source": src,
                "target": tgt,
                "config": config,
                "variant": variant,
                "class": cls,
                "n": rs[0]["n"],
                "n_changed": rs[0]["n_changed"],
                "seeds": len(rs),
                "flagged_native": mean("flagged_native"),
                "flagged_variant": mean("flagged_variant"),
                "delta": mean("delta"),
                "became_flagged": mean("became_flagged"),
                "became_clear": mean("became_clear"),
                "p_holm": max(float(r["p_holm"]) for r in rs),
                "sig_seeds": sum(float(r["p_holm"]) < 0.05 for r in rs),
            }
        )
    return out


def _per_seed_counts(interventions: list[dict], keep) -> str:
    """'a / b / c of n': significant cells per seed among rows selected by keep."""
    seeds = sorted({r["seed"] for r in interventions})
    parts, total = [], 0
    for s in seeds:
        rows = [r for r in interventions if r["seed"] == s and keep(r)]
        total = max(total, len(rows))
        parts.append(str(sum(float(r["p_holm"]) < 0.05 for r in rows)))
    return f"{' / '.join(parts)} of {total}"


def _cross_mean(table: dict, sources: list[str], metric: str) -> float:
    """Mean over training sources of the mean over the other sources."""
    per = []
    for s in sources:
        vals = [float(table[(s, t)][metric]) for t in sources if t != s and (s, t) in table]
        vals = [v for v in vals if not math.isnan(v)]
        if vals:
            per.append(sum(vals) / len(vals))
    return sum(per) / len(per) if per else float("nan")


def report_robustness(
    summary: list[dict],
    names: list[str],
    configs: list[str],
    groups: list[list[str]] | None,
    exclude: list[str],
) -> str:
    """Cross-dataset means when dependent or special sources are left out."""
    picks = [
        c
        for c in ("lr-raw", "lr-canon", "lr-cstrip", "lr-vmil", "svm-vmil", "crs-pl1", "shape-lr")
        if c in configs
    ]
    if not picks:
        return ""
    subsets = [("all benchmark sources", [names])]
    for g in groups or []:
        g = [n for n in g if n in names]
        if len(g) > 1:
            label = "one of " + " / ".join(g) + " at a time"
            subsets.append((label, [[n for n in names if n not in g or n == rep] for rep in g]))
    for x in exclude:
        if x in names:
            subsets.append((f"without {x}", [[n for n in names if n != x]]))
    md = (
        "\n**Robustness: cross-dataset means with dependent or special sources left out** "
        "(a source left out is neither trained on nor tested on; for a provenance group the "
        "range over the choice of member is shown)\n\n"
    )
    rows = []
    for config in picks:
        table = _lookup(summary, config)
        line = [f"`{config}`"]
        for _, variants in subsets:
            for metric in ("fpr", "bal_acc"):
                vals = [_cross_mean(table, v, metric) for v in variants]
                lo, hi = min(vals), max(vals)
                line.append(pct(lo) if abs(hi - lo) < 5e-4 else f"{pct(lo)}-{pct(hi)}")
        rows.append(line)
    header = ["config"]
    for label, variants in subsets:
        header += [f"FPR ({label}, {len(variants[0])} sources)", f"bal.acc ({label})"]
    md += md_table(header, rows)
    return md


def report_fixed_fpr(summary: list[dict], names: list[str], configs: list[str]) -> str:
    """Detection at the same false-positive rate, for detectors that score."""
    rows = []
    for config in configs:
        table = _lookup(summary, config)
        own = [table[(s, s)] for s in names if (s, s) in table]
        other = [table[(s, t)] for s in names for t in names if s != t and (s, t) in table]
        if not own or math.isnan(_mean(r.get("auc", float("nan")) for r in other)):
            continue
        line = [f"`{config}`"]
        for key in ("auc", "det_at_fpr1", "det_at_fpr5"):
            line += [pct(_mean(r[key] for r in own)), pct(_mean(r[key] for r in other))]
        rows.append(line)
    if not rows:
        return ""
    md = (
        "\n**Ranking quality and detection at a fixed false-positive rate** (threshold set on "
        "each cell's own benign strings so that at most 1% or 5% are flagged; a best-case "
        "operating point that puts every detector at the same FPR; mean over cells)\n\n"
    )
    if any(r[0].strip("`").startswith(("and-", "or-")) for r in rows):
        md += (
            "`and-…` and `or-…` share one ranking (the CRS verdict first, then the learned "
            "score), so their AUC and fixed-FPR detection are the same; they differ only in "
            "the default decision shown in the tables above.\n\n"
        )
    md += md_table(
        [
            "config",
            "AUC own",
            "AUC other",
            "det @1% FPR own",
            "det @1% FPR other",
            "det @5% FPR own",
            "det @5% FPR other",
        ],
        rows,
    )
    return md


def report_transfer(
    summary: list[dict],
    names: list[str],
    headline: str,
    configs: list[str],
    held: Collection[str] = frozenset(),
    groups: list[list[str]] | None = None,
    exclude: Collection[str] = (),
) -> str:
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
    md += (
        f"Headline configuration: `{headline}`. Rows are the training source, columns the "
        "test source; the diagonal is in-distribution. Means over seeds.\n\n"
    )
    md += "**Benign inputs flagged (false-positive rate, %)**\n\n"
    md += md_table(
        ["train \\ test"] + names, [[a] + [cell("fpr")(a, b) for b in names] for a in trained]
    )
    md += "\n**Attack inputs flagged (detection rate, %)**\n\n"
    md += md_table(
        ["train \\ test"] + names, [[a] + [cell("det")(a, b) for b in names] for a in trained]
    )
    md += "\n**Balanced accuracy (%)**\n\n"
    md += md_table(
        ["train \\ test"] + names, [[a] + [cell("bal_acc")(a, b) for b in names] for a in trained]
    )

    sds = [
        float(r[m + "_sd"])
        for r in table.values()
        for m in ("fpr", "det")
        if not math.isnan(float(r[m + "_sd"]))
    ]
    seeds = max(int(r["seeds"]) for r in table.values())
    purged = max(table.values(), key=lambda r: int(r["purged"]))
    md += (
        f"\n{seeds} seed(s); the largest standard deviation across seeds in the two rate "
        f"matrices is {100 * max(sds):.1f} points. Leakage purge: at most {purged['purged']} test "
        f"strings removed from a cell ({purged['source']} -> {purged['target']}).\n"
    )

    md += f"\n**Per training source (`{headline}`): in-distribution versus mean of the other sources**\n\n"
    md += md_table(
        ["source", "FPR in", "FPR out", "det in", "det out", "bal.acc in", "bal.acc out"],
        [
            [
                p["source"],
                pct(p["in_fpr"]),
                pct(p["out_fpr"]),
                pct(p["in_det"]),
                pct(p["out_det"]),
                pct(p["in_bal_acc"]),
                pct(p["out_bal_acc"]),
            ]
            for p in per_source(summary, headline, names)
        ],
    )

    md += f"\n**Detection by attack type (`{headline}`, %, mean over cells whose test source labels the type)**\n\n"
    type_rows = []
    for t in TYPED:
        ins = [float(r[f"det_{t}"]) for (a, b), r in table.items() if a == b]
        outs = [float(r[f"det_{t}"]) for (a, b), r in table.items() if a != b]
        ins = [v for v in ins if not math.isnan(v)]
        outs = [v for v in outs if not math.isnan(v)]
        if outs:
            type_rows.append(
                [
                    t,
                    pct(sum(ins) / len(ins)) if ins else "-",
                    len(ins),
                    pct(sum(outs) / len(outs)),
                    len(outs),
                ]
            )
    md += md_table(["type", "in-distribution", "cells", "cross-dataset", "cells"], type_rows)

    md += "\n**In-distribution versus mean cross-dataset, per configuration**\n\n"
    rows = []
    for config in configs:
        ps = per_source(summary, config, names)
        if not ps:
            continue
        avg = lambda k, ps=ps: (
            sum(p[k] for p in ps if not math.isnan(p[k]))
            / max(1, sum(not math.isnan(p[k]) for p in ps))
        )
        rows.append(
            [
                f"`{config}`",
                pct(avg("in_fpr")),
                pct(avg("out_fpr")),
                pct(avg("in_det")),
                pct(avg("out_det")),
                pct(avg("in_bal_acc")),
                pct(avg("out_bal_acc")),
                pct(avg("out_fpr_abstain")),
                pct(avg("out_det_abstain")),
            ]
        )
    md += md_table(
        [
            "config",
            "FPR in",
            "FPR out",
            "det in",
            "det out",
            "bal.acc in",
            "bal.acc out",
            "FPR out (abstain)",
            "det out (abstain)",
        ],
        rows,
    )
    md += (
        '\n"Abstain" lets an input through when it shares no feature with the model\'s '
        "vocabulary, instead of deciding from the intercept or prior.\n"
    )

    md += "\n**Consistency across learners (raw input)**\n\n"
    family = {
        "lr": "linear (logistic regression)",
        "mnb": "linear (naive Bayes)",
        "svm": "linear (SVM)",
        "rf": "bagged trees (random forest)",
        "gbm": "boosted trees (LightGBM)",
        "mlp": "neural network (one hidden layer)",
    }
    rows = []
    for kind, label in family.items():
        ps = per_source(summary, f"{kind}-raw", names)
        if not ps:
            continue
        worse = sum(p["out_fpr"] > p["in_fpr"] for p in ps)
        rows.append(
            [
                f"`{kind}-raw`",
                label,
                pct(_mean(p["in_fpr"] for p in ps)),
                pct(_mean(p["out_fpr"] for p in ps)),
                pct(_mean(p["in_bal_acc"] for p in ps)),
                pct(_mean(p["out_bal_acc"] for p in ps)),
                f"{worse}/{len(ps)}",
            ]
        )
    md += md_table(
        [
            "config",
            "learner",
            "FPR in",
            "FPR out",
            "bal.acc in",
            "bal.acc out",
            "sources with higher FPR out than in",
        ],
        rows,
    )

    md += (
        "\n**Source-level bootstrap, 95% interval** (10,000 resamples of the training "
        "sources; `gap` is cross-dataset minus in-distribution)\n\n"
    )
    picks = [
        c
        for c in configs
        if c.endswith("-raw")
        or c in ("lr-canon", "lr-cstrip", "lr-vmil", "sig-canon", "crs-pl1", "crs-pl2", "shape-lr")
    ]
    rows = []
    for config in picks:
        ps = per_source(summary, config, names)
        if not ps:
            continue
        ci = lambda vals: "{} [{}, {}]".format(*(pct(v) for v in bootstrap_mean(list(vals))))
        # Signatures and the CRS are not trained, so they have no
        # in-distribution/cross-dataset gap to estimate.
        is_trained = not config.startswith(("sig-", "crs-"))
        rows.append(
            [
                f"`{config}`",
                ci(p["out_fpr"] for p in ps),
                ci(p["out_fpr"] - p["in_fpr"] for p in ps) if is_trained else "-",
                ci(p["out_bal_acc"] for p in ps),
                ci(p["out_bal_acc"] - p["in_bal_acc"] for p in ps) if is_trained else "-",
            ]
        )
    md += md_table(["config", "FPR out", "FPR gap", "bal.acc out", "bal.acc gap"], rows)

    own = [r for (a, b), r in table.items() if a == b and "overlap_cstrip" in r]
    other = [r for (a, b), r in table.items() if a != b and "overlap_cstrip" in r]
    if own and other and not math.isnan(_mean(r["overlap_cstrip"] for r in own)):
        worst = max(other, key=lambda r: float(r["overlap_cstrip"]))
        md += (
            "\n**Overlap after the container is removed.** Share of test strings whose "
            "container-free, canonicalized form also occurs in the training split: "
            f"{pct(_mean(r['overlap_cstrip'] for r in own))}% on the own source (mean; "
            f"largest {pct(max(float(r['overlap_cstrip']) for r in own))}%), "
            f"{pct(_mean(r['overlap_cstrip'] for r in other))}% on other sources (mean; largest "
            f"{pct(float(worst['overlap_cstrip']))}%, {worst['source']} -> {worst['target']}). "
            f"Without those strings, `{headline}` flags {pct(_mean(r['fpr_novl'] for r in other))}% "
            f"of benign and {pct(_mean(r['det_novl'] for r in other))}% of attack strings on other "
            f"sources (all strings: {pct(_mean(r['fpr'] for r in other))}% and "
            f"{pct(_mean(r['det'] for r in other))}%).\n"
        )
    md += report_robustness(summary, names, configs, groups, list(exclude))
    md += report_fixed_fpr(summary, names, configs)
    return md


def report_interventions(interventions: list[dict], names: list[str], headline: str) -> str:
    if not interventions:
        return ""
    raw, interventions = interventions, pool_seeds(interventions)
    seeds = len({r["seed"] for r in raw})
    md = "## 4. Shape-only interventions\n\n"
    md += (
        f"Configuration `{headline}`, {seeds} seed(s), rates averaged over seeds. Each model is "
        "tested on its **own** source's "
        "test split, first as collected and then with only the container changed "
        "(`bare`: keys removed; `kv`: wrapped as key=value; `json`: flat JSON object). "
        "Content is identical, so any change is caused by shape.\n\n"
    )
    rows = []
    for src in names:
        for cls in ("benign", "attack"):
            base = None
            line = [src, cls]
            for v in INTERVENTIONS:
                r = next(
                    (
                        x
                        for x in interventions
                        if x["config"] == headline
                        and x["source"] == src
                        and x["target"] == src
                        and x["variant"] == v
                        and x["class"] == cls
                    ),
                    None,
                )
                if r is None:
                    line.append("-")
                    continue
                base = r["flagged_native"]
                star = "*" if r["p_holm"] < 0.05 else ""
                line.append(f"{pct(r['flagged_variant'])}{star}")
            if base is None:
                continue
            rows.append(line[:2] + [pct(base)] + line[2:])
    md += md_table(
        ["source", "class", "flagged as collected (%)"] + [f"as {v} (%)" for v in INTERVENTIONS],
        rows,
    )
    md += (
        "\n`*` Holm-adjusted exact McNemar p < 0.05 in every seed (Holm within each seed, "
        "configuration and class).\n"
    )

    md += (
        "\n**Benign decisions changed by the container alone, per configuration** "
        "(own test split, summed over sources)\n\n"
    )
    rows = []
    for config in sorted({r["config"] for r in interventions}):
        own = [
            r
            for r in interventions
            if r["config"] == config
            and r["source"] == r["target"]
            and r["class"] == "benign"
            and r["source"] in names
        ]
        if not own:
            continue
        line = [f"`{config}`", sum(r["n"] for r in own if r["variant"] == "kv")]
        for v in INTERVENTIONS:
            vs = [r for r in own if r["variant"] == v]
            line.append(round(sum(r["became_flagged"] + r["became_clear"] for r in vs)))
        rows.append(line)
    md += md_table(["config", "benign strings"] + [f"changed as {v}" for v in INTERVENTIONS], rows)

    sel = [r for r in interventions if r["config"] == headline]
    n_src = len({r["source"] for r in sel})
    for cls in ("benign", "attack"):
        sub = [r for r in sel if r["class"] == cls]
        if not sub:
            continue
        sig = sum(r["p_holm"] < 0.05 for r in sub)
        n_tgt = len({r["target"] for r in sub})
        big = max(sub, key=lambda r: abs(r["delta"]))
        per_seed = _per_seed_counts(
            raw, lambda r, c=cls: r["config"] == headline and r["class"] == c
        )
        md += (
            f"\nFor the {cls} class there are {len(sub)} train/test/variant cells "
            f"({n_src} training sources x {n_tgt} test sources with {cls} strings x "
            f"{len(INTERVENTIONS)} rewrites). Significant after Holm adjustment, per seed: "
            f"{per_seed}; in every seed: {sig}. The largest mean shift is "
            f"{100 * big['delta']:+.1f} points ({big['source']} -> {big['target']}, as {big['variant']}).\n"
        )
    return md


GROUPS = {
    "wild-ssh": "SSH/Telnet honeypots (shell commands typed after login)",
    "wild-web": "Web honeypots and exposed servers (request parameters)",
    "curated": "Curated payload lists (attack strings only)",
}


def _mean(values) -> float:
    vals = [float(v) for v in values if v is not None and not math.isnan(float(v))]
    return sum(vals) / len(vals) if vals else float("nan")


def report_held_out(
    summary: list[dict],
    interventions: list[dict],
    names: list[str],
    held: set[str],
    headline: str,
    configs: list[str],
    cfg: dict,
    corpus: dict[str, list[Any]],
    reference: str = "sig",
) -> str:
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
    md += (
        "These sources are never trained on; every detector fitted on a benchmark source is "
        "applied to them unchanged. *Distinct* counts each different string once; *events* "
        "weights a string by how often it was observed. For honeypot sources the attack class "
        "means *input received from the wild*: it is hostile traffic, not traffic confirmed "
        "to be an injection. The control class (tried usernames and passwords) is hostile "
        "input that is not an injection payload.\n\n"
    )

    inv = []
    for h in held_names:
        rows = corpus[h]
        att = [r for r in rows if r["y"] == "attack"]
        ctl = [r for r in rows if r["y"] == "benign"]
        w = lambda rs: int(sum(float(r.get("weight", 1)) for r in rs))
        inv.append(
            [
                h,
                group_of[h],
                entry[h].get("period", "-"),
                len(att),
                w(att),
                len(ctl) or "-",
                w(ctl) if ctl else "-",
            ]
        )
    md += "**Held-out sources as used**\n\n"
    md += md_table(
        [
            "source",
            "group",
            "period",
            "attack-class strings",
            "events",
            "control strings",
            "events",
        ],
        inv,
    )

    def matrix(metric, cols, title):
        if not cols:
            return ""
        body = [
            [b] + [pct(float(table[(b, h)][metric])) if (b, h) in table else "-" for h in cols]
            for b in trained
        ]
        body.append(
            ["**mean**"]
            + [pct(_mean(table[(b, h)][metric] for b in trained if (b, h) in table)) for h in cols]
        )
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
        rows.append(
            [
                h,
                pct(share),
                pct(_mean(c["det_ref_pos"] for c in cells)),
                pct(_mean(c["det_ref_neg"] for c in cells)),
            ]
        )
    ref_name = (
        "the OWASP CRS (paranoia level 1) blocks"
        if reference == "crs"
        else "the local signatures fire"
    )
    md += md_table(
        [
            "source",
            f"strings where {ref_name} (%)",
            "of those, flagged by the model (%)",
            "of the rest, flagged by the model (%)",
        ],
        rows,
    )
    md += (
        "\nThe reference is "
        + (
            "the real OWASP Core Rule Set run through libmodsecurity"
            if reference == "crs"
            else "the canonicalized local signatures"
        )
        + ". It marks explicit injection syntax; it is not ground truth.\n"
    )

    md += "\n**Per configuration: mean over training sources and over the sources of each group (%)**\n\n"
    groups = [g for g in GROUPS if g in group_of.values()] + sorted(
        set(group_of.values()) - set(GROUPS)
    )
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
        md += (
            f"\n`{g}`: {GROUPS.get(g, g)}: "
            + ", ".join(h for h in held_names if group_of[h] == g)
            + "."
        )
    md += "\n"

    ctl_rows = []
    meta = set("'\"`;|&$<>(){}[]\\")
    crs_tab = _lookup(summary, "crs-pl1")
    for h in with_control:
        ctl = [r for r in corpus[h] if r["y"] == "benign"]
        crs_cell = next((crs_tab[(b, h)] for b in bench if (b, h) in crs_tab), None)
        ctl_rows.append(
            [
                h,
                len(ctl),
                pct(_mean(float(any(ch in meta for ch in r["text"])) for r in ctl)),
                pct(float(crs_cell["fpr"])) if crs_cell else "-",
            ]
        )
    if ctl_rows:
        md += "\n**Is the control class a fair negative?**\n\n"
        md += md_table(
            [
                "source",
                "control strings",
                "with shell or SQL metacharacters (%)",
                "blocked by CRS level 1 (%)",
            ],
            ctl_rows,
        )
        md += (
            "\nMetacharacters: quote, backtick, semicolon, pipe, ampersand, dollar, angle "
            "brackets, parentheses, braces, square brackets, backslash.\n"
        )

    sel = [r for r in pool_seeds(interventions) if r["config"] == headline and r["target"] in held]
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
        md += (
            f"\n**Same strings, container changed (`{headline}`, distinct, %, mean over "
            "training sources and seeds)**\n\n"
        )
        md += md_table(
            ["source", "class", "as observed"] + [f"as {v}" for v in INTERVENTIONS], rows
        )
        md += (
            "\nIn brackets: training sources for which the change is significant in every seed "
            "(Holm-adjusted exact McNemar p < 0.05).\n"
        )
    return md


REMEDIES = (
    ("canon+aug", "shape augmentation"),
    ("cstrip", "container removed"),
    ("vmil", "container removed, one decision per value"),
)


def report_remedies(
    summary: list[dict],
    cells: list[dict],
    names: list[str],
    held: set[str],
    cfg: dict,
    corpus: dict[str, list[dict]],
    groups: list[list[str]] | None = None,
) -> str:
    """Paired comparison of each remedy with plain canonicalization.

    The unit is the training source: for every source, the mean over the other
    benchmark sources (and over seeds).  The three LR comparisons form the
    pre-specified family that is Holm-adjusted; MNB and SVM are shown to check
    that the direction does not depend on the classifier.
    """
    bench = [n for n in names if n not in held]
    kinds = (
        [k for k in cfg["detectors"] if k not in ("sig", "crs")]
        + list(cfg.get("nonlinear_detectors", []))
        + list(cfg.get("neural_detectors", []))
    )
    have = {r["config"] for r in summary}
    with_control = [h for h in names if h in held and any(r["y"] == "benign" for r in corpus[h])]
    wild = [
        h for h in names if h in held and cfg["datasets"][h].get("group", "").startswith("wild")
    ]

    def per_source_metric(config, metric, targets, same=False):
        t = _lookup(summary, config)
        out = {}
        for src in bench:
            vals = [
                float(t[(src, tg)][metric])
                for tg in targets
                if (src, tg) in t and (same or tg != src)
            ]
            vals = [v for v in vals if not math.isnan(v)]
            if vals:
                out[src] = sum(vals) / len(vals)
        return out

    views = [
        ("FPR, other benchmark sources", "fpr", bench, -1),
        ("attacks flagged, other benchmark sources", "det", bench, +1),
        ("balanced accuracy, other benchmark sources", "bal_acc", bench, +1),
        ("FPR, own source (in-distribution)", "fpr", None, -1),
        ("control flagged, honeypot sources", "fpr", with_control, -1),
        ("attack class flagged, honeypot sources", "det", wild, 0),
    ]

    md = "## 7. Remedies compared with plain canonicalization\n\n"
    md += (
        "Unit of analysis: the training source (n = " + str(len(bench)) + "). Each value is that "
        "source's mean over the listed test sources and over seeds. `better` counts sources "
        "where the remedy moves the metric in the desired direction. p: exact two-sided "
        "Wilcoxon signed-rank test; the three LR rows of each block are Holm-adjusted "
        "together.\n"
    )
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
                    b = {
                        s_: float(_lookup(summary, base)[(s_, s_)][metric])
                        for s_ in bench
                        if (s_, s_) in _lookup(summary, base)
                    }
                    t = {
                        s_: float(_lookup(summary, treat)[(s_, s_)][metric])
                        for s_ in bench
                        if (s_, s_) in _lookup(summary, treat)
                    }
                else:
                    b = per_source_metric(base, metric, targets)
                    t = per_source_metric(treat, metric, targets)
                common = [s_ for s_ in bench if s_ in b and s_ in t]
                diffs = [t[s_] - b[s_] for s_ in common]
                if not diffs:
                    continue
                _, pval, _ = wilcoxon_exact(diffs)
                better = sum(d * direction > 0 for d in diffs) if direction else "-"
                _, lo, hi = bootstrap_mean(diffs)
                rows.append(
                    [
                        f"`{treat}`",
                        label,
                        pct(_mean(b[s_] for s_ in common)),
                        pct(_mean(t[s_] for s_ in common)),
                        f"{100 * sum(diffs) / len(diffs):+.1f} [{100 * lo:+.1f}, {100 * hi:+.1f}]",
                        f"{better}/{len(diffs)}" if direction else "-",
                        pval,
                        "",
                    ]
                )
                if kind == "lr":
                    lr_idx.append(len(rows) - 1)
                    lr_p.append(pval)
        for i, adj in zip(lr_idx, holm(lr_p)):
            rows[i][7] = f"{adj:.3f}"
        for r in rows:
            r[6] = f"{r[6]:.3f}"
        md += f"\n**{title} (%)**\n\n"
        md += md_table(
            [
                "configuration",
                "remedy",
                "canon",
                "remedy",
                "difference, points [95% bootstrap]",
                "better",
                "p",
                "p (Holm, LR)",
            ],
            rows,
        )

    # Sources that share provenance are not independent units.  Averaging
    # within each provenance group makes the group the unit instead.
    bench_groups = [[n for n in g if n in bench] for g in (groups or [])]
    bench_groups = [g for g in bench_groups if g]
    if bench_groups and any(len(g) > 1 for g in bench_groups) and "lr-canon" in have:
        md += (
            "\n**Provenance groups as the unit** (each group's mean difference over its member "
            "training sources; groups: " + "; ".join(" + ".join(g) for g in bench_groups) + ")\n\n"
        )
        rows, ps = [], []
        for title, metric, targets, direction in views[:3]:
            for suffix, label in REMEDIES:
                treat = f"lr-{suffix}"
                if treat not in have:
                    continue
                b = per_source_metric("lr-canon", metric, targets)
                t_ = per_source_metric(treat, metric, targets)
                diffs = [
                    _mean(t_[s_] - b[s_] for s_ in g if s_ in b and s_ in t_) for g in bench_groups
                ]
                diffs = [d for d in diffs if not math.isnan(d)]
                if not diffs:
                    continue
                _, pval, _ = wilcoxon_exact(diffs)
                _, lo, hi = bootstrap_mean(diffs)
                better = sum(d * direction > 0 for d in diffs)
                rows.append(
                    [
                        title,
                        f"`{treat}`",
                        f"{100 * sum(diffs) / len(diffs):+.1f} [{100 * lo:+.1f}, {100 * hi:+.1f}]",
                        f"{better}/{len(diffs)}",
                        f"{pval:.3f}",
                        "",
                    ]
                )
                ps.append(pval)
        for r, adj in zip(rows, holm(ps)):
            r[5] = f"{adj:.3f}"
        md += md_table(
            [
                "metric",
                "configuration",
                "difference vs lr-canon, points [95% bootstrap]",
                "better",
                "p",
                "p (Holm, all rows)",
            ],
            rows,
        )
        md += (
            f"\nWith {len(bench_groups)} units the smallest attainable two-sided p is "
            f"{2 / 2 ** len(bench_groups):.3f}.\n"
        )

    # Robustness of the headline comparison across seeds and cells.
    if "lr-canon" in have and "lr-cstrip" in have:
        md += (
            "\n**`lr-cstrip` against `lr-canon`: FPR on the other benchmark sources, per seed**\n\n"
        )
        by: dict[tuple, dict[str, float]] = defaultdict(dict)
        for cell in cells:
            if (
                cell["config"] in ("lr-canon", "lr-cstrip")
                and cell["source"] != cell["target"]
                and cell["target"] in bench
                and cell["source"] in bench
            ):
                key = (cell["seed"], cell["source"], cell["target"])
                by[key][cell["config"]] = float(cell["fpr"])
        rows = []
        for seed in sorted({k[0] for k in by}):
            pairs = [v for k, v in by.items() if k[0] == seed and len(v) == 2]
            lower = sum(v["lr-cstrip"] < v["lr-canon"] for v in pairs)
            higher = sum(v["lr-cstrip"] > v["lr-canon"] for v in pairs)
            rows.append(
                [
                    seed,
                    pct(_mean(v["lr-canon"] for v in pairs)),
                    pct(_mean(v["lr-cstrip"] for v in pairs)),
                    f"{lower}/{len(pairs)}",
                    f"{higher}/{len(pairs)}",
                ]
            )
        md += md_table(
            ["seed", "canon", "cstrip", "cells with lower FPR", "cells with higher FPR"], rows
        )
    return md


def report_evasion(
    interventions: list[dict], names: list[str], held: set[str], rewrite: str = "literal"
) -> str:
    """How far an attacker gets by changing only where a payload sits.

    The payload itself is untouched: it is moved into a key=value pair or a
    JSON object.  That costs an attacker nothing, and for key=value it is
    simply how a payload normally reaches an application.  (The `bare`
    variant, which removes a container, is in interventions.csv.)
    """
    bench = [n for n in names if n not in held]
    raw = [
        r
        for r in interventions
        if r["class"] == "attack" and r["source"] in bench and r["target"] in bench
    ]
    if not raw:
        return ""
    sel = pool_seeds(raw)
    n_seeds = len({r["seed"] for r in raw})
    variants = [v for v in ("kv", "json") if v in INTERVENTIONS]
    md = "## 8. Container change as an evasion vector\n\n"
    md += (
        f"Attack strings of each test split, re-sent with only the container changed ({n_seeds} "
        "seed(s), rates averaged). `missed` counts attacks that were flagged as collected and "
        "are no longer flagged (mean over seeds). `significant drops` counts train/test cells "
        "where detection falls in every seed (Holm-adjusted exact McNemar p < 0.05 within each "
        "seed and configuration); `per seed` gives the count in each seed. "
    )
    if rewrite == "faithful":
        md += (
            "Rewrites are `faithful`: values are decoded or encoded the way a client would send "
            "them. Whether a rewritten attack still works is checked by `shapetrap validate` "
            "against a small reference application (section 9).\n"
        )
    else:
        md += (
            "Rewrites are `literal`: values are copied as stored, so a percent-encoded payload "
            "stays encoded inside JSON. A drop measures how sensitive the prediction is to the "
            "representation; `shapetrap validate` checks which rewritten attacks still work.\n"
        )
    for title, same in (("Own source (in-distribution)", True), ("Other benchmark sources", False)):
        rows = []
        for config in sorted({r["config"] for r in sel}):
            sub = [r for r in sel if r["config"] == config and (r["source"] == r["target"]) == same]
            if not sub:
                continue
            total = sum(r["n"] for r in sub if r["variant"] == variants[0])
            line = [
                f"`{config}`",
                total,
                pct(_mean(r["flagged_native"] for r in sub if r["variant"] == variants[0])),
            ]
            drops, seeds_txt = [], []
            for v in variants:
                vs = [r for r in sub if r["variant"] == v]
                worst = min(vs, key=lambda r: r["delta"])
                where = worst["source"] + ("" if same else f" -> {worst['target']}")
                line += [
                    pct(_mean(r["flagged_variant"] for r in vs)),
                    round(sum(r["became_clear"] for r in vs)),
                    f"{100 * worst['delta']:+.1f} ({where})",
                ]
                drops.append(f"{sum(r['p_holm'] < 0.05 and r['delta'] < 0 for r in vs)}/{len(vs)}")
                keep = lambda r, c=config, vv=v, s=same: (
                    r["config"] == c
                    and r["variant"] == vv
                    and (r["source"] == r["target"]) == s
                    and float(r["delta"]) < 0
                )
                seeds_txt.append(_per_seed_counts(raw, keep).split(" of ")[0])
            rows.append(line + [" , ".join(drops), " , ".join(seeds_txt)])
        header = ["config", "attack strings", "flagged as collected (%)"]
        for v in variants:
            header += [f"as {v} (%)", f"missed ({v})", f"largest drop, points ({v})"]
        header.append("significant drops (" + " , ".join(variants) + ")")
        header.append("per seed (" + " , ".join(variants) + ")")
        md += f"\n**{title}**\n\n" + md_table(header, rows)
    md += (
        "\nA drop means the prediction can be changed by repackaging alone. A rise means the "
        "detector was reacting to the container as well as to the payload.\n"
    )
    return md
