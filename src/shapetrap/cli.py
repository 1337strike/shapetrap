"""Command-line entry point: ``shapetrap <command> [--config shapetrap.toml]``."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
import tomllib
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

DEFAULTS = {
    "seed": 42,
    "seeds": [42, 43, 44],
    "test_size": 0.25,
    "max_per_class": 10000,
    "audit_max_per_class": 100000,
    "tokenizer": "web",
    "max_features": 4000,
    "detectors": ["lr", "mnb", "svm", "sig", "crs"],
    "preprocess": ["raw", "canon", "cstrip", "vmil"],
    "mil_rounds": 2,
    "nonlinear_detectors": ["rf", "gbm", "mlp"],
    "nonlinear_preprocess": ["raw", "canon", "cstrip"],
    "neural_detectors": [],
    "neural_preprocess": ["raw", "canon", "cstrip"],
    "crs_path": "data/raw/coreruleset",
    "crs_workers": 2,
    "shape_augment": True,
    "interventions": True,
    "intervention_detectors": ["lr", "rf", "gbm", "mlp"],
    "intervention_seeds": "all",
    "shape_baseline": True,
    "robustness_exclude": ["crs"],
    "headline": "lr-raw",
    "out_dir": "out",
}

# Upstream repositories and the commits this tool was tested against.
SOURCES = [
    # (folder, url, commit, paths to check out; None = whole repository)
    (
        "sqlixss-detector",
        "https://github.com/1337strike/sqlixss-detector.git",
        "0dbdc7a92395702c7cb9858a0b2d2b354ec1c295",
        None,
    ),
    (
        "Offensive-Payloads",
        "https://github.com/InfoSecWarrior/Offensive-Payloads.git",
        "9e67029a4fa4bfd6a2776f99d2df9c1e660abcab",
        None,
    ),
    (
        "HttpParamsDataset",
        "https://github.com/Morzeux/HttpParamsDataset.git",
        "926670a710283f87c05b554680facf3f9530548c",
        None,
    ),
    (
        "Web-Application-Attack-Datasets",
        "https://github.com/msudol/Web-Application-Attack-Datasets.git",
        "424c6e1c1951570473d9d6c0227eaaac6fdd6d02",
        ["/OriginalDataSets", "/README.md", "/LICENSE"],
    ),
    (
        "Machine-Learning-Web-Application-Firewall-and-Dataset",
        "https://github.com/grananqvist/Machine-Learning-Web-Application-Firewall-and-Dataset.git",
        "5f660d91304a5ecbc706ae15beb8306671265d7b",
        None,
    ),
    (
        "Fwaf-Machine-Learning-driven-Web-Application-Firewall",
        "https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall.git",
        "9c92866c55ee361743fbf9379a33b51bdcf376b8",
        None,
    ),
    (
        "modsec-learn-dataset",
        "https://github.com/pralab/modsec-learn-dataset.git",
        "8f2b27ad477eac014719029f59c3eb8ada191a28",
        [
            "/legitimate/openappsec",
            "/malicious/sqlmap",
            "/malicious/openappsec",
            "/malicious/sqli_kaggle",
            "/README.md",
        ],
    ),
    (
        "coreruleset",
        "https://github.com/coreruleset/coreruleset.git",
        "e587261836599206d8c84c945fc1bd3c8fa4b30d",
        ["/tests/regression/tests", "/rules", "/crs-setup.conf.example", "/LICENSE"],
    ),
    (
        "PayloadsAllTheThings",
        "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "08ea40e77db3f42ef8f20c65196f3936a19b6c86",
        None,
    ),
    (
        "shell-attack-evolution-dataset",
        "https://github.com/zyw-286/shell-attack-evolution-dataset.git",
        "d5f7fe120ebd921e04026b6348c3ec5d399c5df6",
        ["/dataset/commands", "/LICENSE", "/README.md"],
    ),
    (
        "Conpot2025",
        "https://github.com/ymlwww/Conpot2025.git",
        "6b608dd69363050ef619118effa84949a2de094c",
        [
            "/cowrie_malicious_anonymized.zip",
            "/tanner_malicious_anonymized.zip",
            "/h0neytr4p_malicious_anonymized.csv",
            "/README.md",
        ],
    ),
    (
        "honeypot-data",
        "https://github.com/0x4D31/honeypot-data.git",
        "0b6a57491134c10f7cc5055999f1cb8b38c67546",
        ["/datasets/finch_20250731-20251101", "/LICENSE", "/README.md"],
    ),
    (
        "vps-attack-dataset",
        "https://github.com/masafykun/vps-attack-dataset.git",
        "b56ea3cd4d584ce5d2354d503c8eb18995ec6ff6",
        None,
    ),
    (
        "SSH-Honeypot-Dataset",
        "https://github.com/samdavi/SSH-Honeypot-Dataset.git",
        "fc35eef0454e8275b53bd113b4905be0c129edc0",
        ["/data", "/README.md"],
    ),
]


def _read_config(path: Path) -> dict:
    with open(path, "rb") as fh:
        user = tomllib.load(fh)
    here = path.resolve().parent
    if "extends" in user:
        # A config can extend another one (path relative to its own folder) and
        # override single keys, so an extra run does not copy every source.
        user = {**_read_config(here / user.pop("extends")), **user}
    if "base_out" in user:
        # Read the corpus and the CRS verdicts from another run's output folder,
        # so an extra run uses exactly the same strings.
        user["base_out"] = str((here / user["base_out"]).resolve())
    return user


def load_config(path: Path) -> tuple[dict, Path]:
    user = _read_config(path)
    cfg = {**DEFAULTS, **user}
    if "datasets" not in cfg or not cfg["datasets"]:
        raise SystemExit("config has no [datasets.*] entries")
    return cfg, path.resolve().parent


def cmd_fetch(args, cfg, base, out):
    raw = base / "data" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    for name, url, commit, paths in SOURCES:
        dest = raw / name
        git = ["git", "-C", str(dest)]
        if not dest.exists():
            # Shallow fetch of exactly the pinned commit: no history, and for
            # large repositories only the paths that are used.
            dest.mkdir()
            subprocess.run(git + ["init", "--quiet"], check=True)
            subprocess.run(git + ["remote", "add", "origin", url], check=True)
            fetch = ["fetch", "--quiet", "--depth", "1"]
            if paths:
                subprocess.run(git + ["sparse-checkout", "set", "--no-cone"] + paths, check=True)
                fetch.append("--filter=blob:none")
            subprocess.run(git + fetch + ["origin", commit], check=True)
            subprocess.run(git + ["checkout", "--quiet", "FETCH_HEAD"], check=True)
        head = subprocess.run(
            git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=False
        ).stdout.strip()
        note = "" if head == commit else f"  (differs from the tested commit {commit[:8]})"
        print(f"  {name} @ {head[:8]}{note}")
    z = (
        raw
        / "Web-Application-Attack-Datasets"
        / "OriginalDataSets"
        / "ecml_pkdd"
        / "learning_dataset_xml.zip"
    )
    target = raw / "ecml_xml"
    if not (target / "learning_dataset.xml").exists():
        target.mkdir(exist_ok=True)
        with zipfile.ZipFile(z) as zf:
            zf.extract("learning_dataset.xml", target)
        print("  unpacked ECML/PKDD learning_dataset.xml")


def cmd_build(args, cfg, base, out):
    from .datasets import build_corpus

    summary = build_corpus(cfg, base, out)
    for name, info in summary.items():
        print(
            f"{name:10} kept {info['kept']:6d}  families {info['families']:6d}  {info['by_atype']}"
        )


def _corpus(cfg, out, audit=False):
    from .datasets import load_corpus

    src = Path(cfg["base_out"]) if cfg.get("base_out") else out
    corpus = load_corpus(cfg, src, audit=audit)
    if not audit:
        from . import crs

        crs.attach(corpus, src)  # no-op unless `shapetrap crs` has been run
    return corpus


def cmd_crs(args, cfg, base, out, optional=False):
    """Evaluate every corpus string with the real OWASP CRS (libmodsecurity)."""
    from . import crs
    from .datasets import load_corpus

    corpus = load_corpus(cfg, out)
    try:
        info = crs.run_crs(cfg, base, out, corpus)
    except RuntimeError as exc:
        if optional:
            print(f"  skipped: {exc}\n  The run continues with the local signatures as reference.")
            return
        raise SystemExit(str(exc))
    print(f"  stored CRS verdicts for {info['strings']} distinct strings in {out / 'crs'}")


def cmd_audit(args, cfg, base, out):
    from .audit import run_audit
    from .datasets import held_out_sources

    md = run_audit(_corpus(cfg, out, audit=True), out, held=held_out_sources(cfg))
    (out / "section_1_audit.md").write_text(md, encoding="utf-8")
    print(md)


def cmd_run(args, cfg, base, out):
    from .experiment import run_experiment

    run_experiment(cfg, _corpus(cfg, out), out)
    cmd_render(args, cfg, base, out)


def cmd_render(args, cfg, base, out):
    """Rebuild the transfer, intervention, held-out and remedy sections from
    the CSV files of the last `run`, without fitting anything."""
    from .datasets import held_out_sources
    from .models import config_name, detector_grid
    from .report import (
        report_evasion,
        report_held_out,
        report_interventions,
        report_remedies,
        report_transfer,
    )
    from .tables import read_typed_csv

    corpus = _corpus(cfg, out)
    summary = read_typed_csv(out / "transfer_summary.csv")
    cells = read_typed_csv(out / "transfer_cells.csv")
    iv_path = out / "interventions.csv"
    interventions = read_typed_csv(iv_path) if iv_path.exists() else []
    configs = [config_name(*g) for g in detector_grid(cfg)]
    names = list(corpus)
    held = held_out_sources(cfg)
    groups = None
    overlap = (Path(cfg["base_out"]) if cfg.get("base_out") else out) / "audit_overlap.csv"
    if overlap.exists():
        from .audit import provenance_groups

        groups, _ = provenance_groups(read_typed_csv(overlap), names, held)
    md3 = report_transfer(
        summary, names, cfg["headline"], configs, held, groups, cfg.get("robustness_exclude", [])
    )
    md4 = report_interventions(interventions, [n for n in names if n not in held], cfg["headline"])
    reference = "crs" if all("crs1" in rows[0] for rows in corpus.values() if rows) else "sig"
    md6 = report_held_out(
        summary, interventions, names, held, cfg["headline"], configs, cfg, corpus, reference
    )
    md8 = report_evasion(interventions, names, held, cfg.get("rewrite", "literal"))
    (out / "section_8_evasion.md").write_text(md8, encoding="utf-8")
    (out / "section_3_transfer.md").write_text(md3, encoding="utf-8")
    (out / "section_4_interventions.md").write_text(md4, encoding="utf-8")
    md7 = report_remedies(summary, cells, names, held, cfg, corpus, groups)
    (out / "section_6_held_out.md").write_text(md6, encoding="utf-8")
    (out / "section_7_remedies.md").write_text(md7, encoding="utf-8")
    print(md3 + "\n" + md4 + "\n" + md6 + "\n" + md7 + "\n" + md8)


def cmd_probe(args, cfg, base, out):
    from .probe import run_probe
    from .report import per_source
    from .tables import read_csv

    corpus = _corpus(cfg, out)
    ps = None
    summary_path = out / "transfer_summary.csv"
    if summary_path.exists():
        from .datasets import held_out_sources

        bench = [n for n in corpus if n not in held_out_sources(cfg)]
        ps = per_source(read_csv(summary_path), cfg["headline"], bench)
    md = run_probe(cfg, corpus, out, ps)
    (out / "section_2_probe.md").write_text(md, encoding="utf-8")
    print(md)


def cmd_explain(args, cfg, base, out):
    from .explain import run_explain

    md = run_explain(cfg, _corpus(cfg, out), out, prep=cfg["headline"].split("-")[1].split("+")[0])
    (out / "section_5_explain.md").write_text(md, encoding="utf-8")
    print(md)


def cmd_report(args, cfg, base, out):
    import numpy
    import scipy
    import sklearn

    corpus_out = Path(cfg["base_out"]) if cfg.get("base_out") else out
    summary = json.loads((corpus_out / "corpus" / "summary.json").read_text(encoding="utf-8"))
    versions = f"scikit-learn {sklearn.__version__} · NumPy {numpy.__version__} · SciPy {scipy.__version__}"
    if cfg.get("neural_detectors"):
        try:
            import torch

            versions += f" · PyTorch {torch.__version__}"
            if "bert" in cfg["neural_detectors"]:
                import transformers

                versions += f" · transformers {transformers.__version__}"
        except ImportError:
            pass
    md = "# shapetrap audit report\n\n"
    md += (
        f"Generated {time.strftime('%Y-%m-%d %H:%M')} · Python {platform.python_version()} · "
        f"{versions}\n\n"
    )
    md += (
        f"Seeds {cfg['seeds']} · test share {cfg['test_size']} · cap {cfg['max_per_class']} per class · "
        f"tokenizer `{cfg['tokenizer']}` · {cfg['max_features']} features · "
        f"rewrites `{cfg.get('rewrite', 'literal')}`\n\n"
    )
    md += "## 0. Sources after cleaning\n\n"
    from .tables import md_table

    rows = []
    for name, info in summary.items():
        rows.append(
            [
                name + (" (test only)" if info.get("role") == "test" else ""),
                info["raw"],
                info["unique"],
                info["kept"],
                info["families"],
                info["duplicates_dropped"],
                info["label_conflicts_dropped"],
                ", ".join(f"{k} {v}" for k, v in sorted(info["by_atype"].items())),
            ]
        )
    md += md_table(
        [
            "source",
            "raw",
            "unique",
            "used",
            "families",
            "duplicates",
            "label conflicts",
            "classes used",
        ],
        rows,
    )
    md += "\n"
    for section in (
        "section_1_audit.md",
        "section_2_probe.md",
        "section_3_transfer.md",
        "section_4_interventions.md",
        "section_5_explain.md",
        "section_6_held_out.md",
        "section_7_remedies.md",
        "section_8_evasion.md",
        "section_9_validation.md",
    ):
        p = out / section
        if p.exists():
            md += p.read_text(encoding="utf-8") + "\n"
    (out / "REPORT.md").write_text(md, encoding="utf-8")
    print(f"wrote {out / 'REPORT.md'}")


def cmd_all(args, cfg, base, out):
    lock = base / "requirements.lock"
    if lock.exists() and check_env(lock):
        print("Note: installed packages differ from requirements.lock (run `shapetrap env`).")
    for step in (cmd_build, cmd_audit, cmd_crs, cmd_run, cmd_probe, cmd_explain, cmd_report):
        print(f"\n===== {step.__name__[4:]} =====")
        if step is cmd_crs:
            if "crs" in cfg["detectors"]:
                cmd_crs(args, cfg, base, out, optional=True)
            continue
        step(args, cfg, base, out)


def read_lock(path: Path) -> dict[str, str]:
    """Package name -> pinned version from a requirements lock file."""
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "==" in line and not line.startswith("-"):
            name, version = line.split("==", 1)
            pins[name.strip()] = version.strip()
    return pins


def check_env(lock: Path) -> list[str]:
    """Differences between the installed packages and the lock file."""
    from importlib.metadata import PackageNotFoundError, version

    problems = []
    for name, pinned in read_lock(lock).items():
        try:
            installed = version(name)
        except PackageNotFoundError:
            problems.append(f"{name}: not installed (lock: {pinned})")
            continue
        if installed != pinned:
            problems.append(f"{name}: {installed} installed, lock has {pinned}")
    return problems


def cmd_env(args, cfg, base, out):
    """Compare the installed packages with requirements.lock."""
    lock = base / "requirements.lock"
    if not lock.exists():
        sys.exit(f"no requirements.lock next to {args.config}")
    print(f"Python {platform.python_version()} (the paper's run used 3.12.10)")
    problems = check_env(lock)
    if problems:
        print("Installed packages differ from requirements.lock:")
        for line in problems:
            print("  " + line)
        print("Results can then differ from out/ in single cells; see the README.")
        sys.exit(1)
    print(f"All {len(read_lock(lock))} packages match requirements.lock.")


def cmd_anchor(args, cfg, base, out):
    """Re-derive the earlier paper's HttpParamsDataset numbers (its Table VI)
    with this code base, as a check that the pipeline matches."""
    import re

    from .datasets import load_hpd, load_paper1
    from .models import TfidfDetector

    p1 = next(e for e in cfg["datasets"].values() if e["loader"] == "paper1")
    hp = next(e for e in cfg["datasets"].values() if e["loader"] == "hpd")
    rows, _ = load_paper1({"path": p1["path"]}, base)
    train = [r for r in rows if r["split"] == "train"]
    key = lambda s: re.sub(r"\s+", "", s).lower()
    corpus_keys = {key(r["text"]) for r in rows}
    hpd, _ = load_hpd(hp, base)
    expected = {"raw": (97.03, 99.68, 99.62), "canon": (97.53, 99.68, 99.43)}
    print(f"train {len(train)} strings; paper-1 tokenizer; LR C=10")
    mismatches = 0
    for prep in ("raw", "canon"):
        exp = expected[prep]
        for label, paper in (
            ("as in the paper (default tolerance)", True),
            ("run to full convergence", False),
        ):
            det = TfidfDetector("lr", prep, tokenizer="paper1", paper_settings=paper).fit(
                [r["text"] for r in train], [r["atype"] for r in train]
            )
            got = []
            for atype in ("benign", "sqli", "xss"):
                texts = [
                    r["text"]
                    for r in hpd
                    if r["atype"] == atype
                    and (atype == "benign" or key(r["text"]) not in corpus_keys)
                ]
                flagged = (det.predict(texts) != "benign").mean()
                got.append((atype, len(texts), 100 * flagged))
            line = "  ".join(f"{a} n={n} flagged {v:.2f}%" for a, n, v in got)
            print(f"LR ({prep}), {label}: {line}")
            if paper and tuple(round(v, 2) for _, _, v in got) != exp:
                mismatches += 1
        print(f"   paper reports benign {exp[0]}%, SQLi {exp[1]}%, XSS {exp[2]}%")
    if mismatches:
        sys.exit("anchor check FAILED: the paper settings do not reproduce the reference numbers")
    print("anchor check passed: the reference numbers are reproduced exactly")


def cmd_label_sample(args, cfg, base, out):
    """Draw a random sample of held-out strings for two people to label."""
    from .annotate import draw_sample, write_sample
    from .datasets import held_out_sources

    corpus = _corpus(cfg, out)
    # Curated payload lists are attacks by construction; the labels matter for
    # the wild sources (honeypots and server logs).  `label_sources` overrides.
    held = cfg.get("label_sources") or [
        n
        for n in corpus
        if n in held_out_sources(cfg) and cfg["datasets"][n].get("group", "").startswith("wild")
    ]
    sample = draw_sample(corpus, held, args.n, cfg["seed"])
    path = write_sample(sample, out / "labels")
    per = Counter((r["source"], r["recorded_class"]) for r in sample)
    print(f"  {len(sample)} strings from {len(held)} held-out sources -> {path}")
    for (name, y), k in sorted(per.items()):
        print(f"    {name:12s} {y:7s} {k}")
    print(f"  Label sample_blind.csv (or sample.csv) following {out / 'labels' / 'GUIDE.md'}")


def cmd_label_retest(args, cfg, base, out):
    """A shuffled subset of the labeled sample for the same labeler to label again."""
    from .annotate import draw_retest, read_labels, write_retest

    folder = out / "labels"
    rows = read_labels(folder / "sample.csv")
    path = write_retest(draw_retest(rows, args.n, cfg["seed"]), folder)
    print(f"  {min(args.n, len(rows))} rows in a new order, without labels -> {path}")
    print("  Label them again later (ideally a day after the first pass) without looking at")
    print("  the first labels, in the label_b column; then run `label-score --single`.")


def cmd_label_score(args, cfg, base, out):
    """Agreement between the two labelers, then every detector on the agreed labels."""
    import numpy as np

    from .annotate import agreement, final_label, read_labels, score_flags
    from .datasets import held_out_sources, split_all
    from .models import config_name, make_detector
    from .tables import write_csv

    folder = out / "labels"
    rows = read_labels(folder / "sample.csv")
    blind = folder / "sample_blind.csv"
    if blind.exists():
        # Labels may have been written in the blind copy; merge them by id.
        extra = {r["id"]: r for r in read_labels(blind)}
        for r in rows:
            for col in ("label_a", "label_b", "label_final", "note"):
                if not r.get(col) and extra.get(r["id"], {}).get(col):
                    r[col] = extra[r["id"]][col]
    single = bool(getattr(args, "single", False))
    retest = folder / "retest.csv"
    if single:
        print(f"  one labeler: {sum(1 for r in rows if r['label_a'])} of {len(rows)} rows labeled")
        if retest.exists():
            # Second pass by the same labeler: intra-rater (test-retest) agreement.
            second = {r["id"]: r.get("label_b", "").strip().lower() for r in read_labels(retest)}
            pairs = [
                {**r, "label_b": second[r["id"]]}
                for r in rows
                if r["label_a"] and second.get(r["id"])
            ]
            table, disagree = agreement(pairs)
            for t in table:
                t["kind"] = "intra-rater (same labeler, second pass)"
            write_csv(table, folder / "agreement.csv")
            write_csv(disagree, folder / "disagreements.csv")
            top = table[0]
            print(
                f"  second pass: {top['n']} rows; agreement {top['agree']}, intra-rater "
                f"Cohen's kappa {top['kappa']} (injection vs rest {top['kappa_injection_vs_rest']})"
            )
            print(f"  {len(disagree)} rows labeled differently -> {folder / 'disagreements.csv'}")
        else:
            print("  no retest.csv yet: run `label-retest` for an intra-rater agreement")
    else:
        table, disagree = agreement(rows)
        write_csv(table, folder / "agreement.csv")
        write_csv(disagree, folder / "disagreements.csv")
        top = table[0]
        print(
            f"  labeled by both: {top['n']} of {len(rows)}; agreement {top['agree']}, "
            f"Cohen's kappa {top['kappa']} (injection vs rest {top['kappa_injection_vs_rest']})"
        )
        print(f"  {len(disagree)} disagreements -> {folder / 'disagreements.csv'}")
    done = [r for r in rows if final_label(r, single)]
    if not done:
        print("  no settled labels yet; nothing to score")
        return
    labels = [final_label(r, single) for r in done]
    texts = [r["text"] for r in done]
    print(
        f"  scoring {len(done)} settled labels: "
        + ", ".join(f"{k} {v}" for k, v in sorted(Counter(labels).items()))
    )

    corpus = _corpus(cfg, out)
    held = held_out_sources(cfg)
    seed = cfg["seeds"][0]
    splits = split_all(cfg, corpus, seed)
    results = []
    if all("crs1" in rows_[0] for rows_ in corpus.values() if rows_):
        verdict = {}
        for name in held:
            for r in corpus.get(name, []):
                verdict[r["text"]] = (r["crs1"], r["crs2"])
        for lvl in (1, 2):
            flags = np.array([bool(verdict.get(t, (False, False))[lvl - 1]) for t in texts])
            results.append({"config": f"crs-pl{lvl}", "source": "-", **score_flags(labels, flags)})
    kinds = [k for k in cfg["detectors"] if k not in ("sig", "crs")]
    configs = [(k, p) for k in kinds for p in cfg["preprocess"] if p != "vmil"]
    configs += [
        (k, p)
        for k in cfg.get("neural_detectors", [])
        for p in cfg.get("neural_preprocess", [])
        if p in ("raw", "canon", "cstrip")
    ]
    for src in corpus:
        if src in held:
            continue
        train = splits[src][0]
        if len({r["y"] for r in train}) < 2:
            continue
        xtr, ytr = [r["text"] for r in train], [r["atype"] for r in train]
        for kind, prep in configs:
            det = make_detector(kind, prep, cfg, seed=seed).fit(xtr, ytr)
            flags = np.asarray(det.predict(texts), dtype=object) != "benign"
            results.append(
                {
                    "config": config_name(kind, prep, False),
                    "source": src,
                    **score_flags(labels, flags),
                }
            )
    write_csv(results, folder / "detector_scores.csv")
    print(f"  per training source -> {folder / 'detector_scores.csv'}")
    print(
        f"  {'config':16s} {'injection flagged':>18s} {'benign flagged':>15s} {'other malicious':>16s}"
    )
    by = defaultdict(list)
    for r in results:
        by[r["config"]].append(r)
    for name, rs in by.items():

        def mean(col, rs=rs):
            v = [x[col] for x in rs if x[col] != ""]
            return f"{100 * sum(v) / len(v):.1f}%" if v else "-"

        print(
            f"  {name:16s} {mean('flagged_injection'):>18s} {mean('flagged_benign'):>15s} "
            f"{mean('flagged_other_malicious'):>16s}"
        )


def cmd_validate(args, cfg, base, out):
    """Which changed decisions are real evasions?  Rewritten attacks are sent
    to a small in-process reference application (see testbed.py)."""
    import random

    import numpy as np

    from .datasets import held_out_sources, split_all
    from .models import make_detector
    from .shapes import EXTRA_INTERVENTIONS, interventions
    from .tables import md_table, write_csv
    from .testbed import Testbed

    INTERVENTIONS = dict(interventions(cfg))
    if cfg.get("rewrite", "literal") == "faithful" and cfg.get("validate_extra_containers", True):
        INTERVENTIONS.update(EXTRA_INTERVENTIONS)

    corpus = _corpus(cfg, out)
    held = held_out_sources(cfg)
    bench = [n for n in corpus if n not in held]
    seed = cfg["seeds"][0]
    splits = split_all(cfg, corpus, seed)
    tb = Testbed()
    configs = list(cfg.get("validate_configs") or [cfg["headline"]])

    # The real CRS as a detector under the same rewrites: rewritten strings are
    # sent through libmodsecurity as requests of their new container.
    verdicts = None
    has_crs = all("crs1" in rows[0] for rows in corpus.values() if rows)
    if has_crs and "crs" in cfg["detectors"] and cfg.get("validate_crs", True):
        from . import crs

        try:
            verdicts = crs.Verdicts(cfg, base, Path(cfg.get("base_out") or out))
            configs += [f"crs-pl{lvl}" for lvl in (1, 2)]
        except RuntimeError as exc:
            print(f"  CRS skipped: {exc}")

    # Attacks of every benchmark test split, and their rewrites, with the
    # testbed verdict for each.  Independent of the detector.  Benign test
    # strings (a seeded sample) get the same rewrites, for the false-positive
    # side of container sensitivity.
    cap = int(cfg.get("validate_benign_max", 2000))
    attacks, benign = {}, {}
    for tgt in bench:
        rows = [r for r in splits[tgt][1] if r["y"] == "attack"]
        texts = [r["text"] for r in rows]
        types = [r["atype"] for r in rows]
        a = {
            "texts": texts,
            "native_ok": np.array([tb.effective(t, k) for t, k in zip(texts, types)], dtype=bool),
        }
        for vn, fn in INTERVENTIONS.items():
            vt = [fn(t, seed) for t in texts]
            a[vn] = {
                "texts": vt,
                "changed": np.array([x != y for x, y in zip(texts, vt)], dtype=bool),
                "ok": np.array([tb.effective(t, k) for t, k in zip(vt, types)], dtype=bool),
            }
        attacks[tgt] = a
        ben = [r["text"] for r in splits[tgt][1] if r["y"] == "benign"]
        if len(ben) > cap:
            ben = random.Random(f"{seed}:{tgt}").sample(ben, cap)
        b = {"texts": ben}
        for vn, fn in INTERVENTIONS.items():
            vt = [fn(t, seed) for t in ben]
            b[vn] = {
                "texts": vt,
                "changed": np.array([x != y for x, y in zip(ben, vt)], dtype=bool),
            }
        benign[tgt] = b
        print(
            f"  {tgt}: {len(texts)} attacks, {a['native_ok'].mean() if texts else 0:.1%} "
            f"effective as collected; {len(ben)} benign"
        )

    def detectors(name):
        """(training source, flag function) pairs for one configuration."""
        if name.startswith("crs-pl"):
            lvl = int(name[-1])
            yield "-", lambda texts: np.array(verdicts.blocked(texts, lvl), dtype=bool)
            return
        kind, _, prep = name.partition("-")
        if "+" in prep:
            raise SystemExit(f"validate: augmented configurations are not supported ({name})")
        for src in bench:
            train = splits[src][0]
            if len({r["y"] for r in train}) < 2:
                continue
            det = make_detector(kind, prep, cfg, seed=seed).fit(
                [r["text"] for r in train], [r["atype"] for r in train]
            )
            yield (
                src,
                lambda texts, det=det: (
                    np.asarray(det.predict(texts), dtype=object) != "benign"
                    if texts
                    else np.zeros(0, dtype=bool)
                ),
            )

    rows_out, sens = [], []
    for name in configs:
        for src, flags in detectors(name):
            for tgt in bench:
                a, b = attacks[tgt], benign[tgt]
                native = flags(a["texts"])
                vflag = {vn: flags(a[vn]["texts"]) for vn in INTERVENTIONS}
                for vn in INTERVENTIONS:
                    v = a[vn]
                    m = v["changed"] & a["native_ok"]
                    if not m.any():
                        continue
                    lost = m & native & ~vflag[vn]
                    rows_out.append(
                        {
                            "config": name,
                            "source": src,
                            "target": tgt,
                            "variant": vn,
                            "n": int(m.sum()),
                            "still_effective": round(float(v["ok"][m].mean()), 4),
                            "detected_native": round(float(native[m].mean()), 4),
                            "detected_variant": round(float(vflag[vn][m].mean()), 4),
                            "lost": int(lost.sum()),
                            "confirmed_evasions": int((lost & v["ok"]).sum()),
                        }
                    )
                # Best of all containers: an attacker who may pick any one.
                n_att = len(a["texts"])
                evade = np.zeros(n_att, dtype=bool)
                differs_a = np.zeros(n_att, dtype=bool)
                for vn in INTERVENTIONS:
                    usable = a[vn]["changed"] & a[vn]["ok"]
                    evade |= usable & ~vflag[vn]
                    differs_a |= usable & (vflag[vn] != native)
                caught = native & a["native_ok"]
                bnat = flags(b["texts"])
                n_ben = len(b["texts"])
                any_flag = bnat.copy()
                differs_b = np.zeros(n_ben, dtype=bool)
                for vn in INTERVENTIONS:
                    bf = flags(b[vn]["texts"])
                    ch = b[vn]["changed"]
                    any_flag |= ch & bf
                    differs_b |= ch & (bf != bnat)
                sens.append(
                    {
                        "config": name,
                        "source": src,
                        "target": tgt,
                        "attacks_effective": int(a["native_ok"].sum()),
                        "detected": int(caught.sum()),
                        "evaded_any": int((caught & evade).sum()),
                        "csr_attack": round(float(differs_a[a["native_ok"]].mean()), 4)
                        if a["native_ok"].any()
                        else float("nan"),
                        "benign": n_ben,
                        "fpr_native": round(float(bnat.mean()), 4) if n_ben else float("nan"),
                        "fpr_any": round(float(any_flag.mean()), 4) if n_ben else float("nan"),
                        "csr_benign": round(float(differs_b.mean()), 4) if n_ben else float("nan"),
                    }
                )
        print(f"  {name}: done")
    write_csv(rows_out, out / "validation.csv")
    write_csv(sens, out / "container_sensitivity.csv")
    print(f"  -> {out / 'validation.csv'}, {out / 'container_sensitivity.csv'}")
    print(f"  rewrites: {cfg.get('rewrite', 'literal')} ({', '.join(INTERVENTIONS)})")
    print(f"  {'config':14s} {'rewrite':9s} {'still works':>12s} {'lost':>7s} {'confirmed':>10s}")

    table = []
    for name in configs:
        for vn in INTERVENTIONS:
            rs = [r for r in rows_out if r["config"] == name and r["variant"] == vn]
            if not rs:
                continue
            n = sum(r["n"] for r in rs)
            ok = sum(r["still_effective"] * r["n"] for r in rs) / n
            lost = sum(r["lost"] for r in rs)
            conf = sum(r["confirmed_evasions"] for r in rs)
            share = f"{conf / lost:.1%}" if lost else "-"
            print(f"  {name:14s} {vn:9s} {ok:>12.1%} {lost:>7d} {share:>10s}")
            table.append([name, vn, n, f"{100 * ok:.1f}", lost, conf, share])
    md = "## 9. Rewritten attacks against the reference application\n\n"
    md += (
        f"Seed {seed}, `{cfg.get('rewrite', 'literal')}` rewrites. Attacks of every benchmark test "
        "split that work as collected, moved to another container, and sent to the in-process "
        "reference application (see README). *Lost*: detections lost after the rewrite, summed over "
        "training and test sources. *Confirmed*: lost detections whose rewritten attack still "
        "works. `crs-pl1` and `crs-pl2` are the OWASP CRS, given each rewritten string as a "
        "request of its new container.\n\n"
    )
    md += md_table(
        ["config", "rewrite", "attacks", "still work (%)", "lost", "confirmed", "confirmed share"],
        table,
    )
    md += report_sensitivity(sens, list(INTERVENTIONS))
    (out / "section_9_validation.md").write_text(md + "\n", encoding="utf-8")
    print(report_sensitivity(sens, list(INTERVENTIONS)))


def report_sensitivity(sens: list[dict], variants: list[str]) -> str:
    """Best-of-container evasion and container sensitivity, per configuration."""
    import math

    from .tables import md_table, pct

    def mean(vals):
        vals = [float(v) for v in vals if not math.isnan(float(v))]
        return sum(vals) / len(vals) if vals else float("nan")

    rows = []
    for name in dict.fromkeys(r["config"] for r in sens):
        for scope, keep in (
            ("cross", lambda r: r["source"] != r["target"]),
            ("own", lambda r: r["source"] == r["target"]),
        ):
            rs = [r for r in sens if r["config"] == name and keep(r)]
            if not rs:
                continue
            det = sum(int(r["detected"]) for r in rs)
            ev = sum(int(r["evaded_any"]) for r in rs)
            rows.append(
                [
                    f"`{name}`",
                    "all" if rs[0]["source"] == "-" else scope,
                    det,
                    ev,
                    pct(ev / det) if det else "-",
                    pct(mean(r["csr_attack"] for r in rs)),
                    pct(mean(r["csr_benign"] for r in rs)),
                    pct(mean(r["fpr_native"] for r in rs)),
                    pct(mean(r["fpr_any"] for r in rs)),
                ]
            )
    md = (
        "\n**Container choice as an attack and as a false-positive source** "
        f"(containers: as collected, {', '.join(variants)}). *Evaded*: attacks that work as "
        "collected and are detected, but have at least one container in which they still work "
        "and are not detected (summed over cells). *CSR*: container sensitivity rate, the share of "
        "strings whose decision changes in at least one container (attacks: working rewrites "
        "only); mean over cells. *FPR any*: benign strings flagged in at least one container. "
        "`cross` cells train on one source and test on another, `own` cells on the same "
        "source.\n\n"
    )
    md += md_table(
        [
            "config",
            "cells",
            "detected",
            "evaded",
            "evaded (%)",
            "CSR attack (%)",
            "CSR benign (%)",
            "FPR native (%)",
            "FPR any (%)",
        ],
        rows,
    )
    return md


COMMANDS = {
    "fetch": cmd_fetch,
    "build": cmd_build,
    "audit": cmd_audit,
    "run": cmd_run,
    "crs": cmd_crs,
    "render": cmd_render,
    "probe": cmd_probe,
    "explain": cmd_explain,
    "report": cmd_report,
    "all": cmd_all,
    "anchor": cmd_anchor,
    "env": cmd_env,
    "label-sample": cmd_label_sample,
    "label-retest": cmd_label_retest,
    "label-score": cmd_label_score,
    "validate": cmd_validate,
}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shapetrap", description=__doc__)
    ap.add_argument("command", choices=list(COMMANDS))
    ap.add_argument("--config", default="shapetrap.toml")
    ap.add_argument("--out", default=None, help="output directory (overrides the config)")
    ap.add_argument(
        "--n", type=int, default=400, help="label-sample / label-retest: number of strings"
    )
    ap.add_argument(
        "--single", action="store_true", help="label-score: one labeler, label_a is the label"
    )
    args = ap.parse_args(argv)
    cfg, base = load_config(Path(args.config))
    out = Path(args.out) if args.out else base / cfg["out_dir"]
    out.mkdir(parents=True, exist_ok=True)
    COMMANDS[args.command](args, cfg, base, out)


if __name__ == "__main__":
    sys.exit(main())
