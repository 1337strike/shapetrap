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
from pathlib import Path

DEFAULTS = {
    "seed": 42, "seeds": [42, 43, 44], "test_size": 0.25, "max_per_class": 10000,
    "audit_max_per_class": 100000, "tokenizer": "web", "max_features": 4000,
    "detectors": ["lr", "mnb", "svm", "sig", "crs"],
    "preprocess": ["raw", "canon", "cstrip", "vmil"], "mil_rounds": 2,
    "nonlinear_detectors": ["rf", "gbm", "mlp"], "nonlinear_preprocess": ["raw", "canon", "cstrip"],
    "crs_path": "data/raw/coreruleset", "crs_workers": 2,
    "shape_augment": True, "interventions": True,
    "intervention_detectors": ["lr", "rf", "gbm", "mlp"],
    "headline": "lr-raw", "out_dir": "out",
}

# Upstream repositories and the commits this tool was tested against.
SOURCES = [
    # (folder, url, commit, paths to check out; None = whole repository)
    ("sqlixss-detector", "https://github.com/1337strike/sqlixss-detector.git",
     "0dbdc7a92395702c7cb9858a0b2d2b354ec1c295", None),
    ("Offensive-Payloads", "https://github.com/InfoSecWarrior/Offensive-Payloads.git",
     "9e67029a4fa4bfd6a2776f99d2df9c1e660abcab", None),
    ("HttpParamsDataset", "https://github.com/Morzeux/HttpParamsDataset.git",
     "926670a710283f87c05b554680facf3f9530548c", None),
    ("Web-Application-Attack-Datasets", "https://github.com/msudol/Web-Application-Attack-Datasets.git",
     "424c6e1c1951570473d9d6c0227eaaac6fdd6d02", ["/OriginalDataSets", "/README.md", "/LICENSE"]),
    ("Machine-Learning-Web-Application-Firewall-and-Dataset",
     "https://github.com/grananqvist/Machine-Learning-Web-Application-Firewall-and-Dataset.git",
     "5f660d91304a5ecbc706ae15beb8306671265d7b", None),
    ("Fwaf-Machine-Learning-driven-Web-Application-Firewall",
     "https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall.git",
     "9c92866c55ee361743fbf9379a33b51bdcf376b8", None),
    ("modsec-learn-dataset", "https://github.com/pralab/modsec-learn-dataset.git",
     "8f2b27ad477eac014719029f59c3eb8ada191a28",
     ["/legitimate/openappsec", "/malicious/sqlmap", "/malicious/openappsec",
      "/malicious/sqli_kaggle", "/README.md"]),
    ("coreruleset", "https://github.com/coreruleset/coreruleset.git",
     "e587261836599206d8c84c945fc1bd3c8fa4b30d",
     ["/tests/regression/tests", "/rules", "/crs-setup.conf.example", "/LICENSE"]),
    ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
     "08ea40e77db3f42ef8f20c65196f3936a19b6c86", None),
    ("shell-attack-evolution-dataset", "https://github.com/zyw-286/shell-attack-evolution-dataset.git",
     "d5f7fe120ebd921e04026b6348c3ec5d399c5df6", ["/dataset/commands", "/LICENSE", "/README.md"]),
    ("Conpot2025", "https://github.com/ymlwww/Conpot2025.git",
     "6b608dd69363050ef619118effa84949a2de094c",
     ["/cowrie_malicious_anonymized.zip", "/tanner_malicious_anonymized.zip",
      "/h0neytr4p_malicious_anonymized.csv", "/README.md"]),
    ("honeypot-data", "https://github.com/0x4D31/honeypot-data.git",
     "0b6a57491134c10f7cc5055999f1cb8b38c67546",
     ["/datasets/finch_20250731-20251101", "/LICENSE", "/README.md"]),
    ("vps-attack-dataset", "https://github.com/masafykun/vps-attack-dataset.git",
     "b56ea3cd4d584ce5d2354d503c8eb18995ec6ff6", None),
    ("SSH-Honeypot-Dataset", "https://github.com/samdavi/SSH-Honeypot-Dataset.git",
     "fc35eef0454e8275b53bd113b4905be0c129edc0", ["/data", "/README.md"]),
]


def load_config(path: Path) -> tuple[dict, Path]:
    with open(path, "rb") as fh:
        user = tomllib.load(fh)
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
        head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        note = "" if head == commit else f"  (differs from the tested commit {commit[:8]})"
        print(f"  {name} @ {head[:8]}{note}")
    z = raw / "Web-Application-Attack-Datasets" / "OriginalDataSets" / "ecml_pkdd" / "learning_dataset_xml.zip"
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
        print(f"{name:10} kept {info['kept']:6d}  families {info['families']:6d}  {info['by_atype']}")


def _corpus(cfg, out, audit=False):
    from .datasets import load_corpus
    corpus = load_corpus(cfg, out, audit=audit)
    if not audit:
        from . import crs
        crs.attach(corpus, out)      # no-op unless `shapetrap crs` has been run
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
    from .experiment import (report_evasion, report_held_out, report_interventions,
                             report_remedies, report_transfer)
    from .models import config_name, detector_grid
    from .tables import read_typed_csv
    corpus = _corpus(cfg, out)
    summary = read_typed_csv(out / "transfer_summary.csv")
    cells = read_typed_csv(out / "transfer_cells.csv")
    iv_path = out / "interventions.csv"
    interventions = read_typed_csv(iv_path) if iv_path.exists() else []
    configs = [config_name(*g) for g in detector_grid(cfg)]
    names = list(corpus)
    held = held_out_sources(cfg)
    md3 = report_transfer(summary, names, cfg["headline"], configs, held)
    md4 = report_interventions(interventions, [n for n in names if n not in held], cfg["headline"])
    reference = "crs" if all("crs1" in rows[0] for rows in corpus.values() if rows) else "sig"
    md6 = report_held_out(summary, interventions, names, held, cfg["headline"], configs, cfg, corpus,
                          reference)
    md8 = report_evasion(interventions, names, held)
    (out / "section_8_evasion.md").write_text(md8, encoding="utf-8")
    (out / "section_3_transfer.md").write_text(md3, encoding="utf-8")
    (out / "section_4_interventions.md").write_text(md4, encoding="utf-8")
    md7 = report_remedies(summary, cells, names, held, cfg, corpus)
    (out / "section_6_held_out.md").write_text(md6, encoding="utf-8")
    (out / "section_7_remedies.md").write_text(md7, encoding="utf-8")
    print(md3 + "\n" + md4 + "\n" + md6 + "\n" + md7 + "\n" + md8)


def cmd_probe(args, cfg, base, out):
    from .experiment import per_source
    from .probe import run_probe
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
    summary = json.loads((out / "corpus" / "summary.json").read_text(encoding="utf-8"))
    md = "# shapetrap audit report\n\n"
    md += (f"Generated {time.strftime('%Y-%m-%d %H:%M')} · Python {platform.python_version()} · "
           f"scikit-learn {sklearn.__version__} · NumPy {numpy.__version__} · SciPy {scipy.__version__}\n\n")
    md += (f"Seeds {cfg['seeds']} · test share {cfg['test_size']} · cap {cfg['max_per_class']} per class · "
           f"tokenizer `{cfg['tokenizer']}` · {cfg['max_features']} features\n\n")
    md += "## 0. Sources after cleaning\n\n"
    from .tables import md_table
    rows = []
    for name, info in summary.items():
        rows.append([name + (" (test only)" if info.get("role") == "test" else ""),
                     info["raw"], info["unique"], info["kept"], info["families"],
                     info["duplicates_dropped"], info["label_conflicts_dropped"],
                     ", ".join(f"{k} {v}" for k, v in sorted(info["by_atype"].items()))])
    md += md_table(["source", "raw", "unique", "used", "families", "duplicates", "label conflicts",
                    "classes used"], rows)
    md += "\n"
    for section in ("section_1_audit.md", "section_2_probe.md", "section_3_transfer.md",
                    "section_4_interventions.md", "section_5_explain.md",
                    "section_6_held_out.md", "section_7_remedies.md", "section_8_evasion.md"):
        p = out / section
        if p.exists():
            md += p.read_text(encoding="utf-8") + "\n"
    (out / "REPORT.md").write_text(md, encoding="utf-8")
    print(f"wrote {out / 'REPORT.md'}")


def cmd_all(args, cfg, base, out):
    for step in (cmd_build, cmd_audit, cmd_crs, cmd_run, cmd_probe, cmd_explain, cmd_report):
        print(f"\n===== {step.__name__[4:]} =====")
        if step is cmd_crs:
            if "crs" in cfg["detectors"]:
                cmd_crs(args, cfg, base, out, optional=True)
            continue
        step(args, cfg, base, out)


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
    for prep in ("raw", "canon"):
        exp = expected[prep]
        for label, paper in (("as in the paper (default tolerance)", True),
                             ("run to full convergence", False)):
            det = TfidfDetector("lr", prep, tokenizer="paper1", paper_settings=paper).fit(
                [r["text"] for r in train], [r["atype"] for r in train])
            got = []
            for atype in ("benign", "sqli", "xss"):
                texts = [r["text"] for r in hpd if r["atype"] == atype
                         and (atype == "benign" or key(r["text"]) not in corpus_keys)]
                flagged = (det.predict(texts) != "benign").mean()
                got.append((atype, len(texts), 100 * flagged))
            line = "  ".join(f"{a} n={n} flagged {v:.2f}%" for a, n, v in got)
            print(f"LR ({prep}), {label}: {line}")
        print(f"   paper reports benign {exp[0]}%, SQLi {exp[1]}%, XSS {exp[2]}%")


COMMANDS = {"fetch": cmd_fetch, "build": cmd_build, "audit": cmd_audit, "run": cmd_run,
            "crs": cmd_crs, "render": cmd_render, "probe": cmd_probe, "explain": cmd_explain, "report": cmd_report,
            "all": cmd_all, "anchor": cmd_anchor}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shapetrap", description=__doc__)
    ap.add_argument("command", choices=list(COMMANDS))
    ap.add_argument("--config", default="shapetrap.toml")
    ap.add_argument("--out", default=None, help="output directory (overrides the config)")
    args = ap.parse_args(argv)
    cfg, base = load_config(Path(args.config))
    out = Path(args.out) if args.out else base / cfg["out_dir"]
    out.mkdir(parents=True, exist_ok=True)
    COMMANDS[args.command](args, cfg, base, out)


if __name__ == "__main__":
    sys.exit(main())
