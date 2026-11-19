"""Tests for the manual-label workflow (label-sample / label-score)."""

import numpy as np
import pytest


def _corpus():
    return {
        "big": [{"text": f"cmd {i}", "y": "attack"} for i in range(900)],
        "small": [{"text": f"user{i}", "y": "benign"} for i in range(40)]
        + [{"text": "user1", "y": "benign"}],
    }


def test_sample_is_stratified_distinct_and_repeatable():
    from shapetrap.annotate import draw_sample

    corpus = _corpus()
    corpus["big"] += [{"text": f"ok {i}", "y": "benign"} for i in range(5)]
    a = draw_sample(corpus, ["big", "small"], 100, seed=3)
    b = draw_sample(corpus, ["big", "small"], 100, seed=3)
    assert a == b
    assert len(a) == 100
    per = {}
    for r in a:
        per[(r["source"], r["recorded_class"])] = per.get((r["source"], r["recorded_class"]), 0) + 1
    # Three strata: the two small ones are taken whole and pass their unused
    # share on to the large one.
    assert per[("big", "benign")] == 5
    assert per[("small", "benign")] == 40
    assert per[("big", "attack")] == 55
    assert len({r["text"] for r in a}) == 100
    small = next(r for r in a if r["source"] == "small")
    assert small["weight"] == 1.0
    big = next(r for r in a if r["recorded_class"] == "attack")
    assert big["weight"] == round(900 / 55, 4)


def test_kappa_and_agreement():
    from shapetrap.annotate import agreement, cohen_kappa, final_label

    assert cohen_kappa(["a", "b"] * 5, ["a", "b"] * 5) == pytest.approx(1.0)
    # Textbook case: po = 0.7, pe = 0.5 -> kappa = 0.4
    a = ["y"] * 5 + ["n"] * 5
    b = ["y"] * 4 + ["n"] + ["y"] * 2 + ["n"] * 3
    assert cohen_kappa(a, b) == pytest.approx(0.4)
    rows = [
        {"id": "1", "source": "s", "label_a": "sqli", "label_b": "sqli", "label_final": ""},
        {"id": "2", "source": "s", "label_a": "benign", "label_b": "unclear", "label_final": ""},
        {"id": "3", "source": "s", "label_a": "xss", "label_b": "benign", "label_final": "xss"},
    ]
    table, disagree = agreement(rows)
    assert table[0]["n"] == 3 and [r["id"] for r in disagree] == ["2", "3"]
    assert [final_label(r) for r in rows] == ["sqli", "", "xss"]
    assert [final_label(r, single=True) for r in rows] == ["sqli", "benign", "xss"]


def test_unknown_label_is_rejected(tmp_path):
    from shapetrap.annotate import read_labels

    p = tmp_path / "sample.csv"
    p.write_text("id,text,label_a,label_b,label_final,note\nL1,x,SQLi,maybe,,\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        read_labels(p)


def test_score_flags():
    from shapetrap.annotate import score_flags

    labels = ["sqli", "xss", "benign", "benign", "other_malicious", "unclear"]
    flags = np.array([True, False, True, False, True, True])
    s = score_flags(labels, flags)
    assert s["n_injection"] == 2 and s["flagged_injection"] == 0.5
    assert s["flagged_benign"] == 0.5
    assert s["flagged_other_malicious"] == 1.0


def test_retest_subset_and_intra_rater_kappa(tmp_path):
    from shapetrap.annotate import agreement, draw_retest, write_retest

    sample = [{"id": f"L{i:04d}", "text": f"t{i}", "label_a": "benign"} for i in range(50)]
    sub = draw_retest(sample, 20, seed=1)
    assert len(sub) == 20 and len({r["id"] for r in sub}) == 20
    assert all(r["label_b"] == "" for r in sub)
    assert [r["id"] for r in sub] != sorted(r["id"] for r in sub)  # new order
    write_retest(sub, tmp_path)
    with pytest.raises(SystemExit):
        write_retest(sub, tmp_path)
    rows = [
        {"id": "1", "source": "s", "label_a": "sqli", "label_b": "sqli", "label_final": ""},
        {"id": "2", "source": "s", "label_a": "benign", "label_b": "benign", "label_final": ""},
    ]
    table, disagree = agreement(rows)
    assert table[0]["kappa"] == 1.0 and not disagree


def _read(path):
    import csv

    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_interactive_labeling_saves_and_resumes(tmp_path):
    import csv

    from shapetrap.annotate import label_interactive, visible

    path = tmp_path / "sample_blind.csv"
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "text", "label_a", "label_b", "label_final", "note"])
        w.writerow(["L0001", "id=5", "", "", "", ""])
        w.writerow(["L0002", "' or 1=1--", "", "", "", ""])
        w.writerow(["L0003", "=cmd|' /c calc'!A0", "", "", "", ""])
    out = []
    # 1 -> benign, 2 then back, then sqli by name, note on the third, then quit
    answers = iter(["1", "2", "b", "sqli", "n", "spreadsheet formula", "x", "q"])
    left = label_interactive(path, "label_a", ask=lambda _: next(answers), say=out.append)
    assert left == 1
    rows = _read(path)
    assert [r["label_a"] for r in rows] == ["benign", "sqli", ""]
    assert rows[2]["text"] == "=cmd|' /c calc'!A0"  # the string itself is never touched
    assert rows[2]["note"] == "spreadsheet formula"
    # resume: only the unlabeled row is asked
    answers = iter(["7"])
    assert label_interactive(path, "label_a", ask=lambda _: next(answers), say=out.append) == 0
    rows = _read(path)
    assert rows[2]["label_a"] == "unclear"
    assert visible("a\nb\x00") == "a\\nb\\x00"
