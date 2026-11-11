import math

import pytest

from shapetrap.canon import canonicalize, family_key, norm_key
import json

from shapetrap.datasets import held_out_sources, load_cowrie, prepare, split_all, split_rows
from shapetrap.models import Signature, TfidfDetector
from shapetrap.shapes import as_bare, as_json, as_kv, detect_shape, split_kv, values_of
from shapetrap.stats import corrected_paired_t, holm, mcnemar_exact, spearman_exact, wilson
from shapetrap.tokenizer import tokenize_paper1, tokenize_web


# --- canonicalization ------------------------------------------------------

def test_canonicalize_decodes_to_fixed_point():
    assert canonicalize("%2527%2520OR%25201%253D1") == "' or 1=1"


def test_canonicalize_entities_comments_whitespace_case():
    assert canonicalize("&lt;ScRiPt&gt;") == "<script>"
    assert canonicalize("UNI/**/ON\tSELECT") == "union select"


def test_canonicalize_latin1_fallback_and_surrogates():
    assert canonicalize("Jam%F3n+Ib%E9rico") == "jamón ibérico"
    canonicalize("\\ud83d").encode("utf-8")  # must not raise


def test_keys():
    assert norm_key("ID = 5") == norm_key("id=5")
    assert family_key("ORDER BY 1--") == family_key("ORDER BY 31337--")
    assert family_key("x='a'") == family_key("x='bcd'")


# --- shapes ----------------------------------------------------------------

@pytest.mark.parametrize("text,shape", [
    ("", "empty"), ("   ", "empty"), ("id=5&sort=asc", "kv"), ("laptop", "bare"),
    ('{"q": "laptop"}', "json"), ("/a/b?x=1", "path"), ("' OR 1=1 --", "bare"),
    ("a=1&broken", "bare"),
])
def test_detect_shape(text, shape):
    assert detect_shape(text) == shape


def test_split_and_values():
    assert split_kv("a=1&b=two") == [("a", "1"), ("b", "two")]
    assert split_kv("no container") is None
    assert values_of("a=1&b=two&c=") == ["1", "two"]
    assert values_of('{"a": {"b": "x"}, "c": [1, "y"]}') == ["x", "1", "y"]
    assert values_of("plain") == ["plain"]


def test_interventions_change_only_the_container():
    assert as_bare("id=5&q=laptop") == "5 laptop"
    assert as_bare("laptop") == "laptop"
    wrapped = as_kv("laptop", seed=1)
    assert wrapped.endswith("=laptop") and detect_shape(wrapped) == "kv"
    assert as_kv("id=5") == "id=5"
    assert values_of(as_json("id=5&q=laptop")) == ["5", "laptop"]
    assert values_of(as_json("laptop")) == ["laptop"]
    assert as_kv("x", seed=7) == as_kv("x", seed=7)  # deterministic


# --- tokenizers ------------------------------------------------------------

def test_paper1_tokenizer_matches_earlier_paper():
    assert tokenize_paper1("id=5&sort=asc") == ["id", "=", "5", "sort", "=", "asc"]
    assert tokenize_paper1("<script>alert(1)</script>")[0] == "<script"


def test_web_tokenizer_keeps_shell_and_path_syntax():
    assert "../" in tokenize_web("../../etc/passwd")
    toks = tokenize_web("a && cat /etc/passwd | $(id)")
    assert "&&" in toks and "|" in toks and "$(" in toks
    assert "&" in tokenize_web("id=5&sort=asc")


# --- statistics ------------------------------------------------------------

def test_wilson_zero_of_16000_matches_earlier_paper():
    lo, hi = wilson(0, 16000)
    assert lo == 0.0 and round(100 * hi, 3) == 0.024


def test_mcnemar_and_holm():
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(10, 0) == pytest.approx(2 * 0.5 ** 10)
    assert holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])


def test_spearman_exact_matches_known_values():
    rho, p = spearman_exact([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
    assert rho == pytest.approx(-1.0) and p == pytest.approx(2 / 720)
    # One and two adjacent swaps away from a perfect inversion: the values a
    # six-source study most often reports.
    rho, p = spearman_exact([1, 2, 3, 4, 5, 6], [5, 6, 4, 3, 2, 1])
    assert rho == pytest.approx(-0.943, abs=1e-3) and p == pytest.approx(0.017, abs=1e-3)
    rho, p = spearman_exact([1, 2, 3, 4, 5, 6], [5, 6, 4, 3, 1, 2])
    assert rho == pytest.approx(-0.886, abs=1e-3) and p == pytest.approx(0.033, abs=1e-3)


def test_corrected_paired_t_reproduces_earlier_paper_lr_row():
    # LR row of the earlier paper: mean gain 0.2029, paired SD 0.0358, 15 folds,
    # train/test 809.6/202.4 -> t about 10.07.
    n, mean, sd = 15, 0.2029, 0.035800
    diffs = [mean + sd * math.sqrt((n - 1) / n) * (1 if i % 2 else -1) for i in range(n - 1)]
    diffs.append(n * mean - sum(diffs))
    out = corrected_paired_t(diffs, 809.6, 202.4)
    assert out["mean"] == pytest.approx(mean)
    assert out["se"] == pytest.approx(math.sqrt(1 / 15 + 202.4 / 809.6) * (
        math.sqrt(sum((d - mean) ** 2 for d in diffs) / 14)))


# --- data handling ---------------------------------------------------------

def _toy():
    keys = ["id", "page", "sort", "q", "lang", "ref", "tab", "view"]
    rows = [{"text": f"{keys[i % 8]}={i}&{keys[(i * 3 + 1) % 8]}=w{i % 7}", "atype": "benign"}
            for i in range(60)]
    rows += [{"text": f"' OR {i}={i} -- {'x' * (i % 5)}", "atype": "sqli"} for i in range(40)]
    rows += [{"text": f"<script>alert('{'a' * (i % 6)}')</script>{'!' * (i % 4)}", "atype": "xss"}
             for i in range(40)]
    return rows


def test_prepare_drops_duplicates_conflicts_and_caps():
    rows = _toy() + [dict(_toy()[0]),
                     {"text": "dup", "atype": "benign"}, {"text": "dup", "atype": "sqli"},
                     {"text": "   ", "atype": "benign"}]
    kept, audit, info = prepare(rows, seed=1, max_per_class=30)
    assert info["empty_dropped"] == 1
    assert info["label_conflicts_dropped"] == 1
    assert all(r["text"] != "dup" for r in kept)
    assert info["by_atype"]["benign"] == 30
    assert len(audit) >= len(kept)
    assert {"y", "family", "shape", "key"} <= set(kept[0])


def test_split_is_family_disjoint_and_seeded():
    rows, _, _ = prepare(_toy(), seed=1, max_per_class=None)
    train, test = split_rows(rows, seed=42, test_size=0.25)
    assert train and test
    assert not ({r["family"] for r in train} & {r["family"] for r in test})
    again = split_rows(rows, seed=42, test_size=0.25)
    assert [r["text"] for r in test] == [r["text"] for r in again[1]]
    assert {r["atype"] for r in test} == {"benign", "sqli", "xss"}


# --- detectors -------------------------------------------------------------

def test_signature_rules():
    raw, canon = Signature("raw"), Signature("canon")
    assert list(raw.predict(["id=5", "' OR 1=1 --", "<script>x</script>",
                             "../../etc/passwd", "a; cat /etc/hosts"])) == \
        ["benign", "sqli", "xss", "traversal", "traversal"]
    assert raw.predict(["x | whoami"])[0] == "cmdi"
    encoded = "%27%20UNION%20SELECT%20a%20FROM%20b"
    assert raw.predict([encoded])[0] == "benign"
    assert canon.predict([encoded])[0] == "sqli"


def test_shape_shortcut_is_learned_and_flagged():
    """A detector trained on kv-shaped benign and bare attacks treats the
    container as the signal: the same benign value without its key flips."""
    rows, _, _ = prepare(_toy(), seed=1, max_per_class=None)
    det = TfidfDetector("lr", "raw").fit([r["text"] for r in rows], [r["atype"] for r in rows])
    assert det.predict(["id=5&q=w3"])[0] == "benign"
    assert det.predict(["' OR 3=3 -- x"])[0] == "sqli"
    pred, known = det.predict_and_mask(["zzzz", "id=5"])
    assert not known[0] and known[1]
    assert det.empty_prediction() == det.predict([""])[0]


def test_json_intervention_keeps_repeated_keys_and_existing_json():
    assert values_of(as_json("a=1&a=2&b=3")) == ["1", "2", "3"]
    assert as_json('{"a": "1"}') == '{"a": "1"}'
    assert as_bare('{"a": "x", "b": ["y"]}') == "x y"


# --- honeypot logs ---------------------------------------------------------

def _cowrie_file(tmp_path):
    events = [
        {"event_type": "cowrie.session.connect", "session_id": "s1", "src_ip": "192.0.2.1",
         "timestamp_utc": "2026-10-22T00:00:01Z"},
        {"event_type": "cowrie.login.failed", "session_id": "s1", "src_ip": "192.0.2.1",
         "username": "root", "password": "admin123", "timestamp_utc": "2026-10-22T00:00:02Z"},
        {"event_type": "cowrie.login.success", "session_id": "s1", "src_ip": "192.0.2.1",
         "username": "root", "password": "root", "timestamp_utc": "2026-10-22T00:00:03Z"},
        {"event_type": "cowrie.command.input", "session_id": "s1", "src_ip": "192.0.2.1",
         "input": "uname -a", "timestamp_utc": "2026-10-22T00:00:04Z"},
        {"event_type": "cowrie.command.input", "session_id": "s2", "src_ip": "192.0.2.2",
         "input": "uname -a", "timestamp_utc": "2026-10-22T00:00:05Z"},
        # native Cowrie field names
        {"eventid": "cowrie.command.failed", "session": "s2", "src_ip": "192.0.2.2",
         "input": "nproc", "timestamp": "2026-10-22T00:00:06Z"},
        {"event_type": "cowrie.direct-tcpip.data", "session_id": "s2", "src_ip": "192.0.2.2",
         "data": "ignored", "timestamp_utc": "2026-10-22T00:00:07Z"},
    ]
    path = tmp_path / "cowrie.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\nnot json\n", encoding="utf-8")
    return path


def test_cowrie_loader_separates_records_strings_and_events(tmp_path):
    _cowrie_file(tmp_path)
    rows, notes = load_cowrie({"path": "cowrie.jsonl"}, tmp_path)
    by = {r["text"]: r for r in rows}
    assert by["uname -a"]["atype"] == "shell" and by["uname -a"]["weight"] == 2
    assert by["nproc"]["weight"] == 1
    assert by["root"]["atype"] == "benign" and by["root"]["weight"] == 3  # 2x user, 1x password
    assert by["admin123"]["weight"] == 1
    assert "ignored" not in by
    assert notes["records"] == 7 and notes["unparsed_lines"] == 1
    assert notes["sessions"] == 2 and notes["source_addresses"] == 2
    assert notes["command_events"] == 3 and notes["distinct_commands"] == 2
    rows, _ = load_cowrie({"path": "cowrie.jsonl", "credentials_as_control": False}, tmp_path)
    assert {r["atype"] for r in rows} == {"shell"}
    rows, _ = load_cowrie({"path": "."}, tmp_path)  # a folder of logs
    assert len(rows) == 4


def test_held_out_source_is_never_trained_on(tmp_path):
    cfg = {"test_size": 0.25, "datasets": {"bench": {}, "wild": {"role": "test"}}}
    assert held_out_sources(cfg) == {"wild"}
    rows, _, _ = prepare(_toy(), seed=1, max_per_class=None)
    splits = split_all(cfg, {"bench": rows, "wild": rows[:20]}, seed=42)
    assert splits["wild"][0] == [] and len(splits["wild"][1]) == 20
    assert splits["bench"][0] and splits["bench"][1]


def test_event_weighted_rates():
    import numpy as np
    from shapetrap.experiment import _score
    flag = np.array([True, False, True, False])
    is_attack = np.array([True, True, False, False])
    out = _score(flag, is_attack, np.array(["shell"] * 2 + ["benign"] * 2, dtype=object),
                 np.ones(4, dtype=bool), np.array([9.0, 1.0, 1.0, 3.0]))
    assert out["det"] == 0.5 and out["det_w"] == pytest.approx(0.9)
    assert out["fpr"] == 0.5 and out["fpr_w"] == pytest.approx(0.25)


# --- loaders for the public sources ----------------------------------------
# Every fixture below is a tiny synthetic file in the source's real layout.

def test_modsec_loader(tmp_path):
    from shapetrap.datasets import load_modsec
    (tmp_path / "legitimate" / "openappsec").mkdir(parents=True)
    (tmp_path / "legitimate" / "openappsec" / "legitimate_0.json").write_text(
        json.dumps(["a=1&b=2", "q=shoes"]), encoding="utf-8")
    for part, items in (("sqlmap", ["p=1%27"]), ("openappsec", ["p=x"]), ("sqli_kaggle", ["p=y", "p=z"])):
        (tmp_path / "malicious" / part).mkdir(parents=True)
        (tmp_path / "malicious" / part / "sqli_parsed.json").write_text(json.dumps(items), encoding="utf-8")
    rows, notes = load_modsec({"path": "."}, tmp_path)
    assert sum(r["atype"] == "benign" for r in rows) == 2
    assert sum(r["atype"] == "sqli" for r in rows) == 4
    assert notes["strings_per_part"]["sqli_kaggle"] == 2


def test_crs_loader_reads_attacks_and_hard_negatives(tmp_path):
    from shapetrap.datasets import load_crs
    folder = tmp_path / "tests" / "regression" / "tests" / "REQUEST-942-APPLICATION-ATTACK-SQLI"
    folder.mkdir(parents=True)
    (folder / "942100.yaml").write_text("""
tests:
  - test_id: 1
    stages:
      - input: {uri: "/get?var=1%20union%20select%202", method: GET}
        output: {log: {expect_ids: [942100]}}
  - test_id: 2
    stages:
      - input: {uri: "/post", method: POST, data: "note=select a colour"}
        output: {log: {no_expect_ids: [942100]}}
  - test_id: 3
    stages:
      - input: {uri: "/get", headers: {Cookie: "x"}}
        output: {log: {expect_ids: [942100]}}
""", encoding="utf-8")
    rows, notes = load_crs({"path": "."}, tmp_path)
    assert {(r["text"], r["atype"]) for r in rows} == {
        ("var=1%20union%20select%202", "sqli"), ("note=select a colour", "benign")}
    assert notes["skipped"]["payload_not_in_query_or_body"] == 1


def test_patt_and_shellevo_loaders(tmp_path):
    from shapetrap.datasets import load_patt, load_shellevo
    d = tmp_path / "SQL Injection" / "Intruder"
    d.mkdir(parents=True)
    (d / "list.txt").write_text("' OR 1=1\n\nadmin'--\n", encoding="utf-8")
    rows, notes = load_patt({"path": "."}, tmp_path)
    assert [r["atype"] for r in rows] == ["sqli", "sqli"] and notes["files"] == 1

    c = tmp_path / "dataset" / "commands"
    c.mkdir(parents=True)
    (c / "2024.jsonl").write_text(
        json.dumps({"command": "uname -a", "frequency": 7}) + "\n" +
        json.dumps({"command": "nproc", "frequency": 1}) + "\n", encoding="utf-8")
    rows, notes = load_shellevo({"path": ".", "period": "2024"}, tmp_path)
    assert {r["text"]: r["weight"] for r in rows} == {"uname -a": 7, "nproc": 1}
    assert notes["command_events"] == 8 and all(r["atype"] == "shell" for r in rows)


def test_copot_and_tpot_loaders(tmp_path):
    import csv as _csv
    import zipfile
    from shapetrap.datasets import load_copot, load_tpot_csv
    with zipfile.ZipFile(tmp_path / "cowrie_malicious_anonymized.zip", "w") as zf:
        zf.writestr("cowrie.csv", "Session ID,Username(s),Password(s),Commands\n"
                                  "s1,root,admin,uname -a\ns2,root,1234,uname -a\ns3,pi,raspberry,\n")
    rows, notes = load_copot({"path": ".", "part": "cowrie"}, tmp_path)
    by = {r["text"]: r for r in rows}
    assert by["uname -a"]["weight"] == 2 and by["uname -a"]["atype"] == "shell"
    assert by["root"]["weight"] == 2 and by["root"]["atype"] == "benign"
    assert notes["sessions"] == 3

    with zipfile.ZipFile(tmp_path / "tanner_malicious_anonymized.zip", "w") as zf:
        zf.writestr("tanner.csv", "path\n/index.php?id=1\n/index.php?id=1\n/robots.txt\n")
    (tmp_path / "h0neytr4p_malicious_anonymized.csv").write_text(
        "request_uri\n/a?x=y\n", encoding="utf-8")
    rows, notes = load_copot({"path": ".", "part": "web"}, tmp_path)
    assert {r["text"]: r["weight"] for r in rows} == {"id=1": 2, "x=y": 1}
    assert notes["requests"] == 4 and notes["requests_with_parameters"] == 3

    with open(tmp_path / "List of Commands.csv", "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerows([["session", "eventid", "input"], ["a", "cowrie.command.input", "nproc"],
                     ["a", "cowrie.session.file_download", ""], ["b", "cowrie.command.input", "nproc"]])
    (tmp_path / "List of Attempted Usernames.csv").write_text(
        '@timestamp,username\n"Nov 30, 2025 @ 12:47:34.076",user\n', encoding="utf-8")
    rows, notes = load_tpot_csv({"path": "."}, tmp_path)
    assert {(r["text"], r["atype"], r["weight"]) for r in rows} == {("nproc", "shell", 2), ("user", "benign", 1)}
    assert notes["sessions_with_commands"] == 2


def test_vps_and_finch_loaders(tmp_path):
    import gzip
    from shapetrap.datasets import load_finch, load_vps
    (tmp_path / "data").mkdir()
    with gzip.open(tmp_path / "data" / "web_attacks_x.csv.gz", "wt", encoding="utf-8") as fh:
        fh.write("timestamp_utc,path\nt,/a.php?cmd=id\nt,/a.php?cmd=id\nt,/.env\n")
    with gzip.open(tmp_path / "data" / "ssh_failed_logins_x.csv.gz", "wt", encoding="utf-8") as fh:
        fh.write("timestamp_utc,username,event\nt,admin,invalid_user\nt,admin,disconnected_preauth\n")
    rows, notes = load_vps({"path": "."}, tmp_path)
    assert {(r["text"], r["atype"], r["weight"]) for r in rows} == {("cmd=id", "attack", 2), ("admin", "benign", 1)}
    assert notes["requests"] == 3 and notes["requests_with_parameters"] == 2

    zstandard = pytest.importorskip("zstandard")
    events = [{"eventTime": "2025-08-01T00:00:00Z", "request": "/x?a=1", "body": ""},
              {"eventTime": "2025-08-02T00:00:00Z", "request": "/y", "body": "k=v"},
              {"eventTime": "2025-08-03T00:00:00Z", "request": "/z", "body": "B" * 9000}]
    raw = "\n".join(json.dumps(e) for e in events).encode()
    (tmp_path / "events.jsonl.zst").write_bytes(zstandard.ZstdCompressor().compress(raw))
    rows, notes = load_finch({"path": "events.jsonl.zst"}, tmp_path)
    assert {r["text"] for r in rows} == {"a=1", "k=v"}
    assert notes["requests"] == 3 and notes["bodies_over_limit_skipped"] == 1


def test_reference_split_in_score():
    import numpy as np
    from shapetrap.experiment import _score
    flag = np.array([True, True, False, False, True])
    is_attack = np.array([True, True, True, True, False])
    ref = np.array([True, False, True, False, False])
    out = _score(flag, is_attack, np.array(["attack"] * 4 + ["benign"], dtype=object),
                 np.ones(5, dtype=bool), np.ones(5), ref)
    assert out["n_ref_pos"] == 2 and out["n_ref_neg"] == 2
    assert out["det_ref_pos"] == 0.5 and out["det_ref_neg"] == 0.5


# --- container canonicalization -------------------------------------------

def test_decontain_drops_plain_keys_only():
    from shapetrap.shapes import decontain
    assert decontain("id=5&q=x") == ["5", "x"]
    assert decontain('{"id": "5", "q": ["x", {"n": 2}]}') == ["5", "x", "2"]
    assert decontain("/p.php?id=5&q=x") == ["/p.php", "5", "x"]
    assert decontain("laptop") == ["laptop"] and decontain("  ") == []
    # a payload in a key position is kept, so it cannot hide in a parameter name
    assert decontain("%3Cscript%3E=1&id=2") == ["%3Cscript%3E", "1", "2"]
    assert decontain('{"a<b": "1"}') == ["a<b", "1"]
    assert decontain("{not json") == ["{not json"]


def test_cstrip_gives_one_form_for_every_container():
    from shapetrap.models import preprocess
    forms = {preprocess(fn("Hello%20World", 0), "cstrip") for fn in (as_bare, as_kv, as_json)}
    assert forms == {"hello world"}
    forms = {preprocess(fn("id=5&q=x", 0), "cstrip") for fn in (as_bare, as_kv, as_json)}
    assert forms == {"5 x"}
    with pytest.raises(ValueError):
        preprocess("x", "nope")


def test_cstrip_detector_ignores_the_container():
    rows, _, _ = prepare(_toy(), seed=1, max_per_class=None)
    texts, labels = [r["text"] for r in rows], [r["atype"] for r in rows]
    raw = TfidfDetector("lr", "raw").fit(texts, labels)
    strip = TfidfDetector("lr", "cstrip").fit(texts, labels)
    attack = "' OR 7=7 -- x"
    variants = [attack, as_kv(attack, 0), as_json(attack, 0)]
    assert len(set(strip.predict(variants))) == 1 and strip.predict(variants)[0] == "sqli"
    benign = "id=5&q=w3"
    assert len(set(strip.predict([benign, as_bare(benign), as_json(benign)]))) == 1
    assert raw.predict([benign])[0] == "benign"


def test_value_space_multiple_instance_training():
    import numpy as np
    from shapetrap.models import ValueSpace, attack_score
    names, cities = ["alice", "bob", "carol", "dan"], ["paris", "rome", "oslo"]
    benign = [f"name={names[i % 4]}&city={cities[i % 3]}&page={i}" for i in range(60)]
    # The attack sits in one of three values; the other two are values that
    # benign requests carry as well, which is what lets training single it out.
    attacks = [f"name={names[(i + 1) % 4]}&city={cities[(i + 2) % 3]}&q=' OR {i}={i} --"
               for i in range(60)]
    space = ValueSpace(rounds=2)
    X = space.fit_transform(benign + attacks, ["benign"] * 60 + ["sqli"] * 60)
    assert X.shape[0] == 360 and int(space._multi.sum()) == 180
    clf = space.fit_clf("lr")
    assert attack_score(clf, X).shape == (360,)
    tests = ["name=carol&city=oslo&page=3",            # benign values only
             "' OR 5=5 --",                            # bare attack
             '{"name": "dan", "q": "\' OR 9=9 --"}',   # attack inside JSON
             "rome"]                                   # a benign value on its own
    flag, known = space.flags(clf, *space.transform(tests))
    assert list(flag) == [False, True, True, False]
    assert known.all()
    for kind in ("mnb", "svm"):
        assert space.flags(space.fit_clf(kind), *space.transform(tests))[0][1]


def test_wilcoxon_exact():
    from shapetrap.stats import wilcoxon_exact
    w, p, n = wilcoxon_exact([-1, -2, -3, -4, -5, -6, -7, -8])
    assert w == 0 and n == 8 and p == pytest.approx(2 / 256)
    w, p, n = wilcoxon_exact([1, -2, 3, -4, 0.0])
    assert n == 4 and p == pytest.approx(1.0, abs=0.2)
    assert wilcoxon_exact([0, 0]) == (0.0, 1.0, 0)
    import scipy.stats as sps
    d = [0.31, -0.12, 0.27, 0.45, -0.05, 0.38, 0.22, 0.19]
    assert wilcoxon_exact(d)[1] == pytest.approx(sps.wilcoxon(d, method="exact").pvalue)


def test_read_typed_csv(tmp_path):
    from shapetrap.tables import read_typed_csv, write_csv
    write_csv([{"a": 1, "b": 0.5, "c": "lr-raw", "d": float("nan")}], tmp_path / "x.csv")
    row = read_typed_csv(tmp_path / "x.csv")[0]
    assert row["a"] == 1 and row["b"] == 0.5 and row["c"] == "lr-raw" and math.isnan(row["d"])


def test_detector_grid_skips_redundant_configurations():
    from shapetrap.models import config_name, detector_grid
    cfg = {"detectors": ["lr", "sig"], "preprocess": ["raw", "canon", "cstrip", "vmil"],
           "shape_augment": True}
    names = [config_name(*g) for g in detector_grid(cfg)]
    assert names == ["lr-raw", "lr-raw+aug", "lr-canon", "lr-canon+aug", "lr-cstrip", "lr-vmil",
                     "sig-raw", "sig-canon"]


# --- non-linear learners, bootstrap, CRS reference -------------------------

def test_nonlinear_learners_fit_and_predict():
    from shapetrap.models import Features, NONLINEAR, make_clf
    pytest.importorskip("lightgbm")
    rows, _, _ = prepare(_toy(), seed=1, max_per_class=None)
    feats = Features("cstrip")
    X, y = feats.fit_transform([r["text"] for r in rows], [r["atype"] for r in rows])
    probe = feats.transform(["' OR 3=3 -- x", "id=5&q=w3"])
    for kind in NONLINEAR:
        clf = make_clf(kind, seed=0).fit(X, y)
        pred = list(clf.predict(probe))
        assert set(pred) <= {"benign", "sqli", "xss"}, kind
        # The MLP is configured for real corpora (early stopping after at most
        # 30 epochs) and underfits this 140-row toy, so only the tree models
        # are held to the exact answer here.
        if kind != "mlp":
            assert pred == ["sqli", "benign"], kind
    with pytest.raises(ValueError):
        make_clf("nope")


def test_grid_with_nonlinear_and_crs():
    from shapetrap.models import config_name, detector_grid
    cfg = {"detectors": ["lr", "sig", "crs"], "preprocess": ["raw", "cstrip", "vmil"],
           "shape_augment": False, "nonlinear_detectors": ["rf"],
           "nonlinear_preprocess": ["raw", "cstrip", "vmil"]}
    assert [config_name(*g) for g in detector_grid(cfg)] == [
        "lr-raw", "lr-cstrip", "lr-vmil", "sig-raw", "rf-raw", "rf-cstrip", "crs-pl1", "crs-pl2"]


def test_bootstrap_mean():
    from shapetrap.stats import bootstrap_mean
    m, lo, hi = bootstrap_mean([0.2, 0.2, 0.2])
    assert m == lo == hi == pytest.approx(0.2)
    m, lo, hi = bootstrap_mean([0.0, 1.0] * 4, seed=1)
    assert m == 0.5 and lo < 0.5 < hi and 0.0 <= lo and hi <= 1.0
    assert bootstrap_mean([0.1, 0.9], seed=3) == bootstrap_mean([0.1, 0.9], seed=3)
    assert all(math.isnan(v) for v in bootstrap_mean([]))


def test_crs_request_building():
    from shapetrap.crs import build_request
    assert build_request("id=5&sort=asc") == ("GET", "/?id=5&sort=asc", "-", "-")
    assert build_request("' OR 1=1 --") == ("GET", "/?q=%27%20OR%201%3D1%20--", "-", "-")
    assert build_request("/a/b.php?x=1") == ("GET", "/a/b.php?x=1", "-", "-")
    assert build_request("http://h.example/p?q=<s>") == ("GET", "/p?q=%3Cs%3E", "-", "-")
    assert build_request('{"q": "x"}') == ("POST", "/", "application/json", '{"q": "x"}')
    assert build_request("  ") == ("GET", "/", "-", "-")
    # already-encoded input is sent as it was, a stray fragment marker is not
    assert build_request("a=%27&b=x#y")[1] == "/?a=%27&b=x%23y"


def test_crs_attach_rejects_verdicts_from_another_corpus(tmp_path):
    from shapetrap import crs
    corpus = {"s": [{"text": "a=1"}, {"text": "b=2"}]}
    assert crs.attach(corpus, tmp_path) is False            # nothing stored yet
    (tmp_path / "crs").mkdir()
    def store(texts):
        with open(tmp_path / "crs" / "s.csv", "w", encoding="utf-8") as fh:
            fh.write("idx,text_sha1,pl1,pl2,rules_pl1\n")
            for i, t in enumerate(texts):
                fh.write(f"{i},{crs._tag(t)},{i % 2},1,\n")
    store(["a=1", "zzz"])
    assert crs.attach(corpus, tmp_path) is False and "crs1" not in corpus["s"][0]
    store(["a=1", "b=2"])
    assert crs.attach(corpus, tmp_path) is True
    assert [r["crs1"] for r in corpus["s"]] == [False, True] and corpus["s"][0]["crs2"] is True


def test_evasion_report_counts_missed_attacks():
    from shapetrap.experiment import report_evasion
    base = {"seed": 42, "source": "a", "target": "a", "config": "lr-raw", "class": "attack",
            "n": 100, "n_changed": 100, "flagged_native": 0.9, "became_flagged": 0}
    iv = [dict(base, variant="kv", flagged_variant=0.6, became_clear=30, delta=-0.3, p_holm=0.001),
          dict(base, variant="json", flagged_variant=0.9, became_clear=0, delta=0.0, p_holm=1.0)]
    md = report_evasion(iv, ["a"], set())
    assert "| `lr-raw` | 100 | 90.0 | 60.0 | 30 | -30.0 (a) | 90.0 | 0 | +0.0 (a) | 1/1 , 0/1 |" in md
    assert report_evasion([], ["a"], set()) == ""


def test_logistic_regression_is_run_to_convergence_except_for_the_anchor():
    from shapetrap.models import make_clf
    assert make_clf("lr").tol == 1e-8 and make_clf("lr").max_iter >= 20000
    assert make_clf("lr", paper_settings=True).tol == 1e-4       # scikit-learn default
    assert make_clf("lr", paper_settings=True).max_iter == 1000
    assert TfidfDetector("lr", "raw", paper_settings=True).clf.tol == 1e-4
