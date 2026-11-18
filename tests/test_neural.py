"""Tests for the character-level detector and the config options it brought."""

import numpy as np
import pytest


def test_encode_keeps_head_and_tail():
    from shapetrap.neural import encode

    long = "a" * 300 + "' or 1=1--"
    (x,) = encode([long], 64)
    assert len(x) == 64
    assert bytes((x[-10:] - 1).astype(np.uint8)).decode() == "' or 1=1--"
    assert bytes((x[:32] - 1).astype(np.uint8)).decode() == "a" * 32
    (e,) = encode([""], 64)
    assert len(e) == 0


def test_grid_adds_neural_configs_without_vmil():
    from shapetrap.models import config_name, detector_grid

    cfg = {
        "detectors": ["lr"],
        "preprocess": ["raw", "vmil"],
        "neural_detectors": ["charcnn"],
        "neural_preprocess": ["raw", "cstrip", "vmil"],
    }
    names = [config_name(*g) for g in detector_grid(cfg)]
    assert names == ["lr-raw", "lr-vmil", "charcnn-raw", "charcnn-cstrip"]


def test_config_extends_and_overrides(tmp_path):
    from shapetrap.cli import load_config

    (tmp_path / "base.toml").write_text(
        'seeds = [1, 2]\nheadline = "lr-raw"\n[datasets.a]\nloader = "hpd"\npath = "x"\n'
    )
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "extra.toml").write_text(
        'extends = "../base.toml"\nheadline = "charcnn-raw"\nbase_out = "../out"\n'
    )
    cfg, _ = load_config(tmp_path / "sub" / "extra.toml")
    assert cfg["seeds"] == [1, 2]
    assert cfg["headline"] == "charcnn-raw"
    assert "a" in cfg["datasets"]
    assert cfg["base_out"] == str((tmp_path / "out").resolve())
    assert "extends" not in cfg


def _toy():
    rng = np.random.default_rng(0)
    words = ["laptop", "shoes", "basket", "madrid", "anna", "red", "blue", "item", "cart"]
    benign = [" ".join(rng.choice(words, 2)) + str(i) for i in range(150)]
    sqli = [f"{i}' or {i}={i}--" for i in range(75)] + [
        f"1 union select {i},2--" for i in range(75)
    ]
    xss = [f"<script>alert({i})</script>" for i in range(75)] + [
        f"<img src=x onerror=alert({i})>" for i in range(75)
    ]
    texts = benign + sqli + xss
    labels = ["benign"] * 150 + ["sqli"] * 150 + ["xss"] * 150
    return texts, labels


SMALL = {"emb": 8, "filters": 16, "epochs": 6, "batch_size": 32, "threads": 1, "lr": 0.01}


def test_charcnn_learns_and_is_deterministic():
    pytest.importorskip("torch")
    from shapetrap.neural import CharCNNDetector

    texts, labels = _toy()
    a = CharCNNDetector("raw", seed=7, params=SMALL).fit(texts, labels)
    b = CharCNNDetector("raw", seed=7, params=SMALL).fit(texts, labels)
    pa, pb = a.proba(texts), b.proba(texts)
    np.testing.assert_allclose(pa, pb)
    pred, score = a.predict_and_score(texts)
    assert (pred == np.array(labels, dtype=object)).mean() > 0.9
    assert score.shape == (len(texts),)
    assert ((score >= 0) & (score <= 1)).all()
    benign_mean = score[:150].mean()
    attack_mean = score[150:].mean()
    assert attack_mean > benign_mean


def test_charcnn_handles_empty_and_modes():
    pytest.importorskip("torch")
    from shapetrap.neural import CharCNNDetector

    texts, labels = _toy()
    det = CharCNNDetector("cstrip", seed=1, params=SMALL).fit(texts, labels)
    pred, mask = det.predict_and_mask(["", "q=laptop", '{"q":"<script>alert(1)</script>"}'])
    assert len(pred) == 3
    assert mask.tolist() == [False, True, True]
    assert det.empty_prediction() in det.classes_
    with pytest.raises(ValueError):
        CharCNNDetector("vmil")


def _tiny_bert(folder, texts):
    """A small random BERT with a word-piece vocabulary built on the toy data,
    so the test needs no download."""
    from tokenizers import BertWordPieceTokenizer
    from transformers import BertConfig, BertForSequenceClassification, PreTrainedTokenizerFast

    wp = BertWordPieceTokenizer(lowercase=True)
    wp.train_from_iterator(texts, vocab_size=300, min_frequency=1)
    tok = PreTrainedTokenizerFast(
        tokenizer_object=wp._tokenizer,
        unk_token="[UNK]",
        cls_token="[CLS]",
        sep_token="[SEP]",
        pad_token="[PAD]",
        mask_token="[MASK]",
    )
    tok.save_pretrained(str(folder))
    cfg = BertConfig(
        vocab_size=len(tok),
        hidden_size=32,
        num_hidden_layers=2,
        num_attention_heads=2,
        intermediate_size=64,
        max_position_embeddings=64,
    )
    import torch

    torch.manual_seed(0)
    BertForSequenceClassification(cfg).save_pretrained(str(folder))
    return str(folder)


def test_bert_detector_trains_on_a_local_model(tmp_path):
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    from shapetrap.neural import BertDetector, make_neural

    texts, labels = _toy()
    model = _tiny_bert(tmp_path, texts)
    params = {
        "model": model,
        "max_tokens": 16,
        "epochs": 12,
        "batch_size": 16,
        "lr": 2e-3,
        "threads": 1,
        "device": "cpu",
    }
    det = BertDetector("canon", seed=3, params=params).fit(texts, labels)
    pred, score = det.predict_and_score(texts)
    assert (pred == np.array(labels, dtype=object)).mean() > 0.8
    assert score[150:].mean() > score[:150].mean()
    # Head and tail are kept when a string is longer than max_tokens.
    ids = det._ids(["laptop " * 40 + "<script>alert(1)</script>"])[0]
    assert len(ids) == 16
    assert det.tok.unk_token_id not in ids
    assert ids[-2] == det._ids(["</script>"])[0][-2]
    sub = make_neural("bert", "raw", {"bert": {**params, "max_train": 90}}, seed=1).fit(
        texts, labels
    )
    assert set(sub.classes_) == {"benign", "sqli", "xss"}


def _mini_corpus():
    from shapetrap.shapes import detect_shape

    rng = np.random.default_rng(1)
    words = ["laptop", "shoes", "basket", "madrid", "anna", "red", "blue", "item", "cart", "box"]

    def row(text, atype, crs1):
        return {
            "text": text,
            "atype": atype,
            "y": "benign" if atype == "benign" else "attack",
            "key": text.lower(),
            "family": text,
            "shape": detect_shape(text),
            "crs1": crs1,
            "crs2": crs1,
        }

    a = [row(" ".join(rng.choice(words, 2)) + str(i), "benign", i % 17 == 0) for i in range(120)]
    a += [row(f"{i}' or {i}={i}--", "sqli", True) for i in range(60)]
    a += [row(f"<script>alert({i})</script>", "xss", i % 3 > 0) for i in range(60)]
    b = [row(f"q={rng.choice(words)}{i}&page={i}", "benign", False) for i in range(120)]
    b += [row(f"q=%27%20or%20{i}%3D{i}--&page=1", "sqli", i % 2 == 0) for i in range(60)]
    h = [row(f"user{i}", "benign", False) for i in range(30)]
    h += [row(f"id=1;cat /etc/passwd #{i}", "cmdi", True) for i in range(30)]
    return {"a": a, "b": b, "h": h}


def test_run_with_neural_hybrid_and_faithful_rewrites(tmp_path):
    pytest.importorskip("torch")
    from shapetrap.experiment import run_experiment

    cfg = {
        "seeds": [1],
        "test_size": 0.3,
        "tokenizer": "web",
        "max_features": 4000,
        "detectors": ["lr", "crs"],
        "preprocess": ["raw", "cstrip"],
        "nonlinear_detectors": [],
        "shape_augment": False,
        "interventions": True,
        "intervention_detectors": ["lr", "charcnn"],
        "intervention_seeds": "all",
        "shape_baseline": False,
        "neural_detectors": ["charcnn"],
        "neural_preprocess": ["raw", "cstrip"],
        "charcnn": SMALL,
        "hybrid_configs": ["lr-cstrip"],
        "rewrite": "faithful",
        "datasets": {"a": {}, "b": {}, "h": {"role": "test"}},
    }
    cells, _, iv = run_experiment(cfg, _mini_corpus(), tmp_path, log=lambda *_: None)
    configs = {c["config"] for c in cells}
    assert {"lr-raw", "lr-cstrip", "charcnn-raw", "charcnn-cstrip", "crs-pl1"} <= configs
    assert {"and-lr-cstrip", "or-lr-cstrip"} <= configs
    by = {(c["source"], c["target"], c["config"]): c for c in cells}
    for (src, tgt, name), c in by.items():
        if name != "and-lr-cstrip":
            continue
        lr, crs = by[(src, tgt, "lr-cstrip")], by[(src, tgt, "crs-pl1")]
        orc = by[(src, tgt, "or-lr-cstrip")]
        for m in ("fpr", "det"):
            if not np.isnan(c[m]):
                assert c[m] <= min(lr[m], crs[m]) + 1e-12
                assert orc[m] >= max(lr[m], crs[m]) - 1e-12
    assert {r["config"] for r in iv} >= {"lr-raw", "charcnn-raw"}
    assert (tmp_path / "transfer_summary.csv").exists()

    # A second run with the same configuration resumes from the saved
    # progress and gives the same cells without training anything.
    msgs: list[str] = []
    cells2, _, iv2 = run_experiment(cfg, _mini_corpus(), tmp_path, log=msgs.append)
    assert any("resumed" in m for m in msgs) and not any("trained" in m for m in msgs)
    key = lambda r: (r["source"], r["target"], r["config"])
    a = {key(r): r["fpr"] for r in cells}
    b = {key(r): r["fpr"] for r in cells2}
    assert a.keys() == b.keys()
    assert all(a[k] == b[k] or (np.isnan(a[k]) and np.isnan(b[k])) for k in a)
    assert len(iv2) == len(iv)
