"""Neural detectors: a small byte CNN and a small pretrained transformer.

TF-IDF over word tokens is one representation; a reviewer can fairly ask
whether a model that reads characters falls into the same trap.  This module
adds one such model with the same interface as the TF-IDF detectors, so it
runs through the same transfer cells, container rewrites and thresholds.

The network reads UTF-8 bytes (vocabulary 256 plus padding), embeds each byte,
applies parallel 1-D convolutions of widths 3, 5 and 7, takes the maximum of
each filter over the string, and classifies with one linear layer.  Strings
longer than ``max_len`` bytes keep their first and last ``max_len / 2`` bytes,
so a payload at the end of a long query string is still seen.

PyTorch is optional: ``pip install torch`` (on a machine without a GPU the
CPU build is enough and much smaller).
"""

from __future__ import annotations

import os
import time

import numpy as np

from .models import preprocess

PARAMS = {
    "max_len": 512,  # bytes per string; longer strings keep head and tail
    "emb": 32,  # byte embedding size
    "filters": 128,  # filters per kernel width
    "kernels": [3, 5, 7],
    "dropout": 0.2,
    "epochs": 4,
    "batch_size": 256,
    "lr": 1e-3,
    "threads": 0,  # 0 = min(4, CPU count)
}
NEURAL = ("charcnn", "bert")
NEURAL_PREPS = ("raw", "canon", "cstrip")


def _torch():
    try:
        import torch
    except ImportError:
        raise SystemExit(
            "The charcnn detector needs PyTorch: pip install torch "
            "(CPU only: pip install torch --index-url https://download.pytorch.org/whl/cpu)"
        ) from None
    return torch


def encode(texts, max_len: int) -> list[np.ndarray]:
    """Bytes of each string shifted by one (0 is padding), head and tail kept."""
    half = max_len // 2
    out = []
    for t in texts:
        b = np.frombuffer(t.encode("utf-8", errors="replace"), dtype=np.uint8).astype(np.int64)
        if len(b) > max_len:
            b = np.concatenate([b[:half], b[-(max_len - half) :]])
        out.append(b + 1)
    return out


def _pad(seqs):
    n = max(1, max((len(s) for s in seqs), default=1))
    x = np.zeros((len(seqs), n), dtype=np.int64)
    for i, s in enumerate(seqs):
        x[i, : len(s)] = s
    return x


def _net(torch, n_classes: int, p: dict):
    nn = torch.nn

    class CharCNN(nn.Module):  # type: ignore[name-defined]
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(257, p["emb"], padding_idx=0)
            self.convs = nn.ModuleList(
                nn.Conv1d(p["emb"], p["filters"], k, padding=k // 2) for k in p["kernels"]
            )
            self.drop = nn.Dropout(p["dropout"])
            self.out = nn.Linear(p["filters"] * len(p["kernels"]), n_classes)

        def forward(self, x):
            mask = (x > 0).unsqueeze(1)  # (batch, 1, length)
            e = self.emb(x).transpose(1, 2)
            pooled = []
            for conv in self.convs:
                h = torch.relu(conv(e)[:, :, : x.shape[1]])
                # ReLU output is >= 0, so zeroing padded positions keeps them
                # out of the maximum.  An empty string pools to all zeros and
                # is decided by the output bias alone.
                pooled.append(h.masked_fill(~mask, 0.0).amax(dim=2))
            return self.out(self.drop(torch.cat(pooled, dim=1)))

    return CharCNN()


class CharCNNDetector:
    kind = "charcnn"

    def __init__(self, prep: str, seed: int = 0, params: dict | None = None, log=None):
        if prep not in NEURAL_PREPS:
            raise ValueError(f"charcnn supports {', '.join(NEURAL_PREPS)}, not {prep}")
        self.prep, self.seed = prep, seed
        self.p = {**PARAMS, **(params or {})}
        self.log = log
        self.train_seconds = 0.0

    def _setup(self):
        torch = _torch()
        threads = int(self.p["threads"]) or min(4, os.cpu_count() or 1)
        torch.set_num_threads(threads)
        torch.manual_seed(self.seed)
        torch.use_deterministic_algorithms(True)
        return torch

    def _encode(self, texts):
        return encode([preprocess(t, self.prep) for t in texts], int(self.p["max_len"]))

    def fit(self, texts, labels):
        torch = self._setup()
        t0 = time.time()
        seqs = self._encode(texts)
        self.classes_ = np.array(sorted(set(labels)), dtype=object)
        index = {c: i for i, c in enumerate(self.classes_)}
        y = np.array([index[v] for v in labels], dtype=np.int64)
        self.model = _net(torch, len(self.classes_), self.p)
        opt = torch.optim.Adam(self.model.parameters(), lr=float(self.p["lr"]))
        loss_fn = torch.nn.CrossEntropyLoss()
        rng = np.random.default_rng(self.seed)
        bs = int(self.p["batch_size"])
        lengths = np.array([len(s) for s in seqs])
        self.model.train()
        for epoch in range(int(self.p["epochs"])):
            # Batches of similar length keep padding small: shuffle, sort
            # within chunks of 50 batches, then shuffle the batch order.
            order = rng.permutation(len(seqs))
            batches = []
            for c in range(0, len(order), bs * 50):
                chunk = order[c : c + bs * 50]
                chunk = chunk[np.argsort(lengths[chunk], kind="stable")]
                batches += [chunk[i : i + bs] for i in range(0, len(chunk), bs)]
            total = 0.0
            for bi in rng.permutation(len(batches)):
                idx = batches[bi]
                xb = torch.from_numpy(_pad([seqs[i] for i in idx]))
                yb = torch.from_numpy(y[idx])
                opt.zero_grad()
                loss = loss_fn(self.model(xb), yb)
                loss.backward()
                opt.step()
                total += loss.item() * len(idx)
            if self.log:
                self.log(f"    charcnn-{self.prep} epoch {epoch + 1}: loss {total / len(seqs):.4f}")
        self.model.eval()
        self.train_seconds = time.time() - t0
        return self

    def proba(self, texts) -> np.ndarray:
        """Class probabilities, one row per string, columns in ``classes_``."""
        torch = _torch()
        seqs = self._encode(texts)
        out = np.zeros((len(seqs), len(self.classes_)), dtype=np.float64)
        if not seqs:
            return out
        order = np.argsort([len(s) for s in seqs], kind="stable")
        bs = int(self.p["batch_size"]) * 4
        with torch.no_grad():
            for i in range(0, len(order), bs):
                idx = order[i : i + bs]
                logits = self.model(torch.from_numpy(_pad([seqs[j] for j in idx])))
                out[idx] = torch.softmax(logits, dim=1).double().numpy()
        return out

    def predict_and_score(self, texts):
        """(predicted class, attack score = 1 - P(benign)) per string."""
        p = self.proba(texts)
        pred = self.classes_[p.argmax(axis=1)] if len(p) else np.array([], dtype=object)
        b = list(self.classes_).index("benign")
        return np.asarray(pred, dtype=object), 1.0 - p[:, b]

    def predict(self, texts):
        return self.predict_and_score(texts)[0]

    def known_mask(self, texts):
        """A byte model has evidence for every non-empty string."""
        return np.array([len(preprocess(t, self.prep)) > 0 for t in texts], dtype=bool)

    def predict_and_mask(self, texts):
        return self.predict(texts), self.known_mask(texts)

    def empty_prediction(self) -> str:
        return str(self.predict([""])[0])


BERT_PARAMS = {
    # BERT-small (4 layers, 512 hidden, about 29M parameters) from Turc et al.,
    # "Well-Read Students Learn Better", 2019.  Any Hugging Face sequence
    # classification checkpoint, or a local folder, can be named instead.
    "model": "google/bert_uncased_L-4_H-512_A-8",
    "max_tokens": 128,  # word pieces per string; longer strings keep head and tail
    "epochs": 2,
    "batch_size": 32,
    "lr": 5e-5,
    "warmup": 0.06,  # share of steps with a linear warm-up
    "max_train": 0,  # 0 = all; otherwise a stratified subsample of the training split
    "device": "auto",  # auto | cpu | cuda
    "threads": 0,
}


def _transformers():
    try:
        import transformers
    except ImportError:
        raise SystemExit(
            "The bert detector needs PyTorch and transformers: pip install torch transformers"
        ) from None
    return transformers


class BertDetector:
    """Fine-tuned small transformer with the same interface as the others.

    Each string is preprocessed for its mode, split into word pieces, and cut
    to ``max_tokens`` by keeping its first and last pieces.  The whole model
    is fine-tuned with AdamW and a linear schedule.  On a CUDA device it runs
    in mixed precision; there results are close to, but not bit-for-bit
    equal to, a CPU run.
    """

    kind = "bert"

    def __init__(self, prep: str, seed: int = 0, params: dict | None = None, log=None):
        if prep not in NEURAL_PREPS:
            raise ValueError(f"bert supports {', '.join(NEURAL_PREPS)}, not {prep}")
        self.prep, self.seed = prep, seed
        self.p = {**BERT_PARAMS, **(params or {})}
        self.log = log
        self.train_seconds = 0.0

    def _setup(self):
        torch = _torch()
        tf = _transformers()
        threads = int(self.p["threads"]) or min(4, os.cpu_count() or 1)
        torch.set_num_threads(threads)
        torch.manual_seed(self.seed)
        dev = self.p["device"]
        if dev == "auto":
            dev = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(dev)
        return torch, tf

    def _ids(self, texts):
        """Word-piece ids per string, head and tail kept, with [CLS] and [SEP]."""
        n = int(self.p["max_tokens"]) - 2
        head = n // 2
        enc = self.tok(
            [preprocess(t, self.prep) for t in texts],
            add_special_tokens=False,
            truncation=False,
            return_attention_mask=False,
        )["input_ids"]
        cls, sep = self.tok.cls_token_id, self.tok.sep_token_id
        out = []
        for ids in enc:
            if len(ids) > n:
                ids = ids[:head] + ids[-(n - head) :]
            out.append([cls] + ids + [sep])
        return out

    def _batch(self, torch, seqs):
        n = max(len(s) for s in seqs)
        pad = self.tok.pad_token_id or 0
        x = torch.full((len(seqs), n), pad, dtype=torch.long)
        m = torch.zeros((len(seqs), n), dtype=torch.long)
        for i, s in enumerate(seqs):
            x[i, : len(s)] = torch.tensor(s, dtype=torch.long)
            m[i, : len(s)] = 1
        return x.to(self.device), m.to(self.device)

    def fit(self, texts, labels):
        torch, tf = self._setup()
        t0 = time.time()
        texts, labels = list(texts), list(labels)
        rng = np.random.default_rng(self.seed)
        cap = int(self.p["max_train"])
        if cap and len(texts) > cap:
            # Stratified subsample: every class keeps its share.
            by: dict[str, list[int]] = {}
            for i, y in enumerate(labels):
                by.setdefault(y, []).append(i)
            keep: list[int] = []
            for idx in by.values():
                k = max(1, round(cap * len(idx) / len(texts)))
                keep += list(rng.choice(idx, size=min(k, len(idx)), replace=False))
            keep.sort()
            texts = [texts[i] for i in keep]
            labels = [labels[i] for i in keep]
        self.classes_ = np.array(sorted(set(labels)), dtype=object)
        index = {c: i for i, c in enumerate(self.classes_)}
        y = np.array([index[v] for v in labels], dtype=np.int64)
        self.tok = tf.AutoTokenizer.from_pretrained(self.p["model"])
        self.model = tf.AutoModelForSequenceClassification.from_pretrained(
            self.p["model"], num_labels=len(self.classes_), ignore_mismatched_sizes=True
        ).to(self.device)
        seqs = self._ids(texts)
        bs = int(self.p["batch_size"])
        steps = int(self.p["epochs"]) * ((len(seqs) + bs - 1) // bs)
        opt = torch.optim.AdamW(self.model.parameters(), lr=float(self.p["lr"]))
        warm = max(1, int(steps * float(self.p["warmup"])))
        sched = torch.optim.lr_scheduler.LambdaLR(
            opt, lambda s: min((s + 1) / warm, max(0.0, (steps - s) / max(1, steps - warm)))
        )
        amp = self.device.type == "cuda"
        scaler = torch.amp.GradScaler("cuda") if amp else None
        lengths = np.array([len(s) for s in seqs])
        self.model.train()
        for epoch in range(int(self.p["epochs"])):
            order = rng.permutation(len(seqs))
            batches = []
            for c in range(0, len(order), bs * 50):
                chunk = order[c : c + bs * 50]
                chunk = chunk[np.argsort(lengths[chunk], kind="stable")]
                batches += [chunk[i : i + bs] for i in range(0, len(chunk), bs)]
            total = 0.0
            for bi in rng.permutation(len(batches)):
                idx = batches[bi]
                x, m = self._batch(torch, [seqs[i] for i in idx])
                yb = torch.from_numpy(y[idx]).to(self.device)
                opt.zero_grad()
                with torch.autocast(self.device.type, enabled=amp):
                    loss = torch.nn.functional.cross_entropy(
                        self.model(input_ids=x, attention_mask=m).logits.float(), yb
                    )
                if scaler:
                    scaler.scale(loss).backward()
                    scaler.step(opt)
                    scaler.update()
                else:
                    loss.backward()
                    opt.step()
                sched.step()
                total += loss.item() * len(idx)
            if self.log:
                self.log(f"    bert-{self.prep} epoch {epoch + 1}: loss {total / len(seqs):.4f}")
        self.model.eval()
        self.train_seconds = time.time() - t0
        return self

    def proba(self, texts) -> np.ndarray:
        torch = _torch()
        out = np.zeros((len(texts), len(self.classes_)), dtype=np.float64)
        if not len(texts):
            return out
        seqs = self._ids(texts)
        order = np.argsort([len(s) for s in seqs], kind="stable")
        bs = int(self.p["batch_size"]) * 8
        amp = self.device.type == "cuda"
        with torch.no_grad(), torch.autocast(self.device.type, enabled=amp):
            for i in range(0, len(order), bs):
                idx = order[i : i + bs]
                x, m = self._batch(torch, [seqs[j] for j in idx])
                logits = self.model(input_ids=x, attention_mask=m).logits.float()
                out[idx] = torch.softmax(logits, dim=1).double().cpu().numpy()
        return out

    predict_and_score = CharCNNDetector.predict_and_score
    predict = CharCNNDetector.predict
    known_mask = CharCNNDetector.known_mask
    predict_and_mask = CharCNNDetector.predict_and_mask
    empty_prediction = CharCNNDetector.empty_prediction


def make_neural(kind: str, prep: str, cfg: dict, seed: int = 0, log=None):
    if kind == "charcnn":
        return CharCNNDetector(prep, seed, cfg.get("charcnn", {}), log=log)
    if kind == "bert":
        return BertDetector(prep, seed, cfg.get("bert", {}), log=log)
    raise ValueError(f"unknown neural detector: {kind}")
