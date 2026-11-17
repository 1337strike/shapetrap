"""Character-level detector: a small byte CNN.

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
NEURAL = ("charcnn",)
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


def make_neural(kind: str, prep: str, cfg: dict, seed: int = 0, log=None):
    if kind != "charcnn":
        raise ValueError(f"unknown neural detector: {kind}")
    return CharCNNDetector(prep, seed, cfg.get("charcnn", {}), log=log)
