"""Lightweight detectors: TF-IDF with LR / MNB / linear SVM, and a local
signature baseline, each with raw or canonicalized preprocessing.

Hyper-parameters follow the earlier paper (unigrams+bigrams, 4,000 features,
sublinear TF; LR C=10; MNB Laplace smoothing; linear SVM C=1).  The SVM is
uncalibrated by default: the earlier paper found the calibration wrapper
changed latency, not the confusion matrices.
"""

from __future__ import annotations

import re

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

from .canon import canonicalize
from .shapes import INTERVENTIONS, decontain
from .tokenizer import TOKENIZERS

# The 11 SQLi and 8 XSS expressions of the earlier paper's local baseline.
SQLI_RULES = [
    r"(\bunion\b.{0,40}\bselect\b)",
    r"(\bor\b\s+1\s*=\s*1)",
    r"('|\")\s*or\s*('|\")?\d+\s*=\s*\d+",
    r"(--|\#)\s*$",
    r"(\bdrop\b\s+\btable\b)",
    r"(\bselect\b.{0,40}\bfrom\b)",
    r"(\bsleep\s*\()",
    r"(\bexec\b\s+\bxp_cmdshell\b)",
    r"(\binformation_schema\b)",
    r"(;\s*--)",
    r"(\bhaving\b\s+\d+\s*=\s*\d+)",
]
XSS_RULES = [
    r"(<\s*script\b)",
    r"(on\w+\s*=\s*['\"]?\s*alert\s*\()",
    r"(javascript\s*:)",
    r"(<\s*img\b[^>]*\bonerror\b)",
    r"(<\s*svg\b[^>]*\bonload\b)",
    r"(<\s*iframe\b)",
    r"(document\.cookie)",
    r"(<\s*body\b[^>]*\bonload\b)",
]
# New for this project.  Local and small, like the rest: not a production set.
TRAVERSAL_RULES = [
    r"(\.\.[/\\])",
    r"(/etc/(passwd|shadow|hosts)\b)",
    r"(\b(boot|win)\.ini\b)",
    r"(\bfile\s*:\s*/)",
]
CMDI_RULES = [
    r"([;|&`]\s*(cat|ls|id|whoami|uname|ping|dir|type|wget|curl|nc|sleep|echo)\b)",
    r"(\$\([^)]*\))",
    r"(`[^`]+`)",
    r"(\bcmd(\.exe)?\s*/c\b)",
]
RULESETS = [("sqli", SQLI_RULES), ("xss", XSS_RULES),
            ("traversal", TRAVERSAL_RULES), ("cmdi", CMDI_RULES)]


class Signature:
    kind = "sig"

    def __init__(self, prep: str):
        self.prep = prep
        self._rules = [(label, [re.compile(p, re.IGNORECASE) for p in pats])
                       for label, pats in RULESETS]

    def fit(self, texts, labels):
        return self

    def _one(self, text: str) -> str:
        if self.prep == "canon":
            text = canonicalize(text)
        for label, pats in self._rules:
            if any(p.search(text) for p in pats):
                return label
        return "benign"

    def predict(self, texts):
        return np.array([self._one(t) for t in texts], dtype=object)

    def known_mask(self, texts):
        return np.ones(len(texts), dtype=bool)

    def predict_and_mask(self, texts):
        return self.predict(texts), self.known_mask(texts)


# Preprocessing modes.
#   raw     the string as sent
#   canon   canonicalized (decode, strip comments, lowercase)
#   cstrip  container canonicalization: keys and separators removed, each
#           value canonicalized, values joined by one space
#   vmil    container canonicalization with one decision per value (see
#           ValueSpace); a string is flagged when any of its values is
CONTAINER_FREE = ("cstrip", "vmil")
SIGNATURE_PREPS = ("raw", "canon")


def preprocess(text: str, prep: str) -> str:
    if prep == "raw":
        return text
    if prep == "canon":
        return canonicalize(text)
    if prep == "cstrip":
        return " ".join(canonicalize(v) for v in decontain(text))
    raise ValueError(f"unknown preprocessing: {prep}")


LINEAR = ("lr", "mnb", "svm", "svm_cal")
NONLINEAR = ("rf", "gbm", "mlp")


def make_clf(kind: str, seed: int = 0, paper_settings: bool = False):
    """Classifier for a detector kind.

    Logistic regression is run to full convergence (tol=1e-8).  With
    scikit-learn's default tolerance L-BFGS stops after a few dozen
    iterations; in-distribution scores are the same, but a cross-dataset cell
    whose test points sit on the decision boundary can then swing by tens of
    points depending on where the optimizer happened to stop, and so differ
    between machines.  ``paper_settings=True`` restores the default tolerance
    of the earlier paper, which `shapetrap anchor` needs to re-derive its
    published numbers exactly.

    lr / mnb / svm are the linear models of the earlier paper.  rf (bagged
    trees), gbm (boosted trees, LightGBM) and mlp (one hidden layer) are
    non-linear learners on the same features, used to check that an effect
    does not depend on linearity.
    """
    if kind == "rf":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed)
    if kind == "gbm":
        try:
            from lightgbm import LGBMClassifier
        except ImportError:
            raise SystemExit("The gbm detector needs LightGBM: pip install lightgbm") from None
        return LGBMClassifier(n_estimators=100, learning_rate=0.1, num_leaves=31, n_jobs=2,
                              random_state=seed, deterministic=True, force_row_wise=True,
                              verbose=-1)
    if kind == "mlp":
        from sklearn.neural_network import MLPClassifier
        return MLPClassifier(hidden_layer_sizes=(64,), max_iter=30, early_stopping=True,
                             random_state=seed)
    if kind == "lr":
        if paper_settings:
            return LogisticRegression(C=10.0, max_iter=1000)
        return LogisticRegression(C=10.0, max_iter=20000, tol=1e-8)
    if kind == "mnb":
        return MultinomialNB()
    if kind == "svm":
        return LinearSVC(C=1.0) if paper_settings else LinearSVC(C=1.0, tol=1e-8, max_iter=100000)
    if kind == "svm_cal":
        return CalibratedClassifierCV(LinearSVC(C=1.0), cv=3)
    raise ValueError(f"unknown detector kind: {kind}")


class Features:
    """Preprocessing + TF-IDF, shared by every classifier that uses the same
    preprocessing and augmentation, so each string is tokenized once."""

    def __init__(self, prep: str, tokenizer: str = "web", max_features: int = 4000,
                 augment: bool = False, seed: int = 0):
        self.prep, self.augment, self.seed = prep, augment, seed
        self.vec = TfidfVectorizer(tokenizer=TOKENIZERS[tokenizer], token_pattern=None,
                                   lowercase=False, max_features=max_features,
                                   ngram_range=(1, 2), sublinear_tf=True)

    def _prep(self, texts):
        return [preprocess(t, self.prep) for t in texts]

    def fit_transform(self, texts, labels):
        """Returns the training matrix and the labels that go with it (longer
        than the input when augmentation adds rows)."""
        texts, labels = list(texts), list(labels)
        if self.augment:
            # Shape augmentation: every training string is also seen in the
            # other containers, with its label unchanged.
            extra_t, extra_y = [], []
            for fn in INTERVENTIONS.values():
                for t, y in zip(texts, labels):
                    v = fn(t, self.seed)
                    if v != t:
                        extra_t.append(v)
                        extra_y.append(y)
            texts, labels = texts + extra_t, labels + extra_y
        return self.vec.fit_transform(self._prep(texts)), labels

    def transform(self, texts):
        return self.vec.transform(self._prep(texts))


class TfidfDetector:
    def __init__(self, kind: str, prep: str, tokenizer: str = "web",
                 max_features: int = 4000, augment: bool = False, seed: int = 0,
                 paper_settings: bool = False):
        self.kind, self.prep, self.augment, self.seed = kind, prep, augment, seed
        self.features = Features(prep, tokenizer, max_features, augment, seed)
        self.vec = self.features.vec
        self.clf = make_clf(kind, seed, paper_settings=paper_settings)

    def fit(self, texts, labels):
        X, labels = self.features.fit_transform(texts, labels)
        self.clf.fit(X, labels)
        return self

    def _X(self, texts):
        return self.features.transform(texts)

    def predict(self, texts):
        return np.asarray(self.clf.predict(self._X(texts)), dtype=object)

    def known_mask(self, texts):
        """False where the input shares no feature with the vocabulary, i.e.
        the classifier decides from its intercept or prior alone."""
        return np.asarray(self._X(texts).getnnz(axis=1) > 0)

    def predict_and_mask(self, texts):
        X = self._X(texts)
        return np.asarray(self.clf.predict(X), dtype=object), np.asarray(X.getnnz(axis=1) > 0)

    def empty_prediction(self) -> str:
        """What the model says about an input it has no evidence on."""
        return str(self.clf.predict(self.vec.transform([""]))[0])


def attack_score(clf, X) -> np.ndarray:
    """How strongly each row looks like an attack (higher = more)."""
    classes = list(clf.classes_)
    b = classes.index("benign")
    if hasattr(clf, "predict_proba"):
        return 1.0 - clf.predict_proba(X)[:, b]
    d = clf.decision_function(X)
    if d.ndim == 1:
        return d if classes[1] != "benign" else -d
    others = [i for i in range(len(classes)) if i != b]
    return d[:, others].max(axis=1) - d[:, b]


class ValueSpace:
    """Per-value features for the ``vmil`` mode.

    Every string becomes a bag of canonicalized values.  At test time each
    value gets its own decision and the string is flagged when any value is.
    A benign string has only benign values, but in an attack string that
    carries several values it is not known which one is the attack, so
    training is multiple-instance: start by treating every value of such a
    string as an attack, fit, keep only the highest-scoring value of each
    attack bag, and refit (mi-SVM style, ``rounds`` refits).
    """

    def __init__(self, tokenizer: str = "web", max_features: int = 4000, rounds: int = 2):
        self.rounds = rounds
        self.vec = TfidfVectorizer(tokenizer=TOKENIZERS[tokenizer], token_pattern=None,
                                   lowercase=False, max_features=max_features,
                                   ngram_range=(1, 2), sublinear_tf=True)

    @staticmethod
    def bags(texts):
        values, owner = [], []
        for i, t in enumerate(texts):
            vals = [canonicalize(v) for v in decontain(t)] or [""]
            values.extend(vals)
            owner.extend([i] * len(vals))
        return values, np.asarray(owner, dtype=np.int64)

    def fit_transform(self, texts, labels):
        values, owner = self.bags(texts)
        self._y = np.asarray(list(labels), dtype=object)[owner]
        self._owner = owner
        size = np.bincount(owner, minlength=len(texts))
        self._multi = (size[owner] > 1) & (self._y != "benign")
        self._X = self.vec.fit_transform(values)
        return self._X

    def transform(self, texts):
        values, owner = self.bags(texts)
        return self.vec.transform(values), owner, len(texts)

    def fit_clf(self, kind: str):
        X, y, owner, multi = self._X, self._y, self._owner, self._multi
        keep = np.ones(X.shape[0], dtype=bool)
        clf = make_clf(kind).fit(X, y)
        for _ in range(self.rounds):
            if not multi.any():
                break
            score = attack_score(clf, X)
            idx = np.flatnonzero(multi)
            order = idx[np.lexsort((-score[idx], owner[idx]))]      # by bag, best first
            first = np.ones(len(order), dtype=bool)
            first[1:] = owner[order][1:] != owner[order][:-1]
            new_keep = ~multi
            new_keep[order[first]] = True
            if np.array_equal(new_keep, keep):
                break
            keep = new_keep
            clf = make_clf(kind).fit(X[keep], y[keep])
        return clf

    @staticmethod
    def scores(clf, X, owner, n):
        """Attack score per string: the highest score among its values."""
        s = attack_score(clf, X)
        out = np.full(n, -np.inf)
        np.maximum.at(out, owner, s)
        return out

    @staticmethod
    def flags(clf, X, owner, n):
        """(flagged, has_known_feature) per string from per-value decisions."""
        vflag = np.asarray(clf.predict(X), dtype=object) != "benign"
        flag = np.zeros(n, dtype=bool)
        known = np.zeros(n, dtype=bool)
        np.logical_or.at(flag, owner, vflag)
        np.logical_or.at(known, owner, np.asarray(X.getnnz(axis=1) > 0))
        return flag, known


def make_detector(kind: str, prep: str, cfg: dict, augment: bool = False, seed: int = 0):
    if kind == "sig":
        return Signature(prep)
    return TfidfDetector(kind, prep, tokenizer=cfg.get("tokenizer", "web"),
                         max_features=cfg.get("max_features", 4000),
                         augment=augment, seed=seed)


def detector_grid(cfg: dict):
    """(kind, prep, augment) for every configured detector."""
    grid = []
    for kind in cfg["detectors"]:
        if kind == "crs":
            continue
        for prep in cfg["preprocess"]:
            if kind == "sig" and prep not in SIGNATURE_PREPS:
                continue
            grid.append((kind, prep, False))
            # Augmentation is redundant once the container is removed.
            if kind != "sig" and prep not in CONTAINER_FREE and cfg.get("shape_augment", False):
                grid.append((kind, prep, True))
    for kind in cfg.get("nonlinear_detectors", []):
        for prep in cfg["preprocess"]:
            if prep in cfg.get("nonlinear_preprocess", []) and prep != "vmil":
                grid.append((kind, prep, False))
    if "crs" in cfg["detectors"]:
        grid += [("crs", "pl1", False), ("crs", "pl2", False)]
    if cfg.get("shape_baseline", False):
        grid.append(("shape", "lr", False))
    return grid


def config_name(kind: str, prep: str, augment: bool) -> str:
    return f"{kind}-{prep}" + ("+aug" if augment else "")
