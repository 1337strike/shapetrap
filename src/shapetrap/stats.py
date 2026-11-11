"""Small, dependency-light statistics used across the audit."""

from __future__ import annotations

import itertools
import math

from scipy import stats as sps


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = 0.0 if k == 0 else max(0.0, centre - half)
    hi = 1.0 if k == n else min(1.0, centre + half)
    return (lo, hi)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar test on the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    return float(min(1.0, 2 * sps.binom.cdf(min(b, c), n, 0.5)))


def holm(pvalues: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, returned in the input order."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, (m - rank) * pvalues[i])
        adjusted[i] = min(1.0, running)
    return adjusted


def _rank(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def _pearson(x: list[float], y: list[float]) -> float:
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    if sxx == 0 or syy == 0:
        return float("nan")
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / math.sqrt(sxx * syy)


def spearman_exact(x: list[float], y: list[float]) -> tuple[float, float]:
    """Spearman's rho with the exact two-sided permutation p-value.

    All n! orderings are enumerated, so this is only meant for the handful of
    sources an audit has (n <= 9).  The t-approximation is anticonservative at
    that size.
    """
    n = len(x)
    if n < 3 or n > 9:
        raise ValueError("spearman_exact supports 3 <= n <= 9")
    rx, ry = _rank(list(x)), _rank(list(y))
    rho = _pearson(rx, ry)
    if math.isnan(rho):
        return (rho, float("nan"))
    hits = total = 0
    for perm in itertools.permutations(ry):
        total += 1
        if abs(_pearson(rx, list(perm))) >= abs(rho) - 1e-12:
            hits += 1
    return (rho, hits / total)


def corrected_paired_t(diffs: list[float], n_train: float, n_test: float) -> dict:
    """Nadeau-Bengio corrected paired t-test for repeated CV differences."""
    n = len(diffs)
    mean = sum(diffs) / n
    var = sum((d - mean) ** 2 for d in diffs) / (n - 1)
    se = math.sqrt((1 / n + n_test / n_train) * var)
    if se == 0:
        return {"mean": mean, "se": 0.0, "t": float("inf"), "p": 0.0, "ci": (mean, mean)}
    t = mean / se
    p = float(2 * sps.t.sf(abs(t), n - 1))
    half = float(sps.t.ppf(0.975, n - 1)) * se
    return {"mean": mean, "se": se, "t": t, "p": p, "ci": (mean - half, mean + half)}


def mean_sd(values: list[float]) -> tuple[float, float]:
    vals = [v for v in values if v is not None and not math.isnan(v)]
    if not vals:
        return (float("nan"), float("nan"))
    m = sum(vals) / len(vals)
    if len(vals) < 2:
        return (m, 0.0)
    return (m, math.sqrt(sum((v - m) ** 2 for v in vals) / (len(vals) - 1)))


def wilcoxon_exact(diffs: list[float]) -> tuple[float, float, int]:
    """Exact two-sided Wilcoxon signed-rank test on paired differences.

    Zeros are dropped and tied magnitudes share mid-ranks; the null
    distribution is enumerated over all sign assignments, so it stays exact
    for the handful of sources an audit has.  Returns (W+, p, n used).
    """
    d = [x for x in diffs if x != 0 and not math.isnan(x)]
    n = len(d)
    if n == 0:
        return (0.0, 1.0, 0)
    if n > 20:
        raise ValueError("wilcoxon_exact enumerates 2^n sign patterns; n must be <= 20")
    ranks = _rank([abs(x) for x in d])
    w_plus = sum(r for r, x in zip(ranks, d) if x > 0)
    centre = sum(ranks) / 2
    observed = abs(w_plus - centre)
    hits = 0
    for signs in itertools.product((0, 1), repeat=n):
        w = sum(r for r, sgn in zip(ranks, signs) if sgn)
        if abs(w - centre) >= observed - 1e-12:
            hits += 1
    return (w_plus, hits / 2 ** n, n)


def bootstrap_mean(values: list[float], n_boot: int = 10000, seed: int = 0,
                   level: float = 0.95) -> tuple[float, float, float]:
    """Mean with a percentile bootstrap interval, resampling the units (here:
    training sources) with replacement.  With a handful of units the interval
    is coarse; it shows how much one source can move the mean."""
    import numpy as np
    vals = np.asarray([v for v in values if v is not None and not math.isnan(v)], dtype=float)
    if len(vals) == 0:
        return (float("nan"),) * 3
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(vals), size=(n_boot, len(vals)))
    means = vals[idx].mean(axis=1)
    lo, hi = np.quantile(means, [(1 - level) / 2, 1 - (1 - level) / 2])
    return (float(vals.mean()), float(lo), float(hi))
