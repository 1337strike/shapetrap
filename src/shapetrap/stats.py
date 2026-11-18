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
    return (w_plus, hits / 2**n, n)


def bootstrap_mean(
    values: list[float], n_boot: int = 10000, seed: int = 0, level: float = 0.95
) -> tuple[float, float, float]:
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


def crossed_lmm(cells: dict[tuple[str, str], float]) -> dict:
    """Mean of cell-level values with crossed random effects for the row
    (training source) and the column (test source).

    Model: ``y[s, t] = mu + a[s] + b[t] + e[s, t]`` with independent normal
    ``a``, ``b`` and ``e``, fitted by restricted maximum likelihood.  The
    test of ``mu = 0`` uses a t distribution with ``min(rows, columns) - 1``
    degrees of freedom, the conservative containment choice for an intercept
    that both factors share.  Unlike a test over per-source means, every cell
    is used, and a source that is hard to test on (or to train on) is a
    variance component rather than a hidden dependence.

    Returns mu, its standard error, a 95% interval, df, p, and the share of
    the total variance that belongs to rows, columns and cells.
    """
    import numpy as np
    from scipy import optimize
    from scipy import stats as sst

    keys = [k for k, v in cells.items() if v is not None and not math.isnan(v)]
    nan = float("nan")
    out = {"n": len(keys), "mu": nan, "se": nan, "lo": nan, "hi": nan, "df": 0, "p": nan}
    out |= {"share_row": nan, "share_col": nan, "share_cell": nan}
    rows = sorted({s for s, _ in keys})
    cols = sorted({t for _, t in keys})
    if len(keys) < 3 or len(rows) < 2 or len(cols) < 2:
        return out
    y = np.array([cells[k] for k in keys], dtype=float)
    scale = float(y.std()) or 1.0
    y = y / scale
    za = np.array([[s == r for r in rows] for s, _ in keys], dtype=float)
    zb = np.array([[t == c for c in cols] for _, t in keys], dtype=float)
    ka, kb = za @ za.T, zb @ zb.T
    x = np.ones(len(y))
    eye = np.eye(len(y))

    def parts(theta):
        va, vb, ve = np.exp(theta)
        v = va * ka + vb * kb + ve * eye
        c = np.linalg.cholesky(v)
        vi_x = np.linalg.solve(c.T, np.linalg.solve(c, x))
        vi_y = np.linalg.solve(c.T, np.linalg.solve(c, y))
        xvx = float(x @ vi_x)
        beta = float(x @ vi_y) / xvx
        return c, xvx, beta, vi_y - vi_x * beta

    def neg_reml(theta):
        try:
            c, xvx, beta, vi_r = parts(theta)
        except np.linalg.LinAlgError:
            return 1e12
        r = y - beta
        return 0.5 * (2 * np.log(np.diag(c)).sum() + math.log(xvx) + float(r @ vi_r))

    fits = [
        optimize.minimize(neg_reml, np.array(start), method="L-BFGS-B", bounds=[(-20, 5)] * 3)
        for start in ([-1.0, -1.0, -1.0], [-4.0, 0.0, -1.0], [0.0, -4.0, -1.0], [-4.0, -4.0, 0.0])
    ]
    best = min(fits, key=lambda res: res.fun)
    va, vb, ve = np.exp(best.x)
    _, xvx, beta, _ = parts(best.x)
    se = math.sqrt(1.0 / xvx)
    df = min(len(rows), len(cols)) - 1
    tq = float(sst.t.ppf(0.975, df))
    total = va + vb + ve
    out.update(
        mu=beta * scale,
        se=se * scale,
        lo=(beta - tq * se) * scale,
        hi=(beta + tq * se) * scale,
        df=df,
        p=float(2 * sst.t.sf(abs(beta / se), df)),
        share_row=float(va / total),
        share_col=float(vb / total),
        share_cell=float(ve / total),
    )
    return out
