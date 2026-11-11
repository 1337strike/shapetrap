"""Benchmark-integrity audit: how much do the sources share?

Three levels, because two collections can share provenance without sharing a
single string:

* exact       identical strings
* normalized  identical after canonicalization, ignoring whitespace
* value       identical *values* once every input is taken out of its
              container (key=value pairs split, values canonicalized)

The value level is what exposes a collection that was built by cutting the
parameter values out of another one.
"""

from __future__ import annotations

from pathlib import Path

from .canon import norm_key
from .shapes import values_of
from .tables import md_matrix, pct, write_csv


def _informative(key: str) -> bool:
    # Short or purely numeric values ("1", "on", "2010") match everywhere and
    # say nothing about provenance.
    return len(key) >= 5 and not key.isdigit()


def _sets(rows: list[dict]) -> dict:
    exact = {r["text"] for r in rows}
    norm = {r["key"]: r["y"] for r in rows if r["key"]}
    values, benign_values = set(), set()
    for r in rows:
        for v in values_of(r["text"]):
            k = norm_key(v)
            if _informative(k):
                values.add(k)
                if r["y"] == "benign":
                    benign_values.add(k)
    return {"exact": exact, "norm": norm, "values": values, "benign_values": benign_values}


def _share(a: set, b: set) -> tuple[int, float]:
    if not a or not b:
        return 0, float("nan")
    n = len(a & b)
    return n, n / min(len(a), len(b))


def run_audit(corpus: dict[str, list[dict]], out_dir: Path, link_threshold: float = 0.25,
              held: set[str] = frozenset()) -> str:
    names = list(corpus)
    sets = {n: _sets(rows) for n, rows in corpus.items()}
    rows, cells = [], {}
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            A, B = sets[a], sets[b]
            ex_n, ex_p = _share(A["exact"], B["exact"])
            nm_n, nm_p = _share(set(A["norm"]), set(B["norm"]))
            va_n, va_p = _share(A["values"], B["values"])
            bv_n, bv_p = _share(A["benign_values"], B["benign_values"])
            conflicts = sum(1 for k, y in A["norm"].items()
                            if k in B["norm"] and B["norm"][k] != y)
            row = {"a": a, "b": b,
                   "exact_n": ex_n, "exact_share": ex_p,
                   "normalized_n": nm_n, "normalized_share": nm_p,
                   "value_n": va_n, "value_share": va_p,
                   "benign_value_n": bv_n, "benign_value_share": bv_p,
                   "label_conflicts": conflicts}
            rows.append(row)
            cells[(a, b)] = cells[(b, a)] = row
    write_csv(rows, out_dir / "audit_overlap.csv")

    def cell(key):
        return lambda a, b: "-" if a == b else pct(cells[(a, b)][key])

    md = "## 1. Integrity audit\n\n"
    md += ("Share of the smaller set that also appears in the other source (%). "
           "Values are compared after removing the container; short and purely "
           "numeric values are ignored.\n\n")
    md += "**Normalized string overlap (%)**\n\n" + md_matrix(names, cell("normalized_share"), "source")
    md += "\n**Benign value-level overlap (%)**\n\n" + md_matrix(names, cell("benign_value_share"), "source")
    worst = max(rows, key=lambda r: (r["benign_value_share"] if r["benign_value_share"] == r["benign_value_share"] else -1))
    md += (f"\nLargest benign value-level overlap: **{worst['a']} / {worst['b']}** at "
           f"{pct(worst['benign_value_share'])}% ({worst['benign_value_n']} shared values), "
           f"against {pct(worst['normalized_share'])}% at string level.\n")
    # Sources linked by a large overlap are not independent collections.
    parent = {n: n for n in names}

    def find(n):
        while parent[n] != n:
            n = parent[n]
        return n

    # Provenance clusters are drawn among the benchmark (trainable) sources.
    # Pairs involving a held-out source are listed separately: there a large
    # overlap usually means a shared payload list or a common credential
    # dictionary, which is a property of the traffic, not of the collection.
    other_pairs = []
    for r in rows:
        shares = [r["normalized_share"], r["benign_value_share"]]
        if not any(v == v and v >= link_threshold for v in shares):
            continue
        if r["a"] in held or r["b"] in held:
            other_pairs.append(f"{r['a']} / {r['b']}")
        else:
            parent[find(r["a"])] = find(r["b"])
    clusters = {}
    for n in names:
        if n not in held:
            clusters.setdefault(find(n), []).append(n)
    linked = [c for c in clusters.values() if len(c) > 1]
    if linked:
        md += (f"\nBenchmark sources linked at >= {pct(link_threshold, 0)}% on either level (shared "
               "provenance, not independent collections): " + "; ".join(" + ".join(c) for c in linked) + ".\n")
    else:
        md += f"\nNo pair of benchmark sources reaches {pct(link_threshold, 0)}% on either level.\n"
    if other_pairs:
        md += (f"\nPairs involving a held-out source at >= {pct(link_threshold, 0)}% (shared payload lists "
               "or common credential dictionaries): " + "; ".join(other_pairs) + ".\n")
    total_conf = sum(r["label_conflicts"] for r in rows)
    md += f"\nCross-source label conflicts on normalized strings: {total_conf}.\n"
    return md
