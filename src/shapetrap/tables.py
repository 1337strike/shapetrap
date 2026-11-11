"""CSV and Markdown table helpers (no pandas needed)."""

from __future__ import annotations

import csv
import math
from pathlib import Path


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _typed(v: str):
    if v == "":
        return float("nan")
    for cast in (int, float):
        try:
            return cast(v)
        except ValueError:
            pass
    return v


def read_typed_csv(path: Path) -> list[dict]:
    """Like read_csv, but numbers come back as numbers (empty -> NaN)."""
    return [{k: _typed(v) for k, v in row.items()} for row in read_csv(path)]


def fmt(v, digits: int = 3) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        if math.isnan(v):
            return "-"
        return f"{v:.{digits}f}"
    return str(v)


def pct(v, digits: int = 1) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    return f"{100 * v:.{digits}f}"


def md_table(header: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(header) + " |",
           "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def md_matrix(names: list[str], cell, corner: str = "train \\ test") -> str:
    """Square matrix: ``cell(row_name, col_name)`` returns the cell text."""
    return md_table([corner] + names, [[a] + [cell(a, b) for b in names] for a in names])
