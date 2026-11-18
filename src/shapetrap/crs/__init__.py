"""Real OWASP Core Rule Set verdicts through libmodsecurity.

The local signature baseline is 27 regular expressions.  This module runs the
actual CRS instead: every corpus string is placed in an HTTP request the way
its container implies, the request is evaluated by libmodsecurity with the CRS
rules at paranoia level 1 and 2, and the verdict (blocked or not, plus the
rule ids that matched) is stored next to the corpus.

It is optional.  It needs a C compiler and libmodsecurity 3; when either is
missing the rest of the tool runs without it.
"""

from __future__ import annotations

import binascii
import csv
import hashlib
import shutil
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..shapes import detect_shape

HARNESS_SOURCE = Path(__file__).with_name("harness.c")
LEVELS = (1, 2)

# Characters that may stay as they are in a request target.  Everything else
# (spaces, quotes, angle brackets, non-ASCII ...) is percent-encoded, which the
# engine decodes again, so the rules see the value that was meant.
_URI_SAFE = "%&=+;/?:@!$'()*,-._~[]"


MODES = ("container", "value")


def build_request(text: str, mode: str = "container") -> tuple[str, str, str, str]:
    """(method, request target, content type or "-", body or "-") for a string.

    In ``container`` mode the request follows the string's container:
    key=value -> query string, path -> request target, JSON, multipart and
    XML -> request body with that content type, anything else -> the value of
    one parameter.  In ``value`` mode every
    string is sent as the value of one parameter, which is what a learned
    detector sees: the whole string, with no parser in front of it."""
    s = text.strip()
    if not s:
        return ("GET", "/", "-", "-")
    if mode == "value":
        return ("GET", "/?q=" + urllib.parse.quote(s, safe=""), "-", "-")
    shape = detect_shape(text)
    if shape == "empty":
        return ("GET", "/", "-", "-")
    if shape == "kv":
        return ("GET", "/?" + urllib.parse.quote(s, safe=_URI_SAFE), "-", "-")
    if shape == "path":
        if not s.startswith("/"):
            parts = urllib.parse.urlsplit(s)
            s = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        return ("GET", urllib.parse.quote(s, safe=_URI_SAFE), "-", "-")
    if shape == "json":
        return ("POST", "/", "application/json", s)
    if shape == "multipart":
        boundary = s[2 : s.index("\r\n")]
        return ("POST", "/", f"multipart/form-data; boundary={boundary}", s + "\r\n")
    if shape == "xml":
        return ("POST", "/", "application/xml", s)
    return ("GET", "/?q=" + urllib.parse.quote(s, safe=""), "-", "-")


def _tag(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:10]


def _hex(s: str) -> str:
    return binascii.hexlify(s.encode("utf-8", "replace")).decode("ascii")


def _line(text: str, mode: str = "container") -> str:
    method, target, ctype, body = build_request(text, mode)
    return "\t".join((method, _hex(target), ctype, _hex(body) if body != "-" else "-"))


def compile_harness(work: Path) -> Path:
    binary = work / "crs-harness"
    if binary.exists() and binary.stat().st_mtime >= HARNESS_SOURCE.stat().st_mtime:
        return binary
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("no C compiler found (install gcc)")
    proc = subprocess.run(
        [cc, "-O2", "-o", str(binary), str(HARNESS_SOURCE), "-lmodsecurity"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "could not build the CRS harness; is libmodsecurity 3 installed?\n"
            + proc.stderr.strip()[-600:]
        )
    return binary


def write_config(work: Path, crs_root: Path, level: int) -> Path:
    setup = crs_root / "crs-setup.conf.example"
    rules = crs_root / "rules"
    if not setup.exists() or not rules.is_dir():
        raise RuntimeError(f"CRS rules not found under {crs_root} (run `shapetrap fetch`)")
    conf = work / f"pl{level}.conf"
    conf.write_text(
        f"""SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1048576
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
Include {setup.resolve()}
SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level={level},setvar:tx.detection_paranoia_level={level}"
Include {rules.resolve()}/*.conf
""",
        encoding="utf-8",
    )
    return conf


def _evaluate(
    binary: Path, conf: Path, texts: list[str], mode: str = "container"
) -> list[tuple[int, str]]:
    payload = "\n".join(_line(t, mode) for t in texts) + "\n"
    proc = subprocess.run(
        [str(binary), str(conf)], input=payload, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError("CRS harness failed: " + proc.stderr.strip()[-600:])
    out = []
    for ln in proc.stdout.splitlines():
        status, _, ids = ln.partition("\t")
        out.append((int(status), ids))
    if len(out) != len(texts):
        raise RuntimeError(f"CRS harness returned {len(out)} verdicts for {len(texts)} requests")
    return out


def evaluate(
    binary: Path, conf: Path, texts: list[str], workers: int = 2, mode: str = "container"
) -> list[tuple[int, str]]:
    if not texts:
        return []
    size = max(1, -(-len(texts) // workers))
    chunks = [texts[i : i + size] for i in range(0, len(texts), size)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        parts = list(pool.map(lambda c: _evaluate(binary, conf, c, mode), chunks))
    return [v for part in parts for v in part]


class Verdicts:
    """CRS verdicts for arbitrary strings (rewritten ones included), computed
    through the harness on first use and cached by (level, mode, string)."""

    def __init__(self, cfg: dict, base: Path, out: Path):
        self.work = out / "crs"
        self.work.mkdir(parents=True, exist_ok=True)
        self.binary = compile_harness(self.work)
        root = base / cfg.get("crs_path", "data/raw/coreruleset")
        self.conf = {lvl: write_config(self.work, root, lvl) for lvl in LEVELS}
        self.workers = int(cfg.get("crs_workers", 2))
        self.cache: dict[tuple[int, str, str], bool] = {}

    def blocked(self, texts: list[str], level: int = 1, mode: str = "container") -> list[bool]:
        todo = sorted({t for t in texts if (level, mode, t) not in self.cache})
        if todo:
            res = evaluate(self.binary, self.conf[level], todo, self.workers, mode)
            for t, (status, _) in zip(todo, res):
                if status < 0:
                    raise RuntimeError("a request could not be parsed by the harness")
                self.cache[(level, mode, t)] = status != 0
        return [self.cache[(level, mode, t)] for t in texts]


def run_crs(cfg: dict, base: Path, out: Path, corpus: dict[str, list[dict]], log=print) -> dict:
    """Evaluate every distinct corpus string once per paranoia level and store
    the verdicts aligned with each source's corpus file."""
    work = out / "crs"
    work.mkdir(parents=True, exist_ok=True)
    crs_root = base / cfg.get("crs_path", "data/raw/coreruleset")
    binary = compile_harness(work)
    texts = sorted({r["text"] for rows in corpus.values() for r in rows})
    verdict: dict[str, dict] = {t: {} for t in texts}
    for level in LEVELS:
        conf = write_config(work, crs_root, level)
        results = evaluate(binary, conf, texts, workers=int(cfg.get("crs_workers", 2)))
        bad = sum(status < 0 for status, _ in results)
        if bad:
            raise RuntimeError(f"{bad} requests could not be parsed by the harness")
        for t, (status, ids) in zip(texts, results):
            verdict[t][f"pl{level}"] = int(status != 0)
            verdict[t][f"rules{level}"] = ids
        log(
            f"  CRS paranoia level {level}: {sum(v[f'pl{level}'] for v in verdict.values())} of "
            f"{len(texts)} distinct strings blocked"
        )
        # Value mode: the same strings, each sent whole as one parameter.  Where
        # both modes build the same request the verdict is reused.
        same = [t for t in texts if build_request(t, "value") == build_request(t)]
        for t in same:
            verdict[t][f"pl{level}v"] = verdict[t][f"pl{level}"]
        diff = [t for t in texts if build_request(t, "value") != build_request(t)]
        results = evaluate(binary, conf, diff, int(cfg.get("crs_workers", 2)), "value")
        if any(status < 0 for status, _ in results):
            raise RuntimeError("value-mode requests could not be parsed by the harness")
        for t, (status, _) in zip(diff, results):
            verdict[t][f"pl{level}v"] = int(status != 0)
        log(
            f"  CRS paranoia level {level}, value mode: "
            f"{sum(v[f'pl{level}v'] for v in verdict.values())} of {len(texts)} blocked"
        )
    for name, rows in corpus.items():
        with open(work / f"{name}.csv", "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["idx", "text_sha1", "pl1", "pl2", "rules_pl1", "pl1v", "pl2v"])
            for i, r in enumerate(rows):
                v = verdict[r["text"]]
                w.writerow(
                    [i, _tag(r["text"]), v["pl1"], v["pl2"], v["rules1"], v["pl1v"], v["pl2v"]]
                )
    return {"strings": len(texts)}


def attach(corpus: dict[str, list[dict]], out: Path) -> bool:
    """Add stored verdicts (``crs1``, ``crs2``, and ``crs1v``, ``crs2v`` for
    value mode when the files have them) to corpus rows.  Returns False, and
    leaves the corpus untouched, unless every source has a matching file."""
    work = out / "crs"
    loaded = {}
    for name, rows in corpus.items():
        path = work / f"{name}.csv"
        if not path.exists():
            return False
        with open(path, encoding="utf-8", newline="") as fh:
            data = list(csv.DictReader(fh))
        # Verdicts must belong to exactly this corpus: same length, same strings.
        if len(data) != len(rows) or any(
            v["text_sha1"] != _tag(r["text"]) for r, v in zip(rows, data)
        ):
            return False
        loaded[name] = data
    for name, rows in corpus.items():
        for r, v in zip(rows, loaded[name]):
            r["crs1"], r["crs2"] = v["pl1"] == "1", v["pl2"] == "1"
            if v.get("pl1v") not in (None, ""):
                r["crs1v"], r["crs2v"] = v["pl1v"] == "1", v["pl2v"] == "1"
    return True
