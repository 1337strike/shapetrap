"""Dataset loaders, cleaning and group-aware splitting.

Every loader returns ``(rows, notes)`` where a row is ``{"text", "atype"}``
(optionally ``"split"``) and ``atype`` is one of::

    benign | sqli | xss | cmdi | traversal | shell | other | attack

``attack`` means the source labels the sample malicious without a type;
``shell`` is one source's mixed command-injection/traversal class; ``other``
covers LDAP, XPath and SSI.  The binary label is ``atype != "benign"``.
"""

from __future__ import annotations

import csv
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from .canon import family_key, norm_key
from .shapes import detect_shape

csv.field_size_limit(10**9)

ATYPES = ("benign", "sqli", "xss", "cmdi", "traversal", "shell", "other", "attack")


def _read_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


# --------------------------------------------------------------------------
# Loaders
# --------------------------------------------------------------------------

def load_paper1(entry: dict, base: Path):
    """The earlier paper's 1,012-string corpus (template benign + SQLi/XSS
    lists), optionally extended with command-injection and traversal lists
    from the same upstream payload repository."""
    root = base / entry["path"]
    rows, notes = [], {}
    keep_split = entry.get("use_predefined_split", True)
    for fname, split in (("train.csv", "train"), ("test_clean.csv", "test")):
        with open(root / "data" / "processed" / fname, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                row = {"text": r["payload"], "atype": r["label"]}
                if keep_split:
                    row["split"] = split
                rows.append(row)
    extra = entry.get("extra_payloads")
    if extra:
        doc_line = re.compile(r"^\S = ")  # explanatory rows such as ". = %u002e"
        skipped = 0
        for fname, atype in (
            ("Directory-Traversal-Payloads.txt", "traversal"),
            ("OS-Command-Injection-Unix-Payloads.txt", "cmdi"),
            ("OS-Command-Injection-Windows-Payloads.txt", "cmdi"),
        ):
            for ln in _read_lines(base / extra / fname):
                if doc_line.match(ln):
                    skipped += 1
                    continue
                rows.append({"text": ln, "atype": atype})
        notes["extra_doc_lines_skipped"] = skipped
    return rows, notes


def load_hpd(entry: dict, base: Path):
    """HttpParamsDataset: bare parameter values."""
    amap = {"norm": "benign", "sqli": "sqli", "xss": "xss", "cmdi": "cmdi",
            "path-traversal": "traversal"}
    rows, bad = [], 0
    with open(base / entry["path"] / "payload_full.csv", encoding="utf-8",
              errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            atype = amap.get((r.get("attack_type") or "").strip())
            if atype is None or r.get("payload") is None:
                bad += 1
                continue
            rows.append({"text": r["payload"], "atype": atype})
    return rows, {"malformed_rows_skipped": bad}


_REQ_START = re.compile(r"(?m)^(GET|POST|PUT) (\S+) HTTP/1\.[01]\s*$")


def _csic_requests(path: Path):
    text = path.read_text(encoding="latin-1")
    starts = list(_REQ_START.finditer(text))
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        block = text[m.end():end]
        method, url = m.group(1), m.group(2)
        if method == "GET":
            payload = url.partition("?")[2]
        else:
            head, sep, body = block.partition("\n\n")
            payload = body.strip() if sep else ""
        yield payload


def load_csic(entry: dict, base: Path):
    """CSIC 2010: the query string (GET) or body (POST/PUT) as sent.
    Anomalous requests are not typed by the source."""
    root = base / entry["path"]
    files = [("normalTrafficTest.txt", "benign"), ("anomalousTrafficTest.txt", "attack")]
    if entry.get("include_training", True):
        files.insert(0, ("normalTrafficTraining.txt", "benign"))
    rows, total, empty = [], Counter(), Counter()
    for fname, atype in files:
        for payload in _csic_requests(root / fname):
            total[fname] += 1
            if not payload:
                empty[fname] += 1
                continue
            rows.append({"text": payload, "atype": atype})
    return rows, {"requests": dict(total), "requests_without_parameters": dict(empty)}


_ECML_SAMPLE = re.compile(r"<sample id=\"\d+\">(.*?)</sample>", re.S)
_ECML_TYPES = {"Valid": "benign", "SqlInjection": "sqli", "XSS": "xss",
               "OsCommanding": "cmdi", "PathTransversal": "traversal",
               "LdapInjection": "other", "XPathInjection": "other", "SSI": "other"}


def _cdata(tag: str, block: str) -> str:
    m = re.search(rf"<{tag}><!\[CDATA\[(.*?)\]\]></{tag}>", block, re.S)
    return m.group(1).strip() if m else ""


def load_ecml(entry: dict, base: Path):
    """ECML/PKDD 2007 learning set.  Benign: query (plus body).  Attacks: only
    in-context samples whose labelled attack interval lies in the query or the
    body, and the text is that field, so the label matches what is kept."""
    xml = (base / entry["path"]).read_text(encoding="utf-8", errors="replace")
    rows, skipped = [], Counter()
    for m in _ECML_SAMPLE.finditer(xml):
        block = m.group(1)
        atype = _ECML_TYPES.get(re.search(r"<type>(.*?)</type>", block).group(1))
        query, body = _cdata("query", block), _cdata("body", block)
        if atype == "benign":
            text = "&".join(p for p in (query, body) if p)
        else:
            if "<inContext>TRUE</inContext>" not in block:
                skipped["out_of_context"] += 1
                continue
            where = re.search(r"<attackIntervall>(\w+)", block)
            loc = where.group(1) if where else ""
            if loc not in ("query", "body"):
                skipped[f"attack_in_{loc or 'unknown'}"] += 1
                continue
            text = query if loc == "query" else body
        if text:
            rows.append({"text": text, "atype": atype})
        else:
            skipped["empty_field"] += 1
    return rows, {"skipped": dict(skipped)}


def load_gran(entry: dict, base: Path):
    """Granqvist & Holmberg payload collection (mostly bare values)."""
    amap = {"LEGAL": "benign", "SQL": "sqli", "XSS": "xss", "SHELL": "shell"}
    rows, bad = [], 0
    with open(base / entry["path"] / "data" / "payloads.csv", encoding="utf-8",
              errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            atype = amap.get((r.get("injection_type") or "").strip())
            if atype is None or not r.get("payload"):
                bad += 1
                continue
            rows.append({"text": r["payload"], "atype": atype})
    return rows, {"malformed_rows_skipped": bad}


def load_fwaf(entry: dict, base: Path):
    """FWAF good/bad query lists (URL paths with optional query strings)."""
    root = base / entry["path"]
    rows = [{"text": ln, "atype": "benign"} for ln in _read_lines(root / "goodqueries.txt")]
    rows += [{"text": ln, "atype": "attack"} for ln in _read_lines(root / "badqueries.txt")]
    return rows, {}


_COWRIE_COMMAND = ("cowrie.command.input", "cowrie.command.failed")
_COWRIE_LOGIN = ("cowrie.login.failed", "cowrie.login.success")


def load_cowrie(entry: dict, base: Path):
    """Cowrie SSH/Telnet honeypot logs (JSON lines; one file or a directory).

    * Shell commands typed by remote clients become the attack class
      (``shell``).  They are observed in the wild, not taken from a list.
    * Usernames and passwords that were tried become a *non-injection
      control*: hostile input, but not an injection payload, so an injection
      detector has no reason to flag it.  Disable with
      ``credentials_as_control = false``.

    A record is not an attack and a string is not a session, so each distinct
    string carries ``weight`` = the number of events it was seen in, and the
    notes report records, sessions and source addresses separately.  Works
    with native Cowrie field names (``eventid``, ``session``) and with the
    normalized ones (``event_type``, ``session_id``).
    """
    root = base / entry["path"]
    if not root.exists():
        raise SystemExit(f"{root} not found. Put your Cowrie JSONL there, or remove this "
                         "dataset from the config.")
    files = sorted(root.glob("*.json*")) if root.is_dir() else [root]
    commands, controls = Counter(), Counter()
    sessions, sources, stamps = set(), set(), []
    records = bad = 0
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                records += 1
                event = r.get("event_type") or r.get("eventid") or ""
                sessions.add(r.get("session_id") or r.get("session"))
                sources.add(r.get("src_ip") or r.get("src_addr"))
                stamp = r.get("timestamp_utc") or r.get("timestamp")
                if stamp:
                    stamps.append(str(stamp))
                if event in _COWRIE_COMMAND and isinstance(r.get("input"), str):
                    commands[r["input"]] += 1
                elif event in _COWRIE_LOGIN:
                    for field in ("username", "password"):
                        if isinstance(r.get(field), str):
                            controls[r[field]] += 1
    rows = [{"text": t, "atype": "shell", "weight": n} for t, n in commands.items()]
    if entry.get("credentials_as_control", True):
        rows += [{"text": t, "atype": "benign", "weight": n} for t, n in controls.items()]
    notes = {"files": len(files), "records": records, "unparsed_lines": bad,
             "sessions": len(sessions - {None}), "source_addresses": len(sources - {None}),
             "command_events": sum(commands.values()), "distinct_commands": len(commands),
             "credential_events": sum(controls.values()), "distinct_credentials": len(controls),
             "first_timestamp": min(stamps) if stamps else None,
             "last_timestamp": max(stamps) if stamps else None}
    return rows, notes


def _json_lists(paths) -> list[str]:
    out: list[str] = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            out.extend(x for x in json.load(fh) if isinstance(x, str))
    return out


def load_modsec(entry: dict, base: Path):
    """ModSec-Learn dataset (2024): real legitimate query strings collected by
    open-appsec, and SQL injection from sqlmap, open-appsec and a Kaggle set,
    each sent as ``p=<payload>``.  Its HttpParamsDataset part is skipped by
    default because that collection is already a source here."""
    root = base / entry["path"]
    legit = sorted((root / "legitimate" / "openappsec").glob("legitimate_*.json"))
    rows = [{"text": t, "atype": "benign"} for t in _json_lists(legit)]
    parts = entry.get("malicious_parts", ["sqlmap", "openappsec", "sqli_kaggle"])
    counts = {"legitimate": len(rows)}
    for part in parts:
        items = _json_lists([root / "malicious" / part / "sqli_parsed.json"])
        counts[part] = len(items)
        rows += [{"text": t, "atype": "sqli"} for t in items]
    return rows, {"strings_per_part": counts}


_CRS_FAMILIES = {"930": "traversal", "931": "other", "932": "cmdi", "933": "other",
                 "934": "other", "941": "xss", "942": "sqli", "943": "other", "944": "other"}


def load_crs(entry: dict, base: Path):
    """OWASP Core Rule Set regression tests for the application-attack rule
    families.  A test that expects its rule to fire is an attack of that
    family; a test that expects it *not* to fire is a hard negative written by
    the rule authors.  Text is the request body, else the query string; tests
    whose payload sits in headers or cookies are skipped."""
    import yaml
    root = base / entry["path"] / "tests" / "regression" / "tests"
    rows, skipped = [], Counter()
    for folder in sorted(root.glob("REQUEST-9*-APPLICATION-ATTACK-*")):
        atype = _CRS_FAMILIES.get(folder.name.split("-")[1])
        if atype is None:
            continue
        for path in sorted(folder.glob("*.yaml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                skipped["unparsed_file"] += 1
                continue
            for test in (doc or {}).get("tests") or []:
                for stage in test.get("stages") or []:
                    inp, out = stage.get("input") or {}, stage.get("output") or {}
                    log = out.get("log") or {}
                    if log.get("expect_ids"):
                        label = atype
                    elif log.get("no_expect_ids"):
                        label = "benign"
                    else:
                        skipped["no_log_expectation"] += 1
                        continue
                    data, uri = inp.get("data"), inp.get("uri") or ""
                    text = data if isinstance(data, str) and data.strip() else str(uri).partition("?")[2]
                    if not text.strip():
                        skipped["payload_not_in_query_or_body"] += 1
                        continue
                    rows.append({"text": text, "atype": label})
    return rows, {"skipped": dict(skipped)}


_PATT_DIRS = {"SQL Injection": "sqli", "XSS Injection": "xss", "Command Injection": "cmdi",
              "Directory Traversal": "traversal", "File Inclusion": "traversal",
              "NoSQL Injection": "other", "LDAP Injection": "other", "XXE Injection": "other",
              "Server Side Template Injection": "other"}


def load_patt(entry: dict, base: Path):
    """PayloadsAllTheThings Intruder lists: curated attack strings only."""
    root = base / entry["path"]
    rows, files = [], 0
    for topic, atype in _PATT_DIRS.items():
        for folder in (root / topic).glob("Intruder*"):
            for path in sorted(p for p in folder.rglob("*") if p.is_file()):
                files += 1
                rows += [{"text": ln, "atype": atype} for ln in _read_lines(path)]
    return rows, {"files": files}


def load_shellevo(entry: dict, base: Path):
    """Shell-attack-evolution dataset: distinct commands typed into Cowrie
    honeypots, with their observed frequency, for one collection period
    (``2021_2022`` or ``2024``)."""
    period = entry["period"]
    path = base / entry["path"] / "dataset" / "commands" / f"{period}.jsonl"
    rows, events = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            r = json.loads(line)
            n = int(float(r.get("frequency") or 1))
            events += n
            rows.append({"text": r["command"], "atype": "shell", "weight": n})
    return rows, {"period": period, "distinct_commands": len(rows), "command_events": events}


def _zip_or_csv(path: Path):
    """Rows of a CSV file, or of the single CSV inside a zip archive."""
    import io
    import zipfile
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf, zf.open(zf.infolist()[0]) as raw:
            yield from csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline=""))
    else:
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            yield from csv.DictReader(fh)


def load_copot(entry: dict, base: Path):
    """Copot-2025 T-Pot dataset (AWS, 2025).  ``part = "cowrie"``: the command
    string of each SSH/Telnet session is the attack class and the tried
    usernames and passwords are the non-injection control.  ``part = "web"``:
    query strings of requests to the Tanner and h0neytr4p web honeypots
    (requests without parameters are counted, not used)."""
    root = base / entry["path"]
    part = entry.get("part", "cowrie")
    attacks, controls = Counter(), Counter()
    notes: dict = {"part": part}
    if part == "cowrie":
        sessions = 0
        for r in _zip_or_csv(root / "cowrie_malicious_anonymized.zip"):
            sessions += 1
            if r.get("Commands"):
                attacks[r["Commands"]] += 1
            for field in ("Username(s)", "Password(s)"):
                if r.get(field):
                    controls[r[field]] += 1
        notes.update(sessions=sessions, command_events=sum(attacks.values()),
                     credential_events=sum(controls.values()))
    else:
        total = with_params = 0
        for fname, col in (("tanner_malicious_anonymized.zip", "path"),
                           ("h0neytr4p_malicious_anonymized.csv", "request_uri")):
            for r in _zip_or_csv(root / fname):
                total += 1
                query = (r.get(col) or "").partition("?")[2]
                if query.strip():
                    with_params += 1
                    attacks[query] += 1
        notes.update(requests=total, requests_with_parameters=with_params)
    rows = [{"text": t, "atype": "shell" if part == "cowrie" else "attack", "weight": n}
            for t, n in attacks.items()]
    if entry.get("credentials_as_control", True):
        rows += [{"text": t, "atype": "benign", "weight": n} for t, n in controls.items()]
    return rows, notes


def load_vps(entry: dict, base: Path):
    """vps-attack-dataset (2026): scanning and attack requests received by a
    small production VPS, and failed SSH logins.  Attack class: the query
    string of each web request (requests without parameters are counted, not
    used).  Control: the usernames tried over SSH, which are hostile input but
    not injection payloads.  Placeholders written by the dataset's own
    sanitizer (``<email>``, ``<token>``, ``<digits>`` ...) are left as they are."""
    import gzip
    root = base / entry["path"] / "data"
    attacks, controls = Counter(), Counter()
    total = with_params = logins = 0
    for path in sorted(root.glob("web_attacks_*.csv.gz")):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                total += 1
                query = (r.get("path") or "").partition("?")[2]
                if query.strip():
                    with_params += 1
                    attacks[query] += 1
    if entry.get("usernames_as_control", True):
        for path in sorted(root.glob("ssh_failed_logins_*.csv.gz")):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
                for r in csv.DictReader(fh):
                    if r.get("event") == "invalid_user" and r.get("username"):
                        logins += 1
                        controls[r["username"]] += 1
    rows = [{"text": t, "atype": "attack", "weight": n} for t, n in attacks.items()]
    rows += [{"text": t, "atype": "benign", "weight": n} for t, n in controls.items()]
    return rows, {"requests": total, "requests_with_parameters": with_params,
                  "invalid_user_events": logins}


def load_finch(entry: dict, base: Path):
    """Finch reverse-proxy honeypot (0x4D31/honeypot-data): unsolicited HTTP
    requests to an Internet-facing listener.  Text: the query string of each
    request and, separately, its body when there is one.  These are requests
    from the wild, not requests confirmed to be injections."""
    import io
    try:
        import zstandard
    except ImportError:
        raise SystemExit("The finch loader needs the `zstandard` package: pip install zstandard") from None
    path = base / entry["path"]
    max_body = int(entry.get("max_body_chars", 8192))
    attacks, stamps = Counter(), []
    total = with_query = with_body = long_body = 0
    with open(path, "rb") as fh:
        reader = io.TextIOWrapper(zstandard.ZstdDecompressor().stream_reader(fh),
                                  encoding="utf-8", errors="replace")
        for line in reader:
            if not line.strip():
                continue
            r = json.loads(line)
            total += 1
            if r.get("eventTime"):
                stamps.append(str(r["eventTime"]))
            query = str(r.get("request") or "").partition("?")[2]
            if query.strip():
                with_query += 1
                attacks[query] += 1
            body = r.get("body")
            if isinstance(body, str) and body.strip():
                if len(body) > max_body:
                    long_body += 1
                else:
                    with_body += 1
                    attacks[body] += 1
    rows = [{"text": t, "atype": "attack", "weight": n} for t, n in attacks.items()]
    return rows, {"requests": total, "requests_with_query": with_query,
                  "requests_with_body": with_body, "bodies_over_limit_skipped": long_body,
                  "first_timestamp": min(stamps) if stamps else None,
                  "last_timestamp": max(stamps) if stamps else None}


def load_tpot_csv(entry: dict, base: Path):
    """T-Pot/Cowrie CSV export (samdavi/SSH-Honeypot-Dataset): typed shell
    commands as the attack class and attempted usernames as the non-injection
    control."""
    root = base / entry["path"]
    attacks, controls = Counter(), Counter()
    sessions = set()
    with open(root / "List of Commands.csv", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            if r.get("eventid") == "cowrie.command.input" and (r.get("input") or "").strip():
                attacks[r["input"]] += 1
                sessions.add(r.get("session"))
    if entry.get("usernames_as_control", True):
        with open(root / "List of Attempted Usernames.csv", encoding="utf-8-sig",
                  errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                if (r.get("username") or "").strip():
                    controls[r["username"]] += 1
    rows = [{"text": t, "atype": "shell", "weight": n} for t, n in attacks.items()]
    rows += [{"text": t, "atype": "benign", "weight": n} for t, n in controls.items()]
    return rows, {"command_events": sum(attacks.values()), "sessions_with_commands": len(sessions),
                  "username_events": sum(controls.values())}


def load_csv(entry: dict, base: Path):
    """Generic CSV with a text column and a label column, for adding your own
    source.  ``label_map`` maps the file's labels onto the atype vocabulary."""
    text_col = entry.get("text_column", "payload")
    label_col = entry.get("label_column", "label")
    label_map = entry.get("label_map", {})
    rows = []
    with open(base / entry["path"], encoding="utf-8", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            atype = label_map.get(r[label_col], r[label_col])
            if atype in ATYPES:
                rows.append({"text": r[text_col], "atype": atype})
    return rows, {}


LOADERS = {"paper1": load_paper1, "hpd": load_hpd, "csic": load_csic,
           "ecml": load_ecml, "gran": load_gran, "fwaf": load_fwaf, "modsec": load_modsec,
           "crs": load_crs, "patt": load_patt, "shellevo": load_shellevo, "copot": load_copot,
           "vps": load_vps, "finch": load_finch, "tpot_csv": load_tpot_csv,
           "cowrie": load_cowrie, "csv": load_csv}


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------

def _cap(rows: list[dict], cap: int | None, seed: int) -> list[dict]:
    if not cap:
        return list(rows)
    rng = random.Random(seed)
    grouped = defaultdict(list)
    for r in rows:
        grouped[r["atype"]].append(r)
    out = []
    for atype in sorted(grouped):
        items = grouped[atype]
        out.extend(rng.sample(items, cap) if len(items) > cap else items)
    return out


def prepare(rows: list[dict], seed: int, max_per_class: int | None,
            audit_max_per_class: int | None = 100000):
    """Drop empties, de-duplicate, resolve label conflicts, cap each class and
    attach the derived columns.  Also returns a larger sample for the
    integrity audit, which should see as much of each source as possible."""
    info = {"raw": len(rows)}
    rows = [r for r in rows if r["text"] and r["text"].strip()]
    info["empty_dropped"] = info["raw"] - len(rows)

    by_text: dict[str, dict] = {}
    conflicts = set()
    for r in rows:
        prev = by_text.get(r["text"])
        if prev is None:
            by_text[r["text"]] = r
        elif (prev["atype"] == "benign") != (r["atype"] == "benign"):
            conflicts.add(r["text"])
    info["duplicates_dropped"] = len(rows) - len(by_text)
    info["label_conflicts_dropped"] = len(conflicts)
    rows = [r for t, r in by_text.items() if t not in conflicts]

    info["unique"] = len(rows)
    info["unique_by_atype"] = dict(Counter(r["atype"] for r in rows))

    audit_rows = _cap(rows, audit_max_per_class, seed + 1)
    for r in audit_rows:
        r["y"] = "benign" if r["atype"] == "benign" else "attack"
        r["key"] = norm_key(r["text"])
    rows = _cap(rows, max_per_class, seed)
    for r in rows:
        r["y"] = "benign" if r["atype"] == "benign" else "attack"
        r["family"] = family_key(r["text"])
        r["shape"] = detect_shape(r["text"])
        r["key"] = r.get("key") or norm_key(r["text"])
    info["kept"] = len(rows)
    info["audit_rows"] = len(audit_rows)
    info["by_atype"] = dict(Counter(r["atype"] for r in rows))
    info["families"] = len({r["family"] for r in rows})
    return rows, audit_rows, info


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------

def split_rows(rows: list[dict], seed: int, test_size: float):
    """Stratified, group-aware split: whole payload families go to one side,
    stratified by the family's class.  Rows carrying a predefined ``split``
    keep it."""
    fixed = [r for r in rows if r.get("split")]
    free = [r for r in rows if not r.get("split")]
    train = [r for r in fixed if r["split"] == "train"]
    test = [r for r in fixed if r["split"] == "test"]

    fam_class: dict[str, str] = {}
    for r in free:
        fam_class.setdefault(r["family"], r["atype"])
    by_class = defaultdict(list)
    for fam, atype in fam_class.items():
        by_class[atype].append(fam)

    rng = random.Random(seed)
    test_fams = set()
    for atype in sorted(by_class):
        fams = sorted(by_class[atype])
        rng.shuffle(fams)
        n_test = max(1, round(len(fams) * test_size)) if len(fams) > 1 else 0
        test_fams.update(fams[:n_test])
    for r in free:
        (test if r["family"] in test_fams else train).append(r)

    if not fixed:
        assert not ({r["family"] for r in train} & {r["family"] for r in test}), \
            "family leakage between train and test"
    return train, test


def held_out_sources(cfg: dict) -> set[str]:
    """Sources that are evaluated on but never trained on."""
    return {n for n, e in cfg["datasets"].items() if e.get("role", "both") == "test"}


def split_all(cfg: dict, corpus: dict[str, list[dict]], seed: int) -> dict:
    """Train/test split of every source; a test-only source is all test."""
    held = held_out_sources(cfg)
    return {n: (([], rows) if n in held else split_rows(rows, seed, cfg["test_size"]))
            for n, rows in corpus.items()}


# --------------------------------------------------------------------------
# Corpus I/O
# --------------------------------------------------------------------------

def build_corpus(cfg: dict, base: Path, out_dir: Path) -> dict:
    corpus_dir = out_dir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for name, entry in cfg["datasets"].items():
        loader = LOADERS[entry["loader"]]
        try:
            rows, notes = loader(entry, base)
        except FileNotFoundError as exc:
            raise SystemExit(f"[{name}] {exc.filename} not found. Run `shapetrap fetch` first, or "
                             f"fix `path` for [datasets.{name}] in the config.") from None
        cap = entry.get("max_per_class", cfg.get("max_per_class"))
        rows, audit_rows, info = prepare(rows, cfg["seed"], cap, cfg.get("audit_max_per_class", 100000))
        info["notes"] = notes
        info["role"] = entry.get("role", "both")
        with open(corpus_dir / f"{name}.audit.jsonl", "w", encoding="utf-8") as fh:
            for r in audit_rows:
                fh.write(json.dumps({"text": r["text"], "y": r["y"], "key": r["key"]},
                                    ensure_ascii=False) + "\n")
        info["shape_by_class"] = {
            y: dict(Counter(r["shape"] for r in rows if r["y"] == y))
            for y in ("benign", "attack")
        }
        with open(corpus_dir / f"{name}.jsonl", "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        summary[name] = info
    (corpus_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load_corpus(cfg: dict, out_dir: Path, audit: bool = False) -> dict[str, list[dict]]:
    corpus = {}
    for name in cfg["datasets"]:
        path = out_dir / "corpus" / (f"{name}.audit.jsonl" if audit else f"{name}.jsonl")
        if not path.exists():
            raise SystemExit(f"{path} not found. Run `shapetrap build` first.")
        with open(path, encoding="utf-8") as fh:
            corpus[name] = [json.loads(ln) for ln in fh]
    return corpus
