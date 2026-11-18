"""A small reference application for checking container rewrites.

The `run` step counts decisions that change when an attack is moved into
another container.  A changed decision is only an evasion if the rewritten
request still attacks the application.  This module checks that, without any
server or network traffic:

1. ``receive`` turns a request body into the parameter values a typical web
   framework hands to the application: ``key=value`` bodies through
   ``urllib.parse.parse_qsl`` (so percent-escapes are decoded), JSON bodies
   through ``json.loads`` (no decoding), anything else as one raw value.
2. Every value goes into deliberately vulnerable sinks, and an oracle decides
   whether the value changed what the sink does:

   ``sqli``       SQLite queries built by string concatenation, in a string and
                  a numeric context.  Effective when the result differs from
                  the same query with a bound parameter, or the query fails.
   ``xss``        an HTML template without escaping, in element and attribute
                  position.  Effective when the parsed page gains a tag, an
                  ``on*`` attribute or a ``javascript:`` URL that the escaped
                  page does not have.
   ``traversal``  a file path under a fixed root.  Effective when the
                  normalized path leaves the root or names a system file.
   ``cmdi``       a shell command line, parsed but never run.  Effective when
                  the value adds a shell operator or command substitution.

These oracles are simple and generous (a failing SQL query counts), and they
are the same for the original and the rewritten request, so what they measure
is whether a rewrite keeps an attack working, not whether it works on any
particular production system.
"""

from __future__ import annotations

import json
import posixpath
import shlex
import sqlite3
from html import escape
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote

from .shapes import detect_shape, split_multipart, split_xml

ATTACK_TYPES = ("sqli", "xss", "traversal", "cmdi")


# --- receiving a request -----------------------------------------------------


def _json_leaves(obj, out: list[str]) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _json_leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _json_leaves(v, out)
    elif obj is not None and not isinstance(obj, bool):
        out.append(str(obj))


def receive(text: str) -> list[str]:
    """The parameter values an application receives for this request body."""
    shape = detect_shape(text)
    if shape == "json":
        try:
            obj = json.loads(text)
        except ValueError:
            return []  # the framework rejects the request
        out: list[str] = []
        _json_leaves(obj, out)
        return out
    if shape == "kv":
        return [v for _, v in parse_qsl(text.strip(), keep_blank_values=True)]
    if shape == "multipart":
        return [v for _, v in split_multipart(text) or []]
    if shape == "xml":
        return [v for _, v in split_xml(text) or []]
    if shape == "path":
        path, _, query = text.partition("?")
        vals = [unquote(p) for p in path.split("/") if p]
        return vals + [v for _, v in parse_qsl(query, keep_blank_values=True)]
    return [text]


# --- sinks and oracles -------------------------------------------------------


class _DB:
    def __init__(self):
        self.con = sqlite3.connect(":memory:")
        self.con.execute("CREATE TABLE items (id INTEGER, name TEXT, secret TEXT)")
        self.con.executemany(
            "INSERT INTO items VALUES (?, ?, ?)",
            [(1, "laptop", "s1"), (2, "shoes", "s2"), (3, "basket", "s3")],
        )

    def _rows(self, sql, params=()):
        try:
            rows = self.con.execute(sql, params).fetchall()
            return sorted((tuple(r) for r in rows), key=repr), None
        except (sqlite3.Error, OverflowError, ValueError) as exc:
            return None, type(exc).__name__

    def effective(self, v: str) -> bool:
        """Structural test: does the value leave the literal it was meant to be?

        String context: an unescaped single quote ends the literal early, so
        whatever follows is SQL (doubled quotes are the SQL escape and stay
        inside).  Numeric context: the query must still run, and either its
        result differs from the bound-parameter query or the value is more
        than one number.  A query that only fails on junk is not an attack.
        """
        v = v.replace("\x00", "")
        if "'" in v.replace("''", ""):
            return True
        safe, _ = self._rows("SELECT id, name FROM items WHERE id = ?", (v,))
        bad, err = self._rows(f"SELECT id, name FROM items WHERE id = {v}")
        if err:
            # Stacked queries: the driver runs one statement only, so accept
            # a valid first statement followed by more SQL.
            head, sep, rest = v.partition(";")
            if sep and rest.strip():
                return self._rows(f"SELECT id, name FROM items WHERE id = {head}")[1] is None
            return False
        try:
            float(v.strip())
            plain_number = True
        except ValueError:
            plain_number = False
        return bad != safe or not plain_number


class _Elements(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found: list[tuple] = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            name = (name or "").lower()
            value = (value or "").strip().lower()
            if name.startswith("on") or value.startswith(("javascript:", "data:text/html")):
                self.found.append(("attr", tag, name))
        self.found.append(("tag", tag, tuple(sorted(a for a, _ in attrs))))


def _page(v: str) -> str:
    return f'<div class="q">{v}</div><input name="q" value="{v}">'


def _structure(html: str) -> list[tuple]:
    p = _Elements()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001
        # Python's HTML parser gives up on some malformed markup, such as the
        # declaration "<![<CDATA[" (an AssertionError in recent 3.12 and 3.13
        # releases).  Only unescaped input can trigger this, since the escaped
        # page has no "<", so the value did put markup into the page.
        return [("unparsable",)]
    return p.found


def xss_effective(v: str) -> bool:
    return _structure(_page(v)) != _structure(_page(escape(v, quote=True)))


ROOT = "/srv/app/static"


def traversal_effective(v: str) -> bool:
    low = v.replace("\\", "/").lower()
    if low.startswith("file:"):
        return True
    path = posixpath.normpath(
        posixpath.join(ROOT, low.lstrip("/") if not low.startswith("/") else low)
    )
    if not path.startswith(ROOT + "/") and path != ROOT:
        return True
    return any(s in low for s in ("/etc/passwd", "/etc/shadow", "boot.ini", "win.ini"))


def cmdi_effective(v: str) -> bool:
    if "`" in v or "$(" in v or "${" in v:
        return True
    try:
        lex = shlex.shlex(f"ping -c 1 {v}", posix=True, punctuation_chars=True)
        tokens = list(lex)
    except ValueError:
        return any(c in v for c in ";|&\n")
    return any(t and set(t) <= set(";|&\n<>") for t in tokens)


class Testbed:
    def __init__(self):
        self.db = _DB()

    def effective(self, text: str, atype: str) -> bool:
        """Does any value of this request attack the sink for ``atype``?  For
        an attack without a type (``attack``), any sink counts."""
        values = receive(text)
        if atype == "sqli":
            return any(self.db.effective(v) for v in values)
        if atype == "xss":
            return any(xss_effective(v) for v in values)
        if atype == "traversal":
            return any(traversal_effective(v) for v in values)
        if atype == "cmdi":
            return any(cmdi_effective(v) for v in values)
        # Untyped attacks: effective when any sink is attacked.
        return any(self.effective(text, t) for t in ATTACK_TYPES)
