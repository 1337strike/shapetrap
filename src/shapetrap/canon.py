"""Input canonicalization and comparison keys.

``canonicalize`` follows the five steps of the earlier paper (percent-decoding
to a fixed point bounded at three rounds, HTML-entity and \\uXXXX decoding, SQL
comment removal, whitespace compression, lowercasing).  One deliberate change:
percent-decoded bytes that are not valid UTF-8 fall back to Latin-1 instead of
becoming U+FFFD, because CSIC 2010 sends Latin-1 form values (``Jam%F3n``).
"""

from __future__ import annotations

import functools
import html
import re
import urllib.parse

_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_UNICODE_ESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_WS_RE = re.compile(r"\s+")


def pct_decode(text: str) -> str:
    """One round of form decoding (``+`` -> space, ``%XX`` -> byte)."""
    raw = urllib.parse.unquote_to_bytes(text.replace("+", " "))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


@functools.lru_cache(maxsize=1_000_000)
def canonicalize(payload: str, max_decode_rounds: int = 3) -> str:
    text = payload
    for _ in range(max_decode_rounds):
        decoded = pct_decode(text)
        if decoded == text:
            break
        text = decoded
    text = html.unescape(text)
    text = _UNICODE_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    # 😀-style escapes arrive as two surrogates: join pairs, and
    # replace a lone one so the result is always valid Unicode.
    text = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    text = _COMMENT_RE.sub("", text)
    text = _WS_RE.sub(" ", text)
    return text.strip().lower()


def norm_key(payload: str) -> str:
    """Key for overlap and leakage checks: canonical form with all whitespace
    removed, so trivial surface variants collapse to one key."""
    return _WS_RE.sub("", canonicalize(payload))


_DIGITS_RE = re.compile(r"\d+")
_SQ_RE = re.compile(r"'[^']*'")
_DQ_RE = re.compile(r'"[^"]*"')


def family_key(payload: str) -> str:
    """Heuristic payload family (same rule as the earlier paper): digit runs
    and quoted literals become placeholders, whitespace is compressed, text is
    lowercased.  Not a semantic-equivalence test."""
    f = _DIGITS_RE.sub("N", payload)
    f = _SQ_RE.sub("'S'", f)
    f = _DQ_RE.sub('"S"', f)
    return _WS_RE.sub(" ", f).strip().lower()
