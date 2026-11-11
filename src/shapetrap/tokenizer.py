"""Tokenizers that keep security-relevant punctuation.

Two profiles:

* ``paper1`` reproduces the token pattern of the earlier SQLi/XSS paper, so
  its numbers can be re-derived as an anchor.
* ``web`` (default) extends it with the characters that command injection and
  path traversal depend on (``../``, ``|``, ``&&``, backtick, ``$(`` ...).

Note that ``=`` (both profiles) and ``&`` (web profile) are tokens.  They are
also what a key=value *shape* looks like, which is the channel this tool
audits.
"""

from __future__ import annotations

import re

_PAPER1 = re.compile(
    r"""
    %[0-9A-Fa-f]{2}
    | </?[a-zA-Z][\w-]*
    | -{2,}
    | /\*!?\d*
    | \*/
    | \b[a-zA-Z_][a-zA-Z0-9_]*\b
    | \d+
    | [='"<>();]
    """,
    re.VERBOSE,
)

_WEB = re.compile(
    r"""
    %[0-9A-Fa-f]{2}
    | </?[a-zA-Z][\w-]*
    | -{2,}
    | /\*!?\d*
    | \*/
    | \.\.[/\\]
    | && | \|\| | \$\( | \$\{
    | \b[a-zA-Z_][a-zA-Z0-9_]*\b
    | \d+
    | [='"<>();|&`$/\\{}.:]
    """,
    re.VERBOSE,
)

_WORD = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _tokenize(pattern: re.Pattern, payload: str) -> list[str]:
    if not isinstance(payload, str):
        payload = str(payload)
    return [t.lower() if _WORD.match(t) else t for t in pattern.findall(payload)]


def tokenize_paper1(payload: str) -> list[str]:
    return _tokenize(_PAPER1, payload)


def tokenize_web(payload: str) -> list[str]:
    return _tokenize(_WEB, payload)


TOKENIZERS = {"paper1": tokenize_paper1, "web": tokenize_web}
