"""Input shape: detection, decomposition and shape-only interventions.

"Shape" is the container an input arrives in, independent of what it says:
``q=laptop`` (kv), ``laptop`` (bare), ``{"q": "laptop"}`` (json), ``/a/b``
(path) or nothing at all (empty).  The interventions below change only that
container, so a prediction that flips under them cannot be explained by the
content.
"""

from __future__ import annotations

import hashlib
import json
import re

SHAPES = ("empty", "kv", "json", "path", "bare")

_KEY = r"[A-Za-z0-9_.\-\[\]%]{1,64}"
_KV_SEG = re.compile(rf"^{_KEY}=")
_PATH = re.compile(r"^(?:https?://|/)[^\s]*$", re.IGNORECASE)

NEUTRAL_KEYS = ("q", "id", "name", "value", "data", "input", "text", "param")


def split_kv(text: str) -> list[tuple[str, str]] | None:
    """Split ``a=1&b=2`` into pairs.  Returns None if the string is not a
    key=value list.  Values are left exactly as sent (not decoded)."""
    if "=" not in text:
        return None
    pairs = []
    for seg in text.split("&"):
        if not _KV_SEG.match(seg):
            return None
        key, _, value = seg.partition("=")
        pairs.append((key, value))
    return pairs


def detect_shape(text: str) -> str:
    s = text.strip()
    if not s:
        return "empty"
    if s[0] in "{[":
        try:
            json.loads(s)
            return "json"
        except ValueError:
            pass
    if split_kv(s) is not None:
        return "kv"
    if _PATH.match(s):
        return "path"
    return "bare"


def values_of(text: str) -> list[str]:
    """The values an input carries: kv values, JSON leaf strings, or the
    string itself."""
    s = text.strip()
    pairs = split_kv(s)
    if pairs is not None:
        return [v for _, v in pairs if v]
    if s[:1] in "{[":
        try:
            obj = json.loads(s)
        except ValueError:
            return [s] if s else []
        out: list[str] = []

        def walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
            elif o is not None:
                out.append(str(o))

        walk(obj)
        return out
    return [s] if s else []


_PLAIN_KEY = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")


def _json_items(obj, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not _PLAIN_KEY.match(str(k)):
                out.append(str(k))
            _json_items(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _json_items(v, out)
    elif obj is not None:
        out.append(str(obj))


def decontain(text: str) -> list[str]:
    """Container canonicalization: the values an input carries, with keys,
    separators and JSON structure removed.  ``a=1&b=x``, ``{"a": "1", "b":
    "x"}`` and a request for ``/p?a=1&b=x`` all yield the same values (the
    last one also yields the path).  A bare string is its own single value.

    A key is dropped only when it is a plain identifier.  Anything else in a
    key position (percent-encoding, punctuation) is kept as a value, so a
    payload cannot hide in a parameter name.
    """
    s = text.strip()
    if not s:
        return []
    pairs = split_kv(s)
    if pairs is not None:
        out = []
        for key, value in pairs:
            if not _PLAIN_KEY.match(key):
                out.append(key)
            if value:
                out.append(value)
        return out
    if s[0] in "{[":
        try:
            obj = json.loads(s)
        except ValueError:
            return [s]
        out: list[str] = []
        _json_items(obj, out)
        return out
    if _PATH.match(s) and "?" in s:
        head, _, query = s.partition("?")
        return [head] + (decontain(query) if query else [])
    return [s]


def _neutral_key(text: str, seed: int) -> str:
    h = hashlib.sha256(f"{seed}:{text}".encode("utf-8", "replace")).digest()
    return NEUTRAL_KEYS[h[0] % len(NEUTRAL_KEYS)]


def as_bare(text: str, seed: int = 0) -> str:
    """Drop the container: keys and separators go, values stay."""
    pairs = split_kv(text.strip())
    if pairs is not None:
        return " ".join(v for _, v in pairs if v)
    if detect_shape(text) == "json":
        return " ".join(values_of(text))
    return text


def as_kv(text: str, seed: int = 0) -> str:
    """Put a non-kv input behind one neutral parameter name."""
    if split_kv(text.strip()) is not None:
        return text
    return f"{_neutral_key(text, seed)}={text}"


def as_json(text: str, seed: int = 0) -> str:
    """Re-express the same keys and values as a flat JSON object."""
    if detect_shape(text) == "json":
        return text
    pairs = split_kv(text.strip())
    if pairs is None:
        pairs = [(_neutral_key(text, seed), text)]
    obj: dict = {}
    for key, value in pairs:  # a repeated key keeps every value, as a list
        if key in obj:
            obj[key] = (obj[key] if isinstance(obj[key], list) else [obj[key]]) + [value]
        else:
            obj[key] = value
    return json.dumps(obj, ensure_ascii=False)


INTERVENTIONS = {"bare": as_bare, "kv": as_kv, "json": as_json}


def shape_features(text: str) -> list[float]:
    """Content-free description of an input, for the shape-only probe."""
    shape = detect_shape(text)
    pairs = split_kv(text.strip()) or []
    return [float(shape == s) for s in SHAPES] + [float(min(len(pairs), 8))]
