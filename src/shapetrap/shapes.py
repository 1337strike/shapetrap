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
from urllib.parse import unquote_plus

SHAPES = ("empty", "kv", "json", "path", "bare")
# Two more containers a value can travel in.  They are recognized only in the
# strict form the rewrites below produce, so strings collected in the wild (an
# XXE payload that starts with ``<?xml``, say) stay ``bare``.
EXTRA_SHAPES = ("multipart", "xml")

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


_MP_OPEN = re.compile(r"--([0-9A-Za-z'()+_,\-./:=?]{1,70})\r\n")
_MP_HEAD = re.compile(r'Content-Disposition: form-data; name="([^"\r\n]*)"\r\n\r\n')
_XML_NAME = r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}"
_XML_DOC = re.compile(
    rf'<\?xml version="1\.0" encoding="UTF-8"\?>\n?<({_XML_NAME})>(.*)</\1>', re.DOTALL
)
_XML_CHILD = re.compile(rf"\s*<({_XML_NAME})>([^<]*)</\1>|\s*<({_XML_NAME})/>")
_XML_BAD_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos);)")
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def split_multipart(text: str) -> list[tuple[str, str]] | None:
    """Fields of a multipart/form-data body (text fields only), or None."""
    s = text.strip()
    m = _MP_OPEN.match(s)
    if not m:
        return None
    delim = "--" + m.group(1)
    if not s.endswith(delim + "--"):
        return None
    chunks = s[: -len(delim) - 2].split(delim)
    if chunks[0] != "" or len(chunks) < 2:
        return None
    pairs = []
    for c in chunks[1:]:
        if not c.startswith("\r\n") or not c.endswith("\r\n"):
            return None
        head = _MP_HEAD.match(c, 2)
        if not head:
            return None
        pairs.append((head.group(1), c[head.end() : -2]))
    return pairs


def _xml_unescape(v: str) -> str:
    return (
        v.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&amp;", "&")
    )


def split_xml(text: str) -> list[tuple[str, str]] | None:
    """Children of a flat XML document (one root, simple child elements, no
    attributes, no DOCTYPE), or None.  Parsed with regular expressions, so no
    entity is ever expanded."""
    m = _XML_DOC.fullmatch(text.strip())
    if not m:
        return None
    inner, pos, pairs = m.group(2), 0, []
    while pos < len(inner):
        if not inner[pos:].strip():
            break
        c = _XML_CHILD.match(inner, pos)
        if not c:
            return None
        if c.group(1):
            raw = c.group(2)
            if _XML_BAD_AMP.search(raw) or ">" in raw:
                return None
            pairs.append((c.group(1), _xml_unescape(raw)))
        else:
            pairs.append((c.group(3), ""))
        pos = c.end()
    return pairs if pairs else None


def detect_shape(text: str) -> str:
    s = text.strip()
    if not s:
        return "empty"
    if s.startswith("--") and split_multipart(s) is not None:
        return "multipart"
    if s.startswith("<?xml") and split_xml(s) is not None:
        return "xml"
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
    pairs = _extra_pairs(s)
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


def _extra_pairs(s: str) -> list[tuple[str, str]] | None:
    if s.startswith("--"):
        return split_multipart(s)
    if s.startswith("<?xml"):
        return split_xml(s)
    return None


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
        out: list[str] = []
        for key, value in pairs:
            if not _PLAIN_KEY.match(key):
                out.append(key)
            if value:
                out.append(value)
        return out
    pairs = _extra_pairs(s)
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
        out = []
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


# Faithful rewrites.  The literal rewrites above copy values exactly as they
# were stored, so a percent-encoded query string such as ``q=%27%20or%201=1``
# becomes the JSON string "%27%20or%201=1", which no client would send and no
# server would decode.  The faithful variants produce what a client would
# actually send: values are decoded the way a framework parses a form body
# before they go into JSON or a bare value, and a value put behind a key is
# encoded just enough (``%``, ``&``, ``+``) to survive parsing unchanged.


def _decoded_pairs(text: str, seed: int) -> list[tuple[str, str]]:
    s = text.strip()
    pairs = split_kv(s)
    if pairs is not None:
        return [(unquote_plus(k), unquote_plus(v)) for k, v in pairs]
    pairs = _extra_pairs(s)
    if pairs is not None:
        return pairs
    if detect_shape(s) == "json":
        obj = json.loads(s)
        if isinstance(obj, dict):
            out: list[tuple[str, str]] = []
            for k, v in obj.items():
                items = v if isinstance(v, list) else [v]
                for item in items:
                    if isinstance(item, (dict, list)):
                        out.append((str(k), json.dumps(item, ensure_ascii=False)))
                    elif item is not None:
                        out.append((str(k), item if isinstance(item, str) else json.dumps(item)))
            return out
        return [(_neutral_key(text, seed), v) for v in values_of(s)]
    return [(_neutral_key(text, seed), text)]


def _form_quote(value: str) -> str:
    return value.replace("%", "%25").replace("&", "%26").replace("+", "%2B")


def as_bare_faithful(text: str, seed: int = 0) -> str:
    """The decoded values, without keys or separators."""
    if detect_shape(text) not in ("kv", "json", "multipart", "xml"):
        return text
    return " ".join(v for _, v in _decoded_pairs(text, seed) if v)


def as_kv_faithful(text: str, seed: int = 0) -> str:
    """A non-kv input as one form field, encoded so that parsing returns it."""
    if split_kv(text.strip()) is not None:
        return text
    if detect_shape(text) in ("json", "multipart", "xml"):
        pairs = _decoded_pairs(text, seed)
        return "&".join(f"{_form_quote(k)}={_form_quote(v)}" for k, v in pairs)
    return f"{_neutral_key(text, seed)}={_form_quote(text)}"


def as_json_faithful(text: str, seed: int = 0) -> str:
    """The decoded keys and values as a flat JSON object."""
    if detect_shape(text) == "json":
        return text
    obj: dict = {}
    for key, value in _decoded_pairs(text, seed):
        if key in obj:
            obj[key] = (obj[key] if isinstance(obj[key], list) else [obj[key]]) + [value]
        else:
            obj[key] = value
    return json.dumps(obj, ensure_ascii=False)


def _boundary(pairs: list[tuple[str, str]], seed: int) -> str:
    """A boundary that occurs in no field, as a client library would pick."""
    blob = "\n".join(k + "\x00" + v for k, v in pairs)
    n = 0
    while True:
        h = hashlib.sha256(f"{seed}:{n}:{blob}".encode("utf-8", "replace")).hexdigest()[:16]
        b = "----shapetrap" + h
        if b not in blob:
            return b
        n += 1


def as_multipart_faithful(text: str, seed: int = 0) -> str:
    """The decoded keys and values as a multipart/form-data body (text fields).
    Field names keep only characters that are safe inside the quoted name."""
    if detect_shape(text) == "multipart":
        return text
    pairs = [(re.sub(r'["\r\n\\]', "_", k), v) for k, v in _decoded_pairs(text, seed)] or [
        (_neutral_key(text, seed), "")
    ]
    b = _boundary(pairs, seed)
    parts = "".join(
        f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in pairs
    )
    return parts + f"--{b}--"


def _xml_name(key: str, seed: int, text: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", key)[:64]
    if not name or not re.match(r"[A-Za-z_]", name) or name.lower().startswith("xml"):
        name = ("_" + name)[:64] if name else _neutral_key(text, seed)
    return name


def as_xml_faithful(text: str, seed: int = 0) -> str:
    """The decoded keys and values as a flat XML document.  Values are escaped
    (``&``, ``<``, ``>``) the way an XML library writes them.  A value with a
    character XML 1.0 cannot carry has no XML form; the input is then left as
    it is."""
    if detect_shape(text) == "xml":
        return text
    pairs = _decoded_pairs(text, seed) or [(_neutral_key(text, seed), "")]
    if any(_XML_ILLEGAL.search(v) for _, v in pairs):
        return text
    body = "".join(
        "<{0}>{1}</{0}>".format(
            _xml_name(k, seed, text),
            v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
        )
        for k, v in pairs
    )
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<request>{body}</request>'


FAITHFUL_INTERVENTIONS = {"bare": as_bare_faithful, "kv": as_kv_faithful, "json": as_json_faithful}
# Used by `shapetrap validate` only.
EXTRA_INTERVENTIONS = {"multipart": as_multipart_faithful, "xml": as_xml_faithful}


def interventions(cfg: dict) -> dict:
    """The rewrites a run uses: ``rewrite = "literal"`` (default, the
    published results) or ``"faithful"``."""
    mode = cfg.get("rewrite", "literal")
    if mode == "literal":
        return INTERVENTIONS
    if mode == "faithful":
        return FAITHFUL_INTERVENTIONS
    raise SystemExit(f"rewrite must be 'literal' or 'faithful', not {mode!r}")


def shape_features(text: str) -> list[float]:
    """Content-free description of an input, for the shape-only probe."""
    shape = detect_shape(text)
    pairs = split_kv(text.strip()) or []
    return [float(shape == s) for s in SHAPES + EXTRA_SHAPES] + [float(min(len(pairs), 8))]
