"""Tests for the reference application and the faithful rewrites."""

import pytest


@pytest.fixture(scope="module")
def tb():
    from shapetrap.testbed import Testbed

    return Testbed()


@pytest.mark.parametrize(
    "text,atype,expected",
    [
        ("' or 1=1--", "sqli", True),
        ("q=%27%20or%201%3D1--", "sqli", True),  # decoded by the form parser
        ('{"q":"%27%20or%201%3D1--"}', "sqli", False),  # JSON is not decoded
        ("1 union select 1,2", "sqli", True),
        ("1; drop table items", "sqli", True),
        ("O''Brien", "sqli", False),
        ("laptop", "sqli", False),
        ("40184", "sqli", False),
        ("<script>alert(1)</script>", "xss", True),
        ('"><img src=x onerror=alert(1)>', "xss", True),
        ("hello world", "xss", False),
        ('<![<CDATA[C%Ada b="c"', "xss", True),  # malformed declaration
        ("../../etc/passwd", "traversal", True),
        ("images/a.png", "traversal", False),
        ("; cat /etc/passwd", "cmdi", True),
        ("a=1&b=$(id)", "cmdi", True),
        ("127.0.0.1", "cmdi", False),
        ("<script>alert(1)</script>", "attack", True),  # untyped: any sink
        ("laptop", "attack", False),
    ],
)
def test_oracles(tb, text, atype, expected):
    assert tb.effective(text, atype) is expected


def test_receive_by_container():
    from shapetrap.testbed import receive

    assert receive("a=1&b=x+y%21") == ["1", "x y!"]
    assert receive('{"a": 1, "b": ["x", {"c": "y"}], "d": null}') == ["1", "x", "y"]
    assert receive("{not json") == ["{not json"]
    assert receive("/item/la%20ptop?x=1") == ["item", "la ptop", "1"]
    assert receive("plain value") == ["plain value"]


def test_faithful_rewrites_keep_the_values(tb):
    from shapetrap.shapes import FAITHFUL_INTERVENTIONS, interventions
    from shapetrap.testbed import receive

    cases = ["q=%27%20or%201%3D1--&page=2", "' or 1=1--", "a+b&c=%", "<svg onload=alert(1)>"]
    for text in cases:
        want = sorted(receive(text)) if "=" in text and "&" in text else None
        for name, fn in FAITHFUL_INTERVENTIONS.items():
            v = fn(text, 1)
            if name != "bare" and want is not None:
                assert sorted(receive(v)) == want, (text, name, v)
    # A bare value put behind a key survives form parsing unchanged.
    assert receive(FAITHFUL_INTERVENTIONS["kv"]("a+b&c=%", 1)) == ["a+b&c=%"]
    assert receive(FAITHFUL_INTERVENTIONS["json"]("q=%3Cscript%3E", 1)) == ["<script>"]
    assert interventions({})["kv"].__name__ == "as_kv"
    assert interventions({"rewrite": "faithful"})["kv"].__name__ == "as_kv_faithful"
    with pytest.raises(SystemExit):
        interventions({"rewrite": "other"})
    # Faithful rewrites keep an attack working where the literal ones do not.
    assert tb.effective(FAITHFUL_INTERVENTIONS["json"]("q=%27%20or%201%3D1--", 1), "sqli")


@pytest.mark.parametrize(
    "text",
    [
        "q=%27%20or%201%3D1--&page=2",
        "' or 1=1--",
        '{"user": "<script>alert(1)</script>", "n": 3}',
        "a & b <c> \"d\" 'e'",
        "line1\r\n--not-a-boundary\r\nline2",
    ],
)
def test_multipart_and_xml_rewrites_keep_the_values(text):
    from shapetrap.shapes import (
        EXTRA_INTERVENTIONS,
        FAITHFUL_INTERVENTIONS,
        decontain,
        detect_shape,
        values_of,
    )
    from shapetrap.testbed import receive

    want = sorted(receive(FAITHFUL_INTERVENTIONS["json"](text, 7)))
    for name, fn in EXTRA_INTERVENTIONS.items():
        v = fn(text, 7)
        assert detect_shape(v) == name, (name, v)
        assert sorted(receive(v)) == want, (name, v)
        assert sorted(values_of(v)) == sorted(x for x in want if x)
        assert sorted(decontain(v)) == sorted(x for x in want if x)
        assert fn(v, 7) == v  # already in that container
        # and back: the decoded values survive a rewrite into JSON or kv
        assert sorted(receive(FAITHFUL_INTERVENTIONS["json"](v, 7))) == want
        assert sorted(receive(FAITHFUL_INTERVENTIONS["kv"](v, 7))) == want


def test_strict_container_recognition():
    from shapetrap.shapes import as_xml_faithful, detect_shape

    xxe = '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>'
    assert detect_shape(xxe) == "bare"
    assert detect_shape('<?xml version="1.0" encoding="UTF-8"?><r><a x="1">v</a></r>') == "bare"
    assert detect_shape('<?xml version="1.0" encoding="UTF-8"?><r><a>&x;</a></r>') == "bare"
    assert detect_shape("--b\r\nnot a part\r\n--b--") == "bare"
    assert detect_shape("-- comment") == "bare"
    # XML 1.0 cannot carry a NUL: no XML form, the input stays as it is.
    assert as_xml_faithful("a\x00b", 1) == "a\x00b"


def test_crs_requests_for_new_containers():
    from shapetrap.crs import build_request
    from shapetrap.shapes import as_multipart_faithful, as_xml_faithful

    mp = as_multipart_faithful("q=1", 1)
    method, target, ctype, body = build_request(mp)
    assert (method, target) == ("POST", "/")
    assert ctype == "multipart/form-data; boundary=" + mp.split("\r\n")[0][2:]
    assert body == mp + "\r\n"
    assert build_request(as_xml_faithful("q=1", 1))[2] == "application/xml"
    # value mode: every string whole, as one parameter
    assert build_request('{"q": "x"}', "value") == (
        "GET",
        "/?q=%7B%22q%22%3A%20%22x%22%7D",
        "-",
        "-",
    )
    assert build_request("id=5", "value") == ("GET", "/?q=id%3D5", "-", "-")
