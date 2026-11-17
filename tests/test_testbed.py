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
