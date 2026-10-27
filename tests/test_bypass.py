"""Regression tests for bypasses found in the threat-model review."""

import pytest

from cheoyong import Cheoyong, Effect
from cheoyong.policies import arg_rules

CANARY = {"*": {"*": {"denies": "CANARY-[0-9A-F]{4}"}}}


def check(rules, tool, args):
    return Cheoyong([arg_rules(rules)], default=Effect.ALLOW).check(tool, args)


def test_canary_in_nested_dict_key_denies() -> None:
    assert check(CANARY, "t", {"d": {"CANARY-7F3A": 1}}).effect is Effect.DENY


def test_canary_in_top_level_key_denies() -> None:
    assert check(CANARY, "t", {"CANARY-7F3A": 1}).effect is Effect.DENY


def test_fullwidth_canary_in_nested_key_denies() -> None:
    assert check(CANARY, "t", {"d": {"ＣＡＮＡＲＹ-7F3A": 1}}).effect is Effect.DENY


def test_nfkc_colliding_nested_keys_cannot_hide_a_value() -> None:
    args = {"d": {"ａ": "CANARY-7F3A", "a": "safe"}}
    assert check(CANARY, "t", args).effect is Effect.DENY


def test_redaction_also_covers_nested_keys() -> None:
    rules = {"*": {"*": {"denies": "CANARY-[0-9A-F]{4}", "on_violation": "redact"}}}
    decision = check(rules, "t", {"d": {"CANARY-7F3A": "x"}})
    assert decision.effect is Effect.ALLOW
    assert "CANARY-7F3A" not in repr(decision.args)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(("CANARY-7F3A",), id="tuple"),
        pytest.param({"CANARY-7F3A"}, id="set"),
        pytest.param(b"CANARY-7F3A", id="bytes"),
        pytest.param(object(), id="object"),
        pytest.param({1: "CANARY-7F3A"}, id="non-str-nested-key"),
    ],
)
def test_non_json_argument_values_deny(value) -> None:
    decision = check(CANARY, "t", {"d": value})
    assert decision.effect is Effect.DENY
    assert decision.policy == "normalization"


@pytest.mark.parametrize(
    ("rule", "value"),
    [
        pytest.param({"allow_hosts": [".example.com"]}, "http://evil.com\\.example.com/", id="backslash-url"),
        pytest.param({"allow_hosts": [".example.com"]}, "a@evil.com;x.example.com", id="semicolon-email"),
        pytest.param({"allow_hosts": ["example.com"]}, "a@example.com>", id="angle-bracket"),
        pytest.param({"type": "list", "allow_hosts": [".example.com"]}, ["a@evil.com,b@x.example.com"], id="comma-in-list-item"),
    ],
)
def test_allow_hosts_rejects_non_hostname_characters(rule, value) -> None:
    assert check({"t": {"to": rule}}, "t", {"to": value}).effect is Effect.DENY


def test_allow_hosts_still_accepts_plain_and_idn_hosts() -> None:
    rule = {"t": {"to": {"allow_hosts": [".example.com", "bücher.de"]}}}
    assert check(rule, "t", {"to": "https://api.example.com:443/x?y=1"}).effect is Effect.ALLOW
    assert check(rule, "t", {"to": "a@bücher.de"}).effect is Effect.ALLOW


@pytest.mark.parametrize(
    ("rule", "value"),
    [
        pytest.param({"matches": "^/workspace/"}, "／workspace/x", id="fullwidth-solidus-path"),
        pytest.param({"enum": ["r"]}, "ｒ", id="fullwidth-enum"),
        pytest.param({"allow_hosts": ["example.com"]}, "a@ｅxample.com", id="fullwidth-host"),
    ],
)
def test_value_that_changes_under_nfkc_denies_allowlist_rules(rule, value) -> None:
    decision = check({"t": {"a": rule}}, "t", {"a": value})
    assert decision.effect is Effect.DENY
    assert "normalization" in decision.reason


def test_max_len_counts_raw_code_points() -> None:
    decision = check({"t": {"s": {"max_len": 3}}}, "t", {"s": "é" * 3})
    assert decision.effect is Effect.DENY


def test_unlisted_argument_on_constrained_tool_denies() -> None:
    rules = {"send_email": {"to": {"allow_hosts": ["example.com"]}}}
    decision = check(rules, "send_email", {"to": "a@example.com", "bcc": "x@evil.com"})
    assert decision.effect is Effect.DENY
    assert decision.policy == "arg_rules:send_email.bcc"
    assert "unexpected argument" in decision.reason


def test_argument_wildcard_opts_out_of_strict_arguments() -> None:
    rules = {"send_email": {"to": {"allow_hosts": ["example.com"]}, "*": {}}}
    args = {"to": "a@example.com", "bcc": "x@example.com"}
    assert check(rules, "send_email", args).effect is Effect.ALLOW


def test_global_rules_alone_do_not_make_tools_strict() -> None:
    assert check(CANARY, "anything", {"x": 1, "y": "z"}).effect is Effect.ALLOW
