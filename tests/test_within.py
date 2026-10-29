"""`within` resolves symlinks before checking path containment (#17)."""

import json
import os

import pytest

from cheoyong import Cheoyong, Effect
from cheoyong.loader import load_policy_file
from cheoyong.policies import arg_rules
from cheoyong.types import PolicyError


@pytest.fixture
def root(tmp_path):
    root = tmp_path / "workspace"
    (root / "sub").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "passwd").write_text("x")
    (root / "link-out").symlink_to(tmp_path / "outside")
    (root / "file-link").symlink_to(tmp_path / "outside" / "passwd")
    return root


def check(root, path):
    rules = {"write": {"path": {"type": "str", "within": [str(root)]}}}
    return Cheoyong([arg_rules(rules)], default=Effect.ALLOW).check("write", {"path": path})


@pytest.mark.parametrize("rel", ["sub/new.txt", "new.txt", ""])
def test_paths_under_root_allow(root, rel) -> None:
    assert check(root, os.path.join(root, rel)).effect is Effect.ALLOW


@pytest.mark.parametrize("rel", ["link-out/passwd", "file-link", "sub/../../outside/passwd"])
def test_symlink_or_dotdot_escape_denies(root, rel) -> None:
    decision = check(root, os.path.join(root, rel))
    assert decision.effect is Effect.DENY
    assert "within violation" in decision.reason


@pytest.mark.parametrize(
    "value", ["relative/path", "~/x", "/workspace\0/x", 7, None], ids=str
)
def test_relative_unresolvable_non_string_or_null_denies(root, value) -> None:
    rules = {"write": {"path": {"within": [str(root)]}}}
    wall = Cheoyong([arg_rules(rules)], default=Effect.ALLOW)
    assert wall.check("write", {"path": value}).effect is Effect.DENY


def test_absent_optional_path_is_not_checked(root) -> None:
    rules = {"write": {"path": {"within": [str(root)]}, "x": {}}}
    wall = Cheoyong([arg_rules(rules)], default=Effect.ALLOW)
    assert wall.check("write", {"x": 1}).effect is Effect.ALLOW


def test_symlink_loop_under_root_denies(root) -> None:
    (root / "loop").symlink_to(root / "loop")
    assert check(root, str(root / "loop" / "x")).effect is Effect.DENY


def test_sibling_prefix_is_not_inside(root) -> None:
    sibling = root.parent / "workspace-evil"
    sibling.mkdir()
    assert check(root, str(sibling / "x")).effect is Effect.DENY


def test_root_that_is_a_symlink_is_resolved_at_load(root, tmp_path) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    assert check(alias, str(root / "sub" / "x")).effect is Effect.ALLOW


@pytest.mark.parametrize("within", ["/w", [], ["relative"], [""], [1]], ids=str)
def test_loader_rejects_bad_within(tmp_path, within) -> None:
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps(
        {"version": 1, "default": "deny", "tools": {"w": {"args": {"p": {"within": within}}}}}
    ))
    with pytest.raises(PolicyError, match="within: must be"):
        load_policy_file(policy)
