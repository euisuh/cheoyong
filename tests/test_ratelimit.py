from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cheoyong.engine import Cheoyong
from cheoyong.policies import arg_rules, rate_limit
from cheoyong.types import Effect


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def wall(max_calls=3, per_seconds=60, *, clock=None, key=()):
    return Cheoyong(
        [rate_limit("send", max_calls, per_seconds, key, clock or Clock())],
        default=Effect.ALLOW,
    )


def test_first_three_calls_allow_and_fourth_denies():
    limiter = wall()

    decisions = [limiter.check("send", {}) for _ in range(4)]
    assert [decision.effect for decision in decisions] == [
        Effect.ALLOW,
        Effect.ALLOW,
        Effect.ALLOW,
        Effect.DENY,
    ]
    assert decisions[-1].policy == "rate_limit:send"
    assert "3 calls per 60 seconds" in decisions[-1].reason


def test_advancing_clock_past_window_reallows():
    clock = Clock()
    limiter = wall(1, clock=clock)

    assert limiter.check("send", {}).effect is Effect.ALLOW
    assert limiter.check("send", {}).effect is Effect.DENY
    clock.now = 61
    assert limiter.check("send", {}).effect is Effect.ALLOW


def test_calls_denied_by_earlier_policy_do_not_consume_budget():
    clock = Clock()
    limiter = Cheoyong(
        [
            arg_rules({"send": {"to": {"required": True}}}),
            rate_limit("send", 3, 60, clock=clock),
        ],
        default=Effect.ALLOW,
    )

    assert all(limiter.check("send", {}).effect is Effect.DENY for _ in range(5))
    assert all(
        limiter.check("send", {"to": "ok"}).effect is Effect.ALLOW
        for _ in range(3)
    )
    assert limiter.check("send", {"to": "ok"}).effect is Effect.DENY


def test_rejected_attempts_do_not_extend_window():
    clock = Clock()
    limiter = wall(1, clock=clock)

    assert limiter.check("send", {}).effect is Effect.ALLOW
    for now in (10, 20, 30, 40, 50, 60):
        clock.now = now
        assert limiter.check("send", {}).effect is Effect.DENY
    clock.now = 61
    assert limiter.check("send", {}).effect is Effect.ALLOW


def test_context_key_isolates_sessions():
    limiter = wall(1, key=("session_id",))

    assert limiter.check("send", {}, {"session_id": "A"}).effect is Effect.ALLOW
    assert limiter.check("send", {}, {"session_id": "A"}).effect is Effect.DENY
    assert limiter.check("send", {}, {"session_id": "B"}).effect is Effect.ALLOW


def test_concurrent_calls_allow_exactly_the_limit():
    limiter = wall(50)
    barrier = Barrier(8)

    def issue_calls():
        barrier.wait()
        return sum(
            limiter.check("send", {}).effect is Effect.ALLOW for _ in range(100)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        allowed = sum(pool.map(lambda _: issue_calls(), range(8)))

    assert allowed == 50


def _hook_like_check(policy_and_state):
    # A fresh engine per call, as in one cheoyong-hook process per tool call.
    policy, state = policy_and_state
    return Cheoyong.from_file(policy, state_dir=state).check("send", {}).effect


def test_file_store_counts_exactly_across_concurrent_processes(tmp_path):
    from concurrent.futures import ProcessPoolExecutor

    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\ndefault: allow\ntools:\n"
        "  send:\n    rate_limit: {max: 5, per_seconds: 60}\n"
    )
    with ProcessPoolExecutor(8) as pool:
        effects = list(pool.map(_hook_like_check, [(str(policy), str(tmp_path))] * 20))
    assert effects.count(Effect.ALLOW) == 5


def _store_wall(tmp_path, max_calls=1):
    from cheoyong.policies import FileWindowStore

    store = FileWindowStore(tmp_path)
    return Cheoyong([rate_limit("send", max_calls, 60, store=store)], default=Effect.ALLOW)


@pytest.mark.parametrize(
    "state",
    [
        '{"rate_limit:send": {"[\\"send\\"]": [NaN]}}',
        '{"rate_limit:send": {"[\\"send\\"]": ["nan"]}}',
        '{"rate_limit:send": {"[\\"send\\"]": 5}}',
        "[]",
        "{not json",
    ],
)
def test_malformed_store_state_denies(tmp_path, state):
    (tmp_path / "rate_limit.json").write_text(state)
    assert _store_wall(tmp_path).check("send", {}).effect is Effect.DENY


def test_failed_state_write_keeps_previous_window(tmp_path, monkeypatch):
    import json as json_module

    wall = _store_wall(tmp_path)
    assert wall.check("send", {}).effect is Effect.ALLOW

    def broken_dump(*args, **kwargs):
        raise OSError("disk full")

    with monkeypatch.context() as patch:
        patch.setattr(json_module, "dump", broken_dump)
        assert wall.check("other", {}).effect is Effect.DENY
    assert wall.check("send", {}).effect is Effect.DENY
