# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martínez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from scope_lib import (
    Action,
    Anchor,
    Policy,
    PolicyStore,
    Verdict,
    evaluate_scope,
    load_policy_store,
    save_policy_store,
)
from scope_lib.schema import SCHEMA_VERSION


def _policy() -> Policy:
    return Policy(
        policy_id="p1",
        task_id="t1",
        authorized_subobjectives=["research_prices"],
        authorized_resources={"domain": ["example.com"], "recipient": ["boss@x.com"]},
        deny=["malware.exe"],
        allowed_transitions={"read": ["write"], "navigate": ["extract"]},
    )


def _anchor(confirmed: bool = True) -> Anchor:
    return Anchor(
        task_id="t1",
        objective="research flight prices",
        subobjectives=["research_prices"],
        confirmed_by_user=confirmed,
        signature="sig",
    )


def test_criterion_i_subobjective():
    v = evaluate_scope(
        Action(task_id="t1", tool="search", claimed_subobjective="research_prices"),
        _policy(),
        _anchor(),
    )
    assert v.verdict == Verdict.ALLOW
    assert v.criterion == "i_subobjective"


def test_criterion_ii_resource():
    v = evaluate_scope(
        Action(task_id="t1", tool="send_email", target="boss@x.com"),
        _policy(),
        _anchor(),
    )
    assert v.verdict == Verdict.ALLOW
    assert v.criterion == "ii_resource"


def test_criterion_iii_transitive_non_reversible():
    # transitive support WITHOUT an authorized sub-objective claim, but the
    # target is an authorized resource reached via a CLOSED allowed transition.
    # Here (i)/(ii) do not match (no claimed sub-obj / target not in resources
    # directly), so (iii) applies. Use a transition whose target is authorized.
    p = _policy()
    p.authorized_resources = {"domain": ["store.example"]}
    p.allowed_transitions = {"navigate": ["extract"]}
    v = evaluate_scope(
        Action(
            task_id="t1",
            tool="navigate",
            target="store.example",
        ),
        p,
        _anchor(),
    )
    assert v.verdict == Verdict.ALLOW
    assert v.criterion == "iii_transitive"


def test_criterion_iii_rejects_irreversible():
    # an irreversible action must NOT enter via (iii); here it matches (i)
    # by sub-objective, but without explicit irreversible authorization it
    # escalates to CONFIRM, never a blind ALLOW.
    v = evaluate_scope(
        Action(
            task_id="t1",
            tool="read",
            claimed_subobjective="research_prices",
            target="example.com",
            irreversible=True,
        ),
        _policy(),
        _anchor(),
    )
    assert v.verdict == Verdict.CONFIRM
    assert "irreversible" in v.criterion


def test_irreversible_explicitly_authorized_allows():
    p = _policy()
    p.authorized_irreversible = ["research_prices"]
    v = evaluate_scope(
        Action(
            task_id="t1",
            tool="read",
            claimed_subobjective="research_prices",
            target="example.com",
            irreversible=True,
        ),
        p,
        _anchor(),
    )
    assert v.verdict == Verdict.ALLOW
    assert v.criterion == "i_subobjective"


def test_deny_blocks():
    v = evaluate_scope(
        Action(task_id="t1", tool="run", target="malware.exe"),
        _policy(),
        _anchor(),
    )
    assert v.verdict == Verdict.BLOCK
    assert v.criterion == "deny"


def test_no_anchor_fails_confirm_not_allow():
    # anchor absent -> CONFIRM, never ALLOW (closes arranque window)
    v = evaluate_scope(
        Action(task_id="t1", tool="search", claimed_subobjective="research_prices"),
        _policy(),
        None,
    )
    assert v.verdict == Verdict.CONFIRM
    assert v.criterion == "no_active_anchor"

    v2 = evaluate_scope(
        Action(task_id="t1", tool="search", claimed_subobjective="research_prices"),
        _policy(),
        _anchor(confirmed=False),
    )
    assert v2.verdict == Verdict.CONFIRM


def test_default_out_of_scope_is_confirm_not_block():
    v = evaluate_scope(
        Action(task_id="t1", tool="mystery", target="unknown.example"),
        _policy(),
        _anchor(),
    )
    assert v.verdict == Verdict.CONFIRM
    assert v.in_scope is False


def test_schema_roundtrip_and_version_guard():
    store = PolicyStore(
        policies={"t1": _policy().to_dict()},
        anchors={"t1": _anchor().to_dict()},
    )
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        save_policy_store(store, path)
        loaded = load_policy_store(path)
        assert loaded.schema_version == SCHEMA_VERSION
        assert loaded.policies["t1"]["policy_id"] == "p1"
        assert loaded.anchors["t1"]["confirmed_by_user"] is True
    finally:
        os.remove(path)


def test_schema_version_mismatch_raises():
    import tempfile
    import os
    import json

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": "scope-lib/0.0", "policies": {}, "anchors": {}}, fh)
        raised = False
        try:
            load_policy_store(path)
        except ValueError:
            raised = True
        assert raised, "version mismatch must raise"
    finally:
        os.remove(path)
