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

"""Schema definitions for policy store, anchor and scope evaluation.

All schemas are plain dataclasses + explicit (de)serialization so that the
on-disk format is versioned and reviewed. The SAME schema is used by every
sensor (single source of truth for format -- avoids schema drift).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "scope-lib/1.0"


class Verdict(Enum):
    """Three states reused across every sensor (no binary block)."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


@dataclass
class Policy:
    """Static, user-declared policy for a task type.

    Declared by the HUMAN (operator), never inferred by the model.
    """

    policy_id: str
    task_id: str
    # (i) sub-objectives authorized by the user
    authorized_subobjectives: list[str] = field(default_factory=list)
    # (ii) authorized resources (domains, repo paths, recipients) by category
    authorized_resources: dict[str, list[str]] = field(default_factory=dict)
    # explicit deny list (state 3 / block)
    deny: list[str] = field(default_factory=list)
    # budget of admission by action category (wallet-guard)
    admission_budget: dict[str, float] = field(default_factory=dict)
    # allowed transitive-support transitions (goal-anchor criterion iii),
    # a CLOSED list, e.g. {"read": ["write"], "navigate": ["extract"]}
    allowed_transitions: dict[str, list[str]] = field(default_factory=dict)
    # EXPLICIT authorization for IRREVERSIBLE actions (payments, mass-sends,
    # deletes). Without an entry here, irreversible actions escalate to CONFIRM
    # even if matched by (i)/(ii).
    authorized_irreversible: list[str] = field(default_factory=list)
    # EXPLICIT authorization for flows where the OBJECTIVE/DESTINATION is
    # derived from UNTRUSTED_DATA (ADI). Lists the specific values that are
    # allowed to come from untrusted data (e.g. "boss@x.com" for re-forward).
    # Empty -> no untrusted-derived flow is auto-allowed (falls to confirm).
    authorized_flows: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "task_id": self.task_id,
            "authorized_subobjectives": self.authorized_subobjectives,
            "authorized_resources": self.authorized_resources,
            "deny": self.deny,
            "admission_budget": self.admission_budget,
            "allowed_transitions": self.allowed_transitions,
            "authorized_irreversible": self.authorized_irreversible,
            "authorized_flows": self.authorized_flows,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        return cls(
            policy_id=d["policy_id"],
            task_id=d["task_id"],
            authorized_subobjectives=d.get("authorized_subobjectives", []),
            authorized_resources=d.get("authorized_resources", {}),
            deny=d.get("deny", []),
            admission_budget=d.get("admission_budget", {}),
            allowed_transitions=d.get("allowed_transitions", {}),
            authorized_irreversible=d.get("authorized_irreversible", []),
            authorized_flows=d.get("authorized_flows", []),
        )


@dataclass
class Anchor:
    """Dynamic per-task goal anchor established at runtime.

    The MODEL PROPOSES the decomposition; the anchor only ACTIVATES after
    explicit human confirmation. The model cannot move the anchor once fixed.
    """

    task_id: str
    objective: str
    subobjectives: list[str] = field(default_factory=list)
    confirmed_by_user: bool = False
    signature: str = ""  # user signature over objective+subobjectives

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "objective": self.objective,
            "subobjectives": self.subobjectives,
            "confirmed_by_user": self.confirmed_by_user,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Anchor:
        return cls(
            task_id=d["task_id"],
            objective=d["objective"],
            subobjectives=d.get("subobjectives", []),
            confirmed_by_user=d.get("confirmed_by_user", False),
            signature=d.get("signature", ""),
        )

    @property
    def active(self) -> bool:
        return self.confirmed_by_user


@dataclass
class Action:
    """A tool-call action evaluated for scope."""

    task_id: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    # the sub-objective this action claims to serve (may be absent)
    claimed_subobjective: str | None = None
    # the resource/objective the action targets (e.g. recipient, url, path)
    target: str | None = None
    # whether the action has an IRREVERSIBLE effect (criterion iii exclusion)
    irreversible: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tool": self.tool,
            "args": self.args,
            "claimed_subobjective": self.claimed_subobjective,
            "target": self.target,
            "irreversible": self.irreversible,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Action:
        return cls(
            task_id=d["task_id"],
            tool=d["tool"],
            args=d.get("args", {}),
            claimed_subobjective=d.get("claimed_subobjective"),
            target=d.get("target"),
            irreversible=d.get("irreversible", False),
        )


@dataclass
class ScopeVerdict:
    verdict: Verdict
    in_scope: bool
    criterion: str  # which of i/ii/iii/deny/none applied
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "in_scope": self.in_scope,
            "criterion": self.criterion,
            "reason": self.reason,
        }


@dataclass
class PolicyStore:
    """Local store holding static policies and dynamic anchors by task_id.

    Read directly by sensors at decision time (no network). On-disk format
    is versioned; any schema change requires a version bump + review.
    """

    schema_version: str = SCHEMA_VERSION
    policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    anchors: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policies": self.policies,
            "anchors": self.anchors,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyStore:
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"schema version mismatch: store={d.get('schema_version')} lib={SCHEMA_VERSION}"
            )
        return cls(
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            policies=d.get("policies", {}),
            anchors=d.get("anchors", {}),
        )


def load_policy_store(path: str) -> PolicyStore:
    """Load a policy store from disk (JSON). Raises on version mismatch."""
    import json

    with open(path, "r", encoding="utf-8") as fh:
        return PolicyStore.from_dict(json.load(fh))


def save_policy_store(store: PolicyStore, path: str) -> None:
    """Persist a policy store to disk (JSON, atomic-ish)."""
    import json
    import os

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store.to_dict(), fh, indent=2)
    os.replace(tmp, path)
