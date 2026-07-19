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

"""Scope evaluation -- goal-anchor SDD §B, criteria (i)/(ii)/(iii).

Evaluates whether an Action is IN SCOPE for a given task, using:
  (i)   action's claimed sub-objective is in the policy's authorized list
  (ii)  action's target resource is in the policy's authorized resources
  (iii) action is a transitive-support step toward an authorized sub-objective,
        BUT restricted to a CLOSED list of allowed transitions, and NEVER
        admissible for IRREVERSIBLE actions.

No network. Pure local evaluation.
"""

from __future__ import annotations


from .schema import Action, Anchor, Policy, ScopeVerdict, Verdict


def evaluate_scope(
    action: Action,
    policy: Policy | None,
    anchor: Anchor | None,
) -> ScopeVerdict:
    """Return a scope verdict for ``action`` under ``policy``/``anchor``.

    Decision logic (goal-anchor SDD §B + §C):
      - explicit deny  -> BLOCK (state 3)
      - anchor absent / not confirmed -> CONFIRM (state 2), never ALLOW (1)
      - (i) claimed sub-objective in authorized list -> ALLOW (1)
      - (ii) target in authorized resources -> ALLOW (1)
      - (iii) transitive support, CLOSED allowed_transitions, non-irreversible
              -> ALLOW (1); irreversible actions CANNOT use (iii)
      - otherwise -> CONFIRM (2)
    """
    # explicit deny
    if policy is not None:
        for d in policy.deny:
            if d == action.tool or d == action.target:
                return ScopeVerdict(Verdict.BLOCK, False, "deny", f"explicit deny: {d}")

    # anchor absent or unconfirmed -> never ALLOW by default (fail-safe)
    if anchor is None or not anchor.active:
        return ScopeVerdict(
            Verdict.CONFIRM,
            False,
            "no_active_anchor",
            "no confirmed anchor for task; default to human confirmation",
        )

    # (i) sub-objective in authorized list
    if policy is not None and action.claimed_subobjective is not None:
        if action.claimed_subobjective in policy.authorized_subobjectives:
            # irreversible actions need EXPLICIT authorization in the
            # authorized_irreversible list; otherwise escalate to CONFIRM
            if action.irreversible and action.claimed_subobjective not in getattr(
                policy, "authorized_irreversible", []
            ):
                return ScopeVerdict(
                    Verdict.CONFIRM,
                    False,
                    "i_subobjective_irreversible",
                    "irreversible action needs explicit irreversible authorization",
                )
            return ScopeVerdict(
                Verdict.ALLOW,
                True,
                "i_subobjective",
                f"sub-objective {action.claimed_subobjective} authorized",
            )

    # (iii) transitive support, CLOSED transitions, non-irreversible only.
    # Placed BEFORE (ii): a support action (e.g. navigate/read) whose target
    # is an authorized resource reached through a CLOSED allowed transition
    # is evaluated as transitive support, not as a direct resource hit.
    if (
        policy is not None
        and not action.irreversible
        and action.tool in policy.allowed_transitions
    ):
        if action.target is not None:
            for cat, values in policy.authorized_resources.items():
                if action.target in values:
                    return ScopeVerdict(
                        Verdict.ALLOW,
                        True,
                        "iii_transitive",
                        f"transitive support toward authorized {cat}",
                    )
        if (
            action.claimed_subobjective is not None
            and action.claimed_subobjective in policy.authorized_subobjectives
        ):
            return ScopeVerdict(
                Verdict.ALLOW,
                True,
                "iii_transitive",
                f"transitive support {action.tool} toward authorized objective",
            )

    # (ii) target resource in authorized resources
    if policy is not None and action.target is not None:
        for cat, values in policy.authorized_resources.items():
            if action.target in values:
                if action.irreversible and action.target not in getattr(
                    policy, "authorized_irreversible", []
                ):
                    return ScopeVerdict(
                        Verdict.CONFIRM,
                        False,
                        "ii_resource_irreversible",
                        "irreversible target needs explicit irreversible authorization",
                    )
                return ScopeVerdict(
                    Verdict.ALLOW,
                    True,
                    "ii_resource",
                    f"target {action.target} authorized under {cat}",
                )

    # default: needs human confirmation (state 2), not a hard block
    return ScopeVerdict(
        Verdict.CONFIRM,
        False,
        "none",
        "action not matched to any authorized scope; needs confirmation",
    )
