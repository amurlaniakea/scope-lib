# SPDX-FileCopyrightText: 2026 Pedro Sordo Martinez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 Pedro Sordo Martinez
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

"""scope-lib: shared trust kernel for agent-defense sensors.

Single source of truth for:
  - policy store schema (static user-declared policy)
  - anchor schema (dynamic per-task goal anchor + sub-objectives)
  - scope evaluation (criteria i/ii/iii from goal-anchor SDD §B)

This package is imported LOCALLY by adi-shield, wallet-guard and goal-anchor.
It contains NO network calls by design (review rule: a network call here
would silently turn option (a) into option (b) -- prohibited).
"""

from .schema import (
    Action,
    Anchor,
    Policy,
    PolicyStore,
    ScopeVerdict,
    Verdict,
    load_policy_store,
    save_policy_store,
)
from .evaluate import evaluate_scope

__version__ = "0.1.0"
__all__ = [
    "Action",
    "Anchor",
    "Policy",
    "PolicyStore",
    "ScopeVerdict",
    "Verdict",
    "load_policy_store",
    "save_policy_store",
    "evaluate_scope",
]
