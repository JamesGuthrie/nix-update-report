"""Targets as `normalized-derivations` prints them, and their runtime closures.

`normalized-derivations` prints each target's derivation and the nested systems
that the normalization file declares for it:

    {"myhost": {"drv": "/nix/store/...-nixos-system-myhost.drv",
                "nested": {"vm": {"entry": "/nix/store/...-nixos-disk-image",
                                  "drv": "/nix/store/...-nixos-system-vm.drv"}}}}

A nested system is part of the target, but is reported on its own. The
target's walk stops at the nested system's entry, and the nested system's
closure is walked from its own derivation. See README.md, "Nested systems".
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple, NewType, Union

import package_diff as pd

# A machine, or dev-shell-<system>.
Target = NewType("Target", str)
# A derivation in /nix/store, with the /nix/store/ prefix.
DrvPath = NewType("DrvPath", str)
# A nested system's name within its target.
NestedLabel = NewType("NestedLabel", str)

STORE = "/nix/store/"


class Nested(NamedTuple):
    # The output where the target's walk stops.
    entry: pd.StorePath
    drv: DrvPath


class TargetSpec(NamedTuple):
    drv: DrvPath
    nested: dict[NestedLabel, Nested]


Targets = dict[Target, TargetSpec]


def parse_targets(text: str) -> Targets:
    """Parse the output of `normalized-derivations`; raise ValueError if malformed."""
    value: pd.Json = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object of target names to targets")
    return {Target(name): parse_target(name, spec) for name, spec in value.items()}


def parse_target(name: str, value: pd.Json) -> TargetSpec:
    if not isinstance(value, dict):
        raise ValueError(f"{name}: expected an object with a drv and nested systems")
    drv, nested_value = value.get("drv"), value.get("nested")
    if not isinstance(drv, str) or not isinstance(nested_value, dict):
        raise ValueError(f"{name}: expected an object with a drv and nested systems")
    nested: dict[NestedLabel, Nested] = {}
    for label, n in nested_value.items():
        entry = n.get("entry") if isinstance(n, dict) else None
        nested_drv = n.get("drv") if isinstance(n, dict) else None
        if not isinstance(entry, str) or not isinstance(nested_drv, str) \
                or not entry.startswith(STORE):
            raise ValueError(f"{name}/{label}: expected an object with an entry in "
                             f"{STORE} and a drv")
        nested[NestedLabel(label)] = Nested(pd.StorePath(entry.removeprefix(STORE)),
                                            DrvPath(nested_drv))
    return TargetSpec(DrvPath(drv), nested)


# --- Closures ----------------------------------------------------------------

class Part(NamedTuple):
    """The target itself, or one of its nested systems."""

    drvs: pd.Derivations
    closure: set[pd.StorePath]


class LoadedTarget(NamedTuple):
    host: Part
    nested: dict[NestedLabel, Part]


# Dataclasses rather than NamedTuples: the failures have the same fields, and
# NamedTuples with equal fields compare equal across classes.
@dataclass(frozen=True)
class EntryNotReached:
    target: Target
    label: NestedLabel

    def message(self) -> str:
        return (f"{self.target}/{self.label}: the target's closure doesn't contain the "
                "nested system's entry")


@dataclass(frozen=True)
class SystemNotUnderEntry:
    target: Target
    label: NestedLabel

    def message(self) -> str:
        return (f"{self.target}/{self.label}: the nested system isn't in the closure of "
                "its entry")


@dataclass(frozen=True)
class NestedLeak:
    target: Target
    label: NestedLabel

    def message(self) -> str:
        return (f"{self.target}/{self.label}: the target's closure contains the nested "
                "system other than through its entry")


NestedFailure = Union[EntryNotReached, SystemNotUnderEntry, NestedLeak]


def load_target(
    target: Target,
    spec: TargetSpec,
    derivations: Callable[[DrvPath], pd.Derivations] = pd.nix_derivations,
    lookup: pd.Lookup = pd.cache_references,
) -> Union[LoadedTarget, NestedFailure]:
    """The closures of the target and of its nested systems.

    Fails unless each nested system is part of the target through its entry,
    and only through it, so that its packages are counted once, under the
    nested system.
    """
    cached: pd.Lookup = functools.cache(lookup)
    drvs = derivations(spec.drv)
    entries = frozenset(n.entry for n in spec.nested.values())
    host = pd.runtime_closure(drvs, pd.root(drvs, spec.drv), cached, entries)
    nested: dict[NestedLabel, Part] = {}
    for label, n in sorted(spec.nested.items()):
        nested_drvs = derivations(n.drv)
        nested_root = pd.root(nested_drvs, n.drv)
        if n.entry not in host:
            return EntryNotReached(target, label)
        if nested_root in host:
            return NestedLeak(target, label)
        if nested_root not in pd.runtime_closure(drvs, n.entry, cached):
            return SystemNotUnderEntry(target, label)
        nested[label] = Part(nested_drvs, pd.runtime_closure(nested_drvs, nested_root, cached))
    return LoadedTarget(Part(drvs, host), nested)
