#!/usr/bin/env python3
"""List the packages whose version changes between two system derivations.

Usage: package_diff.py [--json] OLD_DRV NEW_DRV

Nothing is built: the runtime closure of each system is approximated from its
derivations and cache.nixos.org. See README.md, "Finding the installed packages".

With --json, prints

    {"changes": [{"pname": "curl", "old": ["8.20.0"], "new": ["8.22.0"]}], "rebuilt": 199}

where `old` and `new` are empty if the package is absent on that side, and
`rebuilt` counts packages rebuilt without a version change.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple, NewType, Optional, TypedDict, Union

# A store path without the /nix/store/ prefix, as `nix derivation show` and
# .narinfo files write them: "<hash>-<name>".
StorePath = NewType("StorePath", str)
# A derivation's key in `nix derivation show`: "<hash>-<name>.drv".
DrvName = NewType("DrvName", str)

Json = Union[str, int, float, bool, None, list["Json"], dict[str, "Json"]]


class Output(TypedDict, total=False):
    # Absent for fixed-output derivations.
    path: StorePath


class InputDrv(TypedDict):
    outputs: list[str]
    dynamicOutputs: dict[str, Json]


class Inputs(TypedDict):
    drvs: dict[DrvName, InputDrv]
    srcs: list[StorePath]


class _DerivationRequired(TypedDict):
    name: str
    outputs: dict[str, Output]
    inputs: Inputs


class Derivation(_DerivationRequired, total=False):
    env: dict[str, str]
    structuredAttrs: Optional[dict[str, Json]]
    args: list[str]


Derivations = dict[DrvName, Derivation]

# Runtime references of a cached path, or None if the path is not cached.
Lookup = Callable[[StorePath], Optional[list[StorePath]]]


class Package(NamedTuple):
    pname: str
    version: str


# Package name -> version -> store paths of that version.
Packages = dict[str, dict[str, set[StorePath]]]


class Change(NamedTuple):
    pname: str
    # Sorted; empty if the package is absent on that side.
    old: list[str]
    new: list[str]


CACHE = "https://cache.nixos.org"

# Attributes that only carry build machinery, or dependency sources that the
# build compiles or copies into the output (cargoDeps, goModules, npmDeps).
# Store paths that appear only in these are not followed for derivations that
# are not in the cache.
BUILD_ONLY_ATTRS = frozenset({
    "builder",
    "cargoDeps",
    "depsBuildBuild",
    "depsBuildBuildPropagated",
    "depsBuildTarget",
    "depsBuildTargetPropagated",
    "goModules",
    "nativeBuildInputs",
    "npmDeps",
    "propagatedNativeBuildInputs",
    "stdenv",
})

STORE_PATH = re.compile(r"[0-9a-df-np-sv-z]{32}-[^/\"'\s:]+")

# A store path at the start of a line of `buildCommand` is a program the build
# runs, e.g. the perl that runs buildEnv's builder.pl, not a reference the
# build writes into its output.
EXECUTED = re.compile(r"^(\s*)/nix/store/[0-9a-df-np-sv-z]{32}-[^/\s]+/\S*", re.MULTILINE)

# Same split as builtins.parseDrvName: the version starts at the first "-"
# followed by a digit.
DRV_NAME = re.compile(r"^(.+?)-(\d.*)$")


def nix_derivations(drv: str) -> Derivations:
    """The derivation of `drv` and all derivations it depends on."""
    out = subprocess.run(
        ["nix", "derivation", "show", "--recursive", drv],
        capture_output=True, text=True, check=True,
    ).stdout
    derivations: Derivations = json.loads(out)["derivations"]
    return derivations


def cache_references(path: StorePath) -> Optional[list[StorePath]]:
    """Runtime references of `path` according to the binary cache.

    Returns None if the cache does not have `path`. Any other failure raises,
    so that a cache outage is not mistaken for missing paths.
    """
    url = f"{CACHE}/{path[:32]}.narinfo"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            narinfo: str = response.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    for line in narinfo.splitlines():
        if line.startswith("References:"):
            return [StorePath(ref) for ref in line.split()[1:] if ref != path]
    return []


def strings(value: Json, skip: frozenset[str]) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item, skip)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in skip:
                yield from strings(item, skip)


def without_executed(build_command: str) -> str:
    return EXECUTED.sub(r"\1", build_command)


def mentioned_inputs(drvs: Derivations, drv: DrvName) -> list[StorePath]:
    """Output paths of `drv`'s inputs that appear in its attributes."""
    d = drvs[drv]
    env = dict(d.get("env", {}))
    if "buildCommand" in env:
        env["buildCommand"] = without_executed(env["buildCommand"])
    structured = dict(d.get("structuredAttrs") or {})
    command = structured.get("buildCommand")
    if isinstance(command, str):
        structured["buildCommand"] = without_executed(command)
    attrs: Json = [dict(env), structured, list(d.get("args", []))]
    mentioned: set[StorePath] = set()
    for s in strings(attrs, BUILD_ONLY_ATTRS):
        mentioned.update(StorePath(p) for p in STORE_PATH.findall(s))
    paths: list[StorePath] = []
    for input_drv, spec in d["inputs"]["drvs"].items():
        for output in spec["outputs"]:
            path = drvs[input_drv]["outputs"][output].get("path")
            if path is None:
                # `nix derivation show` omits the path of fixed-output
                # derivations; their single output is named like the
                # derivation.
                suffix = "-" + drvs[input_drv]["name"]
                paths.extend(p for p in mentioned if p.endswith(suffix))
            elif path in mentioned:
                paths.append(path)
    return paths


def producers(drvs: Derivations) -> dict[StorePath, DrvName]:
    """Map each output path to the derivation that produces it."""
    return {
        output["path"]: name
        for name, d in drvs.items()
        for output in d["outputs"].values()
        if "path" in output
    }


def runtime_closure(
    drvs: Derivations, root: StorePath, lookup: Lookup, workers: int = 32,
) -> set[StorePath]:
    """Approximate the runtime closure of the output path `root`."""
    produced_by = producers(drvs)
    seen: set[StorePath] = set()
    frontier = {root}
    with ThreadPoolExecutor(workers) as pool:
        while frontier:
            seen |= frontier
            batch = sorted(frontier)
            frontier = set()
            for path, refs in zip(batch, pool.map(lookup, batch)):
                if refs is None:
                    drv = produced_by.get(path)
                    refs = mentioned_inputs(drvs, drv) if drv else []
                frontier.update(refs)
            frontier -= seen
    return seen


def string_attr(d: Derivation, key: str) -> Optional[str]:
    value = d.get("env", {}).get(key) or (d.get("structuredAttrs") or {}).get(key)
    return value if isinstance(value, str) and value else None


def package(d: Derivation) -> Optional[Package]:
    """The package a derivation builds, or None if it has no version."""
    pname, version = string_attr(d, "pname"), string_attr(d, "version")
    if pname and version:
        return Package(pname, version)
    match = DRV_NAME.match(string_attr(d, "name") or d.get("name", ""))
    return Package(match[1], match[2]) if match else None


def packages(drvs: Derivations, paths: set[StorePath]) -> Packages:
    produced_by = producers(drvs)
    result: Packages = {}
    for path in paths:
        drv = produced_by.get(path)
        pkg = package(drvs[drv]) if drv else None
        if pkg:
            result.setdefault(pkg.pname, {}).setdefault(pkg.version, set()).add(path)
    return result


def compare(old: Packages, new: Packages) -> tuple[list[Change], int]:
    """Version changes and the number of packages rebuilt without one."""
    changes: list[Change] = []
    rebuilt = 0
    for pname in sorted(old.keys() | new.keys()):
        before, after = old.get(pname, {}), new.get(pname, {})
        if before.keys() != after.keys():
            changes.append(Change(pname, sorted(before), sorted(after)))
        elif any(before[v] != after[v] for v in before):
            rebuilt += 1
    return changes, rebuilt


def text(changes: list[Change], rebuilt: int) -> str:
    rows = [(c.pname, ", ".join(c.old) or "-", ", ".join(c.new) or "-") for c in changes]
    pname_width = max((len(r[0]) for r in rows), default=0)
    old_width = max((len(r[1]) for r in rows), default=0)
    lines = [f"{p:<{pname_width}}  {o:<{old_width}}  -> {n}" for p, o, n in rows]
    if not lines:
        lines.append("No version changes.")
    lines.append(f"{rebuilt} packages rebuilt without a version change.")
    return "\n".join(lines)


def to_json(changes: list[Change], rebuilt: int) -> str:
    return json.dumps({"changes": [c._asdict() for c in changes], "rebuilt": rebuilt})


def root(drvs: Derivations, drv: str) -> StorePath:
    """The `out` path of the derivation `drv`, a path in /nix/store."""
    return drvs[DrvName(drv.removeprefix("/nix/store/"))]["outputs"]["out"]["path"]


def system_packages(drv: str, lookup: Lookup = cache_references) -> Packages:
    drvs = nix_derivations(drv)
    return packages(drvs, runtime_closure(drvs, root(drvs, drv), lookup))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("old", help="derivation of the old system")
    parser.add_argument("new", help="derivation of the new system")
    args = parser.parse_args()
    changes, rebuilt = compare(system_packages(args.old), system_packages(args.new))
    print(to_json(changes, rebuilt) if args.json else text(changes, rebuilt))


if __name__ == "__main__":
    main()
