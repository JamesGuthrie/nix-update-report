#!/usr/bin/env python3
"""Describe what a flake update changes on each target.

Usage:
  update_report.py affected BEFORE_JSON AFTER_JSON
  update_report.py body --log UPDATE_LOG [--no-cves] [VULNIX OPTIONS] BEFORE_JSON AFTER_JSON

BEFORE_JSON and AFTER_JSON are outputs of `normalized-derivations` before and
after the update. Both must list the same targets.

`affected` prints the targets whose derivation changed, as a JSON list.

`body` prints a Markdown PR body: the update log without warnings, then for
each affected target its version changes and, unless --no-cves, the CVEs the
update resolves and introduces. See README.md, "Update PR".
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import NamedTuple, NewType, Optional, Union

import cves
import package_diff as pd

# A key of normalized-derivations' output: a machine, or dev-shell-<system>.
Target = NewType("Target", str)
# A derivation in /nix/store.
DrvPath = NewType("DrvPath", str)
Derivations = dict[Target, DrvPath]

NVD = "https://nvd.nist.gov/vuln/detail/"

# GitHub rejects PR bodies over 65536 characters.
MAX_BODY = 60000


class TargetChange(NamedTuple):
    target: Target
    before: DrvPath
    after: DrvPath


class TargetMismatch(NamedTuple):
    """The two evaluations list different targets."""

    # Sorted, and not both empty.
    missing_before: list[Target]
    missing_after: list[Target]

    def message(self) -> str:
        parts = []
        if self.missing_before:
            parts.append("missing before the update: " + ", ".join(self.missing_before))
        if self.missing_after:
            parts.append("missing after the update: " + ", ".join(self.missing_after))
        return "targets " + "; ".join(parts)


class TargetReport(NamedTuple):
    target: Target
    changes: list[pd.Change]
    rebuilt: int
    # None if CVEs are not reported.
    cves: Optional[cves.Comparison]


def parse_derivations(text: str) -> Derivations:
    value = json.loads(text)
    if not isinstance(value, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError("expected a JSON object of target names to derivations")
    return {Target(k): DrvPath(v) for k, v in value.items()}


def affected(before: Derivations, after: Derivations) -> Union[list[TargetChange], TargetMismatch]:
    """The targets whose derivation changed, sorted by name.

    A target missing on one side is an error rather than a change, so that a
    failed or partial evaluation can't look like an update.
    """
    if before.keys() != after.keys():
        return TargetMismatch(sorted(after.keys() - before.keys()),
                              sorted(before.keys() - after.keys()))
    return [TargetChange(t, before[t], after[t]) for t in sorted(before) if before[t] != after[t]]


# --- Collecting --------------------------------------------------------------

class LoadedSystem(NamedTuple):
    drvs: pd.Derivations
    closure: set[pd.StorePath]


def load(drv: DrvPath) -> LoadedSystem:
    drvs = pd.nix_derivations(drv)
    return LoadedSystem(drvs, pd.runtime_closure(drvs, pd.root(drvs, drv), pd.cache_references))


def target_report(change: TargetChange, options: Optional[cves.VulnixOptions]) -> TargetReport:
    old, new = load(change.before), load(change.after)
    changes, rebuilt = pd.compare(pd.packages(old.drvs, old.closure),
                                  pd.packages(new.drvs, new.closure))
    comparison = None
    if options is not None:
        comparison = cves.compare_systems(cves.runtime_system(old.drvs, old.closure),
                                          cves.runtime_system(new.drvs, new.closure), options)
    return TargetReport(change.target, changes, rebuilt, comparison)


# --- Rendering ---------------------------------------------------------------

def without_warnings(log: str) -> str:
    return "\n".join(line for line in log.splitlines() if not line.startswith("warning:"))


def cell(versions: list[str]) -> str:
    return ", ".join(versions) or "-"


def scores(findings: list[cves.Finding]) -> str:
    known = [f.score for f in findings if f.score is not None]
    if not known:
        return "-"
    low, high = min(known), max(known)
    return f"{low:g}" if low == high else f"{low:g}-{high:g}"


def security(comparison: cves.Comparison) -> list[str]:
    lines = ["#### Security", ""]
    if not comparison.resolved:
        lines += ["No resolved CVEs found.", ""]
    else:
        by_package: dict[str, list[cves.Finding]] = {}
        for r in comparison.resolved:
            by_package.setdefault(r.finding.pname, []).append(r.finding)
        lines += ["Resolved CVEs:", "",
                  "| Package | Resolved | CVSS | Critical | High |",
                  "| --- | --- | --- | --- | --- |"]
        for pname, findings in sorted(by_package.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            critical = sum(f.severity == cves.Severity.CRITICAL for f in findings)
            high = sum(f.severity == cves.Severity.HIGH for f in findings)
            lines.append(f"| {pname} | {len(findings)} | {scores(findings)} | {critical} | {high} |")
        lines.append("")
    if comparison.introduced:
        lines += ["Introduced CVEs:", ""]
        for f in comparison.introduced:
            score = "" if f.score is None else f", CVSS {f.score:g}"
            lines.append(f"- [{f.cve}]({NVD}{f.cve}) in {f.pname} {f.version}"
                         f" ({f.severity.value}{score})")
        lines.append("")
    return lines


def target_section(r: TargetReport) -> list[str]:
    lines = [f"### {r.target}", ""]
    if not r.changes:
        lines += ["No version changes.", ""]
    else:
        lines += ["| Package | Old | New |", "| --- | --- | --- |"]
        lines += [f"| {c.pname} | {cell(c.old)} | {cell(c.new)} |" for c in r.changes]
        lines.append("")
    lines += [f"{r.rebuilt} packages rebuilt without a version change.", ""]
    if r.cves is not None:
        lines += security(r.cves)
    return lines


def body(log: str, reports: list[TargetReport]) -> str:
    lines = ["```", without_warnings(log), "```", ""]
    for r in reports:
        lines += target_section(r)
    text = "\n".join(lines)
    if len(text) > MAX_BODY:
        return text[:MAX_BODY] + "\n\n(truncated)\n"
    return text


# --- Command line ------------------------------------------------------------

def read_derivations(path: str) -> Derivations:
    with open(path) as f:
        return parse_derivations(f.read())


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    affected_parser = sub.add_parser("affected")
    body_parser = sub.add_parser("body")
    body_parser.add_argument("--log", required=True, help="output of `nix flake update`")
    body_parser.add_argument("--no-cves", action="store_true", help="leave out CVEs")
    cves.add_vulnix_arguments(body_parser)
    for p in (affected_parser, body_parser):
        p.add_argument("before")
        p.add_argument("after")
    args = parser.parse_args()

    changed = affected(read_derivations(args.before), read_derivations(args.after))
    if isinstance(changed, TargetMismatch):
        sys.exit(changed.message())
    if args.command == "affected":
        print(json.dumps([c.target for c in changed]))
    else:
        with open(args.log) as f:
            log = f.read()
        options = None if args.no_cves else cves.vulnix_options(args)
        print(body(log, [target_report(c, options) for c in changed]), end="")


if __name__ == "__main__":
    main()
