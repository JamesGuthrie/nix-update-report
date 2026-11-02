#!/usr/bin/env python3
"""Describe what a flake update changes on each target.

Usage:
  update_report.py affected BEFORE_JSON AFTER_JSON
  update_report.py body --log UPDATE_LOG [--no-cves] [VULNIX OPTIONS] BEFORE_JSON AFTER_JSON

BEFORE_JSON and AFTER_JSON are outputs of `normalized-derivations` before and
after the update. Both must list the same targets, and each target the same
nested systems.

`affected` prints the targets whose derivation changed, as a JSON list.

`body` prints a Markdown PR body: the update log without warnings, then for
each affected target its version changes and, unless --no-cves, the CVEs the
update resolves and introduces, and the same for each of its nested systems
that changed. See README.md, "Update PR".
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import NamedTuple, Optional, Union

import cves
import package_diff as pd
from targets import NestedFailure, NestedLabel, Target, Targets, TargetSpec
import targets as tg

NVD = "https://nvd.nist.gov/vuln/detail/"

# GitHub rejects PR bodies over 65536 characters.
MAX_BODY = 60000


class TargetChange(NamedTuple):
    target: Target
    before: TargetSpec
    after: TargetSpec


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


class NestedMismatch(NamedTuple):
    """A target lists different nested systems before and after the update."""

    target: Target
    # Sorted, and not both empty.
    missing_before: list[NestedLabel]
    missing_after: list[NestedLabel]

    def message(self) -> str:
        parts = []
        if self.missing_before:
            parts.append("missing before the update: " + ", ".join(self.missing_before))
        if self.missing_after:
            parts.append("missing after the update: " + ", ".join(self.missing_after))
        return f"{self.target}: nested systems " + "; ".join(parts)


class PartReport(NamedTuple):
    changes: list[pd.Change]
    rebuilt: int
    # None if CVEs are not reported.
    cves: Optional[cves.Comparison]


class TargetReport(NamedTuple):
    target: Target
    host: PartReport
    # Only the nested systems whose derivation changed.
    nested: dict[NestedLabel, PartReport]


def parse_derivations(text: str) -> Targets:
    return tg.parse_targets(text)


def affected(before: Targets, after: Targets
             ) -> Union[list[TargetChange], TargetMismatch, NestedMismatch]:
    """The targets whose derivation changed, sorted by name.

    A target or nested system missing on one side is an error rather than a
    change, so that a failed or partial evaluation can't look like an update.
    A nested system is part of its target's closure, so when it changes, the
    target's derivation changes too.
    """
    if before.keys() != after.keys():
        return TargetMismatch(sorted(after.keys() - before.keys()),
                              sorted(before.keys() - after.keys()))
    for t in sorted(before):
        b, a = before[t].nested.keys(), after[t].nested.keys()
        if b != a:
            return NestedMismatch(t, sorted(a - b), sorted(b - a))
    return [TargetChange(t, before[t], after[t])
            for t in sorted(before) if before[t].drv != after[t].drv]


# --- Collecting --------------------------------------------------------------

def part_report(old: tg.Part, new: tg.Part, options: Optional[cves.VulnixOptions]) -> PartReport:
    changes, rebuilt = pd.compare(pd.packages(old.drvs, old.closure),
                                  pd.packages(new.drvs, new.closure))
    comparison = None
    if options is not None:
        comparison = cves.compare_systems(cves.part_system(old), cves.part_system(new), options)
    return PartReport(changes, rebuilt, comparison)


def target_report(change: TargetChange, options: Optional[cves.VulnixOptions]
                  ) -> Union[TargetReport, NestedFailure]:
    old = tg.load_target(change.target, change.before)
    if not isinstance(old, tg.LoadedTarget):
        return old
    new = tg.load_target(change.target, change.after)
    if not isinstance(new, tg.LoadedTarget):
        return new
    nested = {label: part_report(old.nested[label], new.nested[label], options)
              for label in sorted(new.nested)
              if change.before.nested[label].drv != change.after.nested[label].drv}
    return TargetReport(change.target, part_report(old.host, new.host, options), nested)


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


def security(comparison: cves.Comparison, heading: str) -> list[str]:
    lines = [f"{heading} Security", ""]
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


def part_section(r: PartReport, heading: str) -> list[str]:
    """`heading` is the Markdown heading marker of the part, e.g. "###"."""
    lines = []
    if not r.changes:
        lines += ["No version changes.", ""]
    else:
        lines += ["| Package | Old | New |", "| --- | --- | --- |"]
        lines += [f"| {c.pname} | {cell(c.old)} | {cell(c.new)} |" for c in r.changes]
        lines.append("")
    lines += [f"{r.rebuilt} packages rebuilt without a version change.", ""]
    if r.cves is not None:
        lines += security(r.cves, heading + "#")
    return lines


def target_section(r: TargetReport) -> list[str]:
    lines = [f"### {r.target}", ""] + part_section(r.host, "###")
    for label, part in r.nested.items():
        lines += [f"#### {r.target}/{label}", ""] + part_section(part, "####")
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

def read_derivations(path: str) -> Targets:
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
    if not isinstance(changed, list):
        sys.exit(changed.message())
    if args.command == "affected":
        print(json.dumps([c.target for c in changed]))
    else:
        with open(args.log) as f:
            log = f.read()
        options = None if args.no_cves else cves.vulnix_options(args)
        reports = []
        for c in changed:
            r = target_report(c, options)
            if not isinstance(r, TargetReport):
                sys.exit(r.message())
            reports.append(r)
        print(body(log, reports), end="")


if __name__ == "__main__":
    main()
