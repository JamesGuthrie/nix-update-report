#!/usr/bin/env python3
"""Find the CVEs affecting a system, or the CVEs an update resolves.

Usage:
  cves.py [OPTIONS] open DRV
  cves.py [OPTIONS] compare OLD_DRV NEW_DRV

`open` prints the CVEs affecting the runtime packages of the system DRV:

    {"findings": [FINDING, ...], "suppressed": ["CVE-...", ...]}

`compare` prints the CVEs that changed between two systems:

    {"resolved": [FINDING + {"sources": ["nvd", "patch"]}, ...],
     "introduced": [FINDING, ...]}

where FINDING is

    {"cve": "CVE-2026-56391", "package": "coreutils", "version": "9.11",
     "score": 6.1 or null, "severity": "medium", "description": "..."}

Matching packages to CVEs, scores and descriptions are vulnix's: it compares
package names and versions with NVD's CPE data, and skips CVEs that nixpkgs
patches by name. The score is the first CVSS 3.x base score in NVD's data,
which may be NVD's or the CNA's. vulnix's whitelist suppresses CVEs that are
known noise; they are only listed as "suppressed". A CVE is resolved by an
update if vulnix reports it before but not after the update ("nvd"), or if
nixpkgs newly applies a patch named after it ("patch"). See README.md, "Matching
CVEs".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple, NewType, Optional, TypedDict

import package_diff as pd

DEFAULT_MIRROR = "https://nvd-mirror.fsn1.your-objectstorage.com/"
# Relative to the working directory, which is usually the flake's.
DEFAULT_WHITELIST = "vulnix-whitelist.toml"

CveId = NewType("CveId", str)

# A CVSS 3.x base score, 0.0 to 10.0.
Score = NewType("Score", float)

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class Severity(Enum):
    """NVD's qualitative severity ratings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNSCORED = "unscored"

    @classmethod
    def of(cls, score: Optional[Score]) -> Severity:
        if score is None or score == 0.0:
            return cls.UNSCORED
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


class Finding(NamedTuple):
    """A CVE affecting one package."""

    cve: CveId
    pname: str
    version: str
    score: Optional[Score]
    description: str

    @property
    def severity(self) -> Severity:
        return Severity.of(self.score)


class Source(Enum):
    """How we know that an update resolves a CVE."""

    NVD = "nvd"
    PATCH = "patch"


@dataclass(frozen=True)
class Resolution:
    finding: Finding
    sources: frozenset[Source]

    def __post_init__(self) -> None:
        if not self.sources:
            raise ValueError(f"{self.finding.cve}: a resolution needs a source")


class Report(NamedTuple):
    findings: list[Finding]
    # Whitelisted, so not in `findings`.
    suppressed: list[CveId]


class Comparison(NamedTuple):
    resolved: list[Resolution]
    introduced: list[Finding]


class VulnixEntry(TypedDict):
    """The part of an entry of `vulnix --json` that we use."""

    pname: str
    version: str
    affected_by: list[str]
    whitelisted: list[str]
    # Only CVEs with a CVSS 3.x score, or a description.
    cvssv3_basescore: dict[str, float]
    description: dict[str, str]


# Package name -> CVE IDs named by its patches.
PatchCves = dict[str, set[CveId]]

# Package name -> versions present.
Versions = dict[str, set[str]]


# --- Systems -----------------------------------------------------------------

class System(NamedTuple):
    """A system's runtime derivations, as approximated by package_diff."""

    drvs: pd.Derivations
    runtime: list[pd.DrvName]


def load_system(drv: str) -> System:
    drvs = pd.nix_derivations(drv)
    return runtime_system(drvs, pd.runtime_closure(drvs, pd.root(drvs, drv), pd.cache_references))


def runtime_system(drvs: pd.Derivations, closure: set[pd.StorePath]) -> System:
    produced_by = pd.producers(drvs)
    return System(drvs, sorted({produced_by[p] for p in closure if p in produced_by}))


def patch_cves(system: System) -> PatchCves:
    """CVE IDs in the names of the patches of each runtime package."""
    result: PatchCves = {}
    for name in system.runtime:
        d = system.drvs[name]
        pkg = pd.package(d)
        patches = (d.get("env", {}).get("patches")
                   or (d.get("structuredAttrs") or {}).get("patches"))
        if not pkg or not patches:
            continue
        found = {CveId(c.upper())
                 for s in pd.strings(patches, frozenset()) for c in CVE.findall(s)}
        if found:
            result.setdefault(pkg.pname, set()).update(found)
    return result


def versions(system: System) -> Versions:
    result: Versions = {}
    for name in system.runtime:
        pkg = pd.package(system.drvs[name])
        if pkg:
            result.setdefault(pkg.pname, set()).add(pkg.version)
    return result


class VulnixOptions(NamedTuple):
    # Ends with "/".
    mirror: str
    # An existing file, or None for no whitelist.
    whitelist: Optional[str]
    # None for vulnix's default.
    cache_dir: Optional[str]


def add_vulnix_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mirror", default=DEFAULT_MIRROR,
                        help=f"NVD feed mirror (default: {DEFAULT_MIRROR})")
    parser.add_argument("--whitelist", default=DEFAULT_WHITELIST,
                        help=f"vulnix whitelist, used if it exists (default: {DEFAULT_WHITELIST})")
    parser.add_argument("--cache-dir",
                        help="vulnix's cache of the NVD feeds (default: vulnix's own)")


def vulnix_options(args: argparse.Namespace) -> VulnixOptions:
    whitelist: str = args.whitelist
    return VulnixOptions(args.mirror.rstrip("/") + "/",
                         whitelist if os.path.exists(whitelist) else None,
                         args.cache_dir)


def run_vulnix(system: System, options: VulnixOptions) -> list[VulnixEntry]:
    args = ["vulnix", "--json", "--show-whitelisted", "--no-requisites",
            "--mirror", options.mirror]
    if options.whitelist:
        args += ["--whitelist", options.whitelist]
    if options.cache_dir:
        args += ["--cache-dir", options.cache_dir]
        os.makedirs(options.cache_dir, exist_ok=True)
    result = subprocess.run(args + [f"/nix/store/{n}" for n in system.runtime],
                            capture_output=True, text=True)
    # vulnix exits with 2 if it finds vulnerabilities.
    if result.returncode not in (0, 2):
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"vulnix failed with exit status {result.returncode}")
    entries: list[VulnixEntry] = json.loads(result.stdout or "[]")
    return entries


# --- Findings ----------------------------------------------------------------

def report(entries: list[VulnixEntry]) -> Report:
    findings: list[Finding] = []
    suppressed: set[CveId] = set()
    for e in entries:
        for cve in e["affected_by"]:
            score = e["cvssv3_basescore"].get(cve)
            findings.append(Finding(CveId(cve), e["pname"], e["version"],
                                    None if score is None else Score(score),
                                    e["description"].get(cve, "")))
        suppressed.update(map(CveId, e["whitelisted"]))
    return Report(sorted(set(findings), key=finding_key), sorted(suppressed))


def scan(system: System, options: VulnixOptions) -> Report:
    return report(run_vulnix(system, options))


def compare_systems(old: System, new: System, options: VulnixOptions) -> Comparison:
    return compare(scan(old, options), scan(new, options),
                   patch_cves(old), patch_cves(new), versions(old))


def finding_key(f: Finding) -> tuple[str, str, str]:
    return (f.cve, f.pname, f.version)


def compare(old: Report, new: Report, old_patches: PatchCves, new_patches: PatchCves,
            old_versions: Versions) -> Comparison:
    """CVEs resolved and introduced by an update, per package.

    A CVE that only a patch resolves has no score or description, as vulnix
    did not report it.
    """
    old_by_key = {(f.pname, f.cve): f for f in old.findings}
    new_keys = {(f.pname, f.cve) for f in new.findings}
    sources: dict[tuple[str, CveId], set[Source]] = {}
    for key in old_by_key.keys() - new_keys:
        sources.setdefault(key, set()).add(Source.NVD)
    for pname, cves in new_patches.items():
        for cve in cves - old_patches.get(pname, set()):
            sources.setdefault((pname, cve), set()).add(Source.PATCH)
    resolved = []
    for (pname, cve), srcs in sorted(sources.items()):
        f = old_by_key.get((pname, cve)) or Finding(
            cve, pname, ", ".join(sorted(old_versions.get(pname, set()))), None, "")
        resolved.append(Resolution(f, frozenset(srcs)))
    introduced = sorted((f for f in new.findings if (f.pname, f.cve) not in old_by_key),
                        key=finding_key)
    return Comparison(resolved, introduced)


# --- Output ------------------------------------------------------------------

def finding_json(f: Finding) -> dict[str, object]:
    return {
        "cve": f.cve,
        "package": f.pname,
        "version": f.version,
        "score": f.score,
        "severity": f.severity.value,
        "description": f.description,
    }


def report_json(r: Report) -> dict[str, object]:
    return {"findings": [finding_json(f) for f in r.findings], "suppressed": r.suppressed}


def comparison_json(c: Comparison) -> dict[str, object]:
    return {
        "resolved": [finding_json(r.finding) | {"sources": sorted(s.value for s in r.sources)}
                     for r in c.resolved],
        "introduced": [finding_json(f) for f in c.introduced],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_vulnix_arguments(parser)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("open").add_argument("drv")
    cmp = sub.add_parser("compare")
    cmp.add_argument("old")
    cmp.add_argument("new")
    args = parser.parse_args()

    options = vulnix_options(args)
    if args.command == "open":
        print(json.dumps(report_json(scan(load_system(args.drv), options))))
    else:
        print(json.dumps(comparison_json(compare_systems(
            load_system(args.old), load_system(args.new), options))))


if __name__ == "__main__":
    main()
