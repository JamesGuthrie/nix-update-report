#!/usr/bin/env python3
"""Render the "Open CVEs" issue from `cves.py open` reports.

Usage: cve_issue.py REPORTS_DIR PREVIOUS_BODY HEADER BODY_OUT ALERT_OUT

REPORTS_DIR holds one `cves.py open --json` report per target, named
<target>.json. A target's nested systems are listed as targets of their own,
named <target>/<label>. PREVIOUS_BODY is the issue's current body (empty if there is
none); its hidden state lists the critical and high CVEs reported before.
Writes the new body to BODY_OUT, and to ALERT_OUT a comment listing critical
and high CVEs that are new since the previous body, or nothing.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable
from typing import NamedTuple, Optional

import cves
from cves import Finding, Report, Severity

SEVERITIES = list(Severity)
ALERTING = {Severity.CRITICAL, Severity.HIGH}
NVD = "https://nvd.nist.gov/vuln/detail/"

# GitHub rejects issue bodies over 65536 characters.
MAX_BODY = 60000

STATE = re.compile(r"<!-- cve-report-state: (.*?) -->")


# Machine or <machine>/<label> -> "package CVE" entries of its critical and
# high findings.
State = dict[str, list[str]]


class PackageRow(NamedTuple):
    package: str
    version: str
    findings: list[Finding]


def load_reports(directory: str) -> dict[str, Report]:
    """Raise ValueError, naming the file, if a report is malformed."""
    targets: dict[str, cves.TargetReport] = {}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            with open(os.path.join(directory, name)) as f:
                try:
                    targets[name.removesuffix(".json")] = cves.parse_target_report(f.read())
                except ValueError as e:
                    raise ValueError(f"{name}: {e}") from e
    return flatten(targets)


def flatten(targets: dict[str, cves.TargetReport]) -> dict[str, Report]:
    """Each target, followed by its nested systems as <target>/<label>."""
    reports: dict[str, Report] = {}
    for target, r in targets.items():
        reports[target] = r.host
        for label, nested in sorted(r.nested.items()):
            reports[f"{target}/{label}"] = nested
    return reports


def previous_state(body: str) -> Optional[State]:
    match = STATE.search(body)
    if not match:
        return None
    state: State = json.loads(match[1])
    return state


def state(reports: dict[str, Report]) -> State:
    return {machine: sorted({f"{f.pname} {f.cve}" for f in r.findings
                             if f.severity in ALERTING})
            for machine, r in reports.items()}


def new_alerts(previous: Optional[State], current: State) -> State:
    """Critical and high entries not in the previous state.

    Without a previous state, everything is old: the first report alerts
    about nothing.
    """
    if previous is None:
        return {}
    alerts = {m: sorted(set(entries) - set(previous.get(m, [])))
              for m, entries in current.items()}
    return {m: e for m, e in alerts.items() if e}


def score_text(f: Finding) -> str:
    return "" if f.score is None else f" {f.score}"


def rows(findings: list[Finding]) -> list[PackageRow]:
    by_package: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        by_package.setdefault((f.pname, f.version), []).append(f)
    result = [PackageRow(p, v, sorted(fs, key=lambda f: -(f.score or 0)))
              for (p, v), fs in by_package.items()]
    return sorted(result, key=lambda r: (-len(r.findings), r.package))


def cve_list(findings: list[Finding]) -> str:
    return ", ".join(f"[{f.cve}]({NVD}{f.cve}){score_text(f)}" for f in findings)


def summary(reports: dict[str, Report]) -> list[str]:
    lines = ["| Machine | " + " | ".join(s.value.capitalize() for s in SEVERITIES)
             + " | Suppressed |",
             "| --- " * (len(SEVERITIES) + 2) + "|"]
    for machine, r in reports.items():
        counts = [sum(f.severity == s for f in r.findings) for s in SEVERITIES]
        lines.append(f"| {machine} | " + " | ".join(map(str, counts))
                     + f" | {len(r.suppressed)} |")
    return lines


def machine_section(machine: str, report: Report, linked: set[Severity]) -> list[str]:
    """Severities in `linked` list every CVE; the others only count them."""
    lines = [f"## {machine}", ""]
    if not report.findings:
        return lines + ["No open CVEs.", ""]
    for severity in SEVERITIES:
        findings = [f for f in report.findings if f.severity == severity]
        if not findings:
            continue
        lines += [f"<details><summary>{severity.value.capitalize()} ({len(findings)})</summary>",
                  "",
                  "| Package | Version | CVEs |", "| --- | --- | --- |"]
        for r in rows(findings):
            listed = cve_list(r.findings) if severity in linked else str(len(r.findings))
            lines.append(f"| {r.package} | {r.version} | {listed} |")
        lines += ["", "</details>", ""]
    return lines


def body(reports: dict[str, Report], header: str) -> str:
    """The issue body, listing fewer severities in full until it fits."""
    current = state(reports)
    shorten: list[Callable[[set[Severity]], set[Severity]]] = [
        lambda s: s, lambda s: s - {Severity.UNSCORED, Severity.LOW},
        lambda s: s - {Severity.MEDIUM}, lambda s: s - {Severity.HIGH}, lambda s: set(),
    ]
    text = ""
    for step in shorten:
        linked = step(set(SEVERITIES))
        lines = [f"<!-- cve-report-state: {json.dumps(current)} -->", header, ""]
        lines += summary(reports) + [""]
        if linked != set(SEVERITIES):
            lines += ["Some severities only show counts, to keep this issue within "
                      "GitHub's size limit. Run `cves.py open` on a target for all CVEs.", ""]
        for machine, report in reports.items():
            lines += machine_section(machine, report, linked)
        text = "\n".join(lines)
        if len(text) <= MAX_BODY:
            return text
    return text[:MAX_BODY] + "\n\n(truncated)\n"


def alert(alerts: State) -> str:
    if not alerts:
        return ""
    lines = ["New critical or high CVEs since the last report:", ""]
    for machine, entries in alerts.items():
        links = []
        for entry in entries:
            package, _, cve = entry.partition(" ")
            links.append(f"{package} [{cve}]({NVD}{cve})")
        lines.append(f"- **{machine}**: " + ", ".join(links))
    return "\n".join(lines) + "\n"


def main() -> None:
    reports_dir, previous_path, header, body_out, alert_out = sys.argv[1:]
    try:
        reports = load_reports(reports_dir)
    except ValueError as e:
        sys.exit(f"{reports_dir}/{e}")
    with open(previous_path) as f:
        previous = previous_state(f.read())
    with open(body_out, "w") as f:
        f.write(body(reports, header))
    with open(alert_out, "w") as f:
        f.write(alert(new_alerts(previous, state(reports))))


if __name__ == "__main__":
    main()
