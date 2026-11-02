from __future__ import annotations

import json
import unittest
from typing import Optional

import cve_issue as ci
import cves
from cves import Finding, Report, Score, Severity
from package_diff import Json


def finding_json(cve: str, package: str = "curl", score: Optional[float] = 7.5) -> Json:
    """A finding as `cves.py open` writes it."""
    severity = Severity.of(None if score is None else Score(score))
    return {"cve": cve, "package": package, "version": "8.22.0", "score": score,
            "severity": severity.value, "description": ""}


def report_json(*findings: Json, suppressed: int = 0) -> Json:
    return {"findings": list(findings),
            "suppressed": [f"CVE-2026-9{i:03}" for i in range(suppressed)]}


def finding(cve: str, package: str = "curl", score: Optional[float] = 7.5) -> Finding:
    return cves.parse_finding(finding_json(cve, package, score))


def report(*findings: Json, suppressed: int = 0) -> Report:
    return cves.parse_report(report_json(*findings, suppressed=suppressed))


REPORTS = {
    "router": report(finding_json("CVE-2026-0001", score=9.8),
                     finding_json("CVE-2026-0002"),
                     finding_json("CVE-2026-0003", "vim", 5.5),
                     suppressed=2),
    "titan": report(),
}


class StateTest(unittest.TestCase):
    def test_state_lists_critical_and_high_findings(self) -> None:
        self.assertEqual(ci.state(REPORTS), {
            "router": ["curl CVE-2026-0001", "curl CVE-2026-0002"],
            "titan": [],
        })

    def test_state_round_trips_through_the_body(self) -> None:
        self.assertEqual(ci.previous_state(ci.body(REPORTS, "header")), ci.state(REPORTS))

    def test_no_state_in_an_empty_body(self) -> None:
        self.assertIsNone(ci.previous_state(""))


class AlertTest(unittest.TestCase):
    def test_new_entries_alert(self) -> None:
        previous = {"router": ["curl CVE-2026-0001"]}

        self.assertEqual(ci.new_alerts(previous, ci.state(REPORTS)),
                         {"router": ["curl CVE-2026-0002"]})

    def test_first_report_alerts_about_nothing(self) -> None:
        self.assertEqual(ci.new_alerts(None, ci.state(REPORTS)), {})

    def test_resolved_entries_do_not_alert(self) -> None:
        previous = {"router": ["curl CVE-2026-0001", "curl CVE-2026-0002", "jq CVE-2026-0009"]}

        self.assertEqual(ci.new_alerts(previous, ci.state(REPORTS)), {})

    def test_alert_text(self) -> None:
        self.assertEqual(ci.alert({"router": ["curl CVE-2026-0002"]}), "\n".join([
            "New critical or high CVEs since the last report:",
            "",
            "- **router**: curl [CVE-2026-0002](https://nvd.nist.gov/vuln/detail/CVE-2026-0002)",
            "",
        ]))
        self.assertEqual(ci.alert({}), "")


class NestedTest(unittest.TestCase):
    TARGETS = {name: cves.parse_target_report(json.dumps(value)) for name, value in {
        "midnight": {"findings": [finding_json("CVE-2026-0001")], "suppressed": [],
                     "nested": {"vm": report_json(finding_json("CVE-2026-0002", "openssh"))}},
        "router": {"findings": [], "suppressed": [], "nested": {}},
    }.items()}

    def test_nested_systems_follow_their_target(self) -> None:
        reports = ci.flatten(self.TARGETS)

        self.assertEqual(list(reports), ["midnight", "midnight/vm", "router"])
        self.assertEqual(reports["midnight"], report(finding_json("CVE-2026-0001")))
        self.assertEqual(reports["midnight/vm"],
                         report(finding_json("CVE-2026-0002", "openssh")))

    def test_summary_and_sections(self) -> None:
        reports = ci.flatten(self.TARGETS)

        self.assertIn("| midnight/vm | 0 | 1 | 0 | 0 | 0 | 0 |", ci.summary(reports))
        self.assertIn("## midnight/vm", ci.body(reports, "header").splitlines())

    def test_alerts_name_the_nested_system(self) -> None:
        previous = {"midnight": ["curl CVE-2026-0001"]}

        self.assertEqual(ci.new_alerts(previous, ci.state(ci.flatten(self.TARGETS))),
                         {"midnight/vm": ["openssh CVE-2026-0002"]})


class BodyTest(unittest.TestCase):
    def test_summary(self) -> None:
        self.assertEqual(ci.summary(REPORTS), [
            "| Machine | Critical | High | Medium | Low | Unscored | Suppressed |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            "| router | 1 | 1 | 1 | 0 | 0 | 2 |",
            "| titan | 0 | 0 | 0 | 0 | 0 | 0 |",
        ])

    def test_machine_section_groups_by_severity_and_package(self) -> None:
        lines = ci.machine_section("router", REPORTS["router"], set(ci.SEVERITIES))

        self.assertIn("<details><summary>Critical (1)</summary>", lines)
        self.assertIn("<details><summary>Medium (1)</summary>", lines)
        self.assertNotIn("<details><summary>Low (0)</summary>", lines)
        self.assertIn("| vim | 8.22.0 | [CVE-2026-0003]"
                      "(https://nvd.nist.gov/vuln/detail/CVE-2026-0003) 5.5 |", lines)

    def test_cves_sorted_by_score(self) -> None:
        text = ci.cve_list(ci.rows([finding("CVE-2026-0001", score=7.1),
                                    finding("CVE-2026-0002", score=None),
                                    finding("CVE-2026-0003", score=8.8)])[0].findings)

        self.assertEqual(text, "[CVE-2026-0003](https://nvd.nist.gov/vuln/detail/CVE-2026-0003)"
                               " 8.8, [CVE-2026-0001]"
                               "(https://nvd.nist.gov/vuln/detail/CVE-2026-0001) 7.1, "
                               "[CVE-2026-0002](https://nvd.nist.gov/vuln/detail/CVE-2026-0002)")

    def test_machine_without_findings(self) -> None:
        self.assertEqual(ci.machine_section("titan", REPORTS["titan"], set()),
                         ["## titan", "", "No open CVEs.", ""])

    def test_unlinked_severities_only_count(self) -> None:
        lines = ci.machine_section("router", REPORTS["router"], {Severity.CRITICAL, Severity.HIGH})

        self.assertIn("| vim | 8.22.0 | 1 |", lines)

    def test_long_body_lists_fewer_severities(self) -> None:
        many = report(*[finding_json(f"CVE-2026-{i:04}", f"pkg{i}", 2.0) for i in range(2000)],
                      finding_json("CVE-2026-9999", score=9.8))

        text = ci.body({"router": many}, "header")

        self.assertLessEqual(len(text), ci.MAX_BODY)
        self.assertIn("only show counts", text)
        self.assertIn("[CVE-2026-9999]", text)
        self.assertNotIn("[CVE-2026-0001]", text)


if __name__ == "__main__":
    unittest.main()
