from __future__ import annotations

import unittest
from typing import Optional

import cve_issue as ci
from cve_issue import FindingJson, ReportJson


def finding(cve: str, package: str = "curl", severity: str = "high",
            score: Optional[float] = 7.5) -> FindingJson:
    return {"cve": cve, "package": package, "version": "8.22.0", "score": score,
            "severity": severity, "description": ""}


def report(*findings: FindingJson, suppressed: int = 0) -> ReportJson:
    return {"findings": list(findings),
            "suppressed": [f"CVE-2026-9{i:03}" for i in range(suppressed)]}


REPORTS = {
    "router": report(finding("CVE-2026-0001", severity="critical", score=9.8),
                     finding("CVE-2026-0002"),
                     finding("CVE-2026-0003", "vim", "medium", 5.5),
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
        lines = ci.machine_section("router", REPORTS["router"], {"critical", "high"})

        self.assertIn("| vim | 8.22.0 | 1 |", lines)

    def test_long_body_lists_fewer_severities(self) -> None:
        many = report(*[finding(f"CVE-2026-{i:04}", f"pkg{i}", "low", 2.0) for i in range(2000)],
                      finding("CVE-2026-9999", severity="critical", score=9.8))

        text = ci.body({"router": many}, "header")

        self.assertLessEqual(len(text), ci.MAX_BODY)
        self.assertIn("only show counts", text)
        self.assertIn("[CVE-2026-9999]", text)
        self.assertNotIn("[CVE-2026-0001]", text)


if __name__ == "__main__":
    unittest.main()
