from __future__ import annotations

import unittest
from typing import Optional

import update_report as ur
from cves import Comparison, CveId, Finding, Resolution, Score, Source
from package_diff import Change
from update_report import DrvPath, Target, TargetChange, TargetMismatch, TargetReport

OLD = DrvPath("/nix/store/aaa-nixos-system-old.drv")
NEW = DrvPath("/nix/store/bbb-nixos-system-new.drv")
HOST = Target("host")
OTHER = Target("other")


def finding(cve: str, pname: str, score: Optional[float]) -> Finding:
    return Finding(CveId(cve), pname, "1.0", None if score is None else Score(score), "")


def resolved(*findings: Finding) -> list[Resolution]:
    return [Resolution(f, frozenset({Source.NVD})) for f in findings]


class AffectedTest(unittest.TestCase):
    def test_identical(self) -> None:
        drvs = {HOST: OLD, OTHER: OLD}
        self.assertEqual(ur.affected(drvs, dict(drvs)), [])

    def test_changed_target(self) -> None:
        self.assertEqual(ur.affected({HOST: OLD, OTHER: OLD}, {HOST: NEW, OTHER: OLD}),
                         [TargetChange(HOST, OLD, NEW)])

    def test_mismatch_names_missing_targets(self) -> None:
        result = ur.affected({HOST: OLD}, {OTHER: OLD})
        self.assertEqual(result, TargetMismatch([OTHER], [HOST]))
        assert isinstance(result, TargetMismatch)
        self.assertEqual(result.message(),
                         "targets missing before the update: other; missing after the update: host")

    def test_parse_rejects_non_string_values(self) -> None:
        with self.assertRaises(ValueError):
            ur.parse_derivations('{"host": 1}')


class BodyTest(unittest.TestCase):
    def test_only_affected_targets_get_a_section(self) -> None:
        text = ur.body("", [TargetReport(HOST, [], 0, None)])
        self.assertIn("### host", text)
        self.assertNotIn("### other", text)

    def test_version_changes(self) -> None:
        text = ur.body("", [TargetReport(HOST, [Change("curl", ["8.20.0"], ["8.22.0"]),
                                                Change("gone", ["1"], [])], 3, None)])
        self.assertIn("| curl | 8.20.0 | 8.22.0 |", text)
        self.assertIn("| gone | 1 | - |", text)
        self.assertIn("3 packages rebuilt without a version change.", text)

    def test_no_version_changes(self) -> None:
        text = ur.body("", [TargetReport(HOST, [], 5, None)])
        self.assertIn("No version changes.", text)

    def test_security_section(self) -> None:
        comparison = Comparison(
            resolved(finding("CVE-2026-0001", "openssl", 9.8),
                     finding("CVE-2026-0002", "openssl", 5.5),
                     finding("CVE-2026-0003", "curl", None)),
            [finding("CVE-2026-0004", "curl", 7.0)])
        lines = ur.body("", [TargetReport(HOST, [], 0, comparison)]).splitlines()
        table = lines.index("| Package | Resolved | CVSS | Critical | High |")
        self.assertEqual(lines[table + 2:table + 4],
                         ["| openssl | 2 | 5.5-9.8 | 1 | 0 |", "| curl | 1 | - | 0 | 0 |"])
        self.assertIn("- [CVE-2026-0004](https://nvd.nist.gov/vuln/detail/CVE-2026-0004)"
                      " in curl 1.0 (high, CVSS 7)", lines)

    def test_no_resolved_cves(self) -> None:
        text = ur.body("", [TargetReport(HOST, [], 0, Comparison([], []))])
        self.assertIn("No resolved CVEs found.", text)
        self.assertNotIn("Introduced CVEs:", text)

    def test_without_cves(self) -> None:
        text = ur.body("", [TargetReport(HOST, [], 0, None)])
        self.assertNotIn("Security", text)

    def test_warnings_are_removed_from_the_log(self) -> None:
        log = "warning: Git tree is dirty\nUpdated input 'nixpkgs':\n"
        self.assertTrue(ur.body(log, []).startswith("```\nUpdated input 'nixpkgs':\n```"))

    def test_truncated(self) -> None:
        changes = [Change(f"package-{i}", ["1"], ["2"]) for i in range(5000)]
        text = ur.body("", [TargetReport(HOST, changes, 0, None)])
        self.assertEqual(len(text), ur.MAX_BODY + len("\n\n(truncated)\n"))
        self.assertTrue(text.endswith("\n\n(truncated)\n"))


if __name__ == "__main__":
    unittest.main()
