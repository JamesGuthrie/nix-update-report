from __future__ import annotations

import unittest
from typing import Optional
from unittest import mock

import targets as tg
import update_report as ur
from cves import Comparison, CveId, Finding, Resolution, Score, Source
from package_diff import Change
from targets import DrvPath, Nested, NestedLabel, Target, TargetSpec
from update_report import NestedMismatch, PartReport, TargetChange, TargetMismatch, TargetReport

OLD = TargetSpec(DrvPath("/nix/store/aaa-nixos-system-old.drv"), {})
NEW = TargetSpec(DrvPath("/nix/store/bbb-nixos-system-new.drv"), {})
HOST = Target("host")
OTHER = Target("other")
VM = NestedLabel("vm")
EMPTY = PartReport([], 0, None)


def finding(cve: str, pname: str, score: Optional[float]) -> Finding:
    return Finding(CveId(cve), pname, "1.0", None if score is None else Score(score), "")


def resolved(*findings: Finding) -> list[Resolution]:
    return [Resolution(f, frozenset({Source.NVD})) for f in findings]


def with_vm(spec: TargetSpec, vm_drv: str) -> TargetSpec:
    return TargetSpec(spec.drv, {VM: Nested(tg.pd.StorePath("ccc-image"), DrvPath(vm_drv))})


def report(host: PartReport = EMPTY, nested: Optional[dict[NestedLabel, PartReport]] = None
           ) -> TargetReport:
    return TargetReport(HOST, host, nested or {})


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

    def test_mismatch_names_missing_nested_systems(self) -> None:
        result = ur.affected({HOST: OLD}, {HOST: with_vm(NEW, "/nix/store/v.drv")})
        self.assertEqual(result, NestedMismatch(HOST, [VM], []))
        assert isinstance(result, NestedMismatch)
        self.assertEqual(result.message(),
                         "host: nested systems missing before the update: vm")

    def test_parse_rejects_non_object_targets(self) -> None:
        with self.assertRaises(ValueError):
            ur.parse_derivations('{"host": "/nix/store/aaa-nixos-system-old.drv"}')


class TargetReportTest(unittest.TestCase):
    def test_only_changed_nested_systems_are_reported(self) -> None:
        same_vm = TargetChange(HOST, with_vm(OLD, "/nix/store/v.drv"),
                                   with_vm(NEW, "/nix/store/v.drv"))
        new_vm = TargetChange(HOST, with_vm(OLD, "/nix/store/v1.drv"),
                                 with_vm(NEW, "/nix/store/v2.drv"))
        part = tg.Part({}, set())
        loaded = tg.LoadedTarget(part, {VM: part})

        with mock.patch.object(tg, "load_target", return_value=loaded):
            unchanged = ur.target_report(same_vm, None)
            changed = ur.target_report(new_vm, None)

        assert isinstance(unchanged, TargetReport) and isinstance(changed, TargetReport)
        self.assertEqual(unchanged.nested, {})
        self.assertEqual(list(changed.nested), [VM])

    def test_nested_failure_is_returned(self) -> None:
        failure = tg.NestedLeak(HOST, VM)
        with mock.patch.object(tg, "load_target", return_value=failure):
            self.assertEqual(ur.target_report(TargetChange(HOST, OLD, NEW), None), failure)


class BodyTest(unittest.TestCase):
    def test_only_affected_targets_get_a_section(self) -> None:
        text = ur.body("", [report()])
        self.assertIn("### host", text)
        self.assertNotIn("### other", text)

    def test_version_changes(self) -> None:
        text = ur.body("", [report(PartReport([Change("curl", ["8.20.0"], ["8.22.0"]),
                                               Change("gone", ["1"], [])], 3, None))])
        self.assertIn("| curl | 8.20.0 | 8.22.0 |", text)
        self.assertIn("| gone | 1 | - |", text)
        self.assertIn("3 packages rebuilt without a version change.", text)

    def test_no_version_changes(self) -> None:
        text = ur.body("", [report(PartReport([], 5, None))])
        self.assertIn("No version changes.", text)

    def test_security_section(self) -> None:
        comparison = Comparison(
            resolved(finding("CVE-2026-0001", "openssl", 9.8),
                     finding("CVE-2026-0002", "openssl", 5.5),
                     finding("CVE-2026-0003", "curl", None)),
            [finding("CVE-2026-0004", "curl", 7.0)])
        lines = ur.body("", [report(PartReport([], 0, comparison))]).splitlines()
        self.assertIn("#### Security", lines)
        table = lines.index("| Package | Resolved | CVSS | Critical | High |")
        self.assertEqual(lines[table + 2:table + 4],
                         ["| openssl | 2 | 5.5-9.8 | 1 | 0 |", "| curl | 1 | - | 0 | 0 |"])
        self.assertIn("- [CVE-2026-0004](https://nvd.nist.gov/vuln/detail/CVE-2026-0004)"
                      " in curl 1.0 (high, CVSS 7)", lines)

    def test_no_resolved_cves(self) -> None:
        text = ur.body("", [report(PartReport([], 0, Comparison([], [])))])
        self.assertIn("No resolved CVEs found.", text)
        self.assertNotIn("Introduced CVEs:", text)

    def test_without_cves(self) -> None:
        text = ur.body("", [report()])
        self.assertNotIn("Security", text)

    def test_nested_system_gets_a_subsection(self) -> None:
        nested = PartReport([Change("openssh", ["10.3p1"], ["10.5p1"])], 0, Comparison([], []))
        lines = ur.body("", [report(nested={VM: nested})]).splitlines()

        subsection = lines.index("#### host/vm")
        self.assertIn("| openssh | 10.3p1 | 10.5p1 |", lines[subsection:])
        self.assertIn("##### Security", lines[subsection:])

    def test_warnings_are_removed_from_the_log(self) -> None:
        log = "warning: Git tree is dirty\nUpdated input 'nixpkgs':\n"
        self.assertTrue(ur.body(log, []).startswith("```\nUpdated input 'nixpkgs':\n```"))

    def test_truncated(self) -> None:
        changes = [Change(f"package-{i}", ["1"], ["2"]) for i in range(5000)]
        text = ur.body("", [report(PartReport(changes, 0, None))])
        self.assertEqual(len(text), ur.MAX_BODY + len("\n\n(truncated)\n"))
        self.assertTrue(text.endswith("\n\n(truncated)\n"))


if __name__ == "__main__":
    unittest.main()
