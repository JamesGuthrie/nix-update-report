from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from typing import Optional

import cves
import targets as tg
from cves import CveId, Finding, Report, Resolution, Score, Severity, Source, VulnixEntry
from package_diff import Json
from test_package_diff import Graph
from test_targets import VM, Machine

A = CveId("CVE-2026-0001")
B = CveId("CVE-2026-0002")
C = CveId("CVE-2026-0003")

SCORES = {A: Score(9.8), B: Score(5.5)}
DESCRIPTIONS = {A: "a", B: "b", C: "c"}


def entry(pname: str, version: str, affected: list[CveId],
          whitelisted: Optional[list[CveId]] = None) -> VulnixEntry:
    listed = affected + (whitelisted or [])
    return {"pname": pname, "version": version, "affected_by": list(affected),
            "whitelisted": list(whitelisted or []),
            "cvssv3_basescore": {c: SCORES[c] for c in listed if c in SCORES},
            "description": {c: DESCRIPTIONS[c] for c in listed}}


def finding(cve: CveId, pname: str = "curl", version: str = "8.20.0") -> Finding:
    return Finding(cve, pname, version, SCORES.get(cve), DESCRIPTIONS[cve])


class SeverityTest(unittest.TestCase):
    def test_bands(self) -> None:
        for value, severity in [(10.0, Severity.CRITICAL), (9.0, Severity.CRITICAL),
                                (8.9, Severity.HIGH), (7.0, Severity.HIGH),
                                (6.9, Severity.MEDIUM), (4.0, Severity.MEDIUM),
                                (3.9, Severity.LOW), (0.1, Severity.LOW)]:
            self.assertEqual(Severity.of(Score(value)), severity, value)

    def test_unscored(self) -> None:
        self.assertEqual(Severity.of(None), Severity.UNSCORED)
        self.assertEqual(Severity.of(Score(0.0)), Severity.UNSCORED)

    def test_finding_derives_its_severity_from_its_score(self) -> None:
        self.assertEqual(finding(A).severity, Severity.CRITICAL)
        self.assertEqual(finding(C).severity, Severity.UNSCORED)


class ReportTest(unittest.TestCase):
    def test_findings_from_vulnix(self) -> None:
        r = cves.report([
            entry("curl", "8.20.0", [A, B]),
            entry("jq", "1.8.1", [C]),
        ])

        self.assertEqual(r.findings, [
            finding(A), finding(B), finding(C, "jq", "1.8.1"),
        ])
        self.assertEqual(r.suppressed, [])

    def test_cve_without_score_or_description(self) -> None:
        e = entry("curl", "8.20.0", [C])
        e["description"] = {}
        [f] = cves.report([e]).findings

        self.assertEqual((f.score, f.description, f.severity), (None, "", Severity.UNSCORED))

    def test_whitelisted_cves_are_counted_not_listed(self) -> None:
        r = cves.report([entry("dash", "0.5.13.3", [], whitelisted=[B])])

        self.assertEqual(r.findings, [])
        self.assertEqual(r.suppressed, [B])


class CompareTest(unittest.TestCase):
    def test_resolved_introduced_and_unchanged(self) -> None:
        old = Report([finding(A), finding(B)], [])
        new = Report([finding(B, version="8.22.0"), finding(C, version="8.22.0")], [])

        c = cves.compare(old, new, {}, {}, {})

        self.assertEqual(c.resolved, [Resolution(finding(A), frozenset({Source.NVD}))])
        self.assertEqual(c.introduced, [finding(C, version="8.22.0")])

    def test_sources(self) -> None:
        old = Report([finding(A), finding(B)], [])
        new = Report([], [])

        c = cves.compare(old, new, {}, {"curl": {B, C}}, {"curl": {"8.20.0"}})

        self.assertEqual(c.resolved, [
            Resolution(finding(A), frozenset({Source.NVD})),
            Resolution(finding(B), frozenset({Source.NVD, Source.PATCH})),
            Resolution(Finding(C, "curl", "8.20.0", None, ""), frozenset({Source.PATCH})),
        ])

    def test_patches_already_applied_before_are_not_resolutions(self) -> None:
        c = cves.compare(Report([], []), Report([], []),
                         {"curl": {C}}, {"curl": {C}}, {"curl": {"8.20.0"}})

        self.assertEqual(c.resolved, [])

    def test_resolution_needs_a_source(self) -> None:
        with self.assertRaises(ValueError):
            Resolution(finding(A), frozenset())


class PatchCvesTest(unittest.TestCase):
    def system(self, env: Optional[dict[str, str]] = None,
               structured: Optional[dict[str, Json]] = None) -> cves.System:
        g = Graph()
        drv = g.add("sudo-1.9.17p2", env=env, structured=structured)
        return cves.System(g.drvs, [drv])

    def test_cve_ids_in_patch_names(self) -> None:
        system = self.system(env={"patches": "/nix/store/x-CVE-2026-96512_1.patch "
                                             "/nix/store/y-cve-2026-96513.patch "
                                             "/nix/store/z-fix.patch"})

        self.assertEqual(cves.patch_cves(system),
                         {"sudo": {CveId("CVE-2026-96512"), CveId("CVE-2026-96513")}})

    def test_structured_attrs(self) -> None:
        system = self.system(structured={"patches": ["/nix/store/x-CVE-2026-96512.patch"]})

        self.assertEqual(cves.patch_cves(system), {"sudo": {CveId("CVE-2026-96512")}})

    def test_no_cve_patches(self) -> None:
        self.assertEqual(cves.patch_cves(self.system(env={"patches": "/nix/store/x-fix.patch"})),
                         {})


class TargetReportTest(unittest.TestCase):
    def loaded(self) -> tg.LoadedTarget:
        m = Machine()
        loaded = m.load(m.spec(m.image))
        assert isinstance(loaded, tg.LoadedTarget)
        return loaded

    @staticmethod
    def scan_names(system: cves.System) -> Report:
        """A report with one unscored finding per runtime derivation, named after it."""
        return Report([Finding(CveId(f"CVE-2026-{i:04}"),
                               name.split("-", 1)[1].removesuffix(".drv"), "", None, "")
                       for i, name in enumerate(system.runtime)], [])

    def test_nested_packages_are_only_in_the_nested_report(self) -> None:
        r = cves.scan_target(self.loaded(), self.scan_names)

        host = {f.pname for f in r.host.findings}
        nested = {f.pname for f in r.nested[VM].findings}
        self.assertIn("curl-8.22.0", host)
        self.assertNotIn("openssh-10.3p1", host)
        self.assertIn("openssh-10.3p1", nested)

    def test_json_lists_nested_reports_beside_the_host_report(self) -> None:
        empty = Report([], [])
        r = cves.TargetReport(Report([finding(A)], [B]), {VM: empty})

        self.assertEqual(cves.target_report_json(r), {
            "findings": [cves.finding_json(finding(A))],
            "suppressed": [B],
            "nested": {"vm": {"findings": [], "suppressed": []}},
        })

    def test_json_without_nested_systems(self) -> None:
        r = cves.TargetReport(Report([], []), {})

        self.assertEqual(cves.target_report_json(r),
                         {"findings": [], "suppressed": [], "nested": {}})

    def test_text_lists_nested_findings_beside_the_host_by_score(self) -> None:
        r = cves.TargetReport(Report([finding(B), finding(C, "vim", "9.2")], []),
                              {VM: Report([finding(A, "openssh", "10.3p1")], [])})

        self.assertEqual(cves.target_report_text(tg.Target("myhost"), r), "\n".join([
            "myhost/vm  critical  9.8  openssh  10.3p1  CVE-2026-0001",
            "myhost     medium    5.5  curl     8.20.0  CVE-2026-0002",
            "myhost     unscored  -    vim      9.2     CVE-2026-0003",
        ]))

    def test_text_without_findings(self) -> None:
        r = cves.TargetReport(Report([], [B]), {VM: Report([], [])})

        self.assertEqual(cves.target_report_text(tg.Target("myhost"), r), "No open CVEs.")

    def test_json_parses_back_to_the_report(self) -> None:
        r = cves.TargetReport(Report([finding(A), finding(C)], [B]),
                              {VM: Report([finding(B, "openssh")], [])})

        self.assertEqual(cves.parse_target_report(json.dumps(cves.target_report_json(r))), r)

    def test_malformed_json_fails(self) -> None:
        good = {"cve": A, "package": "curl", "version": "8.20.0", "score": 9.8,
                "severity": "critical", "description": "a"}
        for value in [[], {"findings": [], "suppressed": []},
                      {"findings": [good], "suppressed": [1], "nested": {}},
                      {"findings": [good | {"score": "9.8"}], "suppressed": [], "nested": {}},
                      {"findings": [good | {"score": True}], "suppressed": [], "nested": {}},
                      {"findings": [], "suppressed": [], "nested": {"vm": {}}}]:
            with self.subTest(value), self.assertRaises(ValueError):
                cves.parse_target_report(json.dumps(value))

    def test_unknown_target(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            f.write('{"host": {"drv": "/nix/store/a-host.drv", "nested": {}}}')
            f.flush()
            options = cves.VulnixOptions(cves.DEFAULT_MIRROR, None, None)

            self.assertEqual(cves.open_target(f.name, tg.Target("other"), options),
                             f"other: not in {f.name}")


class VulnixOptionsTest(unittest.TestCase):
    def options(self, *argv: str) -> cves.VulnixOptions:
        parser = argparse.ArgumentParser()
        cves.add_vulnix_arguments(parser)
        return cves.vulnix_options(parser.parse_args(list(argv)))

    def test_default_whitelist_in_working_directory(self) -> None:
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            try:
                self.assertIsNone(self.options().whitelist)
                open(cves.DEFAULT_WHITELIST, "w").close()
                self.assertEqual(self.options().whitelist, cves.DEFAULT_WHITELIST)
            finally:
                os.chdir(cwd)

    def test_defaults(self) -> None:
        options = self.options("--whitelist", "/nonexistent")
        self.assertEqual(options, cves.VulnixOptions(cves.DEFAULT_MIRROR, None, None))

    def test_mirror_ends_with_slash(self) -> None:
        self.assertEqual(self.options("--mirror", "https://example.org/nvd").mirror,
                         "https://example.org/nvd/")


if __name__ == "__main__":
    unittest.main()
