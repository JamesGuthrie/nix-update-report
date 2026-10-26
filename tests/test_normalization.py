"""Tests of normalized-derivations against tests/fixture. They evaluate NixOS
configurations, so they need Nix and take about a minute."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "normalized-derivations")
FIXTURE = "path:" + os.path.join(ROOT, "tests", "fixture")
REVISIONS = ["a" * 40, "b" * 40]
STORE_PATH = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[^/\"'\s]+")


def normalized(*args: str) -> dict[str, str]:
    output = subprocess.run([SCRIPT, "--flake", FIXTURE, *args],
                            check=True, capture_output=True, text=True).stdout
    result: dict[str, str] = json.loads(output)
    return result


def evaluate(expr: str) -> str:
    """The string `expr` evaluates to, where `cfg` is revision-a's configuration."""
    full = (f'let cfg = (builtins.getFlake "{FIXTURE}").nixosConfigurations.revision-a; '
            f"in {expr}")
    return subprocess.run(["nix", "eval", "--impure", "--raw", "--expr", full],
                          check=True, capture_output=True, text=True).stdout


def derivations(drv: str) -> str:
    """`nix derivation show -r` of `drv`, as text."""
    return subprocess.run(["nix", "derivation", "show", "-r", drv],
                          check=True, capture_output=True, text=True).stdout


class RevisionTest(unittest.TestCase):
    def test_revisions_give_the_same_derivation(self) -> None:
        raw = {evaluate(f'(builtins.getFlake "{FIXTURE}").nixosConfigurations.revision-{t}'
                        ".config.system.build.toplevel.drvPath") for t in "ab"}
        self.assertEqual(len(raw), 2, "the fixture's revisions should differ")
        drvs = normalized()
        self.assertEqual(drvs["revision-a"], drvs["revision-b"])

    def test_no_revision_or_source_in_the_closure(self) -> None:
        text = derivations(normalized("revision-a")["revision-a"])
        source = evaluate('(builtins.getFlake "' + FIXTURE + '").inputs.nixpkgs.outPath')
        for leak in [REVISIONS[0], REVISIONS[0][:7], "fake-nixpkgs", source]:
            self.assertNotIn(leak, text)


class W3mTest(unittest.TestCase):
    """Turning off the manual drops nixos-help, and the normalization adds its
    fallback browser back. This fails when nixos-help refers to anything else
    besides the manual, so that the normalization can be updated."""

    def test_nixos_help_refers_only_to_w3m_and_the_manual(self) -> None:
        help_drv = evaluate('(builtins.head (builtins.filter (p: (p.name or "") == "nixos-help")'
                            " cfg.config.environment.systemPackages)).drvPath")
        shown = json.loads(subprocess.run(["nix", "derivation", "show", help_drv],
                                          check=True, capture_output=True, text=True).stdout)
        drvs = shown.get("derivations", shown)
        script_drv = next(name for name in drvs[help_drv.removeprefix("/nix/store/")]["inputs"]["drvs"]
                          if name.endswith("-nixos-help.drv"))
        shown = json.loads(subprocess.run(["nix", "derivation", "show", f"/nix/store/{script_drv}"],
                                          check=True, capture_output=True, text=True).stdout)
        script = next(iter(shown.get("derivations", shown).values()))
        text = script["env"].get("text") or script["structuredAttrs"]["text"]
        expected = {evaluate(f"cfg.{attr}.outPath") for attr in [
            "pkgs.runtimeShellPackage", "pkgs.w3m-nographics",
            "config.system.build.manual.manualHTML"]}
        self.assertEqual(set(STORE_PATH.findall(text)), expected)

    def test_w3m_is_in_the_normalized_system(self) -> None:
        w3m = evaluate("cfg.pkgs.w3m-nographics.outPath")
        self.assertIn(w3m, derivations(normalized("revision-a")["revision-a"]))


class NormalizationFileTest(unittest.TestCase):
    def file(self, text: str) -> str:
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "normalization.nix")
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_unknown_attribute_fails(self) -> None:
        path = self.file("{ flake }: { nixoss = [ ]; }")
        result = subprocess.run([SCRIPT, "--flake", FIXTURE, "--normalization", path, "--list"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown attributes nixoss", result.stderr)

    def test_empty_file_changes_nothing(self) -> None:
        path = self.file("{ flake }: { }")
        self.assertEqual(normalized("--normalization", path, "revision-a"),
                         normalized("revision-a"))

    def test_deployed_replaces_the_toplevel(self) -> None:
        path = self.file("{ flake }: { deployed = name: cfg: cfg.config.system.build.etc; }")
        drv = normalized("--normalization", path, "revision-a")["revision-a"]
        self.assertTrue(drv.endswith("-etc.drv"), drv)

    def test_modules_apply(self) -> None:
        path = self.file('{ flake }: { nixos = [ { environment.etc.marker.text = "x"; } ]; }')
        self.assertNotEqual(normalized("--normalization", path, "revision-a"),
                            normalized("revision-a"))


if __name__ == "__main__":
    unittest.main()
