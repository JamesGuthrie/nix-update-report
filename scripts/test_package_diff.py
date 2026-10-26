from __future__ import annotations

import email.message
import hashlib
import io
import json
import unittest
import urllib.error
from collections.abc import Iterable
from typing import Optional
from unittest import mock

import package_diff as pd
from package_diff import Change, Derivation, Derivations, DrvName, Json, Lookup, StorePath

NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"


def store_path(name: str) -> StorePath:
    digest = hashlib.sha256(name.encode()).digest()
    return StorePath("".join(NIX_BASE32[b % 32] for b in digest[:32]) + "-" + name)


def derivation(
    name: str,
    inputs: Iterable[DrvName] = (),
    env: Optional[dict[str, str]] = None,
    structured: Optional[dict[str, Json]] = None,
) -> Derivation:
    return {
        "name": name,
        "env": env or {},
        "structuredAttrs": structured,
        "args": [],
        "outputs": {"out": {"path": store_path(name)}},
        "inputs": {
            "drvs": {i: {"dynamicOutputs": {}, "outputs": ["out"]} for i in inputs},
            "srcs": [],
        },
    }


class Graph:
    """Builds the `derivations` part of `nix derivation show --recursive`."""

    def __init__(self) -> None:
        self.drvs: Derivations = {}

    def add(
        self,
        name: str,
        inputs: Iterable[DrvName] = (),
        env: Optional[dict[str, str]] = None,
        structured: Optional[dict[str, Json]] = None,
    ) -> DrvName:
        drv = DrvName(store_path(name + ".drv"))
        self.drvs[drv] = derivation(name, inputs, env, structured)
        return drv

    def out(self, drv: DrvName) -> StorePath:
        return store_path(self.drvs[drv]["name"])

    def make_fixed_output(self, drv: DrvName) -> None:
        """Remove the output path, as `nix derivation show` does for fixed-output derivations."""
        del self.drvs[drv]["outputs"]["out"]["path"]


def lookup_from(cache: dict[StorePath, list[StorePath]]) -> Lookup:
    return lambda path: cache.get(path)


def paths(*names: str) -> set[StorePath]:
    return {store_path(n) for n in names}


class RuntimeClosureTest(unittest.TestCase):
    def test_cached_path_contributes_its_narinfo_references(self) -> None:
        g = Graph()
        lib = g.add("lib-1.0")
        tool = g.add("tool-1.0")
        app = g.add("app-1.0", inputs=[lib, tool])
        cache = {g.out(app): [g.out(lib)], g.out(lib): []}

        closure = pd.runtime_closure(g.drvs, g.out(app), lookup_from(cache))

        self.assertEqual(closure, {g.out(app), g.out(lib)})

    def test_uncached_path_follows_only_mentioned_inputs(self) -> None:
        g = Graph()
        used = g.add("used-1.0")
        unused = g.add("unused-1.0")
        etc = g.add("etc", inputs=[used, unused], env={"files": f"/nix/store/{g.out(used)}/bin/x"})
        cache: dict[StorePath, list[StorePath]] = {g.out(used): [], g.out(unused): []}

        closure = pd.runtime_closure(g.drvs, g.out(etc), lookup_from(cache))

        self.assertEqual(closure, {g.out(etc), g.out(used)})

    def test_build_only_attributes_are_not_followed(self) -> None:
        g = Graph()
        compiler = g.add("compiler-1.0")
        stdenv = g.add("stdenv")
        unit = g.add(
            "unit",
            inputs=[compiler, stdenv],
            env={
                "nativeBuildInputs": f"/nix/store/{g.out(compiler)}",
                "stdenv": f"/nix/store/{g.out(stdenv)}",
            },
        )

        closure = pd.runtime_closure(g.drvs, g.out(unit), lookup_from({}))

        self.assertEqual(closure, {g.out(unit)})

    def test_vendored_dependencies_are_not_followed(self) -> None:
        g = Graph()
        crate = g.add("hyper-1.8.1")
        vendor = g.add("cargo-vendor-dir", inputs=[crate],
                       env={"buildCommand": f"ln -s /nix/store/{g.out(crate)} $out/hyper-1.8.1\n"})
        app = g.add("app-0.2.0", inputs=[vendor], env={"cargoDeps": f"/nix/store/{g.out(vendor)}"})

        closure = pd.runtime_closure(g.drvs, g.out(app), lookup_from({}))

        self.assertEqual(closure, {g.out(app)})

    def test_programs_run_by_build_command_are_not_followed(self) -> None:
        g = Graph()
        perl = g.add("perl-5.40.0")
        pkg = g.add("pkg-1.0")
        profile = g.add("profile", inputs=[perl, pkg], env={
            "buildCommand": f"/nix/store/{g.out(perl)}/bin/perl -w builder.pl\n"
                            f"ln -s /nix/store/{g.out(pkg)} $out\n",
        })
        cache: dict[StorePath, list[StorePath]] = {g.out(perl): [], g.out(pkg): []}

        closure = pd.runtime_closure(g.drvs, g.out(profile), lookup_from(cache))

        self.assertEqual(closure, {g.out(profile), g.out(pkg)})

    def test_structured_attrs_are_searched(self) -> None:
        g = Graph()
        pkg = g.add("pkg-1.0")
        env = g.add("system-path", inputs=[pkg],
                    structured={"pkgs": [{"paths": [f"/nix/store/{g.out(pkg)}"]}]})
        cache: dict[StorePath, list[StorePath]] = {g.out(pkg): []}

        closure = pd.runtime_closure(g.drvs, g.out(env), lookup_from(cache))

        self.assertEqual(closure, {g.out(env), g.out(pkg)})

    def test_fixed_output_inputs_are_matched_by_name(self) -> None:
        g = Graph()
        wallpaper = g.add("wallpaper.png")
        g.make_fixed_output(wallpaper)
        unused = g.add("unused.tar.gz")
        g.make_fixed_output(unused)
        etc = g.add("etc", inputs=[wallpaper, unused], env={"x": f"/nix/store/{g.out(wallpaper)}"})

        closure = pd.runtime_closure(g.drvs, g.out(etc), lookup_from({g.out(wallpaper): []}))

        self.assertEqual(closure, {g.out(etc), g.out(wallpaper)})

    def test_walk_returns_to_cache_references_below_uncached_paths(self) -> None:
        g = Graph()
        glibc = g.add("glibc-2.42")
        curl = g.add("curl-8.22.0", inputs=[glibc])
        etc = g.add("etc", inputs=[curl], env={"x": f"/nix/store/{g.out(curl)}"})
        cache = {g.out(curl): [g.out(glibc)], g.out(glibc): []}

        closure = pd.runtime_closure(g.drvs, g.out(etc), lookup_from(cache))

        self.assertEqual(closure, {g.out(etc), g.out(curl), g.out(glibc)})


class PackageTest(unittest.TestCase):
    def test_pname_and_version_from_env(self) -> None:
        d = derivation("curl-8.22.0", env={"pname": "curl", "version": "8.22.0"})
        self.assertEqual(pd.package(d), pd.Package("curl", "8.22.0"))

    def test_pname_and_version_from_structured_attrs(self) -> None:
        d = derivation("glib-2.88.3", structured={"pname": "glib", "version": "2.88.3"})
        self.assertEqual(pd.package(d), pd.Package("glib", "2.88.3"))

    def test_name_is_split_like_parse_drv_name(self) -> None:
        d = derivation("linux-firmware-20261019-zstd")
        self.assertEqual(pd.package(d), pd.Package("linux-firmware", "20261019-zstd"))

    def test_name_without_version(self) -> None:
        self.assertIsNone(pd.package(derivation("etc")))


class CompareTest(unittest.TestCase):
    def test_changes_and_rebuilds(self) -> None:
        old: pd.Packages = {
            "curl": {"8.20.0": paths("a")},
            "glibc": {"2.42": paths("b"), "2.42-61": paths("c")},
            "gone": {"1.0": paths("d")},
            "rebuilt": {"1.0": paths("e")},
            "same": {"1.0": paths("f")},
        }
        new: pd.Packages = {
            "curl": {"8.22.0": paths("g")},
            "glibc": {"2.42": paths("h"), "2.42-100": paths("i")},
            "added": {"2.0": paths("j")},
            "rebuilt": {"1.0": paths("k")},
            "same": {"1.0": paths("f")},
        }

        changes, rebuilt = pd.compare(old, new)

        self.assertEqual(changes, [
            Change("added", [], ["2.0"]),
            Change("curl", ["8.20.0"], ["8.22.0"]),
            Change("glibc", ["2.42", "2.42-61"], ["2.42", "2.42-100"]),
            Change("gone", ["1.0"], []),
        ])
        self.assertEqual(rebuilt, 1)


class OutputTest(unittest.TestCase):
    CHANGES = [
        Change("added", [], ["2.0"]),
        Change("curl", ["8.20.0"], ["8.22.0"]),
        Change("glibc", ["2.42", "2.42-61"], ["2.42", "2.42-100"]),
    ]

    def test_text(self) -> None:
        self.assertEqual(pd.text(self.CHANGES, 3), "\n".join([
            "added  -              -> 2.0",
            "curl   8.20.0         -> 8.22.0",
            "glibc  2.42, 2.42-61  -> 2.42, 2.42-100",
            "3 packages rebuilt without a version change.",
        ]))

    def test_text_without_version_changes(self) -> None:
        self.assertEqual(pd.text([], 5), "\n".join([
            "No version changes.",
            "5 packages rebuilt without a version change.",
        ]))

    def test_json(self) -> None:
        self.assertEqual(json.loads(pd.to_json(self.CHANGES[:2], 3)), {
            "changes": [
                {"pname": "added", "old": [], "new": ["2.0"]},
                {"pname": "curl", "old": ["8.20.0"], "new": ["8.22.0"]},
            ],
            "rebuilt": 3,
        })


class CacheReferencesTest(unittest.TestCase):
    PATH = store_path("curl-8.22.0")

    def http_error(self, code: int) -> urllib.error.HTTPError:
        return urllib.error.HTTPError("url", code, "error", email.message.Message(), io.BytesIO())

    def test_references_exclude_the_path_itself(self) -> None:
        glibc = store_path("glibc-2.42")
        narinfo = f"StorePath: /nix/store/{self.PATH}\nReferences: {glibc} {self.PATH}\n"
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = narinfo.encode()
        with mock.patch("urllib.request.urlopen", return_value=response):
            self.assertEqual(pd.cache_references(self.PATH), [glibc])

    def test_missing_path_is_not_cached(self) -> None:
        with mock.patch("urllib.request.urlopen", side_effect=self.http_error(404)):
            self.assertIsNone(pd.cache_references(self.PATH))

    def test_other_http_errors_raise(self) -> None:
        with mock.patch("urllib.request.urlopen", side_effect=self.http_error(500)):
            with self.assertRaises(urllib.error.HTTPError):
                pd.cache_references(self.PATH)


if __name__ == "__main__":
    unittest.main()
