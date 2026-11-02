from __future__ import annotations

import json
import unittest

import targets as tg
from package_diff import DrvName
from targets import (DrvPath, EntryNotReached, LoadedTarget, Nested, NestedLabel, NestedLeak,
                     SystemNotUnderEntry, Target, TargetSpec)
from test_package_diff import Graph, lookup_from

HOST = Target("host")
VM = NestedLabel("vm")


def drv_path(drv: DrvName) -> DrvPath:
    return DrvPath(f"/nix/store/{drv}")


class Machine:
    """A host that runs a VM: host -> activate -> prepare-vm -> image -> VM system -> openssh.

    The activation script mentions prepare-vm followed by ";", and the image
    mentions the VM system, as with Virby.
    """

    def __init__(self, host_mentions_vm: bool = False) -> None:
        g = self.graph = Graph()
        self.openssh = g.add("openssh-10.3p1")
        self.vm = g.add("nixos-system-vm", inputs=[self.openssh],
                        env={"x": f"/nix/store/{g.out(self.openssh)}"})
        self.image = g.add("nixos-disk-image", inputs=[self.vm],
                           env={"x": f"/nix/store/{g.out(self.vm)}"})
        self.prepare = g.add("prepare-vm", inputs=[self.image],
                             env={"text": f"cp /nix/store/{g.out(self.image)}/vm.img ."})
        self.curl = g.add("curl-8.22.0")
        extra = f" /nix/store/{g.out(self.vm)}" if host_mentions_vm else ""
        self.host = g.add("darwin-system", inputs=[self.prepare, self.curl, self.vm], env={
            "activationScript": f"if ! /nix/store/{g.out(self.prepare)}; then exit 1; fi\n"
                                f"/nix/store/{g.out(self.curl)}/bin/curl{extra}"})

    def spec(self, entry: DrvName, system: DrvName | None = None) -> TargetSpec:
        g = self.graph
        return TargetSpec(drv_path(self.host),
                          {VM: Nested(g.out(entry), drv_path(system or self.vm))})

    def load(self, spec: TargetSpec) -> LoadedTarget | tg.NestedFailure:
        return tg.load_target(HOST, spec, lambda _drv: self.graph.drvs, lookup_from({}))


class ParseTest(unittest.TestCase):
    def test_target_with_a_nested_system(self) -> None:
        text = json.dumps({"host": {
            "drv": "/nix/store/a-host.drv",
            "nested": {"vm": {"entry": "/nix/store/b-image", "drv": "/nix/store/c-vm.drv"}}}})

        self.assertEqual(tg.parse_targets(text), {HOST: TargetSpec(
            DrvPath("/nix/store/a-host.drv"),
            {VM: Nested(tg.pd.StorePath("b-image"), DrvPath("/nix/store/c-vm.drv"))})})

    def test_rejects_malformed_targets(self) -> None:
        for value in [{"host": "/nix/store/a-host.drv"},
                      {"host": {"drv": "/nix/store/a-host.drv"}},
                      {"host": {"nested": {}}},
                      {"host": {"drv": "/nix/store/a.drv", "nested": {"vm": {"drv": "x"}}}},
                      {"host": {"drv": "/nix/store/a.drv",
                                "nested": {"vm": {"entry": "b-image", "drv": "x"}}}}]:
            with self.subTest(value), self.assertRaises(ValueError):
                tg.parse_targets(json.dumps(value))


class LoadTargetTest(unittest.TestCase):
    def test_without_nested_systems_the_whole_closure_is_the_host(self) -> None:
        m = Machine()
        g = m.graph

        loaded = m.load(TargetSpec(drv_path(m.host), {}))

        assert isinstance(loaded, LoadedTarget)
        self.assertIn(g.out(m.openssh), loaded.host.closure)
        self.assertEqual(loaded.nested, {})

    def test_nested_system_is_split_off_at_its_entry(self) -> None:
        m = Machine()
        g = m.graph

        loaded = m.load(m.spec(m.image))

        assert isinstance(loaded, LoadedTarget)
        self.assertEqual(loaded.host.closure,
                         {g.out(m.host), g.out(m.prepare), g.out(m.image), g.out(m.curl)})
        self.assertEqual(loaded.nested[VM].closure, {g.out(m.vm), g.out(m.openssh)})

    def test_entry_not_reached(self) -> None:
        m = Machine()
        unrelated = m.graph.add("unrelated")

        self.assertEqual(m.load(m.spec(unrelated)), EntryNotReached(HOST, VM))

    def test_system_not_under_entry(self) -> None:
        m = Machine()
        other = m.graph.add("nixos-system-other")

        self.assertEqual(m.load(m.spec(m.image, other)), SystemNotUnderEntry(HOST, VM))

    def test_entry_that_is_not_the_only_way_to_the_system_leaks(self) -> None:
        m = Machine()

        self.assertEqual(m.load(m.spec(m.curl)), NestedLeak(HOST, VM))

    def test_failures_with_equal_fields_differ(self) -> None:
        self.assertNotEqual(NestedLeak(HOST, VM), SystemNotUnderEntry(HOST, VM))

    def test_leak_past_the_entry(self) -> None:
        m = Machine(host_mentions_vm=True)

        self.assertEqual(m.load(m.spec(m.image)), NestedLeak(HOST, VM))

    def test_messages_name_the_target_and_label(self) -> None:
        for failure in [EntryNotReached(HOST, VM), SystemNotUnderEntry(HOST, VM),
                        NestedLeak(HOST, VM)]:
            with self.subTest(failure):
                self.assertTrue(failure.message().startswith("host/vm: "))


if __name__ == "__main__":
    unittest.main()
