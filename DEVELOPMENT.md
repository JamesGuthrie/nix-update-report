# Development

The scripts use the Python standard library only.

```
flake.nix                    packages, vulnix input, checks
scripts/
  normalized-derivations
  normalized.nix             common modules, normalization file handling
  targets.py                 parsing targets, nested systems' closures
  package_diff.py
  cves.py
  update_report.py
  cve_issue.py
  test_*.py                  unit tests
update/action.yml
cve-report/action.yml
tests/
  fixture/flake.nix          minimal NixOS configuration with a nested system
  test_normalization.py      Nix tests against the fixture
.github/workflows/ci.yml
Makefile
LICENSE                      MIT
```

Flake outputs:

- `packages.<system>.default`: all scripts on `PATH`, with jq and vulnix.
- `packages.<system>.<name>` for each script, with `<name>` the script's
  name without `.py`, so that `nix run .#<name>` runs it.
- `packages.<system>.vulnix`: the actions put it on `PATH`.
- `checks.<system>.unittest` and `checks.<system>.ty`.

In the dev shell (`nix develop`):

- `make check` runs the unit tests, `ty` and `actionlint`.
- `make check-nix` runs the Nix tests. They evaluate the fixture with
  `builtins.getFlake`, which the build sandbox of `nix flake check`
  doesn't allow.

CI runs both, and runs the `update` action on this repository's own
flake, whose targets are its dev shells.

## Tests

Python:

1. `package_diff.py`, `cves.py` and `cve_issue.py`: unit tests for
   parsing, comparison and rendering. `cve_issue.py` reads reports with
   `cves.py`'s parser, which reads `cves.py open --json`'s output back to the
   same report and rejects a malformed one.
2. `update_report.py affected`: identical files give `[]`; a changed
   target is listed; files with different targets fail and name the
   missing ones.
3. `update_report.py body`:
   - only affected targets get a section;
   - "No version changes." appears for a target without version changes;
   - the Security section lists resolved CVEs per package with CVSS
     ranges, and the introduced CVEs;
   - `warning:` lines are removed from the log;
   - without CVEs, there is no Security section;
   - a body over 60,000 characters is truncated.
4. `cves.py` looks for the default whitelist in the working directory,
   and runs without one when it doesn't exist.
5. `package_diff.py`'s walk:
   - doesn't follow paths that only appear in reference constraints
     (`allowedReferences`, `disallowedReferences` and the like,
     `outputChecks`);
   - ends a store path at characters a store path's name can't contain,
     such as `;`, `<` and `)`, and keeps `+`, `.`, `?` and `=`;
   - keeps a stop path but doesn't follow it, and keeps paths below it
     that are reachable another way.
6. `targets.py`: parsing rejects malformed targets and nested systems; a
   nested system's packages are in its own closure and not in the
   target's; the three failures (entry not reached, system not under the
   entry, leak past the entry) are distinct and name the target and label.
7. Nested systems in the outputs: `cves.py open` reports them beside the
   target, `cve_issue.py` lists them as `<target>/<label>` and alerts
   under that name, `update_report.py` gives a changed nested system a
   subsection and fails on a nested system missing on one side.

Nix tests, on the fixture flake (`tests/test_normalization.py`):

8. Evaluating the fixture at two fake nixpkgs revisions gives the same
   normalized derivation.
9. The normalized closure contains neither the revision, the nixpkgs
   source path, nor the source of a flake registry entry.
10. The `nixos-help` script refers to `w3m-nographics`, the manual and the
    shell, and to nothing else. This fails if nixpkgs changes the fallback
    browser, which would make the w3m line in the common modules wrong.
    The normalized system contains `w3m-nographics`.
11. The normalization file: an unknown attribute fails; an empty file
    gives the same result as no file; a `deployed` hook replaces the
    toplevel; modules in the file change the derivation.
12. Nested systems: none by default; a declared one appears with its entry
    and derivation; a malformed one fails and names the target and label;
    without normalization, its derivation and the target's differ between
    the fake revisions; with `normalize.nixos` added to it, both are the
    same, whether the nested system turns off only the manual or all
    documentation; `normalize.nixos` fails on a nested system with the
    manual.
