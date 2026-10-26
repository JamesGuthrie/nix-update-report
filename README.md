# nix-update-report

Know what a `flake.lock` update changes on your machines before you merge
it, and which known CVEs your machines have.

Use it if you manage NixOS or nix-darwin machines in a flake and update
its inputs on a schedule. An update bot that only runs
`nix flake update` opens a PR for every update. The PR shows which input
revisions changed, but not what changes on your machines. Many of these
updates change nothing that is installed, and you still have to review
them.

nix-update-report gives you two GitHub Actions:

- **`update`** updates `flake.lock` and tells you which machines the
  update affects. Use it to open a PR only when installed software
  changes. The PR body lists, per machine, the packages whose version
  changes and, unless you turn it off, the CVEs the update resolves or
  introduces.
- **`cve-report`** keeps a GitHub issue up to date with the open CVEs on
  each machine, and comments on it when new critical or high CVEs
  appear. Run it daily.

Neither builds your machines. Both evaluate the flake and download
metadata from cache.nixos.org, so they run in a few minutes on a standard
GitHub runner.

The same tools run [from the command line](#command-line), for example to
preview an update locally.

## What you get

### Update PR

An update PR for a machine called `myhost` looks like this:

> ```
> • Updated input 'nixpkgs':
>     'github:NixOS/nixpkgs/1a2b3c4' (2026-10-21)
>   → 'github:NixOS/nixpkgs/5d6e7f8' (2026-10-25)
> ```
>
> ### myhost
>
> | Package | Old | New |
> | --- | --- | --- |
> | openssl | 3.5.3 | 3.5.4 |
> | linux | 6.12.53 | 6.12.54 |
>
> 41 packages rebuilt without a version change.
>
> #### Security
>
> Resolved CVEs:
>
> | Package | Resolved | CVSS | Critical | High |
> | --- | --- | --- | --- | --- |
> | openssl | 3 | 5.9-7.5 | 0 | 1 |
>
> Introduced CVEs:
>
> - [CVE-2026-12345](https://nvd.nist.gov/vuln/detail/CVE-2026-12345) in openssl 3.5.4 (medium, CVSS 5.3)

When an update changes nothing installed on any machine, the `update`
action reports no affected machines, and the workflow below opens no PR.

### CVE report issue

The issue has a table with the number of open CVEs per machine and
severity. Below it, each machine has a section per severity that lists
the affected packages, their versions and their CVEs, with links to NVD.

When a run finds critical or high CVEs that the previous run didn't, it
adds a comment listing them, so you get a notification. The first run
only creates the issue.

## GitHub Actions

Your workflow checks out the repository and installs Nix before it uses
an action. The actions do neither, so you can set up access to private
flake inputs in between.

Pin the actions by commit SHA. The SHA fixes the version of the scripts
and of vulnix together.

In the schedules below, replace the minute with a random one. GitHub
runs many scheduled workflows at the start of each hour, so runs at
minute 0 are often delayed or dropped. A random minute also spreads the
downloads from the NVD mirror.

### Update PRs

This workflow runs weekly. It opens or updates a PR when the update
affects `myhost`, and closes an open PR when the latest update no longer
affects it.

```yaml
name: Update flake.lock

on:
  schedule:
    # Pick a random minute, see above.
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  update:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    env:
      BRANCH: update-flake-lock
    steps:
      - uses: actions/checkout@v7
      - uses: cachix/install-nix-action@v31
      - uses: JamesGuthrie/nix-update-report/update@<sha>
        id: update
        with:
          targets: '["myhost"]'
      - name: Close the PR if no machine is affected
        if: steps.update.outputs.affected == '[]'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          for pr in $(gh pr list --head "$BRANCH" --state open --json number --jq '.[].number'); do
            gh pr close "$pr" --delete-branch --comment "The latest update changes no machine."
          done
      - name: Build myhost
        if: steps.update.outputs.affected != '[]'
        run: nix build .#nixosConfigurations.myhost.config.system.build.toplevel
      - name: Open or update the PR
        if: steps.update.outputs.affected != '[]'
        uses: peter-evans/create-pull-request@v8
        with:
          branch: ${{ env.BRANCH }}
          add-paths: flake.lock
          commit-message: "chore: update flake.lock"
          title: "chore: update flake.lock"
          body-path: ${{ steps.update.outputs.body-path }}
```

The job builds `myhost` itself because a PR opened with `GITHUB_TOKEN`
doesn't trigger other workflows, so your usual PR checks don't run on it.
If you open the PR with a personal access token or a GitHub App token
instead, your PR checks run, and you can drop the build step.

To get one PR per machine or per group of inputs, run the job in a matrix
and pass different `inputs`, `targets` and `BRANCH` values.

### CVE report

This workflow runs daily and keeps the issue labelled `cve-report` up to
date.

```yaml
name: CVE report

on:
  schedule:
    # Pick a random minute, see above.
    - cron: "43 6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  report:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v7
      - uses: cachix/install-nix-action@v31
      - uses: JamesGuthrie/nix-update-report/cve-report@<sha>
```

### `update` inputs and outputs

| Input | Default | |
| --- | --- | --- |
| `inputs` | all | flake inputs to update, separated by spaces |
| `targets` | all | JSON list of [targets](#targets) |
| `cves` | `true` | `false` leaves the Security section out of the PR body |
| `normalization` | none | path to a [normalization file](#normalization-file) |
| `whitelist` | `vulnix-whitelist.toml` | path to a [whitelist](#whitelist), used if it exists |
| `nvd-mirror` | the [default mirror](#nvd-mirror) | |

| Output | |
| --- | --- |
| `affected` | JSON list of affected targets |
| `body-path` | path to the PR body; empty if no target is affected |

The action leaves the updated `flake.lock` in the workspace.

### `cve-report` inputs

| Input | Default | |
| --- | --- | --- |
| `targets` | all NixOS and nix-darwin targets | JSON list of [targets](#targets) |
| `normalization`, `whitelist`, `nvd-mirror` | as `update` | |
| `label` | `cve-report` | label that identifies the issue |
| `title` | `Open CVEs` | title of a new issue |
| `token` | `github.token` | needs `issues: write` |

## Configuration

### Targets

A target is a machine or a dev shell in your flake:

- a name in `nixosConfigurations`;
- a name in `darwinConfigurations`;
- `dev-shell-<system>`, for each `devShells.<system>.default`.

### Whitelist

A whitelist leaves out CVEs that don't apply to you, for example false
matches on a package name. It uses
[vulnix's whitelist format](https://github.com/nix-community/vulnix#whitelisting).
By default the tools read `vulnix-whitelist.toml` from the working
directory when it exists.

### NVD mirror

The tools download the NVD database of CVEs on each run. nvd.nist.gov is
slow and rate limited, so a full download from it can take a long time.

The default mirror, `https://nvd-mirror.fsn1.your-objectstorage.com/`,
is run by the author of this repository. You're welcome to use it, at
your own risk: it comes with no guarantee that it is available or up to
date. To use another mirror, or NVD directly, set `nvd-mirror` or
`--mirror`, for example to `https://nvd.nist.gov/feeds/json/cve/2.0/`.

### Normalization file

Use a normalization file when your machines need extra settings for the
comparison, or when what you deploy isn't the system's toplevel
derivation. [How it works](#comparing-targets) explains why the
comparison changes settings at all.

```nix
{ flake }: {
  nixos = [ <module> ... ];        # default [ ]
  darwin = [ <module> ... ];       # default [ ]
  homeManager = [ <module> ... ];  # default [ ]
  # Target name -> normalized configuration -> derivation to compare.
  deployed = name: cfg: <derivation>;  # default: cfg.config.system.build.toplevel
}
```

- The modules apply to the comparison only, after the common modules.
- An unknown attribute fails the evaluation and names the attribute, so a
  typo such as `nixoss` can't go unnoticed.
- `deployed` applies to NixOS and nix-darwin targets, for example to
  compare a deploy-rs profile that wraps the toplevel.

## Command line

Run the scripts from your flake's directory, in one of two ways:

- From a checkout of this repository. They need Python 3 and jq, and
  vulnix for CVEs.
- From this repository's flake, which includes vulnix:
  `nix shell github:JamesGuthrie/nix-update-report` puts all scripts on
  `PATH`, and `nix run github:JamesGuthrie/nix-update-report#<name> --`
  runs one. `<name>` is the script's name without `.py`, for example
  `update_report`.

Preview an update:

```sh
scripts/normalized-derivations > before.json
nix flake update 2> update.log
scripts/normalized-derivations > after.json
scripts/update_report.py affected before.json after.json
scripts/update_report.py body --log update.log before.json after.json
```

List the open CVEs on `myhost`:

```sh
scripts/normalized-derivations myhost > drvs.json
scripts/cves.py open "$(jq -r .myhost drvs.json)"
```

### Script reference

```
normalized-derivations [--flake REF] [--normalization FILE] [--list] [TARGET...]
  -> {"<target>": "/nix/store/...drv"}
```

Evaluates targets for the comparison. `--list` prints the target names.
Without targets, it evaluates all.

```
package_diff.py [--json] OLD_DRV NEW_DRV
  -> {"changes": [{"pname", "old": [...], "new": [...]}], "rebuilt": N}
```

Lists the version changes between two derivations. `rebuilt` counts the
packages whose store path changed without a version change. Without
`--json`, it prints a table.

```
cves.py [--mirror URL] [--whitelist FILE] [--cache-dir DIR] open DRV
  -> {"findings": [FINDING...], "suppressed": [CVE...]}
cves.py [...] compare OLD_DRV NEW_DRV
  -> {"resolved": [FINDING + {"sources": ["nvd"|"patch"]}], "introduced": [FINDING...]}

FINDING = {"cve", "package", "version", "score": float|null, "severity", "description"}
```

`open` lists the open CVEs, `compare` the CVEs resolved and introduced
between two derivations. `suppressed` lists the CVEs the whitelist left
out. Without `--cache-dir`, vulnix uses its default cache directory.

```
update_report.py affected BEFORE_JSON AFTER_JSON
  -> ["<target>", ...]

update_report.py body --log UPDATE_LOG [--no-cves] [--whitelist F] [--mirror U] [--cache-dir D]
                 BEFORE_JSON AFTER_JSON
  -> Markdown
```

`BEFORE_JSON` and `AFTER_JSON` are outputs of `normalized-derivations`.
Both must have the same targets. Otherwise the script exits with an error
that names the missing ones, because a missing target must not count as
a change. `body` writes the [update PR](#update-pr) body: the update log
without `warning:` lines, then a section per affected target.
`--no-cves` leaves out the Security section and doesn't download the NVD
database. A body
longer than 60,000 characters is cut and ends with "(truncated)", because
GitHub limits a PR body to 65,536 characters.

```
cve_issue.py REPORTS_DIR PREVIOUS_BODY HEADER BODY_OUT ALERT_OUT
```

Writes the [CVE report issue](#cve-report-issue) body to `BODY_OUT`, and
the comment about new critical or high CVEs to `ALERT_OUT` (empty if
there are none). `REPORTS_DIR` holds one `cves.py open` output per
target, named `<target>.json`. `PREVIOUS_BODY` is the issue's current
body, or an empty file.

## How it works

### Comparing targets

A target is affected when its derivation differs before and after the
update.

Compared as they are, two evaluations of the same configuration at
different nixpkgs revisions always differ, even when no package changed.
Some options write the nixpkgs revision or source path into the system,
for example into `nixos-version` and `etc-nix-registry.json`. So the
comparison evaluates each target with common modules that override those
options, all with `lib.mkForce`:

| Platform | Settings |
| --- | --- |
| NixOS | `system.nixos.versionSuffix = ""`, `system.nixos.revision = null`, `nixpkgs.flake.source = null`, `documentation.nixos.enable = false`, `environment.systemPackages = [ pkgs.w3m-nographics ]` |
| nix-darwin | `system.darwinVersionSuffix = ""`, `system.darwinRevision = null`, `system.nixpkgsVersionSuffix = ""`, `system.nixpkgsRevision = null`, `nixpkgs.flake.source = null` |
| home-manager (when the module is present) | `manual.manpages.enable = false` |

Why the NixOS documentation settings:

- The NixOS manual contains `options.json`, which changes on most nixpkgs
  updates. Each change rebuilds `system-path`, `dbus-1` and others, so
  nearly every update would affect every machine, often with no package
  changing at all.
- Turning off the manual also removes `nixos-help` and its fallback
  browser `w3m-nographics`, with its dependency `gpm`. Adding
  `w3m-nographics` back keeps both in the comparison, so their updates
  still count.

The nix-darwin manual needs no such setting, because its derivation
doesn't change between nixpkgs revisions. Dev shells are compared without
changes.

These settings apply to the comparison only. Your machines keep their
manuals, and the binary cache works as before.

### Finding the installed packages

The installed packages are the target's runtime closure: the store paths
the target refers to, directly or through other store paths. To find it
without building the target, the tools start at the target's output and
look up the references of each store path:

- **The store path is in cache.nixos.org.** Its `.narinfo` file there
  lists the store paths it refers to.
- **The store path isn't in the cache**, for example because it is built
  from your own configuration, as `/etc` and the system profile are. Its
  references are unknown until it is built. The tools follow those
  outputs of its derivation's inputs whose store path appears in the
  derivation's attributes, as a stand-in. They skip attributes that only
  carry build tools, such as `nativeBuildInputs`, `stdenv` and `builder`,
  and dependency sources such as `cargoDeps`, `goModules` and `npmDeps`.
  They also skip programs that a `buildCommand` runs, such as the `perl`
  that runs `buildEnv`'s builder.

The stand-in is an estimate, and it can be wrong in both directions:

- It includes an input that the built output doesn't refer to, for
  example a library in `buildInputs` that is linked statically.
- It misses an input that the built output does refer to, when the input
  appears only in a skipped attribute.

A package counts as rebuilt when its store path changes and its version
doesn't, for example because a dependency changed.

### Matching CVEs

[vulnix](https://github.com/nix-community/vulnix) matches the installed
packages, by name and version, against the NVD database. Packages used
only to build the target, such as compilers and bootstrap tools, aren't
checked. vulnix comes from its main branch, because releases lack the
fixes for `__structuredAttrs` derivations (vulnix#184).

A CVE counts as resolved by an update when vulnix no longer matches it on
the new version, or when nixpkgs adds a patch named after the CVE.

### Remembering earlier CVE reports

The CVE report issue stores the critical and high CVEs of each target in
a hidden HTML comment. The next run compares against it to find the new
ones.
