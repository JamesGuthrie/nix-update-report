# Derivations of each machine and dev shell, with the options that stamp input
# revisions into a system set to fixed values. If an update leaves a normalized
# derivation unchanged, it changes nothing installed on that machine. See
# README.md, "Comparing targets".
#
# Each target is { drv; nested; }, where nested maps a label to
# { entry; drv; } for each nested system the normalization file declares. See
# README.md, "Nested systems".
#
# targets: names to evaluate (machine names, or dev-shell-<system>); null
# evaluates all of them.
# normalization: path to a normalization file (see README.md, "Normalization
# file"), or null.
{ flake, targets ? null, normalization ? null }:
let
  inherit (builtins) attrNames concatStringsSep functionArgs intersectAttrs isAttrs
    listToAttrs mapAttrs removeAttrs;

  hooks = [ "nixos" "darwin" "homeManager" "deployed" "nested" ];

  # Passed to the normalization file, for nested systems, e.g. a VM that a
  # machine builds. A nested system often exposes only its `config`, without
  # the configuration before normalization that normalizeNixos needs to tell
  # whether the system has the NixOS manual. So a nested system must not have
  # the manual, and normalize.nixos only checks that it doesn't.
  normalize.nixos = { config, ... }: {
    imports = [ normalizeNixosRevision ];
    assertions = [{
      assertion = !(config.documentation.enable && config.documentation.nixos.enable);
      message = "normalize.nixos: a nested NixOS system must not install the NixOS manual, which changes with most nixpkgs revisions. Set documentation.nixos.enable = false in it.";
    }];
  };

  user =
    let
      fileFunction = import normalization;
      declared = functionArgs fileFunction;
      # A file written as `{ flake }: ...` gets only `flake`.
      arguments = if declared == { } then { inherit flake normalize; }
        else intersectAttrs declared { inherit flake normalize; };
      file = if normalization == null then { } else fileFunction arguments;
      unknown = attrNames (removeAttrs file hooks);
    in
    if unknown != [ ] then
      throw "${toString normalization}: unknown attributes ${concatStringsSep ", " unknown}; expected ${concatStringsSep ", " hooks}"
    else
      {
        nixos = [ ];
        darwin = [ ];
        homeManager = [ ];
        deployed = _name: cfg: cfg.config.system.build.toplevel;
        nested = _name: _cfg: { };
      } // file;

  # A flake registry entry refers to the flake's source, so it changes with
  # every revision of that flake.
  normalizeNixosRevision = { lib, ... }: {
    system.nixos.versionSuffix = lib.mkForce "";
    system.nixos.revision = lib.mkForce null;
    nixpkgs.flake.source = lib.mkForce null;
    nix.registry = lib.mkForce { };
  };

  # The NixOS manual includes options.json, which changes with most nixpkgs
  # revisions. Turning it off also drops nixos-help's fallback browser, so it
  # is added back for systems that have it.
  normalizeNixos = original: { lib, pkgs, ... }:
    let docs = original.config.documentation; in {
      imports = [ normalizeNixosRevision ];
      documentation.nixos.enable = lib.mkForce false;
      environment.systemPackages =
        lib.optional (docs.enable && docs.nixos.enable && docs.doc.enable) pkgs.w3m-nographics;
    };

  normalizeDarwin = _original: { lib, ... }: {
    system.darwinVersionSuffix = lib.mkForce "";
    system.darwinRevision = lib.mkForce null;
    system.nixpkgsVersionSuffix = lib.mkForce "";
    system.nixpkgsRevision = lib.mkForce null;
    nixpkgs.flake.source = lib.mkForce null;
    nix.registry = lib.mkForce { };
  };

  # home-manager's man page lists option declarations by store path, including
  # declarations in nixpkgs, so it changes with every nixpkgs revision.
  normalizeHomeManager = { lib, ... }: {
    home-manager.sharedModules =
      [{ manual.manpages.enable = lib.mkForce false; }] ++ user.homeManager;
  };

  extend = common: modules: cfg: cfg.extendModules {
    modules = [ (common cfg) ] ++ modules
      ++ (if cfg.options ? home-manager then [ normalizeHomeManager ] else [ ]);
  };

  nestedSystem = name: label: value:
    if isAttrs value && attrNames value == [ "entry" "system" ] then
      { entry = value.entry.outPath; drv = value.system.drvPath; }
    else
      throw "${toString normalization}: nested system ${name}/${label}: expected { entry = <derivation>; system = <derivation>; }";

  target = name: cfg: {
    drv = (user.deployed name cfg).drvPath;
    nested = mapAttrs (nestedSystem name) (user.nested name cfg);
  };

  all =
    mapAttrs (name: cfg: target name (extend normalizeNixos user.nixos cfg))
      (flake.nixosConfigurations or { })
    // mapAttrs (name: cfg: target name (extend normalizeDarwin user.darwin cfg))
      (flake.darwinConfigurations or { })
    // listToAttrs (map
      (system: {
        name = "dev-shell-${system}";
        value = { drv = flake.devShells.${system}.default.drvPath; nested = { }; };
      })
      (attrNames (flake.devShells or { })));
in
# Forcing `user` first reports an invalid normalization file even for --list.
builtins.seq user (
  if targets == null then all
  else listToAttrs (map (name: { inherit name; value = all.${name}; }) targets)
)
