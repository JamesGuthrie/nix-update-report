# Derivations of each machine and dev shell, with the options that stamp input
# revisions into a system set to fixed values. If an update leaves a normalized
# derivation unchanged, it changes nothing installed on that machine. See
# README.md, "Comparing targets".
#
# targets: names to evaluate (machine names, or dev-shell-<system>); null
# evaluates all of them.
# normalization: path to a normalization file (see README.md, "Normalization
# file"), or null.
{ flake, targets ? null, normalization ? null }:
let
  inherit (builtins) attrNames concatStringsSep listToAttrs mapAttrs removeAttrs;

  hooks = [ "nixos" "darwin" "homeManager" "deployed" ];

  user =
    let
      file = if normalization == null then { } else import normalization { inherit flake; };
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
      } // file;

  # The NixOS manual includes options.json, which changes with most nixpkgs
  # revisions. Turning it off also drops nixos-help's fallback browser, so it
  # is added back for systems that have it.
  normalizeNixos = original: { lib, pkgs, ... }:
    let docs = original.config.documentation; in {
      system.nixos.versionSuffix = lib.mkForce "";
      system.nixos.revision = lib.mkForce null;
      nixpkgs.flake.source = lib.mkForce null;
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
  };

  # home-manager's man page lists option declarations by store path, including
  # declarations in nixpkgs, so it changes with every nixpkgs revision.
  normalizeHomeManager = { lib, ... }: {
    home-manager.sharedModules =
      [{ manual.manpages.enable = lib.mkForce false; }] ++ user.homeManager;
  };

  normalize = common: modules: cfg: cfg.extendModules {
    modules = [ (common cfg) ] ++ modules
      ++ (if cfg.options ? home-manager then [ normalizeHomeManager ] else [ ]);
  };

  all =
    mapAttrs (name: cfg: (user.deployed name (normalize normalizeNixos user.nixos cfg)).drvPath)
      (flake.nixosConfigurations or { })
    // mapAttrs (name: cfg: (user.deployed name (normalize normalizeDarwin user.darwin cfg)).drvPath)
      (flake.darwinConfigurations or { })
    // listToAttrs (map
      (system: { name = "dev-shell-${system}"; value = flake.devShells.${system}.default.drvPath; })
      (attrNames (flake.devShells or { })));
in
# Forcing `user` first reports an invalid normalization file even for --list.
builtins.seq user (
  if targets == null then all
  else listToAttrs (map (name: { inherit name; value = all.${name}; }) targets)
)
