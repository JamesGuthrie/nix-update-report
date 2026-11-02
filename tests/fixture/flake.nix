# A minimal NixOS configuration, evaluated twice as if at two nixpkgs
# revisions: `revision-a` and `revision-b` differ only in the options that
# stamp the revision into a system.
#
# Each also has a nested system, the way a machine builds a VM image: the
# option `fixture.nested.extraConfig` adds modules to the nested system, and
# `system.build.nestedImage` is a file that refers to the nested system's
# toplevel. The machine installs it only with `fixture.nested.install`.
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";

      stamped = revision: { lib, ... }: {
        boot.loader.grub.enable = false;
        fileSystems."/" = { device = "/dev/sda1"; fsType = "ext4"; };
        system.stateVersion = "26.05";
        # Overrides nixosSystem's definitions, and loses to the
        # normalization's lib.mkForce.
        system.nixos.revision = lib.mkOverride 90 revision;
        system.nixos.versionSuffix = lib.mkOverride 90 ".${builtins.substring 0 7 revision}";
        nixpkgs.flake.source = lib.mkOverride 90 (builtins.toFile "fake-nixpkgs-${revision}" revision);
        nix.registry.fake.flake = { outPath = builtins.toFile "fake-registry-${revision}" revision; };
      };

      machine = revision: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          (stamped revision)
          ({ config, lib, pkgs, ... }:
            let
              nested = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [ (stamped revision) config.fixture.nested.extraConfig ];
              };
              image = pkgs.runCommand "fake-image" { passthru.config = nested.config; } ''
                echo ${nested.config.system.build.toplevel} > $out
              '';
            in
            {
              options.fixture.nested = {
                install = lib.mkEnableOption "installing the nested image";
                extraConfig = lib.mkOption {
                  type = lib.types.deferredModule;
                  default = { };
                };
              };
              config.system.build.nestedImage = image;
              config.environment.etc = lib.mkIf config.fixture.nested.install {
                "nested-image".source = image;
              };
            })
        ];
      };
    in
    {
      nixosConfigurations.revision-a = machine "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      nixosConfigurations.revision-b = machine "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    };
}
