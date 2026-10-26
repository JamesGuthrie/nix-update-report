# A minimal NixOS configuration, evaluated twice as if at two nixpkgs
# revisions: `revision-a` and `revision-b` differ only in the options that
# stamp the revision into a system.
{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";

  outputs = { nixpkgs, ... }:
    let
      machine = revision: nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          ({ lib, ... }: {
            boot.loader.grub.enable = false;
            fileSystems."/" = { device = "/dev/sda1"; fsType = "ext4"; };
            system.stateVersion = "26.05";
            # Overrides nixosSystem's definitions, and loses to the
            # normalization's lib.mkForce.
            system.nixos.revision = lib.mkOverride 90 revision;
            system.nixos.versionSuffix = lib.mkOverride 90 ".${builtins.substring 0 7 revision}";
            nixpkgs.flake.source = lib.mkOverride 90 (builtins.toFile "fake-nixpkgs-${revision}" revision);
          })
        ];
      };
    in
    {
      nixosConfigurations.revision-a = machine "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      nixosConfigurations.revision-b = machine "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    };
}
