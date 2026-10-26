{
  description = "Update reports and CVE reports for NixOS and nix-darwin flakes";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";

    # vulnix from its main branch, which reads the patches of derivations with
    # __structuredAttrs (nix-community/vulnix#184); releases do not yet.
    vulnix = {
      url = "github:nix-community/vulnix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, vulnix }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = function:
        lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ]
          (system: function nixpkgs.legacyPackages.${system} vulnix.packages.${system}.vulnix);

      # Package name -> script in scripts/.
      scripts = {
        normalized-derivations = "normalized-derivations";
        package_diff = "package_diff.py";
        cves = "cves.py";
        update_report = "update_report.py";
        cve_issue = "cve_issue.py";
      };

      sources = lib.fileset.toSource {
        root = ./scripts;
        fileset = lib.fileset.difference ./scripts
          (lib.fileset.fileFilter (file: lib.hasPrefix "test_" file.name) ./scripts);
      };

      tests = lib.fileset.toSource {
        root = ./scripts;
        fileset = lib.fileset.fileFilter (file: file.hasExt "py") ./scripts;
      };
    in
    {
      packages = forAllSystems (pkgs: vulnixPackage:
        let
          # Nix itself comes from the caller's environment, so that scripts
          # evaluate with the caller's Nix version and settings.
          all = pkgs.runCommand "nix-update-report"
            {
              nativeBuildInputs = [ pkgs.makeWrapper ];
              buildInputs = [ pkgs.bash pkgs.python3 ];
            } ''
            mkdir -p $out/bin $out/libexec
            cp ${sources}/* $out/libexec/
            patchShebangs $out/libexec
            for script in ${lib.concatStringsSep " " (lib.attrValues scripts)}; do
              makeWrapper $out/libexec/$script $out/bin/$script \
                --prefix PATH : ${lib.makeBinPath [ pkgs.jq vulnixPackage ]}
            done
          '';
        in
        lib.mapAttrs (_: script: all // { meta = all.meta // { mainProgram = script; }; }) scripts
        // {
          default = all;
          vulnix = vulnixPackage;
        });

      checks = forAllSystems (pkgs: _vulnix: {
        unittest = pkgs.runCommand "unittest" { nativeBuildInputs = [ pkgs.python3 ]; } ''
          cd ${tests} && python3 -m unittest && touch $out
        '';
        ty = pkgs.runCommand "ty" { nativeBuildInputs = [ pkgs.ty ]; } ''
          cd ${tests} && ty check && touch $out
        '';
      });

      devShells = forAllSystems (pkgs: vulnixPackage: {
        default = pkgs.mkShell {
          packages = [
            pkgs.actionlint
            pkgs.jq
            pkgs.python3
            pkgs.ty
            vulnixPackage
          ];
        };
      });
    };
}
