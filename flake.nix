{
  description = "SPIFFE-mTLS GitHub App token broker";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [ "x86_64-linux" ];
      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );
    in
    {
      packages = forAllSystems (
        { pkgs, ... }:
        let
          package = pkgs.callPackage ./package.nix { };
        in
        {
          default = package;
          github-token-broker = package;
          gh-via-spiffe = pkgs.callPackage ./gh-via-spiffe.nix { brokerPackage = package; };
        }
      );

      nixosModules = {
        default = import ./module.nix;
        github-token-broker = import ./module.nix;
      };

      checks = forAllSystems (
        { pkgs, system }:
        {
          github-token-broker = self.packages.${system}.github-token-broker;
          spire = import ./tests/spire.nix {
            inherit pkgs lib;
            brokerPackage = self.packages.${system}.github-token-broker;
          };
        }
      );
    };
}
