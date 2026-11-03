{
  pkgs,
  brokerPackage ? pkgs.callPackage ./package.nix { },
}:
# Wrapper that runs gh with a broker-minted installation token for the current
# checkout; see gh-via-spiffe.sh. `brokerPackage` supplies bin/agent-token.
pkgs.writeShellApplication {
  name = "gh-via-spiffe";
  runtimeInputs = [
    brokerPackage
    pkgs.gh
    pkgs.git
    pkgs.gnused
    pkgs.coreutils
  ];
  text = builtins.readFile ./gh-via-spiffe.sh;

  meta = {
    description = "Run gh as a GitHub App with a token from a SPIFFE token broker";
    mainProgram = "gh-via-spiffe";
    platforms = pkgs.lib.platforms.linux;
  };
}
