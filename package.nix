{ lib, buildGoModule }:

buildGoModule {
  pname = "github-token-broker";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-hFIv5LbK05/Ty7w6Nio4rokqaX4wo/WYb1PuYZhYv/U=";

  subPackages = [
    "cmd/github-token-broker"
    "cmd/agent-token"
  ];

  checkPhase = ''
    runHook preCheck
    go test ./...
    runHook postCheck
  '';

  meta = {
    description = "SPIFFE-mTLS gRPC broker for scoped GitHub App installation tokens";
    mainProgram = "github-token-broker";
  };
}
