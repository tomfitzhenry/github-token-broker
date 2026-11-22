{ lib, buildGoModule }:

buildGoModule {
  pname = "github-token-broker";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-1O7jeGru3yQcUtU3QpfOjuuQ+ImTp36HNFBDEb8n9oc=";

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
