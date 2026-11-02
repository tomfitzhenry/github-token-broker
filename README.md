# github-token-broker

A small SPIFFE-mTLS gRPC service that mints scoped GitHub App installation
tokens for workloads. Agents authenticate with their X509-SVID; the GitHub App
private key stays on the broker. The API is protobuf, not JSON.

```
agent (X509-SVID) ── mTLS ──> broker ── GitHub App JWT ──> installation token
                                  │
                                  └── scoped to one repo + permission subset
```

## Properties

- No public certificate: the broker's TLS identity is its SPIFFE X509-SVID.
- Clients are authenticated by their SPIFFE ID and mTLS.
- The GitHub App private key never leaves the broker.
- Tokens are installation tokens, scoped to a repository and a subset of the
  App's permissions.
- Tokens are cached in broker memory until shortly before their one-hour expiry.

## Dependencies

[`github.com/spiffe/go-spiffe/v2`](https://github.com/spiffe/go-spiffe) provides
the Workload API and SPIFFE transport credentials. `google.golang.org/grpc` and
`google.golang.org/protobuf` provide the gRPC transport and generated types.
Everything else is the Go standard library.

## Build

```sh
go build -o bin/github-token-broker ./cmd/github-token-broker
go build -o bin/agent-token ./cmd/agent-token
go test ./...
```

The generated protobuf and gRPC files are committed. To regenerate them:

```sh
protoc -I proto -I <protobuf-include> \
  --go_out=gen --go_opt=paths=source_relative \
  --go-grpc_out=gen --go-grpc_opt=paths=source_relative \
  proto/tokenbroker/v1/token_broker.proto
```

On NixOS, `<protobuf-include>` can be
`$(nix eval --raw nixpkgs#protobuf)/include`.

## GitHub App

Create a GitHub App with:

- Repository permissions:
  - Contents: Read and write
  - Pull requests: Read and write
  - Metadata: Read-only
- No Administration, Actions, or Workflows permissions.
- Installed only on the repositories the broker should be able to scope to.

Generate an **RSA** private key. GitHub App JWT authentication is RS256; ECDSA
App keys are not supported. The SPIFFE/mTLS side can and normally does use
ECDSA X509-SVIDs.

Record the App ID and installation ID. The private key is read by the broker
from `github.private_key_file`.

## SPIRE

Register the broker workload:

```sh
spire-server entry create \
  -spiffeID spiffe://example.org/github-token-broker \
  -parentID spiffe://example.org/spire/agent/<agent-id> \
  -selector unix:path:/usr/local/bin/github-token-broker
```

Register each agent workload, with a distinct SPIFFE ID:

```sh
spire-server entry create \
  -spiffeID spiffe://example.org/agent/opencode \
  -parentID spiffe://example.org/spire/agent/<agent-id> \
  -selector unix:path:/usr/local/bin/agent-token
```

The broker obtains its own SVID from the local Workload API and serves it as the
TLS server certificate. The client obtains its own SVID and verifies the broker’s
exact SPIFFE ID. No CA or public certificate is configured by hand.

If the broker and agents are on different hosts, each host runs a SPIRE agent and
the registrations point at the appropriate parent agent.

## Configuration

See [`config.example.json`](./config.example.json).

- `trust_domain`: the SPIFFE trust domain the broker accepts at the TLS layer.
- `github.app_id` / `installation_id` / `private_key_file`: GitHub App.
- `policies`: per-SPIFFE-ID allowlist. A policy names repositories and the
  maximum permissions the identity may request. A policy may override
  `installation_id`.
- `cache_skew_seconds`: stop serving a cached token this long before it expires
  (default 300, must be below one hour).

An empty requested permission set means “all permissions in the matching
policy”. A requested permission must be present in the policy and no stronger
than the policy value (`read` < `write`). A request for another repository is
forbidden.

## Run

```sh
sudo install -d -m 700 /etc/github-token-broker
sudo install -m 600 app.pem /etc/github-token-broker/app.pem
sudo install -m 600 config.json /etc/github-token-broker/config.json

./bin/github-token-broker -config /etc/github-token-broker/config.json
```

The process needs access to the SPIRE Workload API socket
(`SPIFFE_ENDPOINT_SOCKET`, normally `/run/spire/sockets/agent.sock`).

## gRPC API

The service is defined in
[`proto/tokenbroker/v1/token_broker.proto`](./proto/tokenbroker/v1/token_broker.proto):

```proto
service TokenBroker {
  rpc MintToken(MintTokenRequest) returns (MintTokenResponse);
}

message MintTokenRequest {
  string repository = 1;
  map<string, string> permissions = 2;
}

message MintTokenResponse {
  string token = 1;
  google.protobuf.Timestamp expires_at = 2;
}
```

The broker selects the installation ID from policy; the client cannot request
an arbitrary installation. An empty `permissions` map means all permissions in
the matching policy. Values are `read` or `write`, and a requested permission
must be present in the policy and no stronger than the policy value.

gRPC status mapping:

- `InvalidArgument`: malformed request, missing repository, invalid permission.
- `Unauthenticated`: no client SVID (normally the mTLS handshake already fails).
- `PermissionDenied`: SPIFFE ID, repository, or permission not allowed.
- `Unavailable`: GitHub token mint failed.
- `ResourceExhausted`: expected for future rate limiting.

The standard `grpc.health.v1.Health` service is registered on the same listener.

## Agent use

Git:

```sh
bin/agent-token exec \
  --broker github-token-broker:8443 \
  --server-id spiffe://example.org/github-token-broker \
  --repository example/repo \
  --permission contents=write \
  --permission pull_requests=write \
  -- git push origin HEAD:chore/example
```

`gh`:

```sh
bin/agent-token exec \
  --broker github-token-broker:8443 \
  --server-id spiffe://example.org/github-token-broker \
  --repository example/repo \
  --permission contents=write \
  --permission pull_requests=write \
  -- gh pr create --base master --head chore/example
```

`--broker` is a gRPC target (`host:port`), not a URL. `agent-token exec` sets
`GH_TOKEN`/`GITHUB_TOKEN`, a temporary `GIT_ASKPASS`,
and clears GitHub credential helpers so the token comes from the broker rather
than the local user’s credentials.

For a service that cannot use `exec`, write an EnvironmentFile:

```sh
bin/agent-token token ... --env-file /run/agent/github.env
```

The file is mode 0600 and remains valid until the installation token expires.

## Security notes

- mTLS authenticates the request. The issued GitHub token is still a bearer
  token; a compromised agent can use or leak it until expiry. Keep tokens
  scoped and short-lived.
- The broker is the trust anchor for the App key. Run it as a minimal service,
  protect the key and config, restrict network access, and audit its logs.
- Do not grant the App Administration. The App token should be unable to change
  branch protection or repository settings.
- Use branch protection on the default branch. The App’s Contents write lets it
  push branches; the broker scopes tokens but cannot prevent a correctly scoped
  write token from updating `master` unless branch protection blocks it.
- The broker caches tokens in memory. There is no refresh token and no token on
  disk.
