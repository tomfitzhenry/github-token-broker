{ pkgs, lib, brokerPackage }:

let
  trustDomain = "example.org";
  nodeID = "spiffe://${trustDomain}/agent/spire-node";
  brokerID = "spiffe://${trustDomain}/agent/github-token-broker";
  clientID = "spiffe://${trustDomain}/agent/agent-token";

  fakeGitHub = pkgs.writeText "fake-github.py" (builtins.readFile ./fake-github.py);

  testKey = pkgs.runCommand "github-token-broker-test-key" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    openssl genrsa -out "$out" 2048
  '';

  spireCerts = pkgs.runCommand "spire-test-certs" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    mkdir -p "$out"
    openssl genrsa -out "$out/ca.key" 2048
    openssl req -x509 -new -key "$out/ca.key" -sha256 -days 1 \
      -subj "/CN=spire-test-ca" -out "$out/ca.crt"
    openssl genrsa -out "$out/agent.key" 2048
    openssl req -new -key "$out/agent.key" -subj "/CN=spire-test-agent" \
      -out "$out/agent.csr"
    printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > "$out/agent.ext"
    openssl x509 -req -in "$out/agent.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" \
      -CAcreateserial -days 1 -sha256 -extfile "$out/agent.ext" -out "$out/agent.crt"
  '';

  bootstrap = pkgs.writeShellScript "spire-agent-bootstrap" ''
    set -eu
    server_socket=/run/spire/server/private/api.sock
    for _ in $(seq 1 120); do
      if ${pkgs.spire}/bin/spire-server healthcheck -socketPath "$server_socket" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    ${pkgs.coreutils}/bin/install -d -m 0750 -o spire-agent -g spire-agent /run/spire/agent
    ${pkgs.spire}/bin/spire-server bundle show -socketPath "$server_socket" -format pem \
      > /run/spire/agent/bundle.pem
    ${pkgs.coreutils}/bin/chown spire-agent:spire-agent /run/spire/agent/bundle.pem
    ${pkgs.coreutils}/bin/chmod 0444 /run/spire/agent/bundle.pem

    have_entry() {
      ${pkgs.spire}/bin/spire-server entry show -socketPath "$server_socket" -output json \
        | ${pkgs.gnugrep}/bin/grep -q "$1"
    }

    if ! have_entry "${nodeID}"; then
      ${pkgs.spire}/bin/spire-server entry create -socketPath "$server_socket" \
        -node -parentID "spiffe://${trustDomain}/spire/server" \
        -spiffeID "${nodeID}" \
        -selector "x509pop:subject:cn:spire-test-agent"
    fi

    if ! have_entry "${brokerID}"; then
      ${pkgs.spire}/bin/spire-server entry create -socketPath "$server_socket" \
        -parentID "${nodeID}" -spiffeID "${brokerID}" \
        -selector "unix:user:github-token-broker"
    fi

    if ! have_entry "${clientID}"; then
      ${pkgs.spire}/bin/spire-server entry create -socketPath "$server_socket" \
        -parentID "${nodeID}" -spiffeID "${clientID}" \
        -selector "unix:uid:0"
    fi
  '';
in
pkgs.testers.nixosTest {
  name = "github-token-broker-spire";

  nodes.machine =
    { pkgs, lib, ... }:
    {
      imports = [ ../module.nix ];

      services.spire.server = {
        enable = true;
        settings = {
          server = {
            trust_domain = trustDomain;
            bind_address = "127.0.0.1";
            bind_port = 8081;
          };
          plugins = {
            DataStore.sql.plugin_data = {
              database_type = "sqlite3";
              connection_string = "$STATE_DIRECTORY/datastore.sqlite3";
            };
            KeyManager.disk.plugin_data = {
              keys_path = "$STATE_DIRECTORY/keys.json";
            };
            NodeAttestor.x509pop.plugin_data = {
              ca_bundle_path = "${spireCerts}/ca.crt";
            };
          };
        };
      };

      services.spire.agent = {
        enable = true;
        settings = {
          agent = {
            trust_domain = trustDomain;
            server_address = "127.0.0.1";
            server_port = 8081;
            socket_path = "/run/spire/agent/public/api.sock";
            trust_bundle_path = "/run/spire/agent/bundle.pem";
          };
          plugins = {
            KeyManager.memory.plugin_data = { };
            NodeAttestor.x509pop.plugin_data = {
              private_key_path = "${spireCerts}/agent.key";
              certificate_path = "${spireCerts}/agent.crt";
            };
            WorkloadAttestor.unix.plugin_data = { };
          };
        };
      };

      systemd.services.spire-agent.after = [ "spire-server.service" ];
      systemd.services.spire-agent.wants = [ "spire-server.service" ];
      systemd.services.spire-agent.serviceConfig.ExecStartPre =
        lib.mkBefore [ "+${bootstrap}" ];

      systemd.services.fake-github = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${fakeGitHub}";
      };

      services.github-token-broker = {
        enable = true;
        package = brokerPackage;
        trustDomain = trustDomain;
        appID = 123;
        installationID = 456;
        privateKeyFile = testKey;
        apiURL = "http://127.0.0.1:8080";
        policies = [
          {
            spiffeID = clientID;
            repositories = [ "example/repo" ];
            permissions = {
              contents = "read";
              pull_requests = "write";
            };
          }
        ];
      };
    };

  testScript = ''
    import json
    import shlex

    start_all()

    machine.wait_for_unit("spire-server.service", timeout=120)
    machine.wait_until_succeeds(
        "spire-server healthcheck -socketPath /run/spire/server/private/api.sock",
        timeout=120,
    )
    machine.wait_for_unit("spire-agent.service", timeout=180)
    machine.wait_until_succeeds(
        "spire-agent healthcheck -socketPath /run/spire/agent/public/api.sock",
        timeout=180,
    )
    machine.wait_until_succeeds(
        "spire-server entry show -socketPath /run/spire/server/private/api.sock "
        "-output json | grep -q github-token-broker",
        timeout=120,
    )
    machine.wait_for_unit("fake-github.service", timeout=60)
    machine.wait_for_unit("github-token-broker.service", timeout=180)

    client_binary = "${brokerPackage}/bin/agent-token"
    token_cmd = (
        "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/public/api.sock "
        f"{shlex.quote(client_binary)} token "
        "--broker 127.0.0.1:8443 "
        f"--server-id {shlex.quote("${brokerID}")} "
        "--repository example/repo "
        "--permission contents=read"
    )

    with subtest("the client gets a scoped token from the broker"):
        output = machine.wait_until_succeeds(token_cmd, timeout=180)
        assert output.strip() == "ghs_test_token", output

        request = json.loads(machine.succeed("cat /tmp/fake-github-request.json"))
        assert request["repositories"] == ["repo"], request
        assert request["permissions"] == {"contents": "read"}, request

    with subtest("policy-denied permissions fail"):
        machine.fail(token_cmd.replace("--permission contents=read", "--permission contents=write"))
  '';
}
