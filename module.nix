{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.github-token-broker;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    concatStringsSep
    escapeShellArg
    optionalString
    ;

  policyArg =
    policy:
    let
      permissions = concatStringsSep "," (
        map (name: "${name}=${policy.permissions.${name}}") (lib.attrNames policy.permissions)
      );
      installation = optionalString (policy.installationID != null) (
        ";installation_id=${toString policy.installationID}"
      );
    in
    "spiffe_id=${policy.spiffeID};repositories=${concatStringsSep "," policy.repositories};permissions=${permissions}${installation}";

  execArgs = [
    "-listen"
    (escapeShellArg cfg.listenAddress)
    "-trust-domain"
    (escapeShellArg cfg.trustDomain)
    "-app-id"
    (toString cfg.appID)
    "-installation-id"
    (toString cfg.installationID)
    "-private-key"
    "%d/app.pem"
    "-api-url"
    (escapeShellArg cfg.apiURL)
    "-cache-skew"
    (escapeShellArg cfg.cacheSkew)
  ]
  ++ map (policy: "-policy ${escapeShellArg (policyArg policy)}") cfg.policies
  ++ cfg.extraArgs;
in
{
  options.services.github-token-broker = {
    enable = mkEnableOption "the SPIFFE-mTLS GitHub App token broker";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The github-token-broker package.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = ":8443";
      description = "TCP address for the gRPC listener.";
    };

    trustDomain = mkOption {
      type = types.str;
      description = "SPIFFE trust domain accepted from clients.";
    };

    appID = mkOption {
      type = types.int;
      description = "GitHub App ID.";
    };

    installationID = mkOption {
      type = types.int;
      description = "Default GitHub App installation ID.";
    };

    privateKeyFile = mkOption {
      type = types.path;
      description = "GitHub App RSA private key. Loaded as a systemd credential.";
    };

    apiURL = mkOption {
      type = types.str;
      default = "https://api.github.com";
      description = "GitHub REST API base URL.";
    };

    cacheSkew = mkOption {
      type = types.str;
      default = "5m";
      description = "Go duration; stop serving cached tokens this long before expiry.";
    };

    spiffeEndpointSocket = mkOption {
      type = types.str;
      default = "unix:///run/spire/agent/public/api.sock";
      description = "SPIFFE Workload API endpoint.";
    };

    spireGroup = mkOption {
      type = types.str;
      default = "spire-agent";
      description = "Group that can read the SPIRE Workload API socket.";
    };

    user = mkOption {
      type = types.str;
      default = "github-token-broker";
      description = "Service user.";
    };

    group = mkOption {
      type = types.str;
      default = "github-token-broker";
      description = "Service group.";
    };

    createUser = mkOption {
      type = types.bool;
      default = true;
      description = "Create the service user and group.";
    };

    policies = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            spiffeID = mkOption {
              type = types.str;
              description = "SPIFFE ID the policy applies to.";
            };
            installationID = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "Optional per-policy installation ID.";
            };
            repositories = mkOption {
              type = types.listOf types.str;
              description = "Repositories this identity may request tokens for.";
            };
            permissions = mkOption {
              type = types.attrsOf (types.enum [ "read" "write" ]);
              description = "Maximum permissions this identity may request.";
            };
          };
        }
      );
      default = [ ];
      description = "Per-SPIFFE-ID allowlist enforced by the broker.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments appended to the broker command line.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.policies != [ ];
        message = "services.github-token-broker.policies must not be empty.";
      }
    ];

    users.groups = lib.mkIf cfg.createUser {
      ${cfg.group} = { };
    };
    users.users = lib.mkIf cfg.createUser {
      ${cfg.user} = {
        isSystemUser = true;
        group = cfg.group;
      };
    };

    systemd.services.github-token-broker = {
      description = "SPIFFE-mTLS GitHub App token broker";
      wantedBy = [ "multi-user.target" ];
      after = [ "spire-agent.service" ];
      wants = [ "spire-agent.service" ];
      startLimitIntervalSec = 0;

      environment.SPIFFE_ENDPOINT_SOCKET = cfg.spiffeEndpointSocket;

      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = [ cfg.spireGroup ];
        LoadCredential = [ "app.pem:${cfg.privateKeyFile}" ];
        ExecStart = "${lib.getExe cfg.package} ${concatStringsSep " " execArgs}";
        Restart = "on-failure";
        RestartSec = 2;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        LockPersonality = true;
        RestrictRealtime = true;
        CapabilityBoundingSet = "";
        SystemCallArchitectures = "native";
      };
    };
  };
}
