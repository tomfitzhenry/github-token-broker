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

  spiffeEnabled = cfg.listenAddress != null && cfg.listenAddress != "";
  peersecEnabled = cfg.peersecListenAddress != null && cfg.peersecListenAddress != "";
  insecureEnabled = cfg.insecureListenAddress != null && cfg.insecureListenAddress != "";

  policyArg =
    policy:
    let
      identity =
        if policy.spiffeID != null then
          "spiffe_id=${policy.spiffeID}"
        else if policy.selinuxType != null then
          "selinux_type=${policy.selinuxType}"
        else
          "insecure=true";
      permissions = concatStringsSep "," (
        map (name: "${name}=${policy.permissions.${name}}") (lib.attrNames policy.permissions)
      );
      installation = optionalString (policy.installationID != null) (
        ";installation_id=${toString policy.installationID}"
      );
    in
    "${identity};permissions=${permissions}${installation}";

  execArgs = [
    "-listen"
    (escapeShellArg (if cfg.listenAddress == null then "" else cfg.listenAddress))
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
  ++ lib.optionals peersecEnabled [
    "-peersec-listen"
    (escapeShellArg cfg.peersecListenAddress)
  ]
  ++ lib.optionals insecureEnabled [
    "-insecure-listen"
    (escapeShellArg cfg.insecureListenAddress)
  ]
  ++ lib.optionals (cfg.trustDomain != null && cfg.trustDomain != "") [
    "-trust-domain"
    (escapeShellArg cfg.trustDomain)
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
      type = types.nullOr types.str;
      default = ":8443";
      description = "TCP address for the SPIFFE-mTLS gRPC listener (null or empty to disable).";
    };

    peersecListenAddress = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "TCP or unix:// address for the SO_PEERSEC gRPC listener (null or empty to disable).";
    };

    insecureListenAddress = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "TCP address for the plain h2c gRPC listener (e.g. a WireGuard IP:port; null or empty to disable).";
    };

    trustDomain = mkOption {
      type = types.nullOr types.str;
      default = null;
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
              type = types.nullOr types.str;
              default = null;
              description = "SPIFFE ID the policy applies to.";
            };
            selinuxType = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "SELinux domain type (from SO_PEERSEC) the policy applies to.";
            };
            insecure = mkOption {
              type = types.bool;
              default = false;
              description = "Apply this policy to callers on the plain h2c (-insecure-listen) listener.";
            };
            installationID = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "Optional per-policy installation ID.";
            };
            permissions = mkOption {
              type = types.attrsOf (types.enum [ "read" "write" ]);
              description = "Maximum permissions this identity may request.";
            };
          };
        }
      );
      default = [ ];
      description = "Per-identity permission grants enforced by the broker. The GitHub App installation restricts which repositories each policy can cover.";
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
      {
        assertion = spiffeEnabled || peersecEnabled || insecureEnabled;
        message = "services.github-token-broker requires at least one of listenAddress, peersecListenAddress, or insecureListenAddress.";
      }
      {
        assertion = !spiffeEnabled || (cfg.trustDomain != null && cfg.trustDomain != "");
        message = "services.github-token-broker.trustDomain is required when listenAddress is enabled.";
      }
      {
        assertion = lib.all (
          p:
          (lib.count (x: x) [
            (p.spiffeID != null)
            (p.selinuxType != null)
            p.insecure
          ]) == 1
        ) cfg.policies;
        message = "Each policy in services.github-token-broker.policies must set exactly one of spiffeID, selinuxType, or insecure = true.";
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
      description = "SPIFFE-mTLS / SO_PEERSEC GitHub App token broker";
      wantedBy = [ "multi-user.target" ];
      after = lib.mkIf spiffeEnabled [ "spire-agent.service" ];
      wants = lib.mkIf spiffeEnabled [ "spire-agent.service" ];
      startLimitIntervalSec = 0;

      environment = lib.mkIf spiffeEnabled {
        SPIFFE_ENDPOINT_SOCKET = cfg.spiffeEndpointSocket;
      };

      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = lib.mkIf spiffeEnabled [ cfg.spireGroup ];
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
