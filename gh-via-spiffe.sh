# gh-via-spiffe: run the GitHub CLI as a GitHub App, using a token minted by a
# SPIFFE token broker.
#
# Intended to be aliased as `gh`:
#
#     alias gh=gh-via-spiffe
#
# For the repository named by the checkout's `origin` remote, it mints a scoped
# installation token from the broker and runs the real gh with GH_TOKEN set.
# Outside a GitHub checkout, or when no token can be minted (no SPIRE agent,
# broker unreachable, repository not authorized), it falls back to gh's normal
# authentication, so the alias is safe to use everywhere.
#
# For non-interactive callers (scripts), a symlink named `gh` earlier in PATH
# has the same effect; aliases only apply to interactive shells.
#
# Configuration:
#   GH_VIA_SPIFFE_BROKER       broker gRPC address, e.g. host:8443     (required)
#   GH_VIA_SPIFFE_SERVER_ID    SPIFFE ID the broker presents           (required)
#   GH_VIA_SPIFFE_REPOSITORY   owner/repo override (default: from origin)
#   GH_VIA_SPIFFE_PERMISSIONS  comma-separated KEY=VALUE list, e.g.
#                              contents=read,pull_requests=write
#                              (default: whatever the broker policy grants)
#   SPIFFE_ENDPOINT_SOCKET     SPIRE Workload API socket, if not the default

if [ -z "${GH_VIA_SPIFFE_BROKER:-}" ] || [ -z "${GH_VIA_SPIFFE_SERVER_ID:-}" ]; then
  echo "gh-via-spiffe: set GH_VIA_SPIFFE_BROKER and GH_VIA_SPIFFE_SERVER_ID" >&2
  exit 2
fi

repository=${GH_VIA_SPIFFE_REPOSITORY:-}
if [ -z "${repository}" ]; then
  remote=$(git config --get remote.origin.url 2>/dev/null || true)
  repository=$(printf '%s\n' "${remote}" | sed -n 's|.*github\.com[:/]\([^/]*/[^/]*\)$|\1|p')
  repository=${repository%.git}
fi

if [ -n "${repository}" ]; then
  # gh cannot infer the repository from non-standard remotes (e.g. the
  # git-remote-gittuf "gittuf::" transport), so tell it explicitly.
  export GH_REPO="${repository}"
  token_args=(
    --broker "${GH_VIA_SPIFFE_BROKER}"
    --server-id "${GH_VIA_SPIFFE_SERVER_ID}"
    --repository "${repository}"
  )
  if [ -n "${GH_VIA_SPIFFE_PERMISSIONS:-}" ]; then
    IFS=',' read -r -a permissions <<<"${GH_VIA_SPIFFE_PERMISSIONS}"
    for permission in "${permissions[@]}"; do
      token_args+=(--permission "${permission}")
    done
  fi
  # Cap the mint so a machine off the broker's network falls back quickly.
  if token=$(timeout 10 agent-token token "${token_args[@]}" 2>/dev/null); then
    export GH_TOKEN="${token}"
    export GITHUB_TOKEN="${token}"
  fi
fi

exec gh "$@"
