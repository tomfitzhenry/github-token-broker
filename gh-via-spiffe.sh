# gh-via-spiffe: run the GitHub CLI as a GitHub App, using a token minted by a
# SPIFFE token broker.
#
# Intended to be aliased as `gh`:
#
#     alias gh=gh-via-spiffe
#
# For the target GitHub repository, it mints a scoped installation token from
# the broker and runs the real gh with GH_TOKEN set. The repository is resolved
# in precedence order from:
#   1. GH_VIA_SPIFFE_REPOSITORY
#   2. --repo / -R flags on the command line
#   3. GH_REPO
#   4. positional `gh repo <subcommand> owner/repo` arguments
#   5. `path=` on stdin for `gh auth git-credential get` (requires git's
#      credential.https://github.com.useHttpPath = true)
#   6. the current checkout's `origin` remote
#
# When no repository can be determined or no token can be minted (no SPIRE
# agent, broker unreachable, repository not authorized), it falls back to gh's
# normal authentication, so the alias is safe to use everywhere.
#
# For non-interactive callers (scripts), a symlink named `gh` earlier in PATH
# has the same effect; aliases only apply to interactive shells.
#
# Configuration:
#   GH_VIA_SPIFFE_BROKER       broker gRPC address, e.g. host:8443     (required)
#   GH_VIA_SPIFFE_SERVER_ID    SPIFFE ID the broker presents           (required)
#   GH_VIA_SPIFFE_REPOSITORY   owner/repo override
#   GH_VIA_SPIFFE_PERMISSIONS  comma-separated KEY=VALUE list, e.g.
#                              contents=read,pull_requests=write
#                              (default: whatever the broker policy grants)
#   SPIFFE_ENDPOINT_SOCKET     SPIRE Workload API socket, if not the default

# nixpkgs' SPIRE module (and this repository's NixOS module) use this path;
# SPIRE's own default is /tmp/spire-agent/public/api.sock.
: "${SPIFFE_ENDPOINT_SOCKET:=unix:///run/spire/agent/public/api.sock}"
export SPIFFE_ENDPOINT_SOCKET

if [ -z "${GH_VIA_SPIFFE_BROKER:-}" ] || [ -z "${GH_VIA_SPIFFE_SERVER_ID:-}" ]; then
  echo "gh-via-spiffe: set GH_VIA_SPIFFE_BROKER and GH_VIA_SPIFFE_SERVER_ID" >&2
  exit 2
fi

normalize_repo() {
  local raw=$1
  raw=${raw%/}
  case "${raw}" in
    github.com[:/]* | *://github.com[:/]* | *@github.com[:/]*)
      raw=${raw#*github.com?}
      raw=${raw#/}
      ;;
    *://* | *:* | */*/*)
      return 0
      ;;
  esac
  local owner=${raw%%/*}
  local rest=${raw#*/}
  if [ "${rest}" = "${raw}" ]; then
    return 0
  fi
  local name=${rest%%/*}
  name=${name%.git}
  if [ -n "${owner}" ] && [ -n "${name}" ]; then
    printf '%s/%s\n' "${owner}" "${name}"
  fi
}

repository=${GH_VIA_SPIFFE_REPOSITORY:-}

# `--repo owner/name` / `-R owner/name` overrides GH_REPO, matching gh itself.
if [ -z "${repository}" ]; then
  expect_repo=""
  for arg in "$@"; do
    if [ -n "${expect_repo}" ]; then
      repository=$(normalize_repo "${arg}")
      expect_repo=""
      break
    fi
    case "${arg}" in
      --) break ;;
      --repo | -R) expect_repo=1 ;;
      --repo=* | -R=*)
        repository=$(normalize_repo "${arg#*=}")
        break
        ;;
    esac
  done
fi

if [ -z "${repository}" ] && [ -n "${GH_REPO:-}" ]; then
  repository=$(normalize_repo "${GH_REPO}")
fi

# `gh repo view owner/name`, `gh repo clone owner/name ...`, and the other
# subcommands that accept the repository positionally.
if [ -z "${repository}" ] && [ "$#" -ge 3 ] && [ "$1" = "repo" ]; then
  case "$2" in
    clone | view | fork | edit | delete | archive | unarchive | rename | sync | set-default)
      case "$3" in
        -*) ;;
        *) repository=$(normalize_repo "$3") ;;
      esac
      ;;
  esac
fi

# `git` invokes `gh auth git-credential get` with key=value pairs on stdin;
# with `credential.https://github.com.useHttpPath = true`, `path=` carries the
# target repository even outside a checkout (e.g. `git clone`). Buffer stdin so
# the real `gh` still receives it verbatim.
replayed_stdin=0
stdin_replay=""
if [ -z "${repository}" ] && [ "${1:-}" = "auth" ] && [ "${2:-}" = "git-credential" ] && [ "${3:-}" = "get" ]; then
  stdin_replay=$(cat)
  replayed_stdin=1
  cred_host=""
  cred_path=""
  while IFS='=' read -r key value; do
    case "${key}" in
      host) cred_host=${value} ;;
      path) cred_path=${value} ;;
    esac
  done <<<"${stdin_replay}"
  if [ "${cred_host}" = "github.com" ] && [ -n "${cred_path}" ]; then
    repository=$(normalize_repo "github.com/${cred_path#/}")
  fi
fi

if [ -z "${repository}" ]; then
  remote=$(git config --get remote.origin.url 2>/dev/null || true)
  if [ -n "${remote}" ]; then
    repository=$(normalize_repo "${remote}")
  fi
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

if [ "${replayed_stdin}" -eq 1 ]; then
  if [ -n "${stdin_replay}" ]; then
    exec gh "$@" <<<"${stdin_replay}"
  else
    exec gh "$@" </dev/null
  fi
fi
exec gh "$@"
