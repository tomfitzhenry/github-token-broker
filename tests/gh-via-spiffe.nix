{ pkgs }:
let
  fakeBroker = pkgs.writeShellScriptBin "agent-token" ''
    repo=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --repository)
          repo="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    printf 'token:%s\n' "$repo"
  '';

  fakeGh = pkgs.writeShellScriptBin "gh" ''
    printf 'GH_TOKEN=%s\n' "''${GH_TOKEN:-}"
    printf 'GH_REPO=%s\n' "''${GH_REPO:-}"
    printf 'ARGS=%s\n' "$*"
    if [ "''${FAKE_GH_READ_STDIN:-0}" = "1" ]; then
      printf 'STDIN_BEGIN\n'
      cat
      printf 'STDIN_END\n'
    fi
  '';

  wrapper = pkgs.callPackage ../gh-via-spiffe.nix {
    brokerPackage = fakeBroker;
    gh = fakeGh;
  };
in
pkgs.runCommand "gh-via-spiffe-test"
  {
    nativeBuildInputs = [
      wrapper
      pkgs.git
    ];
  }
  ''
    set -euo pipefail

    export GH_VIA_SPIFFE_BROKER=broker.example:8443
    export GH_VIA_SPIFFE_SERVER_ID=spiffe://example.org/broker

    fail() {
      echo "FAIL: $*" >&2
      exit 1
    }

    assert_contains() {
      local haystack=$1
      local needle=$2
      local label=$3
      case "$haystack" in
        *"$needle"*) ;;
        *)
          echo "Output was:" >&2
          printf '%s\n' "$haystack" >&2
          fail "$label: expected to contain '$needle'"
          ;;
      esac
    }

    outside=$(mktemp -d)
    checkout=$(mktemp -d)
    git -C "$checkout" init -q
    git -C "$checkout" remote add origin https://github.com/origin-owner/origin-repo.git

    gittuf_checkout=$(mktemp -d)
    git -C "$gittuf_checkout" init -q
    git -C "$gittuf_checkout" remote add origin gittuf::git@github.com:gittuf-owner/gittuf-repo.git

    # 1. Outside a checkout with no repo hints -> fallback without GH_TOKEN.
    res=$(cd "$outside" && gh-via-spiffe auth status)
    assert_contains "$res" "GH_TOKEN="$'\n' "fallback outside checkout"

    # 2. Checkout origin remote (HTTPS + .git).
    res=$(cd "$checkout" && gh-via-spiffe pr list)
    assert_contains "$res" "GH_TOKEN=token:origin-owner/origin-repo" "origin remote HTTPS"
    assert_contains "$res" "GH_REPO=origin-owner/origin-repo" "origin remote exports GH_REPO"

    # 3. Checkout origin remote with gittuf:: SSH transport.
    res=$(cd "$gittuf_checkout" && gh-via-spiffe pr list)
    assert_contains "$res" "GH_TOKEN=token:gittuf-owner/gittuf-repo" "gittuf remote"
    assert_contains "$res" "GH_REPO=gittuf-owner/gittuf-repo" "gittuf remote exports GH_REPO"

    # 4. --repo / -R forms outside a checkout, plus URL normalization.
    res=$(cd "$outside" && gh-via-spiffe issue list --repo flag-owner/flag-repo)
    assert_contains "$res" "GH_TOKEN=token:flag-owner/flag-repo" "--repo space"

    res=$(cd "$outside" && gh-via-spiffe issue list --repo=flag-owner/flag-repo.git)
    assert_contains "$res" "GH_TOKEN=token:flag-owner/flag-repo" "--repo= with .git"

    res=$(cd "$outside" && gh-via-spiffe issue list -R https://github.com/flag-owner/flag-repo)
    assert_contains "$res" "GH_TOKEN=token:flag-owner/flag-repo" "-R URL"

    res=$(cd "$outside" && gh-via-spiffe issue list -R=flag-owner/flag-repo)
    assert_contains "$res" "GH_TOKEN=token:flag-owner/flag-repo" "-R="

    # 5. `--` stops flag scanning (do not misread arguments after `--`).
    res=$(cd "$outside" && gh-via-spiffe api /zen -- -R ignored/repo)
    assert_contains "$res" "GH_TOKEN="$'\n' "stop scanning at --"

    # 6. GH_REPO outside a checkout and overriding origin remote.
    res=$(cd "$outside" && GH_REPO=env-owner/env-repo gh-via-spiffe issue list)
    assert_contains "$res" "GH_TOKEN=token:env-owner/env-repo" "GH_REPO outside checkout"

    res=$(cd "$checkout" && GH_REPO=env-owner/env-repo gh-via-spiffe issue list)
    assert_contains "$res" "GH_TOKEN=token:env-owner/env-repo" "GH_REPO beats origin"

    # 7. Precedence: GH_VIA_SPIFFE_REPOSITORY > --repo/-R > GH_REPO > positional > origin.
    res=$(cd "$checkout" && GH_REPO=env-owner/env-repo gh-via-spiffe issue list -R flag-owner/flag-repo)
    assert_contains "$res" "GH_TOKEN=token:flag-owner/flag-repo" "-R beats GH_REPO"

    res=$(cd "$checkout" && GH_VIA_SPIFFE_REPOSITORY=override-owner/override-repo GH_REPO=env-owner/env-repo gh-via-spiffe issue list -R flag-owner/flag-repo)
    assert_contains "$res" "GH_TOKEN=token:override-owner/override-repo" "GH_VIA_SPIFFE_REPOSITORY beats -R"

    # 8. Positional `gh repo <subcommand> owner/repo` outside and inside a checkout.
    res=$(cd "$outside" && gh-via-spiffe repo view pos-owner/pos-repo --json name)
    assert_contains "$res" "GH_TOKEN=token:pos-owner/pos-repo" "positional gh repo view"

    res=$(cd "$checkout" && gh-via-spiffe repo clone https://github.com/pos-owner/pos-repo.git)
    assert_contains "$res" "GH_TOKEN=token:pos-owner/pos-repo" "positional gh repo clone beats origin"

    # Positional flag like `gh repo view --web` inside a checkout falls through to origin.
    res=$(cd "$checkout" && gh-via-spiffe repo view --web)
    assert_contains "$res" "GH_TOKEN=token:origin-owner/origin-repo" "gh repo view --web uses origin"

    # 9. `gh auth git-credential get` parses path= on stdin and replays stdin to gh.
    res=$(
      cd "$outside" && FAKE_GH_READ_STDIN=1 gh-via-spiffe auth git-credential get <<'EOF'
protocol=https
host=github.com
path=cred-owner/cred-repo.git
EOF
    )
    assert_contains "$res" "GH_TOKEN=token:cred-owner/cred-repo" "git-credential path="
    assert_contains "$res" "host=github.com" "git-credential stdin host replayed"
    assert_contains "$res" "path=cred-owner/cred-repo.git" "git-credential stdin path replayed"

    # 10. `gh auth git-credential get` for non-github.com host does not mint and replays stdin.
    res=$(
      cd "$outside" && FAKE_GH_READ_STDIN=1 gh-via-spiffe auth git-credential get <<'EOF'
protocol=https
host=notgithub.com
path=other-owner/other-repo.git
EOF
    )
    assert_contains "$res" "GH_TOKEN="$'\n' "git-credential non-github.com skips mint"
    assert_contains "$res" "host=notgithub.com" "git-credential non-github.com stdin replayed"

    # 11. `gh auth git-credential get` without path= inside checkout falls back to origin and replays stdin.
    res=$(
      cd "$checkout" && FAKE_GH_READ_STDIN=1 gh-via-spiffe auth git-credential get <<'EOF'
protocol=https
host=github.com
EOF
    )
    assert_contains "$res" "GH_TOKEN=token:origin-owner/origin-repo" "git-credential without path uses origin"
    assert_contains "$res" "host=github.com" "git-credential without path stdin replayed"

    # 12. Non-github.com URLs in --repo are ignored (fall back cleanly).
    res=$(cd "$outside" && gh-via-spiffe issue list -R https://notgithub.com/a/b)
    assert_contains "$res" "GH_TOKEN="$'\n' "non-github.com URL ignored"

    touch "$out"
  ''
