package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomfitzhenry/github-token-broker/internal/agent"
)

const usage = `agent-token - obtain a scoped GitHub token from the SPIFFE broker

Usage:
  agent-token token --broker ADDR --server-id SPIFFE_ID --repository OWNER/REPO [flags]
  agent-token exec  --broker ADDR --server-id SPIFFE_ID --repository OWNER/REPO [flags] -- COMMAND...
  agent-token -h

The client obtains an X509-SVID from the local SPIRE agent, uses it for mTLS,
and asks the broker over gRPC for a short-lived GitHub App installation token.

Flags common to both commands:
  --broker ADDR         broker gRPC address, e.g. github-broker:8443
  --server-id ID        broker SPIFFE ID, e.g. spiffe://example.org/github-broker
  --repository REPO     owner/repo to scope the token to
  --permission KEY=VAL  requested permission, repeatable (default: policy defaults)
  --cache-ttl DURATION  cache minted tokens locally for this long (default 5m; 0 disables)
  --cache-dir DIR       cache directory (default: per-user runtime or cache directory)

The cache is per unix user and per token scope (broker, repository and
permission set), with a mode-0600 file in a mode-0700 directory. A fresh cache
skips the SPIFFE Workload API and broker call, which matters for the many
short-lived gh/git invocations an agent makes. The previous token is removed
before a refresh, so a broker outage fails closed instead of serving an expiry.

token also accepts:
  --env-file FILE       write GH_TOKEN/GITHUB_TOKEN to a 0600 file instead of stdout
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "token":
		return runToken(args[1:], stdout, stderr)
	case "exec":
		return runExec(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s\n", args[0], usage)
		return 2
	}
}

type options struct {
	broker      string
	serverID    string
	repository  string
	permissions permissionFlag
	envFile     string
	cacheTTL    time.Duration
	cacheDir    string
}

func addFlags(fs *flag.FlagSet, opts *options) {
	fs.StringVar(&opts.broker, "broker", "", "broker gRPC address (host:port)")
	fs.StringVar(&opts.serverID, "server-id", "", "broker SPIFFE ID")
	fs.StringVar(&opts.repository, "repository", "", "owner/repo to scope the token to")
	fs.Var(&opts.permissions, "permission", "requested permission KEY=VALUE (repeatable)")
	fs.DurationVar(
		&opts.cacheTTL,
		"cache-ttl",
		defaultCacheTTL,
		"cache minted tokens locally for this long; 0 disables the cache",
	)
	fs.StringVar(
		&opts.cacheDir,
		"cache-dir",
		"",
		"token cache directory (default: $XDG_RUNTIME_DIR, then $XDG_CACHE_HOME, then ~/.cache)",
	)
}

func (o *options) validate() error {
	if o.broker == "" {
		return fmt.Errorf("--broker is required")
	}
	if o.serverID == "" {
		return fmt.Errorf("--server-id is required")
	}
	if o.repository == "" {
		return fmt.Errorf("--repository is required")
	}
	return nil
}

func (o *options) token(ctx context.Context, warn io.Writer) (agent.Token, error) {
	return tokenWithCache(ctx, o, func(ctx context.Context) (agent.Token, error) {
		client, err := agent.New(ctx, o.broker, o.serverID)
		if err != nil {
			return agent.Token{}, err
		}
		defer client.Close()
		return client.Token(ctx, o.repository, o.permissions.values)
	}, warn)
}

func runToken(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts options
	addFlags(fs, &opts)
	fs.StringVar(&opts.envFile, "env-file", "", "write a 0600 EnvironmentFile instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "token takes no positional arguments")
		return 2
	}
	if err := opts.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := opts.token(ctx, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if opts.envFile != "" {
		if err := writeEnvFile(opts.envFile, token.Token); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stderr, "wrote %s\n", opts.envFile)
		return 0
	}
	fmt.Fprintln(stdout, token.Token)
	return 0
}

func runExec(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts options
	addFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(stderr, "exec requires a command after --")
		return 2
	}
	if err := opts.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	token, err := opts.token(ctx, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return runCommand(token.Token, command, stdout, stderr)
}

type permissionFlag struct {
	values map[string]string
}

func (p *permissionFlag) String() string {
	if p == nil || len(p.values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(p.values))
	for key, value := range p.values {
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ",")
}

func (p *permissionFlag) Set(value string) error {
	key, val, ok := strings.Cut(value, "=")
	if !ok || key == "" || val == "" {
		return fmt.Errorf("permission must be KEY=VALUE")
	}
	if p.values == nil {
		p.values = make(map[string]string)
	}
	p.values[key] = val
	return nil
}

func writeEnvFile(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := fmt.Fprintf(file, "GH_TOKEN=%s\nGITHUB_TOKEN=%s\n", token, token); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return file.Close()
}

func runCommand(token string, command []string, stdout, stderr io.Writer) int {
	dir, err := os.MkdirTemp("", "agent-token-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	askpass := filepath.Join(dir, "askpass")
	script := "#!/bin/sh\ncase \"$1\" in\n  *Username*) printf '%s\\n' x-access-token ;;\n  *) printf '%s\\n' \"$GH_TOKEN\" ;;\nesac\n"
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(),
		"GH_TOKEN="+token,
		"GITHUB_TOKEN="+token,
		"GIT_ASKPASS="+askpass,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.https://github.com.helper",
		"GIT_CONFIG_VALUE_0=",
	)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
