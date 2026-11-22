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

const usage = `agent-token - obtain a scoped GitHub token from the token broker

Usage:
  agent-token token --broker ADDR --repository OWNER/REPO [flags]
  agent-token exec  --broker ADDR --repository OWNER/REPO [flags] -- COMMAND...
  agent-token -h

In spiffe mode (default), the client obtains an X509-SVID from the local SPIRE
agent and uses it for mTLS. In peersec mode, the client relies on kernel
SO_PEERSEC (for example, over Labeled IPsec ESP-NULL or a Unix socket).

Flags common to both commands:
  --broker ADDR               broker gRPC address, e.g. github-broker:8443
  --auth MODE                 authentication mode: spiffe or peersec (default: spiffe)
  --server-id ID              broker SPIFFE ID (required when --auth=spiffe)
  --server-selinux-type TYPE  expected broker SELinux type (optional when --auth=peersec)
  --repository REPO           owner/repo to scope the token to
  --permission KEY=VAL        requested permission, repeatable (default: policy defaults)

token also accepts:
  --env-file FILE             write GH_TOKEN/GITHUB_TOKEN to a 0600 file instead of stdout
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
	broker            string
	auth              string
	serverID          string
	serverSELinuxType string
	repository        string
	permissions       permissionFlag
	envFile           string
}

func addFlags(fs *flag.FlagSet, opts *options) {
	fs.StringVar(&opts.broker, "broker", "", "broker gRPC address (host:port or unix:///path)")
	fs.StringVar(&opts.auth, "auth", "spiffe", "authentication mode: spiffe or peersec")
	fs.StringVar(&opts.serverID, "server-id", "", "broker SPIFFE ID (for --auth=spiffe)")
	fs.StringVar(&opts.serverSELinuxType, "server-selinux-type", "", "expected broker SELinux type (for --auth=peersec)")
	fs.StringVar(&opts.repository, "repository", "", "owner/repo to scope the token to")
	fs.Var(&opts.permissions, "permission", "requested permission KEY=VALUE (repeatable)")
}

func (o *options) validate() error {
	if o.broker == "" {
		return fmt.Errorf("--broker is required")
	}
	if o.repository == "" {
		return fmt.Errorf("--repository is required")
	}
	switch o.auth {
	case "spiffe":
		if o.serverID == "" {
			return fmt.Errorf("--server-id is required when --auth=spiffe")
		}
		if o.serverSELinuxType != "" {
			return fmt.Errorf("--server-selinux-type is only valid with --auth=peersec")
		}
	case "peersec":
		if o.serverID != "" {
			return fmt.Errorf("--server-id is only valid with --auth=spiffe")
		}
	default:
		return fmt.Errorf("unknown --auth mode %q (want spiffe or peersec)", o.auth)
	}
	return nil
}

func (o *options) token(ctx context.Context) (agent.Token, error) {
	var (
		client *agent.Client
		err    error
	)
	switch o.auth {
	case "peersec":
		client, err = agent.NewPeerSec(o.broker, o.serverSELinuxType)
	default:
		client, err = agent.New(ctx, o.broker, o.serverID)
	}
	if err != nil {
		return agent.Token{}, err
	}
	defer client.Close()
	return client.Token(ctx, o.repository, o.permissions.values)
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
	token, err := opts.token(ctx)
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
	token, err := opts.token(ctx)
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
