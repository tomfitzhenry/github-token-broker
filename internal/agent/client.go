package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	tokenbrokerv1 "github.com/tomfitzhenry/github-token-broker/gen/tokenbroker/v1"
	"google.golang.org/grpc"
)

// Token is a scoped GitHub installation token returned by the broker.
type Token struct {
	Token     string
	ExpiresAt time.Time
}

// Client obtains tokens from the broker over SPIFFE mTLS.
type Client struct {
	conn   *grpc.ClientConn
	source *workloadapi.X509Source
	client tokenbrokerv1.TokenBrokerClient
}

// New creates a client using the workload's X509-SVID and verifies that the
// broker presents the expected SPIFFE ID. brokerAddr is a gRPC target such as
// "github-broker:8443".
func New(ctx context.Context, brokerAddr, serverID string) (*Client, error) {
	id, err := spiffeid.FromString(serverID)
	if err != nil {
		return nil, fmt.Errorf("server SPIFFE ID: %w", err)
	}
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE Workload API: %w", err)
	}
	creds := grpccredentials.MTLSClientCredentials(
		source,
		source,
		tlsconfig.AuthorizeID(id),
	)
	conn, err := grpc.NewClient(
		brokerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<10)),
	)
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("connect to broker: %w", err)
	}
	return &Client{
		conn:   conn,
		source: source,
		client: tokenbrokerv1.NewTokenBrokerClient(conn),
	}, nil
}

// Close releases the gRPC connection and Workload API source.
func (c *Client) Close() error {
	var first error
	if c.conn != nil {
		first = c.conn.Close()
	}
	if c.source != nil {
		if err := c.source.Close(); first == nil && err != nil {
			first = err
		}
	}
	return first
}

// Token requests a token scoped to one repository and permission set.
func (c *Client) Token(ctx context.Context, repository string, permissions map[string]string) (Token, error) {
	resp, err := c.client.MintToken(ctx, &tokenbrokerv1.MintTokenRequest{
		Repository:  repository,
		Permissions: permissions,
	})
	if err != nil {
		return Token{}, err
	}
	expiresAt := time.Time{}
	if ts := resp.GetExpiresAt(); ts != nil {
		expiresAt = ts.AsTime()
	}
	return Token{Token: resp.GetToken(), ExpiresAt: expiresAt}, nil
}
