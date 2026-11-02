package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Token is a scoped GitHub installation token returned by the broker.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type tokenRequest struct {
	Repository  string            `json:"repository"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// Client obtains tokens from the broker over SPIFFE mTLS.
type Client struct {
	endpoint string
	http     *http.Client
	source   *workloadapi.X509Source
}

// New creates a client using the workload's X509-SVID and verifies that the
// broker presents the expected SPIFFE ID.
func New(ctx context.Context, brokerURL, serverID string) (*Client, error) {
	parsed, err := url.Parse(brokerURL)
	if err != nil {
		return nil, fmt.Errorf("broker URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("broker URL must use https")
	}
	id, err := spiffeid.FromString(serverID)
	if err != nil {
		return nil, fmt.Errorf("server SPIFFE ID: %w", err)
	}
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE Workload API: %w", err)
	}
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	return &Client{
		endpoint: strings.TrimRight(brokerURL, "/") + "/v1/token",
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		source: source,
	}, nil
}

// Close releases the Workload API source.
func (c *Client) Close() error {
	if c.source == nil {
		return nil
	}
	return c.source.Close()
}

// Token requests a token scoped to one repository and permission set.
func (c *Client) Token(ctx context.Context, repository string, permissions map[string]string) (Token, error) {
	body, err := json.Marshal(tokenRequest{Repository: repository, Permissions: permissions})
	if err != nil {
		return Token{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("broker returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var token Token
	if err := json.Unmarshal(respBody, &token); err != nil {
		return Token{}, fmt.Errorf("decode broker response: %w", err)
	}
	if token.Token == "" {
		return Token{}, fmt.Errorf("broker returned an empty token")
	}
	return token, nil
}
