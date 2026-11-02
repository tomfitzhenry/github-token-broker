package githubapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// DefaultAPIURL is the public GitHub REST API.
const DefaultAPIURL = "https://api.github.com"

// Client mints installation tokens for one GitHub App.
type Client struct {
	AppID   int64
	Key     *rsa.PrivateKey
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
}

// Token is a scoped GitHub App installation token.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type tokenRequest struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Mint requests a token scoped to one repository and a subset of the App's
// permissions. GitHub expects repository names, not "owner/name".
func (c *Client) Mint(
	ctx context.Context,
	installationID int64,
	repository string,
	permissions map[string]string,
) (Token, error) {
	if c.AppID <= 0 || c.Key == nil {
		return Token{}, fmt.Errorf("githubapi: App ID and private key are required")
	}
	if installationID <= 0 {
		return Token{}, fmt.Errorf("githubapi: installation ID is required")
	}
	if repository == "" {
		return Token{}, fmt.Errorf("githubapi: repository is required")
	}

	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	jwt, err := SignAppJWT(c.AppID, c.Key, now)
	if err != nil {
		return Token{}, err
	}

	body, err := json.Marshal(tokenRequest{
		Repositories: []string{path.Base(repository)},
		Permissions:  permissions,
	})
	if err != nil {
		return Token{}, err
	}

	baseURL := strings.TrimRight(c.BaseURL, "/")
	if baseURL == "" {
		baseURL = DefaultAPIURL
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", baseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Token{}, fmt.Errorf("GitHub token request failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed tokenResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Token{}, fmt.Errorf("decode GitHub token response: %w", err)
	}
	if parsed.Token == "" {
		return Token{}, fmt.Errorf("GitHub returned an empty token")
	}
	return Token{Token: parsed.Token, ExpiresAt: parsed.ExpiresAt}, nil
}
