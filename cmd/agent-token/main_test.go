package main

import "testing"

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    options
		wantErr bool
	}{
		{
			name: "spiffe valid",
			opts: options{
				broker:     "127.0.0.1:8443",
				auth:       "spiffe",
				serverID:   "spiffe://example.org/broker",
				repository: "owner/repo",
			},
		},
		{
			name: "spiffe missing server-id",
			opts: options{
				broker:     "127.0.0.1:8443",
				auth:       "spiffe",
				repository: "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "spiffe rejects server-selinux-type",
			opts: options{
				broker:            "127.0.0.1:8443",
				auth:              "spiffe",
				serverID:          "spiffe://example.org/broker",
				serverSELinuxType: "svc_github_token_broker_t",
				repository:        "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "peersec valid",
			opts: options{
				broker:     "127.0.0.1:8444",
				auth:       "peersec",
				repository: "owner/repo",
			},
		},
		{
			name: "peersec valid with server-selinux-type",
			opts: options{
				broker:            "127.0.0.1:8444",
				auth:              "peersec",
				serverSELinuxType: "svc_github_token_broker_t",
				repository:        "owner/repo",
			},
		},
		{
			name: "peersec rejects server-id",
			opts: options{
				broker:     "127.0.0.1:8444",
				auth:       "peersec",
				serverID:   "spiffe://example.org/broker",
				repository: "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "insecure valid",
			opts: options{
				broker:     "127.0.0.1:8444",
				auth:       "insecure",
				repository: "owner/repo",
			},
		},
		{
			name: "insecure rejects server-id",
			opts: options{
				broker:     "127.0.0.1:8444",
				auth:       "insecure",
				serverID:   "spiffe://example.org/broker",
				repository: "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "insecure rejects server-selinux-type",
			opts: options{
				broker:            "127.0.0.1:8444",
				auth:              "insecure",
				serverSELinuxType: "svc_github_token_broker_t",
				repository:        "owner/repo",
			},
			wantErr: true,
		},
		{
			name: "unknown auth mode",
			opts: options{
				broker:     "127.0.0.1:8444",
				auth:       "mtls",
				repository: "owner/repo",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
