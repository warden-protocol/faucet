package main

import (
	"testing"

	"github.com/warden-protocol/faucet/pkg/config"
)

func TestConvertCosmosToEVM(t *testing.T) {
	testCases := []struct {
		name      string
		addr      string
		expected  string
		expectErr bool
	}{
		{
			name:      "Valid bech32 warden address",
			addr:      "warden13uw2zuqjpklx48vk24xuwc7qs7f4kpktt25svn",
			expected:  "0x8f1ca170120DbE6A9D96554dc763C087935b06cb",
			expectErr: false,
		},
		{
			name:      "Valid bech32 cosmos address",
			addr:      "cosmos13uw2zuqjpklx48vk24xuwc7qs7f4kpktmy0ft8",
			expected:  "0x8f1ca170120DbE6A9D96554dc763C087935b06cb",
			expectErr: false,
		},
		{
			name:      "Already EVM address",
			addr:      "0x8f1ca170120dbe6a9d96554dc763c087935b06cb",
			expected:  "0x8f1ca170120dbe6a9d96554dc763c087935b06cb",
			expectErr: false,
		},
		{
			name:      "Invalid bech32 address",
			addr:      "invalid123",
			expected:  "",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := convertCosmosToEVM(tc.addr)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else {
					t.Logf("got expected error: %v", err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if addr != tc.expected {
				t.Errorf("expected address %q, got %q", tc.expected, addr)
			}
		})
	}
}

func TestValidAddress(t *testing.T) {
	cfg := config.Config{
		AcceptedPrefixes: "warden,cosmos,osmo,juno,stars",
	}

	testCases := []struct {
		name      string
		addr      string
		expectErr bool
	}{
		{
			name:      "Valid EVM address",
			addr:      "0x8f1ca170120dbe6a9d96554dc763c087935b06cb",
			expectErr: false,
		},
		{
			name:      "Valid warden bech32 address",
			addr:      "warden13uw2zuqjpklx48vk24xuwc7qs7f4kpktt25svn",
			expectErr: false,
		},
		{
			name:      "Valid cosmos bech32 address",
			addr:      "cosmos13uw2zuqjpklx48vk24xuwc7qs7f4kpktmy0ft8",
			expectErr: false,
		},
		{
			name:      "Valid osmo bech32 address",
			addr:      "osmo13uw2zuqjpklx48vk24xuwc7qs7f4kpktnluea4",
			expectErr: false,
		},
		{
			name:      "Unsupported prefix",
			addr:      "terra13uw2zuqjpklx48vk24xuwc7qs7f4kpktcuq4fg",
			expectErr: true,
		},
		{
			name:      "Invalid EVM address",
			addr:      "0xinvalid",
			expectErr: true,
		},
		{
			name:      "Invalid format",
			addr:      "invalid123",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validAddress(tc.addr, cfg)
			if tc.expectErr && err == nil {
				t.Errorf("expected error but got none for address: %s", tc.addr)
			} else if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for address %s: %v", tc.addr, err)
			}
		})
	}
}
