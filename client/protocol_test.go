// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client_test

import (
	"testing"

	"github.com/X-VPN/Talaria/client"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    client.Protocol
		wantErr bool
	}{
		{name: "empty defaults to TalariaUDP", want: client.ProtocolTalariaUDP},
		{name: "TalariaUDP", value: string(client.ProtocolTalariaUDP), want: client.ProtocolTalariaUDP},
		{name: "TalariaTCP", value: string(client.ProtocolTalariaTCP), want: client.ProtocolTalariaTCP},
		{name: "wrong case", value: "talariatcp", wantErr: true},
		{name: "leading space", value: " TalariaTCP", wantErr: true},
		{name: "trailing space", value: "TalariaTCP ", wantErr: true},
		{name: "misspelled", value: "TalariaTCp", wantErr: true},
		{name: "unknown value", value: "unsupported", wantErr: true},
		{name: "control characters", value: "TalariaTCP\nforged-log", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.ParseProtocol(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseProtocol(%q) succeeded with %q", tt.value, got)
				}
				if err.Error() != "unsupported Talaria protocol" {
					t.Fatalf("ParseProtocol(%q) error = %q", tt.value, err)
				}
				if client.ProtocolSupportedOnCurrentPlatform(client.Protocol(tt.value)) {
					t.Fatalf("ProtocolSupportedOnCurrentPlatform(%q) = true", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProtocol(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("ParseProtocol(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
