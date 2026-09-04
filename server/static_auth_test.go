// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestStaticAuthProviderCompilationCopiesCredentials(t *testing.T) {
	credentials := []StaticCredential{{
		ClientID:         "client",
		SecretKey:        "secret",
		AssignedClientID: 42,
	}}
	provider, err := normalizeBoundedAuthProvider(&StaticAuthProvider{Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	credentials[0] = StaticCredential{
		ClientID:         "changed",
		SecretKey:        "changed",
		AssignedClientID: 99,
	}
	result, err := provider.Authenticate(context.Background(), AuthRequest{
		Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
		ClientID:  "client",
		SecretKey: "secret",
	})
	if err != nil || result.ClientID != 42 || result.Version != DefaultAuthVersion {
		t.Fatalf("compiled auth result = %+v, %v", result, err)
	}
	if _, err := provider.Authenticate(context.Background(), AuthRequest{
		Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
		ClientID:  "changed",
		SecretKey: "changed",
	}); err == nil {
		t.Fatal("compiled provider observed caller mutation")
	}
}

func TestStaticAuthProviderUsesFixedLengthSecretDigests(t *testing.T) {
	provider, err := compileStaticAuthProvider(StaticAuthProvider{Credentials: []StaticCredential{{
		ClientID:         "known-client",
		SecretKey:        "known-secret",
		AssignedClientID: 42,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	credential := provider.credentials["known-client"]
	if credential.secret != staticAuthSecretDigest("known-secret") {
		t.Fatal("compiled credential did not retain the expected digest")
	}
	if provider.dummySecret == credential.secret {
		t.Fatal("dummy digest matches a configured credential")
	}
	requests := []AuthRequest{
		{
			Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
			ClientID:  "unknown-client",
			SecretKey: "wrong-secret",
		},
		{
			Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
			ClientID:  "known-client",
			SecretKey: "wrong-secret",
		},
		{
			Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
			ClientID:  "known-client",
			SecretKey: "short",
		},
	}
	for i, request := range requests {
		if _, err := provider.Authenticate(context.Background(), request); err == nil {
			t.Fatalf("invalid authentication request %d succeeded", i)
		}
	}
	result, err := provider.Authenticate(context.Background(), AuthRequest{
		Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
		ClientID:  "known-client",
		SecretKey: "known-secret",
	})
	if err != nil || result.ClientID != 42 {
		t.Fatalf("valid authentication = %+v, %v", result, err)
	}
}

func TestStaticAuthProviderRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		provider StaticAuthProvider
	}{
		{name: "empty"},
		{
			name: "mixed forms",
			provider: StaticAuthProvider{
				ClientID:    "client",
				SecretKey:   "secret",
				Credentials: []StaticCredential{{ClientID: "other", SecretKey: "other", AssignedClientID: 2}},
			},
		},
		{
			name: "duplicate client id",
			provider: StaticAuthProvider{Credentials: []StaticCredential{
				{ClientID: "client", SecretKey: "first", AssignedClientID: 1},
				{ClientID: "client", SecretKey: "second", AssignedClientID: 2},
			}},
		},
		{
			name: "missing assigned client id",
			provider: StaticAuthProvider{Credentials: []StaticCredential{
				{ClientID: "first", SecretKey: "secret", AssignedClientID: 1},
				{ClientID: "second", SecretKey: "secret"},
			}},
		},
		{
			name: "duplicate assigned client id",
			provider: StaticAuthProvider{Credentials: []StaticCredential{
				{ClientID: "first", SecretKey: "first-secret", AssignedClientID: 7},
				{ClientID: "second", SecretKey: "second-secret", AssignedClientID: 7},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeBoundedAuthProvider(tt.provider); err == nil {
				t.Fatal("invalid static auth configuration was accepted")
			}
		})
	}
}

func TestTunSessionAttachDoesNotUseAuthCallbackWorkers(t *testing.T) {
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{Device: discardTunDevice{batchSize: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	srv := &Server{handler: handler, authSlots: slots}
	detach, releaseWorker, err := srv.callPacketSessionAttach(
		context.Background(),
		context.Background(),
		SessionContext{ClientID: 42, Generation: 1, RemoteIP: "192.0.2.1"},
		SessionWriters{
			Packet: func(*vpnpacket.VpnPacket) error { return nil },
			Close:  func() {},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if releaseWorker != nil {
		t.Fatal("built-in attach acquired an auth callback worker")
	}
	if len(slots) != cap(slots) {
		t.Fatalf("auth callback slots = %d, want %d", len(slots), cap(slots))
	}
	if detach == nil {
		t.Fatal("built-in attach returned no detach function")
	}
	detach()
	if err := handler.Err(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
