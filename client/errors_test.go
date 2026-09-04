// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestNewSessionErrorsAreMatchable(t *testing.T) {
	validDeps := client.Deps{
		Dialer: testDialer{Handler: func(context.Context, net.Conn) error { return nil }},
		Tun:    staticTunProvider{tun: newTestMemoryTun(1)},
	}
	base := client.Config{
		Protocol:  client.ProtocolTalariaUDP,
		ClientID:  "id",
		SecretKey: "sk",
	}

	tests := []struct {
		name    string
		mutate  func(*client.Config)
		deps    client.Deps
		wantErr error
	}{
		{
			name:    "unknown protocol",
			mutate:  func(c *client.Config) { c.Protocol = "NotAProtocol" },
			deps:    validDeps,
			wantErr: client.ErrUnsupportedProtocol,
		},
		{
			name:    "negative MTU",
			mutate:  func(c *client.Config) { c.MTU = -1 },
			deps:    validDeps,
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "oversized MTU",
			mutate:  func(c *client.Config) { c.MTU = dataplane.MaxMTU + 1 },
			deps:    validDeps,
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "negative keepalive",
			mutate:  func(c *client.Config) { c.KeepAliveDuration = -time.Second },
			deps:    validDeps,
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "missing client ID",
			mutate:  func(c *client.Config) { c.ClientID = "" },
			deps:    validDeps,
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "missing secret key",
			mutate:  func(c *client.Config) { c.SecretKey = "" },
			deps:    validDeps,
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "missing tun provider",
			mutate:  func(*client.Config) {},
			deps:    client.Deps{Dialer: validDeps.Dialer},
			wantErr: client.ErrInvalidConfig,
		},
		{
			name:    "missing transport",
			mutate:  func(*client.Config) {},
			deps:    client.Deps{Tun: validDeps.Tun},
			wantErr: client.ErrInvalidConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			_, err := client.NewSession(cfg, tt.deps)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewSession error = %v, want errors.Is(..., %v)", err, tt.wantErr)
			}
		})
	}
}

func TestSessionErrReportsAuthRejection(t *testing.T) {
	codec := dataplane.WireCodec{}
	dialer := testDialer{
		Handler: func(_ context.Context, conn net.Conn) error {
			buf := make([]byte, 2048)
			if _, err := conn.Read(buf); err != nil {
				return err
			}
			raw, err := codec.Encode(&vpnpacket.VpnPacket{
				Cmd:          vpnpacket.CmdErr,
				ErrorMessage: "quota exceeded",
			})
			if err != nil {
				return err
			}
			_, err = conn.Write(raw)
			return err
		},
	}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "wrong-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{
		Dialer: dialer,
		Tun:    staticTunProvider{tun: newTestMemoryTun(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	startErr := sess.Start(context.Background())
	if !errors.Is(startErr, client.ErrAuthRejected) {
		t.Fatalf("Start error = %v, want errors.Is(..., ErrAuthRejected)", startErr)
	}
	// The server's own message must survive so it can be surfaced to a user.
	if got := startErr.Error(); !strings.Contains(got, "quota exceeded") {
		t.Fatalf("Start error = %q, want it to carry the server message", got)
	}

	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not fire after authentication was rejected")
	}
	if got := sess.State(); got != client.StateClosed && got != client.StateFailed {
		t.Fatalf("state = %s, want closed or failed", got)
	}
	if err := sess.Err(); !errors.Is(err, client.ErrAuthRejected) {
		t.Fatalf("Err() = %v, want errors.Is(..., ErrAuthRejected)", err)
	}
}

func TestSessionErrIsNilAfterDeliberateClose(t *testing.T) {
	tun := newTestMemoryTun(4)
	dialer := testDialer{
		Handler: func(ctx context.Context, conn net.Conn) error {
			return servePacketEcho(ctx, conn, packetEchoOptions{
				ClientID:         "test-client",
				SecretKey:        "test-secret",
				AssignedClientID: 7,
				Version:          1,
			})
		},
	}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{Dialer: dialer, Tun: staticTunProvider{tun: tun}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sess.Err(); err != nil {
		t.Fatalf("Err() = %v while connected, want nil", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not fire after Close")
	}
	if err := sess.Err(); err != nil {
		t.Fatalf("Err() = %v after a deliberate Close, want nil", err)
	}
}

func TestStartTwiceIsMatchable(t *testing.T) {
	tun := newTestMemoryTun(4)
	dialer := testDialer{
		Handler: func(ctx context.Context, conn net.Conn) error {
			return servePacketEcho(ctx, conn, packetEchoOptions{
				ClientID:         "test-client",
				SecretKey:        "test-secret",
				AssignedClientID: 7,
				Version:          1,
			})
		},
	}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{Dialer: dialer, Tun: staticTunProvider{tun: tun}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); !errors.Is(err, client.ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want errors.Is(..., ErrAlreadyStarted)", err)
	}
}
