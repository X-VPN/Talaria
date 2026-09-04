// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestClientRejectsUntrustedCertificateAndWrongHostname(t *testing.T) {
	for _, trustCase := range []string{"untrusted ca", "wrong hostname"} {
		t.Run(trustCase, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			listener, server, controlCalls, streamCalls := startTunnelEstablishmentServer(t, serverTLS)
			badTLS := clientTLS.Clone()
			switch trustCase {
			case "untrusted ca":
				badTLS.RootCAs = x509.NewCertPool()
			case "wrong hostname":
				badTLS.ServerName = "not-vpn.test"
			}
			client, err := NewClient(ClientConfig{
				Address:      listener.Addr().String(),
				TLSConfig:    badTLS,
				WireIdentity: "vpn.test",
				WireSecret:   testTalariaTCPWireSecret,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return listener.DialContext(ctx)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := client.DialControl(ctx); err == nil {
				_ = conn.Close()
				t.Fatal("control tunnel succeeded with invalid server trust")
			}
			assertNoTunnelHandlerCalls(t, controlCalls, streamCalls)
			_ = server.Close()
		})
	}
}

func TestClientContainsTLSVerificationPanic(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, _, controlCalls, streamCalls := startTunnelEstablishmentServer(t, serverTLS)
	clientTLS = clientTLS.Clone()
	clientTLS.VerifyConnection = func(tls.ConnectionState) error { panic("verification panic") }
	client, err := NewClient(ClientConfig{
		Address:      listener.Addr().String(),
		TLSConfig:    clientTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := client.DialControl(ctx); conn != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("DialControl() = %v, %v; want extension panic", conn, err)
	}
	assertNoTunnelHandlerCalls(t, controlCalls, streamCalls)
}

func TestClientTLSVerificationCanCloseClient(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, _, _, _ := startTunnelEstablishmentServer(t, serverTLS)
	clientTLS = clientTLS.Clone()
	var client *Client
	clientTLS.VerifyConnection = func(tls.ConnectionState) error {
		return client.Close()
	}
	client, err := NewClient(ClientConfig{
		Address:      listener.Addr().String(),
		TLSConfig:    clientTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := client.DialControl(context.Background())
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("DialControl() error = %v, want closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialControl deadlocked when TLS verification closed the client")
	}
}

func TestClientContainsStreamNegotiationPanicAndClosesConnection(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, server, _, _ := startTunnelEstablishmentServer(t, serverTLS)
	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	var raw *panicAfterRoleConn
	client, err := NewClient(ClientConfig{
		Address:              listener.Addr().String(),
		TLSConfig:            clientTLS,
		EstablishmentTimeout: 100 * time.Millisecond,
		WireIdentity:         "vpn.test",
		WireSecret:           testTalariaTCPWireSecret,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := listener.DialContext(ctx)
			if err != nil {
				return nil, err
			}
			raw = &panicAfterRoleConn{Conn: conn}
			return raw, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Activate(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	if conn, err := client.DialStream(context.Background(), testDestination()); conn != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("DialStream() = %v, %v; want extension panic", conn, err)
	}
	if raw == nil || !raw.closed.Load() {
		t.Fatal("stream connection was not closed after negotiation panic")
	}
}

func TestClientRejectsExpiredAndNotYetValidCertificates(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{name: "expired", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)},
		{name: "not yet valid", notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigsWithServerValidity(t, tt.notBefore, tt.notAfter)
			listener, _, controlCalls, streamCalls := startTunnelEstablishmentServer(t, serverTLS)
			client, err := NewClient(ClientConfig{
				Address:      listener.Addr().String(),
				TLSConfig:    clientTLS,
				WireIdentity: "vpn.test",
				WireSecret:   testTalariaTCPWireSecret,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return listener.DialContext(ctx)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := client.DialControl(ctx); err == nil {
				_ = conn.Close()
				t.Fatal("control tunnel succeeded with time-invalid certificate")
			}
			assertNoTunnelHandlerCalls(t, controlCalls, streamCalls)
		})
	}
}

func TestServerRejectsTLS12BeforeConnectionRole(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, _, controlCalls, streamCalls := startTunnelEstablishmentServer(t, serverTLS)
	raw, err := listener.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	clientTLS = clientTLS.Clone()
	clientTLS.MinVersion = tls.VersionTLS12
	clientTLS.MaxVersion = tls.VersionTLS12
	clientTLS.NextProtos = nil
	conn := tls.Client(wrapClientWire(raw, testWireKey(t)), clientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err == nil {
		t.Fatal("TLS 1.2 handshake succeeded against TLS 1.3-only server")
	}
	assertNoTunnelHandlerCalls(t, controlCalls, streamCalls)
}

func TestServerRejectsUnknownEncryptedConnectionRole(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, _, controlCalls, streamCalls := startTunnelEstablishmentServer(t, serverTLS)
	raw, err := listener.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	clientTLS = clientTLS.Clone()
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = nil
	conn := tls.Client(wrapClientWire(raw, testWireKey(t)), clientTLS)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0xff}); err == nil {
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection remained open after unknown encrypted role")
		}
	}
	assertNoTunnelHandlerCalls(t, controlCalls, streamCalls)
}

func startTunnelEstablishmentServer(t *testing.T, tlsConfig *tls.Config) (*pipeListener, *Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{
		Listener:         listener,
		TLSConfig:        tlsConfig,
		HandshakeTimeout: time.Second,
		WireIdentity:     "vpn.test",
		WireSecret:       testTalariaTCPWireSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	controlCalls := new(atomic.Int32)
	streamCalls := new(atomic.Int32)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx,
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error {
				controlCalls.Add(1)
				return nil
			}),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				streamCalls.Add(1)
				return nil, net.ErrClosed
			}),
		)
	}()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve error: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return listener, server, controlCalls, streamCalls
}

func assertNoTunnelHandlerCalls(t *testing.T, controlCalls, streamCalls *atomic.Int32) {
	t.Helper()
	if got := controlCalls.Load(); got != 0 {
		t.Fatalf("control handler calls = %d, want 0", got)
	}
	if got := streamCalls.Load(); got != 0 {
		t.Fatalf("stream handler calls = %d, want 0", got)
	}
}

type panicAfterRoleConn struct {
	net.Conn
	panicRead atomic.Bool
	closed    atomic.Bool
}

func (c *panicAfterRoleConn) Read(p []byte) (int, error) {
	if c.panicRead.Load() {
		_ = c.Conn.Close()
		panic("synthetic SOCKS5 negotiation read failure")
	}
	return c.Conn.Read(p)
}

func (c *panicAfterRoleConn) SetWriteDeadline(deadline time.Time) error {
	err := c.Conn.SetWriteDeadline(deadline)
	if err == nil && deadline.IsZero() {
		c.panicRead.Store(true)
	}
	return err
}

func (c *panicAfterRoleConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}
