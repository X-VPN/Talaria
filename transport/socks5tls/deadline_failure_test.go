// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
	gosocks5 "github.com/things-go/go-socks5"
)

func TestServerRejectsNegotiationDeadlineSetupFailureBeforeHandshake(t *testing.T) {
	want := errors.New("synthetic negotiation deadline failure")
	raw := &deadlineFailureConn{setDeadline: func(time.Time) error { return want }}
	serverTLS, _ := testTLSConfigs(t)
	server := &Server{tlsConfig: serverTLS, handshakeTimeout: time.Second}

	err := server.serveConn(context.Background(), raw, nil, &admissionLease{})
	if !errors.Is(err, want) {
		t.Fatalf("serve connection error = %v, want %v", err, want)
	}
	if raw.readCalled {
		t.Fatal("TLS handshake read after deadline setup failed")
	}
}

func TestServerRejectsControlDeadlineResetFailure(t *testing.T) {
	want := errors.New("synthetic control deadline reset failure")
	serverTLS, clientTLS := testNegotiationTLSConfigs(t)
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	serverConn := &deadlineFailureConn{
		Conn: serverRaw,
		setDeadline: func(deadline time.Time) error {
			if deadline.IsZero() {
				return want
			}
			return serverRaw.SetDeadline(deadline)
		},
	}
	handlerCalled := false
	server := &Server{
		tlsConfig:        serverTLS,
		wireKey:          testWireKey(t),
		wireReplay:       newWireReplayCache(1, 1),
		handshakeTimeout: time.Second,
		now:              time.Now,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.serveConn(context.Background(), serverConn, coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error {
			handlerCalled = true
			return nil
		}), &admissionLease{})
	}()

	clientConn := tls.Client(wrapClientWire(clientRaw, testWireKey(t)), clientTLS)
	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := writeConnectionRole(clientConn, connectionRoleControl); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, want) {
		t.Fatalf("serve connection error = %v, want %v", err, want)
	}
	if handlerCalled {
		t.Fatal("control handler called after deadline reset failed")
	}
}

func TestServerRejectsStreamDeadlineResetFailure(t *testing.T) {
	want := errors.New("synthetic stream deadline reset failure")
	server := &Server{}
	err := server.handleConnect(context.Background(), &deadlineFailureConn{
		setDeadline: func(time.Time) error { return want },
	}, &gosocks5.Request{})
	if !errors.Is(err, want) {
		t.Fatalf("stream connection error = %v, want %v", err, want)
	}
}

func TestClientRejectsRoleWriteDeadlineFailures(t *testing.T) {
	serverTLS, clientTLS := testNegotiationTLSConfigs(t)
	for _, reset := range []bool{false, true} {
		name := "setup"
		if reset {
			name = "reset"
		}
		t.Run(name, func(t *testing.T) {
			want := errors.New("synthetic role write deadline failure")
			clientRaw, serverRaw := net.Pipe()
			serverWire := wrapServerWire(serverRaw, testWireKey(t), newWireReplayCache(1, 1), "source-a", time.Now)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				defer serverRaw.Close()
				conn := tls.Server(serverWire, serverTLS)
				if conn.Handshake() == nil {
					_, _ = readConnectionRole(conn)
				}
			}()

			client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
				Address:   "example.invalid:443",
				TLSConfig: clientTLS,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return &writeDeadlineFailureConn{Conn: clientRaw, err: want, reset: reset}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			conn, err := client.DialControl(context.Background())
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, want) {
				t.Fatalf("dial control error = %v, want %v", err, want)
			}
			<-serverDone
		})
	}
}

func testNegotiationTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	var err error
	serverTLS, err = normalizeServerTLSConfig(serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err = normalizeClientTLSConfig(clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.NextProtos = nil
	clientTLS.NextProtos = nil
	serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		disableAES128GCM(hello)
		return nil, nil
	}
	return serverTLS, clientTLS
}

type deadlineFailureConn struct {
	net.Conn
	setDeadline func(time.Time) error
	readCalled  bool
}

func (c *deadlineFailureConn) Read(p []byte) (int, error) {
	c.readCalled = true
	if c.Conn == nil {
		return 0, io.EOF
	}
	return c.Conn.Read(p)
}
func (c *deadlineFailureConn) Write(p []byte) (int, error) {
	if c.Conn == nil {
		return len(p), nil
	}
	return c.Conn.Write(p)
}
func (c *deadlineFailureConn) Close() error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}
func (c *deadlineFailureConn) LocalAddr() net.Addr {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.LocalAddr()
}
func (c *deadlineFailureConn) RemoteAddr() net.Addr {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.RemoteAddr()
}
func (c *deadlineFailureConn) SetDeadline(deadline time.Time) error {
	return c.setDeadline(deadline)
}
func (c *deadlineFailureConn) SetReadDeadline(deadline time.Time) error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.SetReadDeadline(deadline)
}
func (c *deadlineFailureConn) SetWriteDeadline(deadline time.Time) error {
	if c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(deadline)
}

type writeDeadlineFailureConn struct {
	net.Conn
	err   error
	reset bool
}

func (c *writeDeadlineFailureConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() == c.reset {
		return c.err
	}
	return c.Conn.SetWriteDeadline(deadline)
}
