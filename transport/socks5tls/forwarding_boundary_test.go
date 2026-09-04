// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestSOCKS5ClosesStreamReturnedWithHandlerError(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	remote, remotePeer := net.Pipe()
	defer remotePeer.Close()
	want := errors.New("synthetic stream failure")
	handlerCalled := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = server.Serve(ctx,
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				close(handlerCalled)
				return remote, want
			}),
		)
	}()

	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(ctx, grant); err != nil {
		t.Fatal(err)
	}
	conn := dialRawSOCKSStream(t, listener, clientTLS)
	defer closeRawSOCKS(conn)
	authenticateRawSOCKS(t, conn, grant)
	if _, err := conn.Write([]byte{5, 1, 0, 1, 192, 0, 2, 20, 1, 187}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerCalled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for stream handler")
	}
	if err := remotePeer.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := remotePeer.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection returned with stream handler error remained open")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("timed out waiting for failed stream connection to close")
		}
	}
}

func TestSOCKS5RejectsUnauthorizedAndUnsupportedForwardingBeforeOpen(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var openCalls atomic.Int32
	go func() {
		_ = server.Serve(ctx,
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				openCalls.Add(1)
				return nil, net.ErrClosed
			}),
		)
	}()

	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(ctx, grant); err != nil {
		t.Fatal(err)
	}

	t.Run("no authentication method", func(t *testing.T) {
		conn := dialRawSOCKSStream(t, listener, clientTLS)
		defer closeRawSOCKS(conn)
		writeAndReadExact(t, conn, []byte{5, 1, 0}, []byte{5, 0xff})
	})

	t.Run("wrong credentials", func(t *testing.T) {
		conn := dialRawSOCKSStream(t, listener, clientTLS)
		defer closeRawSOCKS(conn)
		writeAndReadExact(t, conn, []byte{5, 1, 2}, []byte{5, 2})
		writeAndReadExact(t, conn, socksUserPassRequest("1001", "wrong"), []byte{1, 1})
	})

	for _, command := range []byte{2, 3} {
		name := map[byte]string{2: "BIND", 3: "UDP ASSOCIATE"}[command]
		t.Run(name, func(t *testing.T) {
			conn := dialRawSOCKSStream(t, listener, clientTLS)
			defer closeRawSOCKS(conn)
			authenticateRawSOCKS(t, conn, grant)
			request := []byte{5, command, 0, 1, 192, 0, 2, 20, 1, 187}
			if _, err := conn.Write(request); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 10)
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatal(err)
			}
			if reply[0] != 5 || reply[1] != 7 {
				t.Fatalf("reply = %v, want command-not-supported", reply)
			}
		})
	}

	t.Run("invalid address type", func(t *testing.T) {
		conn := dialRawSOCKSStream(t, listener, clientTLS)
		defer closeRawSOCKS(conn)
		authenticateRawSOCKS(t, conn, grant)
		if _, err := conn.Write([]byte{5, 1, 0, 9, 0, 0}); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var reply [2]byte
		if _, err := io.ReadFull(conn, reply[:]); err == nil && reply[1] == 0 {
			t.Fatalf("invalid address type succeeded: %v", reply)
		}
	})

	t.Run("zero destination port", func(t *testing.T) {
		conn := dialRawSOCKSStream(t, listener, clientTLS)
		defer closeRawSOCKS(conn)
		authenticateRawSOCKS(t, conn, grant)
		if _, err := conn.Write([]byte{5, 1, 0, 1, 192, 0, 2, 20, 0, 0}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatal(err)
		}
		if reply[0] != 5 || reply[1] == 0 {
			t.Fatalf("zero-port reply = %v, want failure", reply)
		}
	})

	if got := openCalls.Load(); got != 0 {
		t.Fatalf("open stream calls = %d, want 0", got)
	}
}

func closeRawSOCKS(conn net.Conn) {
	_ = conn.Close()
}

func dialRawSOCKSStream(t *testing.T, listener *pipeListener, tlsConfig *tls.Config) net.Conn {
	t.Helper()
	raw, err := listener.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := normalizeClientTLSConfig(tlsConfig)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	clientTLS.NextProtos = nil
	conn := tls.Client(wrapClientWire(raw, testWireKey(t)), clientTLS)
	if err := conn.HandshakeContext(context.Background()); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := writeConnectionRole(conn, connectionRoleStream); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return &rawSOCKSConn{Conn: conn, raw: raw}
}

type rawSOCKSConn struct {
	net.Conn
	raw net.Conn
}

func (c *rawSOCKSConn) Close() error {
	return c.raw.Close()
}

func authenticateRawSOCKS(t *testing.T, conn net.Conn, grant coretransport.SessionGrant) {
	t.Helper()
	writeAndReadExact(t, conn, []byte{5, 1, 2}, []byte{5, 2})
	password := base64.RawURLEncoding.EncodeToString(grant.DataToken[:])
	writeAndReadExact(t, conn, socksUserPassRequest(strconv.FormatUint(grant.ClientID, 10), password), []byte{1, 0})
}

func socksUserPassRequest(user, password string) []byte {
	payload := []byte{1, byte(len(user))}
	payload = append(payload, user...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	return payload
}

func writeAndReadExact(t *testing.T, conn net.Conn, payload, want []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reply = %v, want %v", got, want)
		}
	}
}
