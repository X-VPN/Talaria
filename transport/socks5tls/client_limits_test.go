// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type clientObservedCloseConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *clientObservedCloseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestClientEstablishmentTimeoutClosesLateDialResult(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	releaseDial := make(chan struct{})
	created := make(chan *clientObservedCloseConn, 1)
	client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Address:              "example.invalid:443",
		TLSConfig:            clientTLS,
		EstablishmentTimeout: 20 * time.Millisecond,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			<-releaseDial
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			observed := &clientObservedCloseConn{Conn: conn, closed: make(chan struct{})}
			created <- observed
			return observed, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if conn, err := client.DialControl(context.Background()); err == nil {
		_ = conn.Close()
		t.Fatal("connection establishment did not time out")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection establishment error = %v, want deadline exceeded", err)
	}
	close(releaseDial)
	late := <-created
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("late client dial result was not closed")
	}
}

func TestClientCloseCancelsDialAndClosesLateResult(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	releaseDial := make(chan struct{})
	dialStarted := make(chan struct{})
	created := make(chan *clientObservedCloseConn, 1)
	client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Address:   "example.invalid:443",
		TLSConfig: clientTLS,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			close(dialStarted)
			<-releaseDial
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			observed := &clientObservedCloseConn{Conn: conn, closed: make(chan struct{})}
			created <- observed
			return observed, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	dialResult := make(chan error, 1)
	go func() {
		conn, err := client.DialControl(context.Background())
		if conn != nil {
			_ = conn.Close()
		}
		dialResult <- err
	}()
	<-dialStarted
	closed := make(chan struct{})
	go func() {
		_ = client.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("client close did not cancel the blocked dial")
	}
	if err := <-dialResult; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial error = %v, want net.ErrClosed", err)
	}

	close(releaseDial)
	late := <-created
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("post-close dial result was not closed")
	}
}

func TestClientBoundsConcurrentConnectionAttempts(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	releaseDial := make(chan struct{})
	started := make(chan struct{}, maxConcurrentClientDials)
	client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Address:   "example.invalid:443",
		TLSConfig: clientTLS,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			started <- struct{}{}
			<-releaseDial
			return nil, errors.New("dial released")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	results := make(chan error, maxConcurrentClientDials)
	for i := 0; i < maxConcurrentClientDials; i++ {
		go func() {
			_, err := client.dialRaw(context.Background())
			results <- err
		}()
	}
	for i := 0; i < maxConcurrentClientDials; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d/%d connection attempts started", i, maxConcurrentClientDials)
		}
	}
	if conn, err := client.dialRaw(context.Background()); conn != nil || err == nil ||
		!strings.Contains(err.Error(), "too many concurrent") {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("overflow dial result = %v, %v", conn, err)
	}
	close(releaseDial)
	for i := 0; i < maxConcurrentClientDials; i++ {
		if err := <-results; err == nil {
			t.Fatal("released blocking dial unexpectedly succeeded")
		}
	}
}
