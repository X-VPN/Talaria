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
)

func TestServerNegotiationDeadlineCoversStreamAuthentication(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:         listener,
		TLSConfig:        serverTLS,
		HandshakeTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ctx,
			coretransport.ControlHandlerFunc(echoControl),
			coretransport.StreamHandlerFunc(openEchoStream),
		)
	}()

	raw, err := listener.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS = clientTLS.Clone()
	clientTLS.MinVersion = tls.VersionTLS13
	clientTLS.MaxVersion = tls.VersionTLS13
	clientTLS.NextProtos = nil
	conn := tls.Client(wrapClientWire(raw, testWireKey(t)), clientTLS)
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{byte(connectionRoleStream)}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream negotiation without SOCKS authentication remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() && time.Since(started) >= 900*time.Millisecond {
		t.Fatal("timed out waiting for negotiation deadline")
	}

	cancel()
	_ = server.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerRejectsConnectionBeforeHandshakeWhenSourceLimitIsFull(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  listener,
		TLSConfig: serverTLS,
		AdmissionLimits: AdmissionLimits{
			MaxConnections:            2,
			MaxConnectionsPerSourceIP: 1,
			MaxPendingHandshakes:      2,
			MaxPendingPerSourceIP:     1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ctx,
			coretransport.ControlHandlerFunc(echoControl),
			coretransport.StreamHandlerFunc(openEchoStream),
		)
	}()

	first, err := listener.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := listener.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	} else {
		if _, err := second.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection above the admission limit remained open")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("timed out waiting for admission rejection")
		}
	}

	cancel()
	_ = server.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestAdmissionLimiterAggregatesIPv6SourcesByPrefix(t *testing.T) {
	limits, err := normalizeAdmissionLimits(AdmissionLimits{
		MaxConnections:            3,
		MaxConnectionsPerSourceIP: 1,
		MaxPendingHandshakes:      3,
		MaxPendingPerSourceIP:     1,
		IPv6SourcePrefixBits:      64,
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := newAdmissionLimiter(limits)
	first, ok := limiter.acquire(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	if !ok {
		t.Fatal("first IPv6 source was rejected")
	}
	defer first.release()
	if _, ok := limiter.acquire(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::2"), Port: 2}); ok {
		t.Fatal("same /64 bypassed the source limit")
	}
	other, ok := limiter.acquire(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3})
	if !ok {
		t.Fatal("different /64 was rejected")
	}
	other.release()
}

func TestNormalizeAdmissionLimitsKeepsCapacityForOtherSources(t *testing.T) {
	limits, err := normalizeAdmissionLimits(AdmissionLimits{
		MaxConnections:       8,
		MaxPendingHandshakes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxConnectionsPerSourceIP != 4 || limits.MaxPendingPerSourceIP != 4 {
		t.Fatalf("scaled limits = %+v", limits)
	}
	if _, err := normalizeAdmissionLimits(AdmissionLimits{
		MaxConnections:            8,
		MaxConnectionsPerSourceIP: 8,
	}); err == nil {
		t.Fatal("source connection limit equal to global limit was accepted")
	}
}
