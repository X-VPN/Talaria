// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/ippacket"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestServerReleasesStreamCapacityWhenOutboundCloses(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	var peersMu sync.Mutex
	var peers []net.Conn
	defer func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	var dialCalls atomic.Int32
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxSessions:              1,
			MaxStreams:               2,
			MaxStreamsPerClient:      1,
			MaxPendingDials:          2,
			MaxPendingDialsPerClient: 1,
			DialTimeout:              time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		conn, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return conn, nil
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	var streams coretransport.StreamHandler
	select {
	case streams = <-transport.streams:
	case <-time.After(time.Second):
		t.Fatal("transport did not receive the stream handler")
	}
	req := coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target: coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Host:    "8.8.8.8",
			Port:    443,
		},
	}
	first, err := streams.OpenStream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := streams.OpenStream(context.Background(), req); err == nil {
		_ = second.Close()
		t.Fatal("second stream exceeded the per-client limit")
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("dial calls while full = %d, want 1", got)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := streams.OpenStream(context.Background(), req)
	if err != nil {
		t.Fatalf("stream capacity was not released: %v", err)
	}
	_ = third.Close()
	if got := dialCalls.Load(); got != 2 {
		t.Fatalf("dial calls after release = %d, want 2", got)
	}
}

func TestResourceLimitedConnReleasesCapacityAfterClosePanic(t *testing.T) {
	var releases atomic.Int32
	conn := &resourceLimitedConn{
		Conn:    panicResourceCloseConn{},
		release: func() { releases.Add(1) },
	}
	if err := conn.Close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Close() error = %v, want extension panic", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("capacity releases = %d, want 1", got)
	}
	if err := conn.Close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("second Close() error = %v, want extension panic", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("capacity releases after second close = %d, want 1", got)
	}
}

func TestResourceLimiterReleasesSessionGenerationsOutOfOrder(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	first, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	third, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}

	second.release()
	first.release()
	third.release()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.sessions != 0 || len(limiter.sessionOwners) != 0 || len(limiter.sessionTokens) != 0 {
		t.Fatalf("session state after out-of-order release = %d/%d/%d, want empty",
			limiter.sessions, len(limiter.sessionOwners), len(limiter.sessionTokens))
	}
}

func TestResourceLimiterBoundsReplacementSessionState(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	current, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		replacement, err := limiter.acquireSession(7)
		if err != nil {
			t.Fatal(err)
		}
		current.release()
		current = replacement
		if len(limiter.sessionTokens) != 1 {
			t.Fatalf("replacement state grew to %d entries", len(limiter.sessionTokens))
		}
	}
	current.release()
}

func TestResourceLimitedConnContainsCloseWritePanic(t *testing.T) {
	conn := &resourceLimitedConn{Conn: panicResourceCloseConn{}}
	if err := conn.CloseWrite(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("CloseWrite() error = %v, want extension panic", err)
	}
}

type panicResourceCloseConn struct{ net.Conn }

func (panicResourceCloseConn) Close() error      { panic("close panic") }
func (panicResourceCloseConn) CloseWrite() error { panic("close write panic") }

func TestResourceLimiterBoundsAuthAttemptsAndResetsWindow(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{
		MaxSessions:                       1,
		MaxStreams:                        2,
		MaxStreamsPerClient:               1,
		MaxPendingDials:                   2,
		MaxPendingDialsPerClient:          1,
		DialTimeout:                       time.Second,
		MaxAuthAttemptsPerWindow:          2,
		MaxAuthAttemptsPerSourcePerWindow: 1,
		AuthAttemptWindow:                 time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := newResourceLimiter(limits)
	now := time.Unix(100, 0)
	tests := []struct {
		name   string
		source string
		now    time.Time
		want   bool
	}{
		{name: "first source", source: "192.0.2.1", now: now, want: true},
		{name: "same source at limit", source: "192.0.2.1", now: now},
		{name: "clock rollback stays limited", source: "192.0.2.1", now: now.Add(-time.Second)},
		{name: "second source before global limit", source: "192.0.2.2", now: now, want: true},
		{name: "global limit", source: "192.0.2.3", now: now},
		{name: "next window", source: "192.0.2.1", now: now.Add(time.Second), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := limiter.allowAuthAttempt(tt.source, tt.now); got != tt.want {
				t.Fatalf("allowAuthAttempt(%q, %v) = %v, want %v", tt.source, tt.now, got, tt.want)
			}
		})
	}
}

func TestResourceLimiterBoundsPendingAuthAndReleasesCapacity(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{
		MaxSessions:                       1,
		MaxStreams:                        2,
		MaxStreamsPerClient:               1,
		MaxPendingDials:                   2,
		MaxPendingDialsPerClient:          1,
		DialTimeout:                       time.Second,
		MaxPendingAuth:                    2,
		MaxPendingAuthPerSource:           1,
		MaxAuthAttemptsPerWindow:          2,
		MaxAuthAttemptsPerSourcePerWindow: 1,
		AuthAttemptWindow:                 time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := newResourceLimiter(limits)
	first, err := limiter.acquirePendingAuth("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.acquirePendingAuth("192.0.2.1"); !errors.Is(err, errResourceLimit) {
		t.Fatalf("same-source pending auth error = %v, want resource limit", err)
	}
	second, err := limiter.acquirePendingAuth("192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.acquirePendingAuth("192.0.2.3"); !errors.Is(err, errResourceLimit) {
		t.Fatalf("global pending auth error = %v, want resource limit", err)
	}
	first.release()
	if replacement, err := limiter.acquirePendingAuth("192.0.2.1"); err != nil {
		t.Fatalf("released pending auth capacity was not reused: %v", err)
	} else {
		replacement.release()
	}
	second.release()
}

func TestResourceLimiterAggregatesIPv6AuthSourcesByPrefix(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{
		MaxSessions:                       1,
		MaxStreams:                        2,
		MaxStreamsPerClient:               1,
		MaxPendingDials:                   2,
		MaxPendingDialsPerClient:          1,
		MaxPendingAuth:                    2,
		MaxPendingAuthPerSource:           1,
		MaxAuthAttemptsPerWindow:          2,
		MaxAuthAttemptsPerSourcePerWindow: 1,
		IPv6SourcePrefixBits:              64,
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter := newResourceLimiter(limits)
	first, err := limiter.acquirePendingAuth("2001:db8:1:2::1")
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	if _, err := limiter.acquirePendingAuth("2001:db8:1:2::2"); !errors.Is(err, errResourceLimit) {
		t.Fatalf("same-prefix pending auth error = %v, want resource limit", err)
	}
	if !limiter.allowAuthAttempt("2001:db8:1:3::1", time.Unix(100, 0)) {
		t.Fatal("first auth attempt was rejected")
	}
	if limiter.allowAuthAttempt("2001:db8:1:3::2", time.Unix(100, 0)) {
		t.Fatal("same /64 bypassed the auth attempt limit")
	}
}

func TestNormalizeResourceLimitsKeepsCapacityForOtherClients(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{
		MaxStreams:               8,
		MaxPendingDials:          8,
		MaxPendingAuth:           8,
		MaxAuthAttemptsPerWindow: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxStreamsPerClient != 4 ||
		limits.MaxPendingDialsPerClient != 4 ||
		limits.MaxPendingAuthPerSource != 4 ||
		limits.MaxAuthAttemptsPerSourcePerWindow != 4 {
		t.Fatalf("scaled limits = %+v", limits)
	}
	unsafe := []ResourceLimits{
		{MaxStreams: 8, MaxStreamsPerClient: 8},
		{MaxPendingDials: 8, MaxPendingDialsPerClient: 8},
		{MaxPendingAuth: 8, MaxPendingAuthPerSource: 8},
		{MaxAuthAttemptsPerWindow: 8, MaxAuthAttemptsPerSourcePerWindow: 8},
	}
	for _, limits := range unsafe {
		if _, err := normalizeResourceLimits(limits); err == nil {
			t.Fatalf("unsafe limits were accepted: %+v", limits)
		}
	}
}

func TestServeControlConnRejectsWhenPendingAuthCapacityIsFull(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{
		MaxPendingAuth:          2,
		MaxPendingAuthPerSource: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		protocol:  client.ProtocolTalariaTCP,
		codec:     dataplane.WireCodec{},
		resources: newResourceLimiter(limits),
	}
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- srv.ServeControlConn(context.Background(), firstServer, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			AuthTimeout: time.Second,
		})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		srv.resources.mu.Lock()
		pending := srv.resources.pendingAuth
		srv.resources.mu.Unlock()
		if pending == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first connection did not acquire pending-auth capacity")
		}
		time.Sleep(time.Millisecond)
	}
	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	if err := srv.ServeControlConn(context.Background(), secondServer, ServeOptions{
		Protocol:    client.ProtocolTalariaTCP,
		AuthTimeout: time.Second,
	}); !errors.Is(err, errResourceLimit) {
		t.Fatalf("second pending auth error = %v, want resource limit", err)
	}
	_ = firstClient.Close()
	select {
	case <-firstResult:
	case <-time.After(time.Second):
		t.Fatal("first pending-auth connection did not exit")
	}
}

func TestServerRejectsStreamBeforeDialWhenPendingDialLimitIsFull(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	dialStarted := make(chan struct{}, 1)
	releaseDial := make(chan struct{})
	var dialCalls atomic.Int32
	srv, err := Start(context.Background(), Config{
		Protocol:      client.ProtocolTalariaTCP,
		Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxSessions:              1,
			MaxStreams:               3,
			MaxStreamsPerClient:      2,
			MaxPendingDials:          2,
			MaxPendingDialsPerClient: 1,
			DialTimeout:              time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		dialStarted <- struct{}{}
		<-releaseDial
		return nil, errors.New("dial stopped")
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	var streams coretransport.StreamHandler
	select {
	case streams = <-transport.streams:
	case <-time.After(time.Second):
		t.Fatal("transport did not receive the stream handler")
	}
	req := coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target:  coretransport.Destination{Network: coretransport.NetworkTCP, Host: "8.8.8.8", Port: 443},
	}
	firstErr := make(chan error, 1)
	go func() {
		_, err := streams.OpenStream(context.Background(), req)
		firstErr <- err
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("first dial did not start")
	}
	if conn, err := streams.OpenStream(context.Background(), req); err == nil {
		_ = conn.Close()
		t.Fatal("second stream exceeded the pending dial limit")
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("dial calls = %d, want 1", got)
	}
	close(releaseDial)
	select {
	case err := <-firstErr:
		if err == nil {
			t.Fatal("first dial returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("first dial did not stop")
	}
}

func TestServerBoundsOutboundDialDuration(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	srv, err := Start(context.Background(), Config{
		Protocol:      client.ProtocolTalariaTCP,
		Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxSessions:              1,
			MaxStreams:               2,
			MaxStreamsPerClient:      1,
			MaxPendingDials:          2,
			MaxPendingDialsPerClient: 1,
			DialTimeout:              50 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	var streams coretransport.StreamHandler
	select {
	case streams = <-transport.streams:
	case <-time.After(time.Second):
		t.Fatal("transport did not receive the stream handler")
	}
	started := time.Now()
	_, err = streams.OpenStream(context.Background(), coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target:  coretransport.Destination{Network: coretransport.NetworkTCP, Host: "8.8.8.8", Port: 443},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("dial timeout took %s, want <= 500ms", elapsed)
	}
}

func TestStartRejectsUnboundedOutboundCallbacks(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config, *atomic.Bool)
		want      string
	}{
		{
			name: "forward",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.ForwardHandler = ForwardHandlerFunc(func(context.Context, ForwardRequest) (ForwardDecision, error) {
					called.Store(true)
					select {}
				})
			},
			want: "ForwardHandler",
		},
		{
			name: "resolver",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.LookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
					called.Store(true)
					select {}
				}
			},
			want: "LookupNetIP",
		},
		{
			name: "target policy",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.TargetPolicy = TargetPolicyFunc(func(context.Context, TargetPolicyRequest) error {
					called.Store(true)
					select {}
				})
			},
			want: "NewReferenceTargetPolicy",
		},
		{
			name: "dial",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.DialContext = func(context.Context, string, string) (net.Conn, error) {
					called.Store(true)
					select {}
				}
			},
			want: "DialContext",
		},
		{
			name: "packet handler",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.PacketHandler = PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
					called.Store(true)
					select {}
				})
			},
			want: "PacketHandler",
		},
		{
			name: "raw frame handler",
			configure: func(cfg *Config, called *atomic.Bool) {
				cfg.PacketHandler = unboundedRawFrameHandler{called: called}
			},
			want: "PacketHandler",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newInjectedServerTransport()
			var called atomic.Bool
			cfg := Config{
				Protocol:      client.ProtocolTalariaTCP,
				Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
				PacketHandler: EchoPacketHandler{},
				Transport:     transport,
			}
			tt.configure(&cfg, &called)
			_, err := Start(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unbounded callback error = %v, want %q", err, tt.want)
			}
			if called.Load() {
				t.Fatal("rejected callback was invoked")
			}
			select {
			case <-transport.started:
				t.Fatal("transport started with an unbounded callback")
			default:
			}
		})
	}
}

func TestStartRejectsUnboundedBuiltinHandlerCallbacks(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *atomic.Bool) PacketHandler
		want  string
	}{
		{
			name: "tun policy",
			setup: func(_ *testing.T, called *atomic.Bool) PacketHandler {
				return &TunPacketHandler{policy: TargetPolicyFunc(func(context.Context, TargetPolicyRequest) error {
					called.Store(true)
					select {}
				})}
			},
			want: "NewReferenceTargetPolicy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newInjectedServerTransport()
			var called atomic.Bool
			_, err := Start(context.Background(), Config{
				Protocol:      client.ProtocolTalariaTCP,
				Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
				PacketHandler: tt.setup(t, &called),
				Transport:     transport,
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unbounded built-in handler error = %v, want %q", err, tt.want)
			}
			if called.Load() {
				t.Fatal("rejected built-in handler callback was invoked")
			}
			select {
			case <-transport.started:
				t.Fatal("transport started with an unbounded built-in handler callback")
			default:
			}
		})
	}
}

func TestBoundedOutboundPathIgnoresLegacyWorkerSlots(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	srv, err := Start(context.Background(), Config{
		Protocol:      client.ProtocolTalariaTCP,
		Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxSessions:              1,
			MaxStreams:               2,
			MaxStreamsPerClient:      1,
			MaxPendingDials:          2,
			MaxPendingDialsPerClient: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for range cap(srv.outboundSlots) {
		srv.outboundSlots <- struct{}{}
	}
	defer func() {
		for len(srv.outboundSlots) != 0 {
			<-srv.outboundSlots
		}
	}()
	srv.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	var peer net.Conn
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		conn, remote := net.Pipe()
		peer = remote
		return conn, nil
	}
	defer func() {
		if peer != nil {
			_ = peer.Close()
		}
	}()
	ref := coretransport.SessionRef{ClientID: 42, Generation: 1}
	activateTestStreamSession(t, srv, ref)
	conn, err := waitForStreamHandler(t, transport).OpenStream(context.Background(), coretransport.StreamRequest{
		Session: ref,
		Target:  coretransport.Destination{Network: coretransport.NetworkTCP, Host: "healthy.example", Port: 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(srv.outboundSlots) != cap(srv.outboundSlots) {
		t.Fatalf("legacy worker slots = %d, want %d", len(srv.outboundSlots), cap(srv.outboundSlots))
	}
}

func TestBuiltinHandlerPoliciesIgnoreLegacyWorkerLimits(t *testing.T) {
	t.Run("tun", func(t *testing.T) {
		handler, err := NewTunPacketHandler(TunPacketHandlerConfig{Device: discardTunDevice{batchSize: 1}})
		if err != nil {
			t.Fatal(err)
		}
		srv, err := Start(context.Background(), Config{
			Protocol:      client.ProtocolTalariaTCP,
			Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
			PacketHandler: handler,
			Transport:     newInjectedServerTransport(),
		})
		if err != nil {
			_ = handler.Close()
			t.Fatal(err)
		}
		defer srv.Close()
		packet, parseErr := ippacket.ParseIPPacket(makeIPv4TCPPacket(
			[4]byte{10, 80, 0, 2},
			[4]byte{8, 8, 8, 8},
		))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if err := handler.validatePacketTarget(context.Background(), SessionContext{ClientID: 42}, packet); err != nil {
			t.Fatal(err)
		}
	})
}

type unboundedRawFrameHandler struct {
	called *atomic.Bool
}

func (h unboundedRawFrameHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	h.called.Store(true)
	select {}
}

func (h unboundedRawFrameHandler) HandleRawFrame(context.Context, SessionContext, []byte) (bool, []*vpnpacket.VpnPacket, error) {
	h.called.Store(true)
	select {}
}

func waitForServerOutboundSlots(t *testing.T, slots chan struct{}, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(slots) != want {
		if time.Now().After(deadline) {
			t.Fatalf("outbound callback slots = %d, want %d", len(slots), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBoundedExtensionRejectsWorkerOverflow(t *testing.T) {
	slots := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallback()
	for range cap(slots) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := callBoundedExtension(ctx, slots, nil, 0, "test outbound callback", func() (struct{}, error) {
			<-release
			return struct{}{}, nil
		}, nil)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("callback error = %v, want deadline exceeded", err)
		}
	}
	if _, err := callBoundedExtension(context.Background(), slots, nil, 0, "overflow callback", func() (struct{}, error) {
		return struct{}{}, nil
	}, nil); !errors.Is(err, errResourceLimit) {
		t.Fatalf("overflow error = %v, want resource limit", err)
	}
	releaseCallback()
	waitForServerOutboundSlots(t, slots, 0)
}

func TestBoundedExtensionRetainsWorkerWhileDiscardBlocks(t *testing.T) {
	slots := make(chan struct{}, 1)
	resources := newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
	ctx := &cancelOnSecondErrContext{Context: context.Background()}
	discardStarted := make(chan struct{})
	releaseDiscard := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := callBoundedExtension(ctx, slots, resources, 7, "test discarded callback", func() (struct{}, error) {
			return struct{}{}, nil
		}, func(struct{}) {
			close(discardStarted)
			<-releaseDiscard
		})
		done <- err
	}()
	select {
	case <-discardStarted:
	case <-time.After(time.Second):
		t.Fatal("discard callback did not start")
	}
	defer func() {
		select {
		case <-releaseDiscard:
		default:
			close(releaseDiscard)
		}
		<-done
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := callBoundedExtension(context.Background(), slots, resources, 7, "overflow callback", func() (struct{}, error) {
		return struct{}{}, nil
	}, nil); !errors.Is(err, errResourceLimit) {
		t.Fatalf("callback during blocked discard = %v, want resource limit", err)
	}
}

type cancelOnSecondErrContext struct {
	context.Context
	calls atomic.Int32
}

func (c *cancelOnSecondErrContext) Err() error {
	if c.calls.Add(1) > 1 {
		return context.Canceled
	}
	return nil
}

func TestServeControlConnPassesAuthDeadlineToProvider(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    dataplane.WireCodec{},
		auth: AuthProviderFunc(func(ctx context.Context, _ AuthRequest) (AuthResult, error) {
			<-ctx.Done()
			return AuthResult{}, ctx.Err()
		}),
		handler: EchoPacketHandler{},
	}
	result := make(chan error, 1)
	go func() {
		result <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			AuthTimeout: 50 * time.Millisecond,
		})
	}()
	writeTestPacket(t, dataplane.WireCodec{}, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	select {
	case serveErr := <-result:
		if !errors.Is(serveErr, context.DeadlineExceeded) {
			t.Fatalf("auth error = %v, want context deadline exceeded", serveErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("auth provider did not receive the authentication deadline")
	}
}

func TestBlockingAuthProviderReleasesPendingCapacity(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{MaxPendingAuth: 4, MaxPendingAuthPerSource: 2})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	srv := &Server{
		protocol:  client.ProtocolTalariaTCP,
		codec:     dataplane.WireCodec{},
		resources: newResourceLimiter(limits),
		authSlots: make(chan struct{}, limits.MaxPendingAuth),
		auth: AuthProviderFunc(func(_ context.Context, req AuthRequest) (AuthResult, error) {
			if req.ClientID == "blocked" {
				started <- struct{}{}
				<-release
			}
			return AuthResult{ClientID: 42, Version: 1}, nil
		}),
		handler: EchoPacketHandler{},
	}

	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- srv.ServeControlConn(context.Background(), firstServer, ServeOptions{
			Protocol: client.ProtocolTalariaTCP, AuthTimeout: 20 * time.Millisecond,
		})
	}()
	writeTestPacket(t, srv.codec, firstClient, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "blocked", Sk: "secret"})
	<-started
	select {
	case err := <-firstResult:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked auth error = %v, want deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocking auth provider retained the connection worker")
	}
	srv.resources.mu.Lock()
	pending := srv.resources.pendingAuth
	srv.resources.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending auth = %d, want 0", pending)
	}

	secondServer, secondClient := net.Pipe()
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- srv.ServeControlConn(context.Background(), secondServer, ServeOptions{
			Protocol: client.ProtocolTalariaTCP, AuthTimeout: time.Second,
		})
	}()
	writeTestPacket(t, srv.codec, secondClient, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "next", Sk: "secret"})
	for _, want := range []byte{vpnpacket.CmdAuthSuccess, vpnpacket.CmdSessionReady} {
		if packet := readTestPacket(t, srv.codec, secondClient); packet.Cmd != want {
			t.Fatalf("response command = %d, want %d", packet.Cmd, want)
		}
	}
	_ = secondClient.Close()
	select {
	case <-secondResult:
	case <-time.After(time.Second):
		t.Fatal("replacement authentication did not finish")
	}
}

func TestStartRejectsUnboundedAuthProvider(t *testing.T) {
	transport := newInjectedServerTransport()
	_, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			select {}
		}),
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	})
	if err == nil || !strings.Contains(err.Error(), "StaticAuthProvider") {
		t.Fatalf("unbounded auth provider error = %v", err)
	}
	select {
	case <-transport.started:
		t.Fatal("transport started with an unbounded auth provider")
	default:
	}
}

func TestStaticAuthProviderDoesNotUseAuthCallbackWorkers(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxPendingAuth:          4,
			MaxPendingAuthPerSource: 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for range cap(srv.authSlots) {
		srv.authSlots <- struct{}{}
	}
	defer func() {
		for len(srv.authSlots) != 0 {
			<-srv.authSlots
		}
	}()
	result, err := srv.callAuthProvider(context.Background(), AuthRequest{
		Packet:    &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest},
		ClientID:  "client",
		SecretKey: "secret",
		RemoteIP:  "192.0.2.10",
	})
	if err != nil || result.ClientID != 42 {
		t.Fatalf("static auth result = %+v, %v", result, err)
	}
}

func TestStartRejectsExternalSessionAttachCallbacks(t *testing.T) {
	for _, handler := range []PacketHandler{
		&callbackSessionHandler{},
		failingSessionPacketHandler{err: errors.New("unused")},
	} {
		transport := newInjectedServerTransport()
		_, err := Start(context.Background(), Config{
			Protocol: client.ProtocolTalariaTCP,
			Auth: StaticAuthProvider{
				ClientID:         "client",
				SecretKey:        "secret",
				AssignedClientID: 42,
			},
			PacketHandler: handler,
			Transport:     transport,
		})
		if err == nil || !strings.Contains(err.Error(), "PacketHandler") {
			t.Fatalf("external attach handler %T error = %v", handler, err)
		}
		select {
		case <-transport.started:
			t.Fatalf("transport started with external attach handler %T", handler)
		default:
		}
	}
}

func TestServerRejectsNewClientWhenSessionLimitIsFull(t *testing.T) {
	transport := newCapturedStreamTransport("127.0.0.1:8443")
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{Credentials: []StaticCredential{
			{ClientID: "first", SecretKey: "secret", AssignedClientID: 1},
			{ClientID: "second", SecretKey: "secret", AssignedClientID: 2},
		}},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ResourceLimits: ResourceLimits{
			MaxSessions:              1,
			MaxStreams:               2,
			MaxStreamsPerClient:      1,
			MaxPendingDials:          2,
			MaxPendingDialsPerClient: 1,
			DialTimeout:              time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	var controls coretransport.ControlHandler
	select {
	case controls = <-transport.controls:
	case <-time.After(time.Second):
		t.Fatal("transport did not receive the control handler")
	}
	codec := dataplane.WireCodec{}
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- controls.HandleControl(firstCtx, firstServer)
	}()
	writeTestPacket(t, codec, firstClient, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "first", Sk: "secret"})
	if packet := readTestPacket(t, codec, firstClient); packet.Cmd != vpnpacket.CmdAuthSuccess {
		t.Fatalf("first auth response command = %d, want CmdAuthSuccess", packet.Cmd)
	}
	if packet := readTestPacket(t, codec, firstClient); packet.Cmd != vpnpacket.CmdSessionGrant {
		t.Fatalf("first session response command = %d, want CmdSessionGrant", packet.Cmd)
	}
	if packet := readTestPacket(t, codec, firstClient); packet.Cmd != vpnpacket.CmdSessionReady {
		t.Fatalf("first ready response command = %d, want CmdSessionReady", packet.Cmd)
	}

	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	secondErr := make(chan error, 1)
	go func() {
		secondErr <- controls.HandleControl(context.Background(), secondServer)
	}()
	writeTestPacket(t, codec, secondClient, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "second", Sk: "secret"})
	if packet := readTestPacket(t, codec, secondClient); packet.Cmd != vpnpacket.CmdAuthSuccess {
		t.Fatalf("second auth response command = %d, want CmdAuthSuccess", packet.Cmd)
	}
	if packet := readTestPacket(t, codec, secondClient); packet.Cmd != vpnpacket.CmdErr {
		t.Fatalf("second session response command = %d, want CmdErr", packet.Cmd)
	}
	select {
	case err := <-secondErr:
		if err == nil {
			t.Fatal("session above the limit returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("session above the limit did not close")
	}

	firstCancel()
	_ = firstClient.Close()
	select {
	case <-firstErr:
	case <-time.After(time.Second):
		t.Fatal("first session did not stop")
	}
}

func TestServeControlConnStopsContextWatcherWhenConnectionReturns(t *testing.T) {
	serverPipe, clientConn := net.Pipe()
	defer clientConn.Close()
	serverConn := &closeCountingConn{
		Conn:   serverPipe,
		closed: make(chan struct{}, 2),
	}
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    dataplane.WireCodec{},
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{}, errors.New("auth denied")
		}),
		handler: EchoPacketHandler{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(ctx, serverConn, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			AuthTimeout: time.Second,
		})
	}()

	codec := dataplane.WireCodec{}
	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "wrong-secret",
	})
	if response := readTestPacket(t, codec, clientConn); response.Cmd != vpnpacket.CmdErr {
		t.Fatalf("response command = %d, want CmdErr", response.Cmd)
	}
	if err := <-errCh; err == nil {
		t.Fatal("rejected connection returned no error")
	}
	select {
	case <-serverConn.closed:
	case <-time.After(time.Second):
		t.Fatal("connection was not closed on return")
	}

	cancel()
	select {
	case <-serverConn.closed:
		t.Fatal("connection was closed again after its handler returned")
	case <-time.After(50 * time.Millisecond):
	}
	if got := serverConn.closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
}

type closeCountingConn struct {
	net.Conn
	closeCalls atomic.Int32
	closed     chan struct{}
}

func (c *closeCountingConn) Close() error {
	c.closeCalls.Add(1)
	select {
	case c.closed <- struct{}{}:
	default:
	}
	return c.Conn.Close()
}
