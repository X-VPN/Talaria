// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/internal/ippacket"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestServerBlocksLocalhostAliasOfTransportListenerBeforeDial(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST."} {
		t.Run(host, func(t *testing.T) {
			assertServerTargetDialCalls(t, host, 8443, 0)
		})
	}
}

func TestServerBlocksUnspecifiedAddressAliasOfTransportListenerBeforeDial(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "::"} {
		t.Run(host, func(t *testing.T) {
			assertServerTargetDialCalls(t, host, 8443, 0)
		})
	}
}

func TestServerBlocksLoopbackAddressOfTransportListenerBeforeDial(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		t.Run(host, func(t *testing.T) {
			assertServerTargetDialCalls(t, host, 8443, 0)
		})
	}
}

func TestServerBlocksUnsafeAndPrivateTargetsButAllowsPublicUnicast(t *testing.T) {
	for _, host := range []string{
		"8.8.8.8", "192.0.0.9",
	} {
		t.Run("public "+host, func(t *testing.T) {
			assertServerTargetDialCalls(t, host, 8443, 1)
		})
	}
	blocked := []string{
		"127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0", "255.255.255.255",
		"::1", "fe80::1", "ff02::1",
		"0.1.2.3", "192.0.2.20", "198.18.0.1", "240.0.0.1",
		"100::1", "2001:db8::1", "3fff::1", "5f00::1",
		"64:ff9b::7f00:1", "64:ff9b::a0f:1442", "64:ff9b::a9fe:a9fe",
		"64:ff9b::808:808", "2001:3::1", "2001:4860:4860::8888",
		"2404:6800:4005::200e", "2606:4700:4700::1111", "2a00:1450:4001::200e", "2c0f:fb50:4003::1",
		"400::1", "2000::1", "2d00::1", "3000::1", "fec0::1",
		"10.15.20.66", "172.16.0.5", "192.168.1.1", "100.64.0.1", "fc00::1", "fd12::1",
	}
	for _, host := range blocked {
		t.Run("blocked "+host, func(t *testing.T) {
			assertServerTargetDialCalls(t, host, 9443, 0)
		})
	}
}

func TestServerAllowsPrivateTargetsWhenConfigured(t *testing.T) {
	policy, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"10.15.20.66", "192.168.1.1", "100.64.0.1"} {
		t.Run(host, func(t *testing.T) {
			assertServerTargetDialCallsWithPolicy(t, policy, host, 443, 1)
		})
	}
	t.Run("still blocks loopback", func(t *testing.T) {
		assertServerTargetDialCallsWithPolicy(t, policy, "127.0.0.1", 443, 0)
	})
	// Three of the four metadata endpoints are only otherwise covered by the
	// private-address rule, which this configuration switches off. If the
	// explicit list ever regresses, an authenticated client reaches the server's
	// own cloud credentials.
	for _, host := range []string{
		"169.254.169.254", // AWS, GCP, Azure, Oracle, OpenStack
		"100.100.100.200", // Alibaba Cloud ECS, in RFC 6598 space
		"168.63.129.16",   // Azure host agent, in a public range
		"fd00:ec2::254",   // AWS IPv6, in ULA space
	} {
		t.Run("still blocks metadata "+host, func(t *testing.T) {
			assertServerTargetDialCallsWithPolicy(t, policy, host, 443, 0)
		})
	}
}

func TestServerBlocksResolvedListenerAliasBeforeDial(t *testing.T) {
	transport := newCapturedStreamTransport("10.15.20.65:8443")
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
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.15.20.65")}, nil
	}
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unexpected outbound dial")
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	streams := waitForStreamHandler(t, transport)
	_, err = streams.OpenStream(context.Background(), coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target: coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Host:    "vpn-listener.internal",
			Port:    8443,
		},
		Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Local:  &net.TCPAddr{IP: net.ParseIP("10.15.20.65"), Port: 8443},
	})
	if err == nil {
		t.Fatal("resolved listener alias was accepted")
	}
	if got := dialCalls.Load(); got != 0 {
		t.Fatalf("outbound dial calls = %d, want 0", got)
	}
}

func TestServerFailsClosedWhenWildcardListenerAddressesCannotBeDiscovered(t *testing.T) {
	srv := &Server{
		addr: "0.0.0.0:8443",
		interfaceAddrs: func() ([]net.Addr, error) {
			return nil, errors.New("synthetic interface discovery failure")
		},
	}
	if !srv.isOwnTransportIP(netip.MustParseAddr("8.8.8.8"), 8443, nil) {
		t.Fatal("wildcard listener check failed open after interface discovery error")
	}
}

func TestServerPinsResolvedAddressBeforeDial(t *testing.T) {
	transport := newCapturedStreamTransport("10.15.20.65:8443")
	var dialAddress string
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	srv.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialAddress = address
		return nil, errors.New("dial probe")
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	streams := waitForStreamHandler(t, transport)
	_, _ = streams.OpenStream(context.Background(), coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target: coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Host:    "allowed.example",
			Port:    443,
		},
		Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Local:  &net.TCPAddr{IP: net.ParseIP("10.15.20.65"), Port: 8443},
	})
	if dialAddress != "8.8.8.8:443" {
		t.Fatalf("dial address = %q, want pinned resolved address", dialAddress)
	}
}

func TestServerClosesConnectionReturnedWithDialError(t *testing.T) {
	want := errors.New("dial failed")
	conn := &serverDialErrorConn{}
	srv := &Server{dial: func(context.Context, string, string) (net.Conn, error) {
		return conn, want
	}}
	got, err := srv.dialResolvedTarget(context.Background(), 0, coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Port:    443,
	}, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	if got != nil || !errors.Is(err, want) {
		t.Fatalf("dial result = %v, %v; want nil, %v", got, err, want)
	}
	if conn.closes.Load() != 1 {
		t.Fatalf("failed connection closes = %d, want 1", conn.closes.Load())
	}
}

func TestServerRetainsOutboundWorkerWhileFailedConnectionCloseBlocks(t *testing.T) {
	want := errors.New("dial failed")
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	conn := &serverBlockingDialErrorConn{
		started: closeStarted,
		release: releaseClose,
	}
	var dialCalls atomic.Int32
	srv := &Server{
		resources:     newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1}),
		outboundSlots: make(chan struct{}, 1),
		dial: func(context.Context, string, string) (net.Conn, error) {
			if dialCalls.Add(1) == 1 {
				return conn, want
			}
			return nil, errors.New("unexpected second dial")
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := srv.dialResolvedTarget(context.Background(), 7, coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Port:    443,
		}, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
		done <- err
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		close(releaseClose)
		t.Fatal("failed connection close did not start")
	}
	defer func() {
		select {
		case <-releaseClose:
		default:
			close(releaseClose)
		}
		if err := <-done; !errors.Is(err, want) {
			t.Errorf("first dial error = %v, want %v", err, want)
		}
	}()
	_, err := srv.dialResolvedTarget(context.Background(), 7, coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Port:    443,
	}, []netip.Addr{netip.MustParseAddr("8.8.4.4")})
	if !errors.Is(err, errResourceLimit) {
		t.Fatalf("dial during blocked close = %v, want resource limit", err)
	}
}

func TestReferenceTargetPolicyRejectsInvalidProtectedPrefix(t *testing.T) {
	if _, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		ProtectedPrefixes: []netip.Prefix{{}},
	}); err == nil {
		t.Fatal("invalid protected prefix was accepted")
	}
}

func TestReferenceTargetPolicyChecksConfiguredNAT64Prefixes(t *testing.T) {
	firstPrefix := netip.MustParsePrefix("2a00:1450:4001:64::/96")
	secondPrefix := netip.MustParsePrefix("2606:4700:4700:64::/96")
	policyValue, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		NAT64Prefixes:     []netip.Prefix{firstPrefix, secondPrefix},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.4.4/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := policyValue.(*referenceTargetPolicy)
	policy.discoverLocalAddresses = func() (map[netip.Addr]struct{}, error) {
		return map[netip.Addr]struct{}{netip.MustParseAddr("9.9.9.9"): {}}, nil
	}
	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{name: "public IPv4", ip: "2a00:1450:4001:64::808:808", allowed: true},
		{name: "second prefix", ip: "2606:4700:4700:64::101:101", allowed: true},
		{name: "RFC1918", ip: "2a00:1450:4001:64::a00:1"},
		{name: "loopback", ip: "2a00:1450:4001:64::7f00:1"},
		{name: "link local", ip: "2a00:1450:4001:64::a9fe:101"},
		{name: "metadata", ip: "2a00:1450:4001:64::a9fe:a9fe"},
		{name: "shared metadata", ip: "2a00:1450:4001:64::6464:64c8"},
		{name: "protected IPv4", ip: "2a00:1450:4001:64::808:404"},
		{name: "local IPv4", ip: "2a00:1450:4001:64::909:909"},
		{name: "native IPv6", ip: "2606:4700:4700::1111"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policy.ValidateTarget(context.Background(), TargetPolicyRequest{IP: netip.MustParseAddr(tt.ip)})
			if tt.allowed && err != nil {
				t.Fatalf("target %s error = %v, want allowed", tt.ip, err)
			}
			if !tt.allowed && !errors.Is(err, errTargetBlocked) {
				t.Fatalf("target %s error = %v, want blocked", tt.ip, err)
			}
		})
	}
	assertServerTargetDialCallsWithPolicy(t, policy, "2a00:1450:4001:64::808:808", 443, 1)
	assertServerTargetDialCallsWithPolicy(t, policy, "2a00:1450:4001:64::a00:1", 443, 0)
}

func TestReferenceTargetPolicyNAT64ConfigurationFailsClosed(t *testing.T) {
	unconfigured, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unconfigured.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2606:4700:4700::1111"),
	}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("unconfigured IPv6 error = %v, want blocked", err)
	}
	if err := unconfigured.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("8.8.8.8"),
	}); err != nil {
		t.Fatalf("unconfigured IPv4 error = %v, want allowed", err)
	}
	configured, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{NAT64Prefixes: []netip.Prefix{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := configured.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2606:4700:4700::1111"),
	}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("NAT64-only native IPv6 error = %v, want blocked", err)
	}
	if err := configured.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("64:ff9b::808:808"),
	}); err != nil {
		t.Fatalf("well-known NAT64 error = %v, want allowed", err)
	}
	if err := configured.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2a00:1450:4001:64::808:808"),
	}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("undeclared NAT64 prefix error = %v, want blocked", err)
	}
	if _, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{AllowNativeIPv6: true}); err == nil {
		t.Fatal("native IPv6 was enabled without an explicit NAT64 declaration")
	}
	native, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		NAT64Prefixes:   []netip.Prefix{},
		AllowNativeIPv6: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := native.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2606:4700:4700::1111"),
	}); err != nil {
		t.Fatalf("native IPv6 opt-in error = %v, want allowed", err)
	}
	if err := native.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("64:ff9b::7f00:1"),
	}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("native opt-in NAT64 loopback error = %v, want blocked", err)
	}
	if err := configured.ValidateTarget(context.Background(), TargetPolicyRequest{}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("invalid target error = %v, want blocked", err)
	}
}

func TestDefaultTargetPolicyRejectsUndeclaredNAT64Targets(t *testing.T) {
	policy := normalizeConfig(Config{}).TargetPolicy
	prefix := netip.MustParsePrefix("2a00:1450:4001:64::/96")
	for _, ipv4 := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "169.254.169.254", "8.8.8.8"} {
		address := testNAT64Address(prefix, netip.MustParseAddr(ipv4))
		if err := policy.ValidateTarget(context.Background(), TargetPolicyRequest{IP: address}); !errors.Is(err, errTargetBlocked) {
			t.Fatalf("default policy target %s error = %v, want blocked", address, err)
		}
	}
	assertServerTargetDialCalls(t, "2a00:1450:4001:64::808:808", 443, 0)
}

func TestReferenceTargetPolicyRejectsInvalidNAT64Configuration(t *testing.T) {
	tests := []ReferenceTargetPolicyConfig{
		{NAT64Prefixes: []netip.Prefix{{}}},
		{NAT64Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		{NAT64Prefixes: []netip.Prefix{netip.MustParsePrefix("fe80::/96")}},
		{NAT64Prefixes: []netip.Prefix{netip.MustParsePrefix("2a00:1450:4001:64::/80")}},
		{NAT64Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2a00:1400::/32"),
			netip.MustParsePrefix("2a00:1400:1::/96"),
		}},
	}
	for _, cfg := range tests {
		if _, err := NewReferenceTargetPolicy(cfg); err == nil {
			t.Fatalf("invalid NAT64 configuration %+v was accepted", cfg.NAT64Prefixes)
		}
	}
}

func TestReferenceTargetPolicyHonorsNAT64PrivateAndPrefixOverrides(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:64::/96")
	privatePolicy, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		NAT64Prefixes:       []netip.Prefix{prefix},
		AllowPrivateTargets: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	privatePolicy.(*referenceTargetPolicy).discoverLocalAddresses = func() (map[netip.Addr]struct{}, error) {
		return map[netip.Addr]struct{}{}, nil
	}
	if err := privatePolicy.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2001:db8:64::a00:1"),
	}); err != nil {
		t.Fatalf("allowed private NAT64 target error = %v", err)
	}
	blockedPolicy, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		NAT64Prefixes:     []netip.Prefix{prefix},
		ProtectedPrefixes: []netip.Prefix{prefix},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := blockedPolicy.ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2001:db8:64::808:808"),
	}); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("protected NAT64 prefix error = %v, want blocked", err)
	}
}

func TestNAT64EmbeddedIPv4(t *testing.T) {
	want := netip.MustParseAddr("8.8.4.4")
	for _, bits := range []int{32, 40, 48, 56, 64, 96} {
		prefix := netip.PrefixFrom(netip.MustParseAddr("2a00:1450:4001:64::"), bits).Masked()
		address := testNAT64Address(prefix, want)
		got, ok := nat64EmbeddedIPv4(address, prefix)
		if !ok || got != want {
			t.Fatalf("/%d embedded IPv4 = %s, %v, want %s", bits, got, ok, want)
		}
		if bits != 96 {
			raw := address.As16()
			raw[8] = 1
			if _, ok := nat64EmbeddedIPv4(netip.AddrFrom16(raw), prefix); ok {
				t.Fatalf("/%d accepted nonzero reserved octet", bits)
			}
			raw = address.As16()
			raw[15] = 1
			if _, ok := nat64EmbeddedIPv4(netip.AddrFrom16(raw), prefix); ok {
				t.Fatalf("/%d accepted nonzero suffix", bits)
			}
		}
	}
}

func testNAT64Address(prefix netip.Prefix, ipv4 netip.Addr) netip.Addr {
	raw := prefix.Addr().As16()
	embedded := ipv4.As4()
	if prefix.Bits() == 96 {
		copy(raw[12:], embedded[:])
		return netip.AddrFrom16(raw)
	}
	prefixBytes := prefix.Bits() / 8
	beforeU := 8 - prefixBytes
	copy(raw[prefixBytes:8], embedded[:beforeU])
	copy(raw[9:], embedded[beforeU:])
	return netip.AddrFrom16(raw)
}

func TestReferenceTargetPolicyRejectsIPv6Zone(t *testing.T) {
	err := ReferenceTargetPolicy().ValidateTarget(context.Background(), TargetPolicyRequest{
		IP: netip.MustParseAddr("2606:4700:4700::1111%en0"),
	})
	if !errors.Is(err, errTargetBlocked) {
		t.Fatalf("zoned IPv6 target error = %v, want blocked", err)
	}
}

func TestReferenceTargetPolicyChecksCurrentLocalAddresses(t *testing.T) {
	local := netip.MustParseAddr("8.8.4.4")
	var mu sync.RWMutex
	addresses := map[netip.Addr]struct{}{}
	var discoveryErr error
	policy := &referenceTargetPolicy{
		discoverLocalAddresses: func() (map[netip.Addr]struct{}, error) {
			mu.RLock()
			defer mu.RUnlock()
			return addresses, discoveryErr
		},
	}
	request := TargetPolicyRequest{IP: local}
	if err := policy.ValidateTarget(context.Background(), request); err != nil {
		t.Fatalf("initial target error = %v, want allowed", err)
	}
	mu.Lock()
	addresses = map[netip.Addr]struct{}{local: {}}
	mu.Unlock()
	if err := policy.ValidateTarget(context.Background(), request); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("new local target error = %v, want blocked", err)
	}

	const validators = 32
	errs := make(chan error, validators)
	for range validators {
		go func() { errs <- policy.ValidateTarget(context.Background(), request) }()
	}
	for range validators {
		if err := <-errs; !errors.Is(err, errTargetBlocked) {
			t.Fatalf("concurrent local target error = %v, want blocked", err)
		}
	}

	mu.Lock()
	addresses = map[netip.Addr]struct{}{}
	mu.Unlock()
	if err := policy.ValidateTarget(context.Background(), request); err != nil {
		t.Fatalf("removed local target error = %v, want allowed", err)
	}
	mu.Lock()
	discoveryErr = errors.New("synthetic interface discovery failure")
	mu.Unlock()
	if err := policy.ValidateTarget(context.Background(), request); !errors.Is(err, errTargetBlocked) {
		t.Fatalf("discovery failure error = %v, want blocked", err)
	}
}

func TestServerTargetPolicyGuardsBuiltinRawIPPaths(t *testing.T) {
	tests := []struct {
		name        string
		handler     PacketHandler
		protocol    byte
		wantNetwork coretransport.Network
		fixed       bool
	}{
		{name: "tun tcp", handler: &TunPacketHandler{}, protocol: 6, wantNetwork: coretransport.NetworkTCP},
		{name: "tun udp", handler: &TunPacketHandler{}, protocol: 17, wantNetwork: coretransport.NetworkUDP},
		{name: "tun ip", handler: &TunPacketHandler{}, protocol: 1, wantNetwork: coretransport.NetworkIP},
		{name: "tun fixed tcp", handler: &TunPacketHandler{}, protocol: 6, wantNetwork: coretransport.NetworkTCP, fixed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := errors.New("server policy blocked target")
			requests := make(chan TargetPolicyRequest, 1)
			srv, session, cleanup := newPacketBoundaryServer(t, tt.handler)
			defer cleanup()
			srv.policy = TargetPolicyFunc(func(_ context.Context, req TargetPolicyRequest) error {
				requests <- req
				return blocked
			})
			srv.outboundSlots = make(chan struct{}, 2)
			srv.resources = newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
			payload := makePolicyIPv4Packet(tt.protocol)
			var err error
			if tt.fixed {
				raw := make([]byte, vpnpacket.FixedV4PayloadOffset()+len(payload))
				if !vpnpacket.WriteRawFixedV4DataHeader(
					raw[:vpnpacket.FixedV4PayloadOffset()], session.ClientID, 1,
					payload[12:16], payload[16:20],
				) {
					t.Fatal("failed to build fixed IPv4 frame")
				}
				copy(raw[vpnpacket.FixedV4PayloadOffset():], payload)
				err = srv.handleRawPacketFrame(context.Background(), nil, session, raw)
			} else {
				err = srv.handleAndWriteResponses(context.Background(), nil, session, &vpnpacket.VpnPacket{
					Cmd:  vpnpacket.CmdData,
					Data: payload,
				})
			}
			if !errors.Is(err, blocked) {
				t.Fatalf("raw target error = %v, want server policy rejection", err)
			}
			select {
			case req := <-requests:
				if req.Network != tt.wantNetwork || req.IP.String() != "8.8.8.8" {
					t.Fatalf("policy request = %+v", req)
				}
				if tt.wantNetwork == coretransport.NetworkIP && req.Port != 0 {
					t.Fatalf("IP policy port = %d, want 0", req.Port)
				}
			case <-time.After(time.Second):
				t.Fatal("server target policy was not called")
			}
		})
	}
}

func TestBuiltinRawIPPolicyConflictFailsClosed(t *testing.T) {
	serverCalls := 0
	handlerPolicy, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:       discardTunDevice{batchSize: 1},
		TargetPolicy: handlerPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	srv.policy = TargetPolicyFunc(func(context.Context, TargetPolicyRequest) error {
		serverCalls++
		return nil
	})
	srv.outboundSlots = make(chan struct{}, 2)
	srv.resources = newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
	detach, err := handler.AttachSessionWriters(context.Background(), session, vipTestWriters())
	if err != nil {
		t.Fatal(err)
	}
	defer detach()
	err = srv.handleAndWriteResponses(context.Background(), nil, session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makePolicyIPv4Packet(6),
	})
	if !errors.Is(err, errTargetBlocked) {
		t.Fatalf("conflicting policy error = %v, want handler rejection", err)
	}
	if serverCalls != 1 {
		t.Fatalf("server policy calls = %d, want 1", serverCalls)
	}
}

func TestBuiltinRawIPPolicyMissingFailsClosed(t *testing.T) {
	srv, session, cleanup := newPacketBoundaryServer(t, &TunPacketHandler{})
	defer cleanup()
	err := srv.handleAndWriteResponses(context.Background(), nil, session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makePolicyIPv4Packet(6),
	})
	if !errors.Is(err, errTargetBlocked) {
		t.Fatalf("missing server policy error = %v, want blocked", err)
	}
}

func TestServerTargetPolicyDoesNotInterpretCustomHandlerPayloads(t *testing.T) {
	handler := &countingPacketHandler{}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	var policyCalls atomic.Int32
	srv.policy = TargetPolicyFunc(func(context.Context, TargetPolicyRequest) error {
		policyCalls.Add(1)
		return errTargetBlocked
	})
	if err := srv.handleAndWriteResponses(context.Background(), nil, session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makePolicyIPv4Packet(6),
	}); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 1 || policyCalls.Load() != 0 {
		t.Fatalf("custom boundary calls = handler %d, policy %d", handler.calls, policyCalls.Load())
	}
}

func makePolicyIPv4Packet(protocol byte) []byte {
	if protocol == 6 {
		return makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{8, 8, 8, 8})
	}
	raw := make([]byte, 28)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = protocol
	copy(raw[12:16], []byte{10, 80, 0, 2})
	copy(raw[16:20], []byte{8, 8, 8, 8})
	if protocol == 17 {
		binary.BigEndian.PutUint16(raw[20:22], 12345)
		binary.BigEndian.PutUint16(raw[22:24], 5202)
		binary.BigEndian.PutUint16(raw[24:26], 8)
	} else {
		raw[20] = 8
	}
	packet, err := ippacket.ParseIPPacket(raw)
	if err != nil {
		panic(err)
	}
	packet.RecomputeChecksum()
	return raw
}

func assertServerTargetDialCalls(t *testing.T, targetHost string, targetPort uint16, wantDialCalls int32) {
	t.Helper()
	assertServerTargetDialCallsWithPolicy(t, nil, targetHost, targetPort, wantDialCalls)
}

func assertServerTargetDialCallsWithPolicy(
	t *testing.T,
	policy TargetPolicy,
	targetHost string,
	targetPort uint16,
	wantDialCalls int32,
) {
	t.Helper()
	transport := newCapturedStreamTransport("127.0.0.1:8443")
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
		TargetPolicy:  policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.dial = func(context.Context, string, string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("unexpected outbound dial")
	}
	activateTestStreamSession(t, srv, coretransport.SessionRef{ClientID: 42, Generation: 1})

	streams := waitForStreamHandler(t, transport)

	_, err = streams.OpenStream(context.Background(), coretransport.StreamRequest{
		Session: coretransport.SessionRef{ClientID: 42, Generation: 1},
		Target: coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Host:    targetHost,
			Port:    targetPort,
		},
		Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000},
		Local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
	})
	if err == nil {
		t.Fatal("listener alias target was accepted")
	}
	if got := dialCalls.Load(); got != wantDialCalls {
		t.Fatalf("outbound dial calls = %d, want %d", got, wantDialCalls)
	}
}

func activateTestStreamSession(t *testing.T, srv *Server, ref coretransport.SessionRef) {
	t.Helper()
	binding, err := srv.activateSession(activeServerSessionConfig{
		Ref: ref,
		Context: SessionContext{
			Protocol:   client.ProtocolTalariaTCP,
			ClientID:   ref.ClientID,
			Generation: ref.Generation,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.releaseSession(binding)
	})
}

func waitForStreamHandler(t *testing.T, transport *capturedStreamTransport) coretransport.StreamHandler {
	t.Helper()
	select {
	case streams := <-transport.streams:
		return streams
	case <-time.After(time.Second):
		t.Fatal("transport did not receive the stream handler")
		return nil
	}
}

type capturedStreamTransport struct {
	addr      net.Addr
	controls  chan coretransport.ControlHandler
	streams   chan coretransport.StreamHandler
	closed    chan struct{}
	closeOnce sync.Once
}

func newCapturedStreamTransport(addr string) *capturedStreamTransport {
	return &capturedStreamTransport{
		addr:     capturedStreamAddr(addr),
		controls: make(chan coretransport.ControlHandler, 1),
		streams:  make(chan coretransport.StreamHandler, 1),
		closed:   make(chan struct{}),
	}
}

func (t *capturedStreamTransport) Serve(
	ctx context.Context,
	controls coretransport.ControlHandler,
	streams coretransport.StreamHandler,
) error {
	t.controls <- controls
	t.streams <- streams
	select {
	case <-ctx.Done():
	case <-t.closed:
	}
	return nil
}

func (*capturedStreamTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (*capturedStreamTransport) Prepare(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (*capturedStreamTransport) Commit(context.Context, coretransport.SessionRef) error {
	return nil
}

func (*capturedStreamTransport) Finalize(context.Context, coretransport.SessionRef) error {
	return nil
}

func (*capturedStreamTransport) Revoke(context.Context, coretransport.SessionRef) error {
	return nil
}

func (t *capturedStreamTransport) Addr() net.Addr {
	return t.addr
}

func (t *capturedStreamTransport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil
}

type capturedStreamAddr string

func (capturedStreamAddr) Network() string  { return "tcp" }
func (a capturedStreamAddr) String() string { return string(a) }

type serverDialErrorConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *serverDialErrorConn) Close() error {
	c.closes.Add(1)
	return nil
}

type serverBlockingDialErrorConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *serverBlockingDialErrorConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return nil
}
