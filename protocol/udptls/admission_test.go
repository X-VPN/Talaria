// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr {
	return c.remote
}

func TestNormalizeAdmissionLimitsUsesFiniteDefaults(t *testing.T) {
	limits, err := normalizeAdmissionLimits(AdmissionLimits{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if limits.AcceptQueue <= 0 || limits.SessionQueue <= 0 || limits.MaxSessions <= 0 ||
		limits.MaxSessionsPerSourceIP <= 0 || limits.MaxPendingHandshakes <= 0 ||
		limits.MaxPendingHandshakesPerSourceIP <= 0 ||
		limits.MaxQueuedBytes <= 0 || limits.MaxQueuedBytesPerSession <= 0 {
		t.Fatalf("admission defaults are not finite: %+v", limits)
	}
	if limits.SessionQueue != defaultSessionQueue || limits.MaxQueuedBytesPerSession != defaultMaxQueuedBytesPerSession {
		t.Fatalf("session queue defaults = %d packets/%d bytes, want %d/%d", limits.SessionQueue, limits.MaxQueuedBytesPerSession, defaultSessionQueue, defaultMaxQueuedBytesPerSession)
	}
}

func TestNormalizeAdmissionLimitsScalesSingleObjectDefaults(t *testing.T) {
	limits, err := normalizeAdmissionLimits(AdmissionLimits{
		SessionQueue:         sessionQueueMemoryBaseline,
		MaxSessions:          8,
		MaxPendingHandshakes: 8,
		MaxQueuedBytes:       8 << 20,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxSessionsPerSourceIP != 4 ||
		limits.MaxPendingHandshakesPerSourceIP != 4 ||
		limits.MaxQueuedBytesPerSourceIP != 4<<20 ||
		limits.MaxQueuedBytesPerSession != 4<<20 {
		t.Fatalf("scaled limits = %+v", limits)
	}
}

func TestNormalizeAdmissionLimitsScalesSessionQueueMemory(t *testing.T) {
	const maxQueueForDefaultSourceBudget = sessionQueueMemoryBaseline + int((defaultMaxQueuedBytes/2-baseMaxQueuedBytesPerSession)/queuedBytesPerAdditionalSessionPacket)
	limits, err := normalizeAdmissionLimits(AdmissionLimits{SessionQueue: maxQueueForDefaultSourceBudget}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxQueuedBytesPerSession != defaultMaxQueuedBytes/2 {
		t.Fatalf("session queued bytes = %d, want %d", limits.MaxQueuedBytesPerSession, defaultMaxQueuedBytes/2)
	}
	if _, err := normalizeAdmissionLimits(AdmissionLimits{SessionQueue: maxQueueForDefaultSourceBudget + 1}, 0); err == nil {
		t.Fatal("session queue exceeding the source byte budget was accepted")
	}
}

func TestNormalizeAdmissionLimitsScalesDependentHandshakeDefaults(t *testing.T) {
	limits, err := normalizeAdmissionLimits(AdmissionLimits{
		MaxSessions:            8,
		MaxSessionsPerSourceIP: 2,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxPendingHandshakes != 8 {
		t.Fatalf("global pending handshakes = %d, want 8", limits.MaxPendingHandshakes)
	}
	if limits.MaxPendingHandshakesPerSourceIP != 2 {
		t.Fatalf("source pending handshakes = %d, want 2", limits.MaxPendingHandshakesPerSourceIP)
	}
}

func TestListenerRejectsHandshakeImmediatelyWhenCapacityIsFull(t *testing.T) {
	listener := &Listener{
		handshakesBySource:     make(map[handshakeSourceKey]int),
		maxHandshakes:          1,
		maxHandshakesPerSource: 1,
		closeCh:                make(chan struct{}),
	}
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	if _, ok := listener.acquireHandshakeSlot(serverConn); !ok {
		t.Fatal("first handshake was rejected")
	}
	result := make(chan bool, 1)
	go func() {
		_, acquired := listener.acquireHandshakeSlot(serverConn)
		result <- acquired
	}()
	select {
	case acquired := <-result:
		if acquired {
			t.Fatal("handshake capacity was exceeded")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("full handshake admission blocked instead of rejecting")
	}
}

func TestServerHandshakeWorkersTimeoutAndDoNotDelayClose(t *testing.T) {
	listener := &Listener{
		handshakeWorkerSlots: make(chan struct{}, 2),
		closeCh:              make(chan struct{}),
	}
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	latePeers := make([]net.Conn, 0, 2)
	startBlocked := func(timeout time.Duration) <-chan error {
		base, basePeer := net.Pipe()
		late, latePeer := net.Pipe()
		t.Cleanup(func() {
			_ = basePeer.Close()
			_ = latePeer.Close()
		})
		latePeers = append(latePeers, latePeer)
		result := make(chan error, 1)
		go func() {
			_, err := listener.awaitServerHandshake(base, handshakeSourceKey{}, timeout, func() (net.Conn, error) {
				started <- struct{}{}
				<-release
				return late, nil
			})
			result <- err
		}()
		return result
	}

	first := startBlocked(20 * time.Millisecond)
	<-started
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked handshake error = %v, want deadline exceeded", err)
	}
	second := startBlocked(time.Second)
	<-started
	close(listener.closeCh)
	select {
	case err := <-second:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed handshake error = %v, want net.ErrClosed", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("listener close waited for certificate callback")
	}
	if got := len(listener.handshakeWorkerSlots); got != cap(listener.handshakeWorkerSlots) {
		t.Fatalf("handshake workers = %d, want hard limit %d", got, cap(listener.handshakeWorkerSlots))
	}
	third, thirdPeer := net.Pipe()
	defer thirdPeer.Close()
	if _, err := listener.awaitServerHandshake(third, handshakeSourceKey{}, time.Second, func() (net.Conn, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("handshake worker hard limit was exceeded")
	}

	close(release)
	deadline := time.Now().Add(time.Second)
	for len(listener.handshakeWorkerSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("late callbacks retained handshake worker slots")
		}
		time.Sleep(time.Millisecond)
	}
	for _, peer := range latePeers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("late handshake connection was not closed")
		}
	}
}

func TestHandshakeWorkerSourceLimitSurvivesOuterTimeout(t *testing.T) {
	listener := &Listener{
		handshakeWorkersBySource: make(map[handshakeSourceKey]int),
		maxHandshakesPerSource:   2,
		handshakeWorkerSlots:     make(chan struct{}, 4),
		closeCh:                  make(chan struct{}),
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	sourceA := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, 64)
	sourceB := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.ParseIP("192.0.2.2")}, 64)

	start := func(source handshakeSourceKey) error {
		base, peer := net.Pipe()
		defer peer.Close()
		_, err := listener.awaitServerHandshake(base, source, 10*time.Millisecond, func() (net.Conn, error) {
			<-release
			return nil, errors.New("released")
		})
		return err
	}
	for range listener.maxHandshakesPerSource {
		if err := start(sourceA); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("source A handshake error = %v, want deadline exceeded", err)
		}
	}
	if err := start(sourceA); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("source A overflow error = %v, want capacity error", err)
	}
	if err := start(sourceB); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("source B handshake error = %v, want deadline exceeded", err)
	}
	if got := len(listener.handshakeWorkerSlots); got != 3 {
		t.Fatalf("handshake workers = %d, want 3", got)
	}
	releaseAll()
	deadline := time.Now().Add(time.Second)
	for {
		listener.handshakeMu.Lock()
		workers := len(listener.handshakeWorkersBySource)
		listener.handshakeMu.Unlock()
		if len(listener.handshakeWorkerSlots) == 0 && workers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("handshake worker ownership was not released: slots=%d sources=%d", len(listener.handshakeWorkerSlots), workers)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHandshakeAdmissionLimitsEachSourceWithoutBlockingOthers(t *testing.T) {
	listener := &Listener{
		handshakesBySource:     make(map[handshakeSourceKey]int),
		maxHandshakes:          4,
		maxHandshakesPerSource: 2,
		closeCh:                make(chan struct{}),
	}

	acquire := func(addr *net.UDPAddr) (handshakeSourceKey, bool) {
		server, peer := net.Pipe()
		t.Cleanup(func() {
			_ = server.Close()
			_ = peer.Close()
		})
		return listener.acquireHandshakeSlot(remoteAddrConn{Conn: server, remote: addr})
	}

	sourceA1, ok := acquire(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001})
	if !ok {
		t.Fatal("source A first handshake was rejected")
	}
	sourceA2, ok := acquire(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1002})
	if !ok {
		t.Fatal("source A second handshake was rejected")
	}
	if sourceA1 != sourceA2 {
		t.Fatal("UDP ports created different source handshake buckets")
	}
	if _, ok := acquire(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1003}); ok {
		t.Fatal("source A exceeded its handshake limit")
	}
	sourceB, ok := acquire(&net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1001})
	if !ok {
		t.Fatal("source B did not retain a handshake slot")
	}

	listener.releaseHandshakeSlot(sourceA1)
	listener.releaseHandshakeSlot(sourceA2)
	listener.releaseHandshakeSlot(sourceB)
	if listener.handshakes != 0 || len(listener.handshakesBySource) != 0 {
		t.Fatalf("handshake counters were not cleared: total=%d sources=%d", listener.handshakes, len(listener.handshakesBySource))
	}
}

func TestHandshakeSourceKeyIncludesIPv6Zone(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	a := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: ip, Port: 1, Zone: "en0"}, 64)
	b := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: ip, Port: 2, Zone: "en0"}, 64)
	c := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: ip, Port: 1, Zone: "en1"}, 64)
	if a != b {
		t.Fatal("UDP port unexpectedly changed the IPv6 source key")
	}
	if a == c {
		t.Fatal("IPv6 zones unexpectedly shared a source key")
	}
}

func TestHandshakeSourceKeyAggregatesIPv6Prefix(t *testing.T) {
	a := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::1")}, 64)
	b := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::ffff")}, 64)
	c := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8:1:3::1")}, 64)
	if a != b {
		t.Fatal("addresses in one /64 used different handshake buckets")
	}
	if a == c {
		t.Fatal("addresses in different /64s shared a handshake bucket")
	}
}

func TestHandshakeAdmissionCountersRemainConsistentUnderConcurrency(t *testing.T) {
	const attempts = 64
	listener := &Listener{
		handshakesBySource:     make(map[handshakeSourceKey]int),
		maxHandshakes:          attempts,
		maxHandshakesPerSource: attempts / 2,
		closeCh:                make(chan struct{}),
	}
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			server, peer := net.Pipe()
			defer peer.Close()
			source, ok := listener.acquireHandshakeSlot(remoteAddrConn{
				Conn:   server,
				remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port},
			})
			if ok {
				listener.releaseHandshakeSlot(source)
				_ = server.Close()
			}
		}(i + 1)
	}
	wg.Wait()
	if listener.handshakes != 0 || len(listener.handshakesBySource) != 0 {
		t.Fatalf("concurrent handshake counters leaked: total=%d sources=%d", listener.handshakes, len(listener.handshakesBySource))
	}
}

func TestNormalizeAdmissionLimitsRejectsUnsafeHandshakeRelationships(t *testing.T) {
	tests := []struct {
		name   string
		limits AdmissionLimits
		match  string
	}{
		{
			name: "source sessions can exhaust global",
			limits: AdmissionLimits{
				MaxSessions:            8,
				MaxSessionsPerSourceIP: 8,
			},
			match: "less than global",
		},
		{
			name: "source can exhaust global",
			limits: AdmissionLimits{
				MaxPendingHandshakes:            8,
				MaxPendingHandshakesPerSourceIP: 8,
			},
			match: "less than global",
		},
		{
			name: "handshakes exceed sessions",
			limits: AdmissionLimits{
				MaxSessions:                     4,
				MaxPendingHandshakes:            8,
				MaxPendingHandshakesPerSourceIP: 2,
			},
			match: "cannot exceed session limit",
		},
		{
			name: "source handshakes exceed source sessions",
			limits: AdmissionLimits{
				MaxSessionsPerSourceIP:          2,
				MaxPendingHandshakes:            8,
				MaxPendingHandshakesPerSourceIP: 4,
			},
			match: "cannot exceed source session limit",
		},
		{
			name: "session bytes can exhaust global",
			limits: AdmissionLimits{
				MaxQueuedBytes:           8 << 20,
				MaxQueuedBytesPerSession: 8 << 20,
			},
			match: "less than global",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeAdmissionLimits(test.limits, 0)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("normalizeAdmissionLimits() error = %v, want containing %q", err, test.match)
			}
		})
	}
}
