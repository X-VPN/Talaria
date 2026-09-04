// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestListenerEnforcesAndReleasesSessionLimits(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:              3,
		SessionQueue:             2,
		MaxSessions:              2,
		MaxSessionsPerSourceIP:   1,
		MaxQueuedBytes:           2 << 20,
		MaxQueuedBytesPerSession: 1 << 20,
	})
	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 10002}
	thirdAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 10003}
	if err := listener.ReceivePacket([]byte{1}, firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{2}, secondAddr); err != nil {
		t.Fatal(err)
	}
	second := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{3}, thirdAddr); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("third source error = %v, want ErrSessionLimit", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.ReceivePacket([]byte{4}, thirdAddr); err != nil {
		t.Fatalf("receive after releasing first session: %v", err)
	}
	third := acceptTestSession(t, listener)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerEnforcesPerSourceSessionLimit(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:              2,
		SessionQueue:             2,
		MaxSessions:              2,
		MaxSessionsPerSourceIP:   1,
		MaxQueuedBytes:           2 << 20,
		MaxQueuedBytesPerSession: 1 << 20,
	})
	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10002}
	if err := listener.ReceivePacket([]byte{1}, firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{2}, secondAddr); !errors.Is(err, ErrSourceSessionLimit) {
		t.Fatalf("second port error = %v, want ErrSourceSessionLimit", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestListenerAggregatesIPv6SourcesByPrefix(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:              3,
		SessionQueue:             2,
		MaxSessions:              3,
		MaxSessionsPerSourceIP:   1,
		MaxQueuedBytes:           3 << 20,
		MaxQueuedBytesPerSession: 1 << 20,
		IPv6SourcePrefixBits:     64,
	})
	firstAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 10001}
	samePrefix := &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::2"), Port: 10002}
	otherPrefix := &net.UDPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 10003}
	if err := listener.ReceivePacket([]byte{1}, firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{2}, samePrefix); !errors.Is(err, ErrSourceSessionLimit) {
		t.Fatalf("same-prefix error = %v, want ErrSourceSessionLimit", err)
	}
	if err := listener.ReceivePacket([]byte{3}, otherPrefix); err != nil {
		t.Fatalf("different prefix was rejected: %v", err)
	}
	second := acceptTestSession(t, listener)
	_ = first.Close()
	_ = second.Close()
}

func TestListenerRejectsNewSessionWhenAcceptQueueIsFull(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:              1,
		SessionQueue:             2,
		MaxSessions:              3,
		MaxSessionsPerSourceIP:   2,
		MaxQueuedBytes:           2 << 20,
		MaxQueuedBytesPerSession: 1 << 20,
	})
	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 10002}
	if err := listener.ReceivePacket([]byte{1}, firstAddr); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := listener.ReceivePacket([]byte{2}, secondAddr); !errors.Is(err, ErrAcceptQueueFull) {
		t.Fatalf("second source error = %v, want ErrAcceptQueueFull", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("full accept queue blocked for %s", elapsed)
	}
	first := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{3}, secondAddr); err != nil {
		t.Fatalf("retry after draining accept queue: %v", err)
	}
	second := acceptTestSession(t, listener)
	_ = first.Close()
	_ = second.Close()
}

func TestListenerBoundsQueuedBytesByRetainedBufferSize(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:              1,
		SessionQueue:             4,
		MaxPacket:                16,
		ReadBufferSize:           16,
		MaxSessions:              2,
		MaxSessionsPerSourceIP:   1,
		MaxQueuedBytes:           32,
		MaxQueuedBytesPerSession: 16,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{2}, addr); !errors.Is(err, ErrQueueMemoryLimit) {
		t.Fatalf("second packet error = %v, want ErrQueueMemoryLimit", err)
	}
	if got := conn.DroppedPackets(); got != 1 {
		t.Fatalf("dropped packets = %d, want 1", got)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := listener.ReceivePacket([]byte{3}, addr); err != nil {
		t.Fatalf("receive after releasing queued bytes: %v", err)
	}
	_ = conn.Close()
}

func TestExistingSessionDropsPacketAboveMaxPacket(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:    1,
		SessionQueue:   2,
		MaxPacket:      4,
		ReadBufferSize: 8,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := listener.ReceivePacket([]byte{1, 2, 3, 4, 5}, addr); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("oversized packet result = %v, want ErrPacketTooLarge", err)
	}
	if conn.isClosed() {
		t.Fatal("oversized packet closed the existing session")
	}
	if got := conn.DroppedPackets(); got != 1 {
		t.Fatalf("dropped packets = %d, want 1", got)
	}
	if err := listener.ReceivePacket([]byte{2}, addr); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || buf[0] != 2 {
		t.Fatalf("packet after oversized drop = %v, want [2]", buf[:n])
	}
}

func TestDeferredInboundActivityRequiresExplicitCommit(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:          1,
		SessionQueue:         2,
		MaxPacket:            4,
		ReadBufferSize:       4,
		DeferInboundActivity: true,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 20002}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	before := conn.lastActive.Load()
	if err := listener.ReceivePacket([]byte{2}, addr); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if got := conn.lastActive.Load(); got != before {
		t.Fatalf("uncommitted inbound packet refreshed activity: %d -> %d", before, got)
	}
	// Windows may return the same wall-clock timestamp for adjacent calls.
	deadline := time.Now().Add(time.Second)
	for time.Now().UnixNano() <= before {
		if time.Now().After(deadline) {
			t.Fatal("wall clock did not advance before explicit activity commit")
		}
		time.Sleep(time.Millisecond)
	}
	conn.MarkActive()
	if got := conn.lastActive.Load(); got <= before {
		t.Fatalf("explicit activity commit did not advance timestamp: %d -> %d", before, got)
	}
}

func TestListenerCompactsQueuedReadBuffersWhenRequested(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:               1,
		SessionQueue:              4,
		MaxPacket:                 16,
		ReadBufferSize:            16,
		MaxSessions:               2,
		MaxSessionsPerSourceIP:    1,
		MaxQueuedBytes:            64,
		MaxQueuedBytesPerSourceIP: 32,
		MaxQueuedBytesPerSession:  32,
		CompactReadBuffers:        true,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	if got := conn.queuedBytes.Load(); got != 1 {
		t.Fatalf("compacted queued bytes = %d, want 1", got)
	}

	conn.SetCompactReadBuffers(false)
	if err := listener.ReceivePacket([]byte{2}, addr); err != nil {
		t.Fatal(err)
	}
	if got := conn.queuedBytes.Load(); got != 17 {
		t.Fatalf("queued bytes after disabling compaction = %d, want 17", got)
	}
	_ = conn.Close()
}

func TestListenerBoundsQueuedBytesAcrossSessions(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:               3,
		SessionQueue:              2,
		MaxPacket:                 16,
		ReadBufferSize:            16,
		MaxSessions:               3,
		MaxSessionsPerSourceIP:    1,
		MaxQueuedBytes:            32,
		MaxQueuedBytesPerSourceIP: 16,
		MaxQueuedBytesPerSession:  16,
	})
	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 10002}
	thirdAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 10003}
	if err := listener.ReceivePacket([]byte{1}, firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{2}, secondAddr); err != nil {
		t.Fatal(err)
	}
	second := acceptTestSession(t, listener)
	if err := listener.ReceivePacket([]byte{3}, thirdAddr); !errors.Is(err, ErrQueueMemoryLimit) {
		t.Fatalf("third session error = %v, want ErrQueueMemoryLimit", err)
	}
	if got := listener.queuedBytes.Load(); got != 32 {
		t.Fatalf("global queued bytes = %d, want 32", got)
	}
	buf := make([]byte, 16)
	if _, err := first.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := listener.ReceivePacket([]byte{4}, thirdAddr); err != nil {
		t.Fatalf("retry after releasing global queued bytes: %v", err)
	}
	third := acceptTestSession(t, listener)
	_ = first.Close()
	_ = second.Close()
	_ = third.Close()
}

func TestListenerScalesAndValidatesSingleObjectLimits(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		MaxSessions:    8,
		MaxQueuedBytes: 8 << 20,
	})
	if listener.maxSessionsPerSourceIP != 4 ||
		listener.maxQueuedBytesPerSourceIP != 4<<20 ||
		listener.maxQueuedBytesPerSession != 4<<20 {
		t.Fatalf("scaled limits = sessions %d/%d, bytes %d/%d/%d",
			listener.maxSessions,
			listener.maxSessionsPerSourceIP,
			listener.maxQueuedBytes,
			listener.maxQueuedBytesPerSourceIP,
			listener.maxQueuedBytesPerSession,
		)
	}
	if _, err := NewListener(NewListenerReq{
		MaxSessions:            8,
		MaxSessionsPerSourceIP: 8,
	}); err == nil {
		t.Fatal("source session limit equal to global limit was accepted")
	}
	if _, err := NewListener(NewListenerReq{
		MaxQueuedBytes:           8 << 20,
		MaxQueuedBytesPerSession: 8 << 20,
	}); err == nil {
		t.Fatal("session byte limit equal to global limit was accepted")
	}
	if _, err := NewListener(NewListenerReq{
		ReadBufferSize: 4,
		MaxPacket:      5,
	}); err == nil {
		t.Fatal("read buffer smaller than max packet was accepted")
	}
}

func newManualTestListener(t *testing.T, req NewListenerReq) *Listener {
	t.Helper()
	pc := &manualPacketConn{}
	req.PacketConn = pc
	req.ManualReceive = true
	listener, err := NewListener(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func acceptTestSession(t *testing.T, listener *Listener) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

type manualPacketConn struct{}

func (*manualPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (*manualPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (*manualPacketConn) Close() error                     { return nil }
func (*manualPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*manualPacketConn) SetDeadline(time.Time) error      { return nil }
func (*manualPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*manualPacketConn) SetWriteDeadline(time.Time) error { return nil }
