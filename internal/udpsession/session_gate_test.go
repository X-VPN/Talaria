// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNewSessionGateRunsBeforeSessionAllocation(t *testing.T) {
	pc := &recordingPacketConn{}
	gate := &testNewSessionGate{}
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		NewSessionGate: gate,
		AcceptQueue:    1,
		SessionQueue:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if got := pc.lastWrite(); len(got) > 0 {
			if string(got) != "retry" {
				t.Fatalf("retry response = %q, want %q", got, "retry")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retry response was not written")
		}
		time.Sleep(time.Millisecond)
	}
	listener.mu.Lock()
	sessionCount := len(listener.sessions)
	listener.mu.Unlock()
	if sessionCount != 0 {
		t.Fatalf("sessions after challenge = %d, want 0", sessionCount)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := listener.Accept(ctx); err == nil {
		t.Fatal("Accept succeeded before the gate admitted a packet")
	}

	if err := listener.ReceivePacket([]byte("cookie:hello"), addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("admitted payload = %q, want %q", got, "hello")
	}

	if err := listener.ReceivePacket([]byte("second"), addr); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "second" {
		t.Fatalf("existing-session payload = %q, want %q", got, "second")
	}
	if gate.calls != 2 {
		t.Fatalf("gate calls = %d, want 2", gate.calls)
	}
}

func TestNewSessionReplyDoesNotBlockAdmissionOrSessionWrites(t *testing.T) {
	pc := newBlockingReplyPacketConn(1)
	listener, err := NewListener(NewListenerReq{
		PacketConn:             pc,
		ManualReceive:          true,
		NewSessionGate:         admissionReplyGate{},
		NewSessionReplyQueue:   2,
		NewSessionRepliesPerIP: 1,
		NewSessionReplyTimeout: 25 * time.Millisecond,
		AcceptQueue:            2,
		SessionQueue:           2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}
	if err := listener.ReceivePacket([]byte("admit"), firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	t.Cleanup(func() { _ = first.Close() })

	retryAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20002}
	replyStartedAt := time.Now()
	if err := listener.ReceivePacket([]byte("probe"), retryAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pc.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("new-session reply write did not start")
	}

	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 20003}
	if err := listener.ReceivePacket([]byte("admit"), secondAddr); err != nil {
		t.Fatal(err)
	}
	second := acceptTestSession(t, listener)
	t.Cleanup(func() { _ = second.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	writeDone := make(chan error, 1)
	go func() {
		_, err := first.WriteBatch(ctx, [][]byte{[]byte("session")}, []int{7})
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("established session write waited for new-session reply")
	}
	waitForReplyAccounting(t, listener, 0)
	deadlines := pc.writeDeadlines()
	if len(deadlines) == 0 || deadlines[0].IsZero() {
		t.Fatalf("new-session reply deadlines = %v", deadlines)
	}
	if deadlines[0].Before(replyStartedAt) || deadlines[0].After(replyStartedAt.Add(100*time.Millisecond)) {
		t.Fatalf("new-session reply deadline = %s", deadlines[0])
	}
	if pc.writeCount() != 2 {
		t.Fatalf("packet writes = %d, want 2", pc.writeCount())
	}
}

func TestNewSessionReplySkipsWriteWhenDeadlineIsUnsupported(t *testing.T) {
	want := errors.New("write deadlines unsupported")
	pc := newBlockingReplyPacketConn(0)
	pc.deadlineErr = want
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		NewSessionGate: &testNewSessionGate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	waitForReplyAccounting(t, listener, 0)
	if pc.writeCount() != 0 {
		t.Fatalf("WriteTo calls = %d, want 0", pc.writeCount())
	}
	if len(pc.writeDeadlines()) != 1 {
		t.Fatalf("write deadline attempts = %d, want 1", len(pc.writeDeadlines()))
	}
}

func TestNewSessionReplyContainsDeadlinePanic(t *testing.T) {
	pc := newBlockingReplyPacketConn(0)
	pc.deadlinePanic = true
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		NewSessionGate: &testNewSessionGate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	waitForReplyAccounting(t, listener, 0)
	if pc.writeCount() != 0 {
		t.Fatalf("WriteTo calls = %d, want 0", pc.writeCount())
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- listener.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener close blocked after deadline panic")
	}
}

func TestNewSessionReplyAllowsReentrantListenerClose(t *testing.T) {
	pc := newBlockingReplyPacketConn(1)
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		NewSessionGate: &testNewSessionGate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	reentered := make(chan struct{})
	pc.onWriteDeadline = func() {
		_ = listener.Close()
		close(reentered)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reentered:
	case <-time.After(time.Second):
		t.Fatal("reentrant listener close blocked reply writer")
	}
	select {
	case <-listener.replyDone:
	case <-time.After(time.Second):
		t.Fatal("reply writer did not exit after reentrant close")
	}
	waitForReplyAccounting(t, listener, 0)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewSessionReplyAllowsReentrantWriteStateAccess(t *testing.T) {
	pc := newBlockingReplyPacketConn(0)
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		NewSessionGate: &testNewSessionGate{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	reentered := make(chan struct{})
	pc.onWriteDeadline = func() {
		listener.writeStateMu.Lock()
		listener.writeStateMu.Unlock()
		close(reentered)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reentered:
	case <-time.After(time.Second):
		t.Fatal("reentrant write-state access blocked reply writer")
	}
	waitForReplyAccounting(t, listener, 0)
}

func TestListenerCloseDoesNotWaitForSessionWriteQueuedBehindReply(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	pc := newBlockingReplyPacketConn(0)
	listener, err := NewListener(NewListenerReq{
		PacketConn:    pc,
		ManualReceive: true,
		AcceptQueue:   1,
		SessionQueue:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("session"), addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)

	listener.writeMu.Lock()
	writeStarted := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		close(writeStarted)
		_, err := conn.Write([]byte("data"))
		writeDone <- err
	}()
	<-writeStarted
	runtime.Gosched()
	if !conn.writeMu.TryLock() {
		listener.writeMu.Unlock()
		t.Fatal("session writer held its connection lock while waiting for the reply writer")
	}
	conn.writeMu.Unlock()
	closeDone := make(chan error, 1)
	go func() { closeDone <- listener.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			listener.writeMu.Unlock()
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		listener.writeMu.Unlock()
		t.Fatal("listener close waited for a session writer queued behind the reply writer")
	}
	listener.writeMu.Unlock()
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued session write error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued session write did not exit after listener close")
	}
}

func TestNewSessionReplyLimitsAndCloseReleaseAccounting(t *testing.T) {
	pc := newBlockingReplyPacketConn(8)
	listener, err := NewListener(NewListenerReq{
		PacketConn:             pc,
		ManualReceive:          true,
		NewSessionGate:         &testNewSessionGate{},
		NewSessionReplyQueue:   2,
		NewSessionRepliesPerIP: 1,
		NewSessionReplyTimeout: time.Second,
		IPv6SourcePrefixBits:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
	addresses := []*net.UDPAddr{
		{IP: net.ParseIP("2001:db8:1:1::1"), Port: 20001},
		{IP: net.ParseIP("2001:db8:1:1::2"), Port: 20002},
		{IP: net.ParseIP("2001:db8:1:2::1"), Port: 20003},
		{IP: net.ParseIP("2001:db8:1:3::1"), Port: 20004},
	}
	if err := listener.ReceivePacket([]byte("probe"), addresses[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pc.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("new-session reply write did not start")
	}
	for _, addr := range addresses[1:] {
		if err := listener.ReceivePacket([]byte("probe"), addr); err != nil {
			t.Fatal(err)
		}
	}
	waitForReplyAccounting(t, listener, 2)
	listener.replyMu.Lock()
	pendingBytes := listener.replyPendingBytes
	sources := len(listener.repliesBySource)
	listener.replyMu.Unlock()
	if pendingBytes != 10 || sources != 2 {
		t.Fatalf("reply accounting bytes=%d sources=%d, want 10 and 2", pendingBytes, sources)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- listener.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener close waited for new-session reply")
	}
	waitForReplyAccounting(t, listener, 0)
	listener.replyMu.Lock()
	pendingBytes = listener.replyPendingBytes
	sources = len(listener.repliesBySource)
	listener.replyMu.Unlock()
	if pendingBytes != 0 || sources != 0 {
		t.Fatalf("closed reply accounting bytes=%d sources=%d", pendingBytes, sources)
	}
	if pc.writeCount() != 1 {
		t.Fatalf("packet writes = %d, want 1", pc.writeCount())
	}
}

func TestNewSessionReplyEnforcesByteLimit(t *testing.T) {
	pc := newBlockingReplyPacketConn(1)
	listener, err := NewListener(NewListenerReq{
		PacketConn:              pc,
		ManualReceive:           true,
		NewSessionGate:          &testNewSessionGate{},
		NewSessionReplyQueue:    2,
		NewSessionRepliesPerIP:  2,
		NewSessionReplyMaxBytes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket([]byte("first"), addr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pc.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("new-session reply write did not start")
	}
	if err := listener.ReceivePacket([]byte("second"), addr); err != nil {
		t.Fatal(err)
	}
	waitForReplyAccounting(t, listener, 1)
	listener.replyMu.Lock()
	pendingBytes := listener.replyPendingBytes
	listener.replyMu.Unlock()
	if pendingBytes != 5 {
		t.Fatalf("pending new-session reply bytes = %d, want 5", pendingBytes)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-listener.replyDone:
	case <-time.After(time.Second):
		t.Fatal("reply writer did not exit after close")
	}
	waitForReplyAccounting(t, listener, 0)
}

func TestReceivePacketRejectsOversizedInputBeforeSessionGate(t *testing.T) {
	gate := &testNewSessionGate{}
	listener, err := NewListener(NewListenerReq{
		PacketConn:     &recordingPacketConn{},
		ManualReceive:  true,
		NewSessionGate: gate,
		MaxPacket:      4,
		ReadBufferSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	if err := listener.ReceivePacket(make([]byte, 5), addr); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("ReceivePacket() error = %v, want ErrPacketTooLarge", err)
	}
	if gate.calls != 0 {
		t.Fatalf("new-session gate calls = %d, want 0", gate.calls)
	}
}

func TestNewSessionCommitRunsAfterCapacityChecks(t *testing.T) {
	commits := 0
	releases := 0
	gate := newSessionCommitGate{commit: func([]byte) (func(), bool) {
		commits++
		return func() { releases++ }, true
	}}
	listener, err := NewListener(NewListenerReq{
		PacketConn:             &recordingPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            2,
		SessionQueue:           2,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	firstAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}
	if err := listener.ReceivePacket([]byte("first"), firstAddr); err != nil {
		t.Fatal(err)
	}
	first := acceptTestSession(t, listener)
	if commits != 1 {
		t.Fatalf("commits = %d, want 1", commits)
	}
	if err := listener.ReceivePacket([]byte("same-source"), &net.UDPAddr{IP: firstAddr.IP, Port: 20002}); !errors.Is(err, ErrSourceSessionLimit) {
		t.Fatalf("same-source admission error = %v, want %v", err, ErrSourceSessionLimit)
	}
	if commits != 1 {
		t.Fatalf("commits after source rejection = %d, want 1", commits)
	}

	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20003}
	if err := listener.ReceivePacket([]byte("second"), secondAddr); err != nil {
		t.Fatal(err)
	}
	second := acceptTestSession(t, listener)
	if commits != 2 {
		t.Fatalf("commits = %d, want 2", commits)
	}
	if err := listener.ReceivePacket([]byte("global"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 20004}); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("global admission error = %v, want %v", err, ErrSessionLimit)
	}
	if commits != 2 {
		t.Fatalf("commits after global rejection = %d, want 2", commits)
	}
	_ = first.Close()
	_ = second.Close()
	if releases != 2 {
		t.Fatalf("releases = %d, want 2", releases)
	}
}

func TestFailedNewSessionCommitReleasesAdmission(t *testing.T) {
	commits := 0
	releases := 0
	gate := newSessionCommitGate{commit: func(packet []byte) (func(), bool) {
		commits++
		if string(packet) != "accept" {
			return nil, false
		}
		return func() { releases++ }, true
	}}
	listener, err := NewListener(NewListenerReq{
		PacketConn:             &recordingPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            1,
		SessionQueue:           2,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if err := listener.ReceivePacket([]byte("reject"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}); err != nil {
		t.Fatal(err)
	}
	listener.mu.Lock()
	sessions := len(listener.sessions)
	listener.mu.Unlock()
	if sessions != 0 || len(listener.acceptSlots) != 0 {
		t.Fatalf("failed commit retained sessions=%d slots=%d", sessions, len(listener.acceptSlots))
	}
	if err := listener.ReceivePacket([]byte("accept"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20002}); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	if commits != 2 {
		t.Fatalf("commits = %d, want 2", commits)
	}
	_ = conn.Close()
	if releases != 1 {
		t.Fatalf("releases = %d, want 1", releases)
	}
}

func TestNewSessionReleaseRunsOnFirstPacketDispatchFailure(t *testing.T) {
	releases := 0
	gate := newSessionCommitGate{commit: func([]byte) (func(), bool) {
		return func() { releases++ }, true
	}}
	listener, err := NewListener(NewListenerReq{
		PacketConn:                &recordingPacketConn{},
		ManualReceive:             true,
		NewSessionGate:            gate,
		AcceptQueue:               1,
		SessionQueue:              1,
		MaxQueuedBytes:            4,
		MaxQueuedBytesPerSourceIP: 2,
		MaxQueuedBytesPerSession:  1,
		MaxSessions:               2,
		MaxSessionsPerSourceIP:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	err = listener.ReceivePacket([]byte("too large"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001})
	if !errors.Is(err, ErrQueueMemoryLimit) {
		t.Fatalf("ReceivePacket() error = %v, want %v", err, ErrQueueMemoryLimit)
	}
	if releases != 1 {
		t.Fatalf("releases = %d, want 1", releases)
	}
	listener.mu.Lock()
	sessions := len(listener.sessions)
	listener.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("sessions = %d, want 0", sessions)
	}
}

func TestNewSessionReleaseRunsOnceOnListenerClose(t *testing.T) {
	releases := 0
	gate := newSessionCommitGate{commit: func([]byte) (func(), bool) {
		return func() { releases++ }, true
	}}
	listener, err := NewListener(NewListenerReq{
		PacketConn:             &recordingPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            1,
		SessionQueue:           1,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}
	if err := listener.ReceivePacket([]byte("accept"), addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if releases != 1 {
		t.Fatalf("releases = %d, want 1", releases)
	}
}

type testNewSessionGate struct {
	calls int
}

func (g *testNewSessionGate) EvaluateNewSession(packet []byte, _ net.Addr) NewSessionDecision {
	g.calls++
	if string(packet) == "cookie:hello" {
		return NewSessionDecision{Admit: true, Payload: []byte("hello")}
	}
	return NewSessionDecision{Reply: []byte("retry")}
}

type newSessionCommitGate struct {
	commit func([]byte) (func(), bool)
}

type admissionReplyGate struct{}

func (admissionReplyGate) EvaluateNewSession(packet []byte, _ net.Addr) NewSessionDecision {
	if string(packet) == "admit" {
		return NewSessionDecision{Admit: true, Payload: packet}
	}
	return NewSessionDecision{Reply: []byte("retry")}
}

func (g newSessionCommitGate) EvaluateNewSession(packet []byte, _ net.Addr) NewSessionDecision {
	payload := append([]byte(nil), packet...)
	return NewSessionDecision{
		Admit:   true,
		Payload: payload,
		Commit: func() (func(), bool) {
			return g.commit(payload)
		},
	}
}

type recordingPacketConn struct {
	mu     sync.Mutex
	writes [][]byte
}

type blockingReplyPacketConn struct {
	mu              sync.Mutex
	deadline        time.Time
	deadlines       []time.Time
	deadlineErr     error
	deadlinePanic   bool
	onWriteDeadline func()
	deadlineOnce    sync.Once
	writes          int
	blockWrites     int
	writeStarted    chan struct{}
	writeStartOnce  sync.Once
	closed          chan struct{}
	closeOnce       sync.Once
}

func newBlockingReplyPacketConn(blockWrites int) *blockingReplyPacketConn {
	return &blockingReplyPacketConn{
		blockWrites:  blockWrites,
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingReplyPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *blockingReplyPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	call := c.writes
	deadline := c.deadline
	block := call <= c.blockWrites
	c.mu.Unlock()
	if !block {
		return len(b), nil
	}
	c.writeStartOnce.Do(func() { close(c.writeStarted) })
	if deadline.IsZero() {
		<-c.closed
		return 0, net.ErrClosed
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-timer.C:
		return 0, timeoutError{}
	}
}

func (c *blockingReplyPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingReplyPacketConn) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (*blockingReplyPacketConn) SetDeadline(time.Time) error { return nil }
func (*blockingReplyPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *blockingReplyPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.deadlinePanic {
		c.mu.Unlock()
		panic("write deadline panic")
	}
	c.deadlines = append(c.deadlines, deadline)
	err := c.deadlineErr
	if err == nil {
		c.deadline = deadline
	}
	callback := c.onWriteDeadline
	c.mu.Unlock()
	if callback != nil {
		c.deadlineOnce.Do(callback)
	}
	return err
}

func (c *blockingReplyPacketConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *blockingReplyPacketConn) writeDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

func waitForReplyAccounting(t *testing.T, listener *Listener, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		listener.replyMu.Lock()
		pending := listener.replyPending
		listener.replyMu.Unlock()
		if pending == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending new-session replies = %d, want %d", pending, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (*recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *recordingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copyOfB := append([]byte(nil), b...)
	c.writes = append(c.writes, copyOfB)
	return len(b), nil
}

func (c *recordingPacketConn) lastWrite() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return nil
	}
	return append([]byte(nil), c.writes[len(c.writes)-1]...)
}

func (*recordingPacketConn) Close() error                     { return nil }
func (*recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
