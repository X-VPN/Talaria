// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnSerializesWritesAndRejectsWritesAfterClose(t *testing.T) {
	pc := &blockingWritePacketConn{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(pc.release) }) }
	defer releaseFirst()
	listener, conn := newWriteTestSession(t, pc)

	first := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte{1})
		first <- err
	}()
	select {
	case <-pc.entered:
	case <-time.After(time.Second):
		t.Fatal("first write did not reach the packet connection")
	}

	second := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte{2})
		second <- err
	}()
	select {
	case <-pc.entered:
		t.Fatal("concurrent write reached per-connection write state")
	case <-time.After(20 * time.Millisecond):
	}

	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the active write finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseFirst()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queued write after Close = %v, want net.ErrClosed", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{3}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close = %v, want net.ErrClosed", err)
	}
	if got := pc.writes.Load(); got != 1 {
		t.Fatalf("packet connection writes = %d, want 1", got)
	}
	_ = listener.Close()
}

func TestConnWriteDeadlineSerializesSharedPacketConnDeadline(t *testing.T) {
	pc := &deadlineTrackingPacketConn{}
	_, conn := newWriteTestSession(t, pc)
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if got := pc.deadlineCalls.Load(); got != 2 {
		t.Fatalf("shared packet connection deadline calls = %d, want 2", got)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{2}); err == nil {
		t.Fatal("expired logical write deadline was ignored")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expired logical write deadline = %v, want timeout", err)
	}
	if got := pc.writes.Load(); got != 1 {
		t.Fatalf("packet connection writes = %d, want 1", got)
	}
}

func TestConnWriteDeadlineInterruptsOnlyItsBlockedWrite(t *testing.T) {
	pc := &deadlineBlockingPacketConn{
		entered:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
	listener, first := newWriteTestSession(t, pc)
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20002}
	if err := listener.ReceivePacket([]byte{1}, secondAddr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := first.Write([]byte{1})
		writeDone <- err
	}()
	select {
	case <-pc.entered:
	case <-time.After(time.Second):
		t.Fatal("write did not block in packet connection")
	}

	if err := second.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pc.interrupted:
		t.Fatal("another session's deadline interrupted the active write")
	case <-time.After(20 * time.Millisecond):
	}
	if err := first.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeDone:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("interrupted write error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not interrupt blocked write")
	}
}

func TestConnCloseInterruptsBlockedWrite(t *testing.T) {
	pc := &deadlineBlockingPacketConn{
		entered:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
	_, conn := newWriteTestSession(t, pc)
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte{1})
		writeDone <- err
	}()
	select {
	case <-pc.entered:
	case <-time.After(time.Second):
		t.Fatal("write did not block in packet connection")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt blocked write")
	}
	if err := <-writeDone; err == nil {
		t.Fatal("interrupted write returned no error")
	}
}

func TestConnWriteContextCancellationInterruptsBlockedWrite(t *testing.T) {
	pc := &deadlineBlockingPacketConn{
		entered:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
	_, conn := newWriteTestSession(t, pc)
	ctx, cancel := context.WithCancel(context.Background())
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteBatch(ctx, [][]byte{{1}}, []int{1})
		writeDone <- err
	}()
	select {
	case <-pc.entered:
	case <-time.After(time.Second):
		t.Fatal("write did not block in packet connection")
	}
	cancel()
	select {
	case err := <-writeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled write error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt blocked write")
	}
}

func TestListenerCloseInterruptsActiveAndQueuedWrites(t *testing.T) {
	pc := &deadlineBlockingPacketConn{
		entered:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
	listener, first := newWriteTestSession(t, pc)
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20002}
	if err := listener.ReceivePacket([]byte{1}, secondAddr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	writesDone := make(chan error, 2)
	go func() {
		_, err := first.Write([]byte{1})
		writesDone <- err
	}()
	select {
	case <-pc.entered:
	case <-time.After(time.Second):
		t.Fatal("first write did not block in packet connection")
	}
	go func() {
		_, err := second.Write([]byte{2})
		writesDone <- err
	}()

	closeDone := make(chan error, 1)
	go func() { closeDone <- listener.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener Close did not interrupt active and queued writes")
	}
	for range 2 {
		if err := <-writesDone; err == nil {
			t.Fatal("write completed successfully after listener close")
		}
	}
}

func TestSessionWriteDoesNotHoldSharedWriterWhileConnectionIsBusy(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	pc := newBlockingReplyPacketConn(0)
	listener, first := newWriteTestSession(t, pc)
	secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 20002}
	if err := listener.ReceivePacket([]byte{1}, secondAddr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}

	first.writeMu.Lock()
	firstUnlocked := false
	defer func() {
		if !firstUnlocked {
			first.writeMu.Unlock()
		}
	}()
	firstStarted := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		close(firstStarted)
		_, err := first.Write([]byte{1})
		firstDone <- err
	}()
	<-firstStarted
	runtime.Gosched()
	if _, err := second.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	first.writeMu.Unlock()
	firstUnlocked = true
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("busy session write did not resume")
	}
}

func TestConnNonBatchWriteRejectsPacketAboveMaxPacket(t *testing.T) {
	pc := &deadlineTrackingPacketConn{}
	listener, err := NewListener(NewListenerReq{
		PacketConn:     pc,
		ManualReceive:  true,
		AcceptQueue:    1,
		SessionQueue:   1,
		ReadBufferSize: 4,
		MaxPacket:      4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(make([]byte, 5)); err == nil {
		t.Fatal("non-batch write accepted oversized packet")
	}
	if got := pc.writes.Load(); got != 0 {
		t.Fatalf("packet connection writes = %d want 0", got)
	}
}

func TestConnNonBatchWriteRejectsShortWrites(t *testing.T) {
	pc := &shortWritePacketConn{}
	_, conn := newWriteTestSession(t, pc)
	if n, err := conn.Write([]byte{1, 2}); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
}

func newWriteTestSession(t *testing.T, pc net.PacketConn) (*Listener, *Conn) {
	t.Helper()
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
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 20001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return listener, conn
}

type blockingWritePacketConn struct {
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int32
}

func (*blockingWritePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *blockingWritePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.writes.Add(1) == 1 {
		c.entered <- struct{}{}
		<-c.release
	} else {
		c.entered <- struct{}{}
	}
	return len(b), nil
}

func (*blockingWritePacketConn) Close() error                     { return nil }
func (*blockingWritePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*blockingWritePacketConn) SetDeadline(time.Time) error      { return nil }
func (*blockingWritePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingWritePacketConn) SetWriteDeadline(time.Time) error { return nil }

type deadlineTrackingPacketConn struct {
	writes        atomic.Int32
	deadlineCalls atomic.Int32
}

type shortWritePacketConn struct {
	deadlineTrackingPacketConn
}

func (*shortWritePacketConn) WriteTo([]byte, net.Addr) (int, error) { return 1, nil }

type deadlineBlockingPacketConn struct {
	entered       chan struct{}
	interrupted   chan struct{}
	interruptOnce sync.Once
}

func (*deadlineBlockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *deadlineBlockingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	close(c.entered)
	<-c.interrupted
	return 0, timeoutError{}
}

func (c *deadlineBlockingPacketConn) Close() error {
	c.interruptOnce.Do(func() { close(c.interrupted) })
	return nil
}

func (*deadlineBlockingPacketConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (*deadlineBlockingPacketConn) SetDeadline(time.Time) error     { return nil }
func (*deadlineBlockingPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *deadlineBlockingPacketConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		c.interruptOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}

func (*deadlineTrackingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *deadlineTrackingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writes.Add(1)
	return len(b), nil
}

func (*deadlineTrackingPacketConn) Close() error                    { return nil }
func (*deadlineTrackingPacketConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (*deadlineTrackingPacketConn) SetDeadline(time.Time) error     { return nil }
func (*deadlineTrackingPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *deadlineTrackingPacketConn) SetWriteDeadline(time.Time) error {
	c.deadlineCalls.Add(1)
	return nil
}
