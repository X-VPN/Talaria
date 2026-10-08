// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

func TestListenerPersistentReadErrorBacksOffAndWakesAccept(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		reads int32
	}{
		{name: "plain", err: errors.New("synthetic persistent read failure"), reads: readErrorLimit},
		{name: "legacy temporary", err: legacyTemporaryReadError{}, reads: readErrorLimit},
		{name: "closed", err: net.ErrClosed, reads: 1},
		{name: "closed and timeout", err: errors.Join(net.ErrClosed, os.ErrDeadlineExceeded), reads: 1},
		{name: "extension panic", err: extension.ErrPanic, reads: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &persistentReadErrorPacketConn{err: tt.err}
			listener, err := NewListener(NewListenerReq{PacketConn: pc})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := listener.Accept(ctx); !errors.Is(err, tt.err) {
				t.Fatalf("Accept() error = %v want %v", err, tt.err)
			}
			if got := pc.reads.Load(); got != tt.reads {
				t.Fatalf("packet reads = %d want %d", got, tt.reads)
			}
			if elapsed := time.Since(start); tt.reads > 1 && elapsed < readErrorInitialBackoff {
				t.Fatalf("persistent read failures spun without backoff: %s", elapsed)
			}
			deadline := time.Now().Add(time.Second)
			for !pc.closed.Load() && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if !pc.closed.Load() {
				t.Fatal("terminal read error did not close packet connection")
			}
		})
	}
}

func TestListenerRecoversReadTimeout(t *testing.T) {
	testListenerRecoversReadError(t, os.ErrDeadlineExceeded)
}

func testListenerRecoversReadError(t *testing.T, readErr error) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		pc := &scriptedReadErrorPacketConn{
			reentrantClosePacketConn: reentrantClosePacketConn{closed: make(chan struct{})},
			packets:                  make(chan scriptedReadResult, 16),
		}
		listener, err := NewListener(NewListenerReq{PacketConn: pc})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 10001}
		pc.packets <- scriptedReadResult{data: "before", addr: peer}
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "before" {
			t.Fatalf("initial read = %q, %v", buf[:n], err)
		}
		unknown := errors.New("unclassified read failure")
		wrapped := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", readErr)}
		// Recoverable errors must neither consume nor inherit the unknown
		// error budget. Even partial data returned with an error is discarded.
		for _, err := range []error{unknown, unknown, wrapped, wrapped, wrapped, wrapped, unknown, unknown} {
			pc.packets <- scriptedReadResult{data: "partial", addr: peer, err: err}
		}
		pc.packets <- scriptedReadResult{data: "after", addr: peer}
		if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "after" {
			t.Fatalf("existing session after read errors = %q, %v", buf[:n], err)
		}
		// A successful read must also reset the unknown error budget.
		pc.packets <- scriptedReadResult{err: unknown}
		pc.packets <- scriptedReadResult{err: unknown}
		pc.packets <- scriptedReadResult{data: "new", addr: &net.UDPAddr{IP: peer.IP, Port: 10002}}
		next, err := listener.Accept(ctx)
		if err != nil {
			t.Fatalf("new session after read errors: %v", err)
		}
		if n, err := next.Read(buf); err != nil || string(buf[:n]) != "new" {
			t.Fatalf("new session read = %q, %v", buf[:n], err)
		}
	})
}

func TestListenerReadErrorBackoffAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		listener, err := NewListener(NewListenerReq{
			PacketConn: &reentrantClosePacketConn{closed: make(chan struct{})}, ManualReceive: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		state := readErrorState{failures: readErrorLimit - 1}
		for _, delay := range []time.Duration{10, 20, 40, 80, 160, 320, 640, 1000, 1000} {
			start := time.Now()
			if !listener.handleReadError(os.ErrDeadlineExceeded, &state) {
				t.Fatal("timeout terminated listener")
			}
			if elapsed := time.Since(start); elapsed != delay*time.Millisecond {
				t.Fatalf("backoff = %s want %s", elapsed, delay*time.Millisecond)
			}
			if state.failures != 0 {
				t.Fatal("timeout retained unknown failure count")
			}
		}
		done := make(chan bool, 1)
		go func() { done <- listener.handleReadError(os.ErrDeadlineExceeded, &state) }()
		synctest.Wait()
		start := time.Now()
		_ = listener.Close()
		if <-done || time.Since(start) != 0 {
			t.Fatal("Close did not immediately interrupt read backoff")
		}
	})
}

type scriptedReadResult struct {
	data string
	addr net.Addr
	err  error
}

type scriptedReadErrorPacketConn struct {
	reentrantClosePacketConn
	packets chan scriptedReadResult
}

func (c *scriptedReadErrorPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case result := <-c.packets:
		return copy(p, result.data), result.addr, result.err
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func TestListenerRejectsInvalidReadFromResults(t *testing.T) {
	tests := []struct {
		name string
		n    int
		addr net.Addr
	}{
		{name: "negative count", n: -1, addr: &net.UDPAddr{}},
		{name: "oversized count", n: defaultReadBufSize + 1, addr: &net.UDPAddr{}},
		{name: "nil address", n: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &invalidReadPacketConn{n: tt.n, addr: tt.addr}
			listener, err := NewListener(NewListenerReq{PacketConn: pc})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := listener.Accept(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Accept() error = %v, want invalid read result", err)
			}
		})
	}
}

func TestListenerCloseAllowsReentrantPacketConnClose(t *testing.T) {
	pc := &reentrantClosePacketConn{closed: make(chan struct{})}
	listener, err := NewListener(NewListenerReq{PacketConn: pc})
	if err != nil {
		t.Fatal(err)
	}
	pc.onClose = func() { _ = listener.Close() }
	done := make(chan error, 1)
	go func() { done <- listener.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reentrant packet connection close deadlocked listener close")
	}
}

func TestListenerCloseContainsPacketConnPanic(t *testing.T) {
	pc := &reentrantClosePacketConn{closed: make(chan struct{}), panicClose: true}
	listener, err := NewListener(NewListenerReq{PacketConn: pc})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Close() error = %v, want extension panic", err)
	}
	if err := listener.Close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("second Close() error = %v, want retained extension panic", err)
	}
}

func TestNewListenerRejectsTypedNilPacketConn(t *testing.T) {
	var pc *net.UDPConn
	listener, err := NewListener(NewListenerReq{PacketConn: pc})
	if listener != nil {
		_ = listener.Close()
	}
	if err == nil {
		t.Fatal("NewListener accepted a typed-nil packet connection")
	}
}

func TestNewListenerClosesPacketConnReturnedWithError(t *testing.T) {
	pc := &reentrantClosePacketConn{closed: make(chan struct{})}
	want := errors.New("synthetic listen failure")
	listener, err := NewListener(NewListenerReq{
		ListenPacket: func(string, string) (net.PacketConn, error) {
			return pc, want
		},
	})
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, want) {
		t.Fatalf("NewListener() error = %v, want %v", err, want)
	}
	select {
	case <-pc.closed:
	default:
		t.Fatal("packet connection returned with an error was not closed")
	}
}

type legacyTemporaryReadError struct{}

func (legacyTemporaryReadError) Error() string { return "synthetic temporary read failure" }
func (legacyTemporaryReadError) Timeout() bool { return false }
func (legacyTemporaryReadError) Temporary() bool {
	panic("deprecated Temporary method was called")
}

type persistentReadErrorPacketConn struct {
	err    error
	reads  atomic.Int32
	closed atomic.Bool
}

type invalidReadPacketConn struct {
	n      int
	addr   net.Addr
	closed atomic.Bool
}

func (c *invalidReadPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return c.n, c.addr, nil
}

func (*invalidReadPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *invalidReadPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (*invalidReadPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*invalidReadPacketConn) SetDeadline(time.Time) error      { return nil }
func (*invalidReadPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*invalidReadPacketConn) SetWriteDeadline(time.Time) error { return nil }

type reentrantClosePacketConn struct {
	closed     chan struct{}
	closeOnce  sync.Once
	onClose    func()
	panicClose bool
}

func (c *reentrantClosePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (*reentrantClosePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *reentrantClosePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	if c.onClose != nil {
		c.onClose()
	}
	if c.panicClose {
		panic("close panic")
	}
	return nil
}

func (*reentrantClosePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*reentrantClosePacketConn) SetDeadline(time.Time) error      { return nil }
func (*reentrantClosePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*reentrantClosePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *persistentReadErrorPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.reads.Add(1)
	return 0, nil, c.err
}

func (*persistentReadErrorPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *persistentReadErrorPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (*persistentReadErrorPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*persistentReadErrorPacketConn) SetDeadline(time.Time) error      { return nil }
func (*persistentReadErrorPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*persistentReadErrorPacketConn) SetWriteDeadline(time.Time) error { return nil }
