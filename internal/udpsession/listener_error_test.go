// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

func TestListenerPersistentReadErrorBacksOffAndWakesAccept(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "plain", err: errors.New("synthetic persistent read failure")},
		{name: "legacy temporary", err: legacyTemporaryReadError{}},
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
			if got := pc.reads.Load(); got != readErrorLimit {
				t.Fatalf("packet reads = %d want %d", got, readErrorLimit)
			}
			if elapsed := time.Since(start); elapsed < readErrorInitialBackoff {
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
