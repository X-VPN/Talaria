// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package netdial

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/lifecycle"
)

type observedCloseConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *observedCloseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestWrapTimeoutClosesLateDialResult(t *testing.T) {
	releaseDial := make(chan struct{})
	created := make(chan *observedCloseConn, 1)
	wrapped := WrapTimeout(WrapTimeoutReq{
		Timeout: 20 * time.Millisecond,
		Dial: func(string, string) (net.Conn, error) {
			<-releaseDial
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			observed := &observedCloseConn{Conn: conn, closed: make(chan struct{})}
			created <- observed
			return observed, nil
		},
	})

	if conn, err := wrapped("tcp", "example.invalid:443"); err == nil {
		_ = conn.Close()
		t.Fatal("late dial did not time out")
	}
	close(releaseDial)
	late := <-created
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("late dial connection was not closed")
	}
}

func TestWrapTimeoutRejectsNilSuccessfulConnection(t *testing.T) {
	closer := lifecycle.NewCloser()
	wrapped := WrapTimeout(WrapTimeoutReq{
		Closer: closer,
		Dial: func(string, string) (net.Conn, error) {
			return nil, nil
		},
	})
	conn, err := wrapped("tcp", "example.invalid:443")
	if conn != nil || err == nil || !strings.Contains(err.Error(), "nil connection") {
		t.Fatalf("dial result = %v, %v; want nil connection error", conn, err)
	}
	closer.Close()
}

func TestWrapTimeoutRejectsTypedNilSuccessfulConnection(t *testing.T) {
	wrapped := WrapTimeout(WrapTimeoutReq{
		Dial: func(string, string) (net.Conn, error) {
			var conn *net.TCPConn
			return conn, nil
		},
	})
	conn, err := wrapped("tcp", "example.invalid:443")
	if conn != nil || err == nil || !strings.Contains(err.Error(), "nil connection") {
		t.Fatalf("dial result = %v, %v; want typed-nil connection error", conn, err)
	}
}

func TestWrapTimeoutContainsDialerPanic(t *testing.T) {
	wrapped := WrapTimeout(WrapTimeoutReq{
		Dial: func(string, string) (net.Conn, error) { panic("boom") },
	})
	if conn, err := wrapped("tcp", "example.invalid:443"); conn != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("dial result = %v, %v; want extension panic", conn, err)
	}
}

func TestWrapTimeoutContainsLifecyclePanic(t *testing.T) {
	wrapped := WrapTimeout(WrapTimeoutReq{
		Closer: panicLifecycleCloser{},
		Dial:   func(string, string) (net.Conn, error) { return nil, nil },
	})
	if conn, err := wrapped("tcp", "example.invalid:443"); conn != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("dial result = %v, %v; want extension panic", conn, err)
	}
}

type panicLifecycleCloser struct{}

func (panicLifecycleCloser) IsClose() bool                 { panic("boom") }
func (panicLifecycleCloser) GetCloseChan() <-chan struct{} { panic("boom") }
func (panicLifecycleCloser) AddOnClose(func()) func()      { panic("boom") }

func TestWrapTimeoutCanLeaveSuccessfulResultUnregistered(t *testing.T) {
	closer := lifecycle.NewCloser()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	observed := &observedCloseConn{Conn: conn, closed: make(chan struct{})}
	wrapper := WrapTimeout(WrapTimeoutReq{
		Closer:              closer,
		DoNotRegisterResult: true,
		Dial: func(string, string) (net.Conn, error) {
			return observed, nil
		},
	})

	got, err := wrapper("tcp", "example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	closer.Close()
	select {
	case <-observed.closed:
		t.Fatal("successful unregistered dial result was closed by the lifecycle group")
	default:
	}
	if err := got.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWrapTimeoutRegistersSuccessfulResultByDefault(t *testing.T) {
	closer := lifecycle.NewCloser()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	observed := &observedCloseConn{Conn: conn, closed: make(chan struct{})}
	wrapper := WrapTimeout(WrapTimeoutReq{
		Closer: closer,
		Dial: func(string, string) (net.Conn, error) {
			return observed, nil
		},
	})

	got, err := wrapper("tcp", "example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	closer.Close()
	select {
	case <-observed.closed:
	default:
		t.Fatal("registered dial result remained open after lifecycle close")
	}
}
