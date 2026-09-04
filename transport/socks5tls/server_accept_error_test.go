// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestNewServerContainsListenerCleanupPanic(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	listener := &panicCloseListener{}
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:        listener,
		TLSConfig:       serverTLS,
		AdmissionLimits: AdmissionLimits{MaxConnections: -1},
	})
	if err == nil {
		_ = server.Close()
		t.Fatal("invalid admission limits were accepted")
	}
	if listener.closes != 1 {
		t.Fatalf("listener closes = %d, want 1", listener.closes)
	}
}

func TestServerAcceptFailureClosesActiveConnectionsBeforeWait(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	want := errors.New("synthetic listener failure")
	listener := &acceptThenErrorListener{conn: serverConn, err: want}
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- server.Serve(
			context.Background(),
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				return nil, net.ErrClosed
			}),
		)
	}()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("Serve() error = %v want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve blocked waiting for an active connection after Accept failed")
	}
}

func TestServerContainsListenerAcceptPanic(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: &panicAcceptListener{}, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Serve(
		context.Background(),
		coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
		coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
			return nil, net.ErrClosed
		}),
	)
	if err == nil {
		t.Fatal("Serve() error = nil, want recovered listener panic")
	}
}

func TestServerClosesConnectionReturnedWithAcceptError(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	want := errors.New("synthetic accept failure")
	listener := &connAndErrorListener{conn: serverConn, err: want}
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Serve(
		context.Background(),
		coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
		coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
			return nil, net.ErrClosed
		}),
	)
	if !errors.Is(err, want) {
		t.Fatalf("Serve() error = %v, want %v", err, want)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("connection returned with accept error was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed accepted connection to close")
	}
}

func TestServerClosesConnectionWhenRemoteAddressPanics(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener := &connAndErrorListener{
		conn: &remoteAddrConn{Conn: serverConn, remote: panicStringAddr{}},
	}
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Serve(
		context.Background(),
		coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
		coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
			return nil, net.ErrClosed
		}),
	)
	if err == nil {
		t.Fatal("Serve() error = nil, want recovered remote address panic")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("connection with panicking remote address was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for invalid accepted connection to close")
	}
}

func TestServerCloseRejectsAcceptedConnectionBeforeTracking(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	remoteStarted := make(chan struct{})
	remoteContinue := make(chan struct{})
	listener := newSingleConnListener(&blockingRemoteAddrConn{
		Conn:    serverConn,
		started: remoteStarted,
		proceed: remoteContinue,
	})
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- server.Serve(
			context.Background(),
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				return nil, net.ErrClosed
			}),
		)
	}()
	select {
	case <-remoteStarted:
	case <-time.After(time.Second):
		t.Fatal("accepted connection did not reach remote address lookup")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	close(remoteContinue)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Close")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("connection accepted during Close was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("connection accepted during Close remained open")
	}
}

type acceptThenErrorListener struct {
	mu     sync.Mutex
	conn   net.Conn
	err    error
	closed bool
}

type connAndErrorListener struct {
	conn net.Conn
	err  error
}

type panicCloseListener struct{ closes int }

type singleConnListener struct {
	mu        sync.Mutex
	conn      net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

type blockingRemoteAddrConn struct {
	net.Conn
	started chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*singleConnListener) Addr() net.Addr { return testAddr("single:443") }

func (c *blockingRemoteAddrConn) RemoteAddr() net.Addr {
	c.once.Do(func() { close(c.started) })
	<-c.proceed
	return testAddr("remote:443")
}

func (*panicCloseListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *panicCloseListener) Close() error {
	l.closes++
	panic("synthetic listener close failure")
}
func (*panicCloseListener) Addr() net.Addr { return testAddr("panic-close:443") }

type panicAcceptListener struct{}

func (*panicAcceptListener) Accept() (net.Conn, error) { panic("synthetic accept failure") }
func (*panicAcceptListener) Close() error              { return nil }
func (*panicAcceptListener) Addr() net.Addr            { return testAddr("panic-accept:443") }

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

type panicStringAddr struct{}

func (panicStringAddr) Network() string { return "panic" }
func (panicStringAddr) String() string  { panic("synthetic address failure") }

func (l *connAndErrorListener) Accept() (net.Conn, error) {
	conn := l.conn
	l.conn = nil
	return conn, l.err
}

func (*connAndErrorListener) Close() error   { return nil }
func (*connAndErrorListener) Addr() net.Addr { return testAddr("accept-error:443") }

func (l *acceptThenErrorListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, net.ErrClosed
	}
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		return conn, nil
	}
	return nil, l.err
}

func (l *acceptThenErrorListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}

func (*acceptThenErrorListener) Addr() net.Addr { return testAddr("accept-error:443") }
