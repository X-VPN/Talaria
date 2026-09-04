// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

func TestListenerPermanentAcceptErrorTerminatesAllAccepts(t *testing.T) {
	want := errors.New("synthetic TalariaUDP packet read failure")
	pc := &udptlsPermanentReadErrorPacketConn{err: want, closed: make(chan struct{})}
	certPEM, keyPEM := newHandshakeTestCertificatePEM(t)
	listener, err := NewListener(NewListenerReq{
		PacketConn: pc, CertPEM: certPEM, KeyPEM: keyPEM,
		WireSecret: bytes.Repeat([]byte{0x41}, minimumWireSecretSize), WireIdentity: testWireIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := listener.Accept(ctx); !errors.Is(err, want) {
		t.Fatalf("first Accept() error = %v want %v", err, want)
	}

	start := time.Now()
	if _, err := listener.Accept(context.Background()); !errors.Is(err, want) {
		t.Fatalf("second Accept() error = %v want %v", err, want)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("second Accept blocked after listener termination: %s", elapsed)
	}
	select {
	case <-pc.closed:
	case <-time.After(time.Second):
		t.Fatal("terminal accept error did not close the TalariaUDP listener")
	}
}

func TestListenerContainsPacketReadPanic(t *testing.T) {
	pc := &udptlsPanicIOPacketConn{closed: make(chan struct{})}
	certPEM, keyPEM := newHandshakeTestCertificatePEM(t)
	listener, err := NewListener(NewListenerReq{
		PacketConn: pc, CertPEM: certPEM, KeyPEM: keyPEM,
		WireSecret: bytes.Repeat([]byte{0x42}, minimumWireSecretSize), WireIdentity: testWireIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := listener.Accept(ctx); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Accept() error = %v, want packet read panic", err)
	}
}

func TestListenerCloseAllowsReentrantPacketConnClose(t *testing.T) {
	pc := &udptlsReentrantClosePacketConn{closed: make(chan struct{})}
	certPEM, keyPEM := newHandshakeTestCertificatePEM(t)
	listener, err := NewListener(NewListenerReq{
		PacketConn: pc, CertPEM: certPEM, KeyPEM: keyPEM,
		WireSecret: bytes.Repeat([]byte{0x43}, minimumWireSecretSize), WireIdentity: testWireIdentity,
	})
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
		t.Fatal("reentrant packet connection close deadlocked TalariaUDP listener close")
	}
}

type udptlsPermanentReadErrorPacketConn struct {
	err       error
	closed    chan struct{}
	closeOnce sync.Once
}

type udptlsReentrantClosePacketConn struct {
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func()
}

type udptlsPanicIOPacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func (*udptlsPanicIOPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	panic("read panic")
}

func (*udptlsPanicIOPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	panic("write panic")
}

func (c *udptlsPanicIOPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*udptlsPanicIOPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*udptlsPanicIOPacketConn) SetDeadline(time.Time) error      { panic("deadline panic") }
func (*udptlsPanicIOPacketConn) SetReadDeadline(time.Time) error  { panic("read deadline panic") }
func (*udptlsPanicIOPacketConn) SetWriteDeadline(time.Time) error { panic("write deadline panic") }

func (c *udptlsReentrantClosePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (*udptlsReentrantClosePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *udptlsReentrantClosePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func (*udptlsReentrantClosePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*udptlsReentrantClosePacketConn) SetDeadline(time.Time) error      { return nil }
func (*udptlsReentrantClosePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*udptlsReentrantClosePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *udptlsPermanentReadErrorPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, c.err
}

func (*udptlsPermanentReadErrorPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (c *udptlsPermanentReadErrorPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*udptlsPermanentReadErrorPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*udptlsPermanentReadErrorPacketConn) SetDeadline(time.Time) error      { return nil }
func (*udptlsPermanentReadErrorPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*udptlsPermanentReadErrorPacketConn) SetWriteDeadline(time.Time) error { return nil }
