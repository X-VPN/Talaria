// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

func TestProtectedPacketConnContainsIOPanics(t *testing.T) {
	protected, err := protectPacketConn(&udptlsPanicIOPacketConn{closed: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := protected.ReadFrom(make([]byte, 1)); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("ReadFrom() error = %v, want extension panic", err)
	}
	if _, err := protected.WriteTo([]byte{1}, &net.UDPAddr{}); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("WriteTo() error = %v, want extension panic", err)
	}
	for name, setDeadline := range map[string]func(time.Time) error{
		"all":   protected.SetDeadline,
		"read":  protected.SetReadDeadline,
		"write": protected.SetWriteDeadline,
	} {
		t.Run(name, func(t *testing.T) {
			if err := setDeadline(time.Now()); !errors.Is(err, extension.ErrPanic) {
				t.Fatalf("deadline error = %v, want extension panic", err)
			}
		})
	}
}

func TestProtectedPacketConnValidatesInjectedResults(t *testing.T) {
	t.Run("read size", func(t *testing.T) {
		protected, err := protectPacketConn(&udptlsResultPacketConn{
			readN:    2,
			readAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := protected.ReadFrom(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "invalid read size") {
			t.Fatalf("ReadFrom() error = %v, want invalid read size", err)
		}
	})

	t.Run("remote address", func(t *testing.T) {
		protected, err := protectPacketConn(&udptlsResultPacketConn{
			readN:    1,
			readAddr: panicPacketAddr{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := protected.ReadFrom(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "is not UDP") {
			t.Fatalf("ReadFrom() error = %v, want invalid UDP address", err)
		}
	})

	t.Run("invalid remote IP", func(t *testing.T) {
		protected, err := protectPacketConn(&udptlsResultPacketConn{
			readN:    1,
			readAddr: &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 1234},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := protected.ReadFrom(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "invalid IP") {
			t.Fatalf("ReadFrom() error = %v, want invalid IP", err)
		}
	})

	t.Run("address snapshot", func(t *testing.T) {
		remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
		protected, err := protectPacketConn(&udptlsResultPacketConn{readN: 1, readAddr: remote})
		if err != nil {
			t.Fatal(err)
		}
		_, got, err := protected.ReadFrom(make([]byte, 1))
		if err != nil {
			t.Fatal(err)
		}
		remote.IP[12] = 203
		remote.Port = 4321
		if got.String() != "192.0.2.1:1234" {
			t.Fatalf("ReadFrom() address = %q, want stable snapshot", got)
		}
	})

	t.Run("short write", func(t *testing.T) {
		protected, err := protectPacketConn(&udptlsResultPacketConn{writeN: 1})
		if err != nil {
			t.Fatal(err)
		}
		if n, err := protected.WriteTo([]byte{1, 2}, &net.UDPAddr{}); n != 1 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("WriteTo() = (%d, %v), want (1, %v)", n, err, io.ErrShortWrite)
		}
	})
}

type udptlsResultPacketConn struct {
	readN    int
	readAddr net.Addr
	writeN   int
}

func (c *udptlsResultPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readN > 0 && c.readN <= len(p) {
		p[0] = 1
	}
	return c.readN, c.readAddr, nil
}

func (c *udptlsResultPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return c.writeN, nil
}

func (*udptlsResultPacketConn) Close() error                     { return nil }
func (*udptlsResultPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*udptlsResultPacketConn) SetDeadline(time.Time) error      { return nil }
func (*udptlsResultPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*udptlsResultPacketConn) SetWriteDeadline(time.Time) error { return nil }

type panicPacketAddr struct{}

func (panicPacketAddr) Network() string { panic("network panic") }
func (panicPacketAddr) String() string  { panic("string panic") }
