// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

type extensionPacketConn struct {
	inner net.PacketConn
	local net.Addr
}

func protectPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	if extension.IsNil(conn) {
		return nil, errors.New("TalariaUDP packet connection is nil")
	}
	if udpConn, ok := conn.(*net.UDPConn); ok && udpConn != nil {
		return udpConn, nil
	}
	var local net.Addr
	if err := extension.Run("TalariaUDP packet connection local address", func() {
		local = conn.LocalAddr()
	}); err != nil {
		return nil, err
	}
	if extension.IsNil(local) {
		return nil, errors.New("TalariaUDP packet connection returned a nil local address")
	}
	local, err := clonePacketUDPAddr(local)
	if err != nil {
		return nil, fmt.Errorf("TalariaUDP packet connection local address: %w", err)
	}
	return &extensionPacketConn{inner: conn, local: local}, nil
}

func (c *extensionPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	err = extension.Do("TalariaUDP packet connection read", func() error {
		var readErr error
		n, addr, readErr = c.inner.ReadFrom(p)
		return readErr
	})
	if err != nil {
		return n, addr, err
	}
	if n < 0 || n > len(p) {
		return 0, nil, fmt.Errorf("TalariaUDP packet connection returned invalid read size %d for %d-byte buffer", n, len(p))
	}
	remote, err := clonePacketUDPAddr(addr)
	if err != nil {
		return 0, nil, fmt.Errorf("TalariaUDP packet connection remote address: %w", err)
	}
	return n, remote, nil
}

func (c *extensionPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = extension.Do("TalariaUDP packet connection write", func() error {
		var writeErr error
		n, writeErr = c.inner.WriteTo(p, addr)
		return writeErr
	})
	if err == nil && n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, err
}

func (c *extensionPacketConn) Close() error {
	return extension.Do("TalariaUDP packet connection close", c.inner.Close)
}

func (c *extensionPacketConn) LocalAddr() net.Addr { return c.local }

func (c *extensionPacketConn) SetDeadline(deadline time.Time) error {
	return extension.Do("TalariaUDP packet connection deadline", func() error {
		return c.inner.SetDeadline(deadline)
	})
}

func (c *extensionPacketConn) SetReadDeadline(deadline time.Time) error {
	return extension.Do("TalariaUDP packet connection read deadline", func() error {
		return c.inner.SetReadDeadline(deadline)
	})
}

func (c *extensionPacketConn) SetWriteDeadline(deadline time.Time) error {
	return extension.Do("TalariaUDP packet connection write deadline", func() error {
		return c.inner.SetWriteDeadline(deadline)
	})
}

func clonePacketUDPAddr(addr net.Addr) (*net.UDPAddr, error) {
	if extension.IsNil(addr) {
		return nil, errors.New("address is nil")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, fmt.Errorf("address type %T is not UDP", addr)
	}
	if udpAddr.Port < 0 || udpAddr.Port > 65535 {
		return nil, fmt.Errorf("UDP port %d is invalid", udpAddr.Port)
	}
	if len(udpAddr.IP) != 0 && udpAddr.IP.To16() == nil {
		return nil, errors.New("UDP address has an invalid IP")
	}
	copyAddr := *udpAddr
	copyAddr.IP = append(net.IP(nil), udpAddr.IP...)
	return &copyAddr, nil
}
