// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package controlframe carries length-delimited records over an established TLS
// control connection.
//
// The framing exists because the control channel multiplexes distinct messages
// over a byte stream. Every length is bounded before allocation: the frame
// maximum is enforced on read, so a declared length can never drive an
// unbounded allocation.
package controlframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

const (
	headerSize   = 2
	MaxFrameSize = int(^uint16(0))
)

var errInvalidReadProgress = errors.New("invalid control frame read progress")

type Conn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	failed  atomic.Bool
}

func New(conn net.Conn) *Conn {
	if extension.IsNil(conn) {
		conn = nil
	}
	return &Conn{Conn: conn}
}

func (c *Conn) Read(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	if c.failed.Load() {
		c.readMu.Unlock()
		return 0, net.ErrClosed
	}
	var header [headerSize]byte
	if n, err := io.ReadFull(validatingReader{c.Conn}, header[:]); err != nil {
		fatal := n > 0 || errors.Is(err, errInvalidReadProgress)
		if fatal {
			c.failed.Store(true)
		}
		c.readMu.Unlock()
		if fatal {
			_ = extension.Do("Talaria control frame failed connection close", c.Conn.Close)
		}
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 {
		c.failed.Store(true)
		c.readMu.Unlock()
		_ = extension.Do("Talaria control frame invalid connection close", c.Conn.Close)
		return 0, fmt.Errorf("invalid zero-length control frame")
	}
	if size > len(p) {
		c.failed.Store(true)
		c.readMu.Unlock()
		_ = extension.Do("Talaria control frame oversized connection close", c.Conn.Close)
		return 0, fmt.Errorf("control frame size %d exceeds read buffer %d", size, len(p))
	}
	n, err := io.ReadFull(validatingReader{c.Conn}, p[:size])
	if err != nil {
		c.failed.Store(true)
	}
	c.readMu.Unlock()
	if err != nil {
		_ = extension.Do("Talaria control frame failed connection close", c.Conn.Close)
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 || len(p) > MaxFrameSize {
		return 0, fmt.Errorf("invalid control frame size %d", len(p))
	}
	c.writeMu.Lock()
	if c.failed.Load() {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}

	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(p)))
	if err := writeFull(c.Conn, header[:]); err != nil {
		c.failed.Store(true)
		c.writeMu.Unlock()
		_ = extension.Do("Talaria control frame failed connection close", c.Conn.Close)
		return 0, err
	}
	if err := writeFull(c.Conn, p); err != nil {
		c.failed.Store(true)
		c.writeMu.Unlock()
		_ = extension.Do("Talaria control frame failed connection close", c.Conn.Close)
		return 0, err
	}
	c.writeMu.Unlock()
	return len(p), nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetDeadline(t)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		if n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type validatingReader struct {
	io.Reader
}

func (r validatingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n < 0 || n > len(p) {
		return 0, fmt.Errorf("%w: %d for %d-byte buffer", errInvalidReadProgress, n, len(p))
	}
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
