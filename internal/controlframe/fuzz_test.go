// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package controlframe

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func FuzzConnRead(f *testing.F) {
	f.Add([]byte{0, 1, 0x42}, uint16(8))
	f.Add([]byte{0xff, 0xff}, uint16(32))
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, wire []byte, bufferSize uint16) {
		if len(wire) > MaxFrameSize+2 {
			t.Skip()
		}
		conn := New(&readOnlyConn{Reader: bytes.NewReader(wire)})
		_, _ = conn.Read(make([]byte, int(bufferSize)))
	})
}

type readOnlyConn struct {
	*bytes.Reader
}

func (c *readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *readOnlyConn) Close() error                     { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c *readOnlyConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c *readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }
