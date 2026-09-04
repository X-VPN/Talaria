// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package controlframe

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnPreservesFrameBoundaries(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	writer := New(left)
	reader := New(right)
	want := []byte("control packet")
	errCh := make(chan error, 1)
	go func() {
		_, err := writer.Write(want)
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("payload = %q want %q", buf[:n], want)
	}
}

func TestConnRejectsFrameLargerThanCallerBuffer(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	writer := New(left)
	reader := New(right)
	go func() {
		_, _ = writer.Write([]byte("too large"))
	}()
	if _, err := reader.Read(make([]byte, 2)); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestConnInvalidFrameCloseMayReenterAndPanic(t *testing.T) {
	underlying := &reentrantControlConn{reader: bytes.NewReader([]byte{0, 0})}
	framed := New(underlying)
	underlying.onClose = func() {
		_, _ = framed.Read(make([]byte, 1))
		panic("close panic")
	}
	done := make(chan error, 1)
	go func() {
		_, err := framed.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || err.Error() != "invalid zero-length control frame" {
			t.Fatalf("Read() error = %v, want invalid zero-length frame", err)
		}
	case <-time.After(time.Second):
		t.Fatal("invalid-frame close deadlocked after reentering Read")
	}
}

func TestConnClosesAfterPartialFrameWrite(t *testing.T) {
	underlying := &partialFrameWriteConn{}
	conn := New(underlying)
	if _, err := conn.Write([]byte{1, 2}); err == nil {
		t.Fatal("partial frame write returned no error")
	}
	if !underlying.closed {
		t.Fatal("connection remained open after a partial frame write")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() after failed write = %v, want net.ErrClosed", err)
	}
}

func TestConnRejectsInvalidWriteProgress(t *testing.T) {
	underlying := &invalidFrameWriteConn{}
	conn := New(underlying)
	if n, err := conn.Write([]byte{1}); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
	if !underlying.closed {
		t.Fatal("connection remained open after invalid write progress")
	}
}

func TestConnRejectsInvalidReadProgress(t *testing.T) {
	for _, n := range []int{-1, 3} {
		underlying := &invalidFrameReadConn{n: n}
		conn := New(underlying)
		if read, err := conn.Read(make([]byte, 1)); read != 0 || !errors.Is(err, errInvalidReadProgress) {
			t.Fatalf("Read() with progress %d = %d, %v; want 0, invalid progress", n, read, err)
		}
		if !underlying.closed {
			t.Fatalf("connection remained open after invalid read progress %d", n)
		}
	}
}

func TestConnClosesAfterPartialFrameRead(t *testing.T) {
	underlying := &partialFrameReadConn{reader: bytes.NewReader([]byte{0, 2, 1})}
	conn := New(underlying)
	if _, err := conn.Read(make([]byte, 2)); err == nil {
		t.Fatal("partial frame read returned no error")
	}
	if !underlying.closed {
		t.Fatal("connection remained open after a partial frame read")
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after failed read = %v, want net.ErrClosed", err)
	}
}

func TestNewTreatsTypedNilConnectionAsClosed(t *testing.T) {
	var underlying *net.TCPConn
	conn := New(underlying)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() error = %v, want net.ErrClosed", err)
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() error = %v, want net.ErrClosed", err)
	}
}

type reentrantControlConn struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	onClose func()
}

func (c *reentrantControlConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.Read(p)
}

func (*reentrantControlConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *reentrantControlConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}
func (*reentrantControlConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*reentrantControlConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*reentrantControlConn) SetDeadline(time.Time) error      { return nil }
func (*reentrantControlConn) SetReadDeadline(time.Time) error  { return nil }
func (*reentrantControlConn) SetWriteDeadline(time.Time) error { return nil }

var _ io.ReadWriter = (*reentrantControlConn)(nil)

type partialFrameWriteConn struct {
	writes int
	closed bool
}

type invalidFrameWriteConn struct {
	partialFrameWriteConn
}

func (*invalidFrameWriteConn) Write(p []byte) (int, error) {
	return len(p) + 1, nil
}

func (*partialFrameWriteConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *partialFrameWriteConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return len(p), nil
	}
	return 1, io.ErrUnexpectedEOF
}
func (c *partialFrameWriteConn) Close() error                   { c.closed = true; return nil }
func (*partialFrameWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*partialFrameWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*partialFrameWriteConn) SetDeadline(time.Time) error      { return nil }
func (*partialFrameWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*partialFrameWriteConn) SetWriteDeadline(time.Time) error { return nil }

type partialFrameReadConn struct {
	reader *bytes.Reader
	closed bool
}

type invalidFrameReadConn struct {
	partialFrameReadConn
	n int
}

func (c *invalidFrameReadConn) Read([]byte) (int, error) {
	return c.n, nil
}

func (c *partialFrameReadConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (*partialFrameReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *partialFrameReadConn) Close() error                   { c.closed = true; return nil }
func (*partialFrameReadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*partialFrameReadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*partialFrameReadConn) SetDeadline(time.Time) error      { return nil }
func (*partialFrameReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*partialFrameReadConn) SetWriteDeadline(time.Time) error { return nil }
