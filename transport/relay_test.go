// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

func TestRelayConvertsConnectionPanicToError(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- Relay(context.Background(), panicReadConn{Conn: left}, right)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("Relay panic error = %v, want extension panic", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Relay did not terminate after a connection panic")
	}
}

func TestRelayRejectsTypedNilConnection(t *testing.T) {
	var left *panicReadConn
	right, peer := net.Pipe()
	defer right.Close()
	defer peer.Close()
	if err := Relay(context.Background(), left, right); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Relay typed-nil error = %v, want net.ErrClosed", err)
	}
}

func TestRelayDoesNotHideCopyErrorBehindCloseWriteError(t *testing.T) {
	copyErr := errors.New("read failed")
	left := &scriptedRelayConn{readErr: copyErr}
	right := &scriptedRelayConn{readErr: io.EOF, closeWriteErr: net.ErrClosed}

	if err := Relay(context.Background(), left, right); !errors.Is(err, copyErr) {
		t.Fatalf("Relay error = %v, want %v", err, copyErr)
	}
}

type panicReadConn struct {
	net.Conn
}

func (panicReadConn) Read([]byte) (int, error) {
	panic("boom")
}

type scriptedRelayConn struct {
	readErr       error
	closeWriteErr error
}

func (c *scriptedRelayConn) Read([]byte) (int, error)       { return 0, c.readErr }
func (*scriptedRelayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*scriptedRelayConn) Close() error                     { return nil }
func (*scriptedRelayConn) LocalAddr() net.Addr              { return nil }
func (*scriptedRelayConn) RemoteAddr() net.Addr             { return nil }
func (*scriptedRelayConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedRelayConn) SetWriteDeadline(time.Time) error { return nil }
func (c *scriptedRelayConn) CloseWrite() error              { return c.closeWriteErr }
