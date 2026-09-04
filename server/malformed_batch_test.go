// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestServePacketBatchRejectsInvalidCount(t *testing.T) {
	s := &Server{handler: EchoPacketHandler{}}
	conn := &malformedPacketBatchConn{count: 2}
	err := s.servePacketBatchDataLoop(context.Background(), conn, 1, ServeOptions{
		ReadBufferSize: 64,
		IdleTimeout:    time.Second,
	}, SessionContext{ClientID: 1, Generation: 1}, SessionWriters{})
	if err == nil {
		t.Fatal("invalid batch count was accepted")
	}
}

func TestServePacketBatchAccountsReadScratchForLoopLifetime(t *testing.T) {
	s := &Server{handler: EchoPacketHandler{}}
	conn := &malformedPacketBatchConn{count: 3}
	err := s.servePacketBatchDataLoop(context.Background(), conn, 2, ServeOptions{
		ReadBufferSize: 64,
		IdleTimeout:    time.Second,
	}, SessionContext{ClientID: 1, Generation: 1}, SessionWriters{})
	if err == nil {
		t.Fatal("invalid batch count was accepted")
	}
	if conn.reservedBytes != 128 {
		t.Fatalf("reserved packet read scratch = %d, want 128", conn.reservedBytes)
	}
	if conn.releasedBytes != conn.reservedBytes {
		t.Fatalf("released packet read scratch = %d, want %d", conn.releasedBytes, conn.reservedBytes)
	}
}

func TestServePacketBatchReducesScratchToAvailableBudget(t *testing.T) {
	s := &Server{handler: EchoPacketHandler{}}
	conn := &malformedPacketBatchConn{count: 3, maxReservation: 128}
	err := s.servePacketBatchDataLoop(context.Background(), conn, 4, ServeOptions{
		ReadBufferSize: 64,
		IdleTimeout:    time.Second,
	}, SessionContext{ClientID: 1, Generation: 1}, SessionWriters{})
	if err == nil {
		t.Fatal("invalid batch count was accepted")
	}
	wantAttempts := []int64{256, 128}
	if len(conn.reserveAttempts) != len(wantAttempts) {
		t.Fatalf("packet read scratch attempts = %v, want %v", conn.reserveAttempts, wantAttempts)
	}
	for i := range wantAttempts {
		if conn.reserveAttempts[i] != wantAttempts[i] {
			t.Fatalf("packet read scratch attempts = %v, want %v", conn.reserveAttempts, wantAttempts)
		}
	}
	if conn.releasedBytes != 128 {
		t.Fatalf("released packet read scratch = %d, want 128", conn.releasedBytes)
	}
}

func TestServePacketBatchRejectsExcessiveAllocation(t *testing.T) {
	tests := []struct {
		name           string
		batchSize      int
		readBufferSize int
	}{
		{name: "batch size", batchSize: maxServePacketBatchSize + 1, readBufferSize: 64},
		{name: "aggregate memory", batchSize: 32, readBufferSize: maxServePacketBatchBytes/32 + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &malformedPacketBatchConn{batchSize: tt.batchSize}
			if _, _, err := preparePacketBatch(conn, ServeOptions{ReadBufferSize: tt.readBufferSize}); err == nil {
				t.Fatal("excessive packet batch allocation was accepted")
			}
			if conn.readCalled {
				t.Fatal("excessive packet batch allocation reached the adapter")
			}
		})
	}
}

func TestWriteRawPacketBatchValidatesBeforeAdapterCall(t *testing.T) {
	conn := &malformedPacketBatchConn{}
	if _, err := writeRawPacketBatch(context.Background(), conn, [][]byte{{1}}, []int{2}); err == nil {
		t.Fatal("oversized raw packet was accepted")
	}
	if conn.writeCalled {
		t.Fatal("invalid batch reached the adapter")
	}
}

func TestWriteAllRawBatchRejectsInvalidProgress(t *testing.T) {
	err := writeAllRawBatch(func(bufs [][]byte, _ []int) (int, error) {
		return len(bufs) + 1, nil
	}, [][]byte{{1}}, []int{1})
	if err == nil {
		t.Fatal("invalid raw batch progress was accepted")
	}
}

func TestServeConnectionsRejectUnsafePublicOptions(t *testing.T) {
	srv := &Server{}
	for _, serve := range []struct {
		name string
		opt  ServeOptions
		fn   func(ServeOptions) error
	}{
		{
			name: "packet oversized buffer",
			opt:  ServeOptions{ReadBufferSize: maxServeReadBufferSize + 1},
			fn: func(opt ServeOptions) error {
				return srv.ServePacketConn(context.Background(), nil, opt)
			},
		},
		{
			name: "control oversized auth timeout",
			opt:  ServeOptions{AuthTimeout: maxServerAuthTimeout + time.Second},
			fn: func(opt ServeOptions) error {
				return srv.ServeControlConn(context.Background(), nil, opt)
			},
		},
	} {
		t.Run(serve.name, func(t *testing.T) {
			if err := serve.fn(serve.opt); err == nil {
				t.Fatal("unsafe public option was accepted")
			}
		})
	}
}

type malformedPacketBatchConn struct {
	count           int
	batchSize       int
	readCalled      bool
	writeCalled     bool
	reservedBytes   int64
	releasedBytes   int64
	maxReservation  int64
	reserveAttempts []int64
}

func (*malformedPacketBatchConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*malformedPacketBatchConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*malformedPacketBatchConn) Close() error                     { return nil }
func (*malformedPacketBatchConn) LocalAddr() net.Addr              { return malformedBatchAddr("local") }
func (*malformedPacketBatchConn) RemoteAddr() net.Addr             { return malformedBatchAddr("remote") }
func (*malformedPacketBatchConn) SetDeadline(time.Time) error      { return nil }
func (*malformedPacketBatchConn) SetReadDeadline(time.Time) error  { return nil }
func (*malformedPacketBatchConn) SetWriteDeadline(time.Time) error { return nil }
func (c *malformedPacketBatchConn) BatchSize() int {
	if c.batchSize > 0 {
		return c.batchSize
	}
	return 1
}

func (c *malformedPacketBatchConn) ReadBatch(context.Context, [][]byte, []int) (int, error) {
	c.readCalled = true
	return c.count, nil
}

func (c *malformedPacketBatchConn) WriteBatch(context.Context, [][]byte, []int) (int, error) {
	c.writeCalled = true
	return 0, nil
}

func (c *malformedPacketBatchConn) ReservePacketReadBufferBytes(n int64) (func(), error) {
	c.reserveAttempts = append(c.reserveAttempts, n)
	if c.maxReservation > 0 && n > c.maxReservation {
		return nil, errors.New("synthetic packet read scratch limit")
	}
	c.reservedBytes += n
	return func() { c.releasedBytes += n }, nil
}

type malformedBatchAddr string

func (a malformedBatchAddr) Network() string { return "test" }
func (a malformedBatchAddr) String() string  { return string(a) }
