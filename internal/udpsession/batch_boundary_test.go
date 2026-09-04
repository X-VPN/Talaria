// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

func TestBatchConnWrapperRejectsInvalidWriteSizes(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	conn := WrapBatchConn(left)
	if _, err := conn.WriteBatch(context.Background(), [][]byte{{1}}, nil); err == nil {
		t.Fatal("missing size was accepted")
	}
	if _, err := conn.WriteBatch(context.Background(), [][]byte{{1}}, []int{-1}); err == nil {
		t.Fatal("negative size was accepted")
	}
	if _, err := conn.WriteBatch(context.Background(), [][]byte{{1}}, []int{2}); err == nil {
		t.Fatal("oversized packet was accepted")
	}
}

func TestBatchConnWrapperRejectsShortWrites(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	conn := WrapBatchConn(shortWriteConn{Conn: left})
	if written, err := conn.WriteBatch(context.Background(), [][]byte{{1, 2}}, []int{2}); written != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteBatch() = %d, %v; want 0, %v", written, err, io.ErrShortWrite)
	}
}

type shortWriteConn struct {
	net.Conn
}

func (shortWriteConn) Write([]byte) (int, error) { return 1, nil }

func TestClientConnRejectsInvalidWriteSizes(t *testing.T) {
	conn := &clientConn{maxPacket: 4, batchSize: 2}
	tests := []struct {
		name  string
		bufs  [][]byte
		sizes []int
	}{
		{name: "missing size", bufs: [][]byte{{1}}},
		{name: "negative size", bufs: [][]byte{{1}}, sizes: []int{-1}},
		{name: "buffer overflow", bufs: [][]byte{{1}}, sizes: []int{2}},
		{name: "packet too large", bufs: [][]byte{{1, 2, 3, 4, 5}}, sizes: []int{5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if written, err := conn.WriteBatch(context.Background(), tt.bufs, tt.sizes); err == nil || written != 0 {
				t.Fatalf("WriteBatch() = %d, %v; want 0 and an error", written, err)
			}
		})
	}
}
