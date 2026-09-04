// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHandshakeAckRemainsDirtyUntilWriteCommit(t *testing.T) {
	c := &handshakeConn{
		recvNext: 42,
		ackDirty: true,
	}
	packet, ackUpto, ackIncluded, err := c.nextOutboundPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !ackIncluded || ackUpto != 42 || len(packet) != handshakeAckHeaderSize {
		t.Fatalf("outbound ACK = included:%v upto:%d size:%d", ackIncluded, ackUpto, len(packet))
	}
	if got := binary.LittleEndian.Uint64(packet[2:10]); got != ackUpto {
		t.Fatalf("encoded ACK = %d, want %d", got, ackUpto)
	}
	if _, dirty := c.snapshotAck(); !dirty {
		t.Fatal("building an ACK committed it before the datagram write")
	}
	c.clearAckDirty(ackUpto)
	if _, dirty := c.snapshotAck(); dirty {
		t.Fatal("successful datagram write did not commit the ACK")
	}
}

func TestHandshakeRetainsEarlyDataPlanePacket(t *testing.T) {
	c := &handshakeConn{
		retainPostHandshake: true,
		maxQueuedBytes:      1024,
	}
	packet := make([]byte, handshakeAckHeaderSize)
	packet[0] = udptlsDataPacketType
	packet[1] = 0xff
	if err := c.handleInboundPacket(packet); err != nil {
		t.Fatal(err)
	}
	packet[1] = 0
	pending := c.takePostHandshakePackets()
	if len(pending) != 1 {
		t.Fatalf("retained data-plane packets = %d, want 1", len(pending))
	}
	if pending[0].n != handshakeAckHeaderSize || pending[0].buf[1] != 0xff {
		t.Fatal("retained data-plane packet did not preserve its bytes")
	}
}

func TestHandshakePostHandshakePacketsRetainSharedBudgetUntilTransferred(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 1 << 20},
	}
	c, err := newHandshakeConnWithReservedOverhead(inner, 1024, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, handshakeAckHeaderSize)
	packet[0] = udptlsDataPacketType
	c.queuePostHandshakePacket(packet)
	if got := inner.used; got != int64(len(packet)) {
		t.Fatalf("post-handshake reservation = %d, want %d", got, len(packet))
	}

	pending := c.closeAndTakePostHandshakePackets()
	if len(pending) != 1 || pending[0].reserved != int64(len(packet)) {
		t.Fatalf("transferred packet = %+v", pending)
	}
	if got := inner.used; got != int64(len(packet)) {
		t.Fatalf("reservation after transfer = %d, want %d", got, len(packet))
	}

	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after data connection close = %d, want 0", inner.used)
	}
}

func TestHandshakeCloseReleasesUntransferredPostHandshakeBudget(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 1 << 20},
	}
	c, err := newHandshakeConnWithReservedOverhead(inner, 1024, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, handshakeAckHeaderSize)
	packet[0] = udptlsDataPacketType
	c.queuePostHandshakePacket(packet)
	if inner.used == 0 {
		t.Fatal("post-handshake packet did not reserve shared budget")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after handshake close = %d, want 0", inner.used)
	}
}

func TestHandshakeRejectsPollingDeadlineFailuresBeforeIO(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*deadlineFailureHandshakeBatchConn, error)
		trigger   func(*handshakeConn) error
		ioCalls   func(*deadlineFailureHandshakeBatchConn) int
	}{
		{
			name: "read",
			configure: func(inner *deadlineFailureHandshakeBatchConn, err error) {
				inner.readDeadlineErr = err
			},
			trigger: func(conn *handshakeConn) error {
				_, err := conn.Read(make([]byte, 1))
				return err
			},
			ioCalls: func(inner *deadlineFailureHandshakeBatchConn) int { return inner.readCalls },
		},
		{
			name: "write",
			configure: func(inner *deadlineFailureHandshakeBatchConn, err error) {
				inner.writeDeadlineErr = err
			},
			trigger: func(conn *handshakeConn) error {
				if _, err := conn.Write([]byte("hello")); err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				return conn.Drain(ctx)
			},
			ioCalls: func(inner *deadlineFailureHandshakeBatchConn) int { return inner.writeCalls },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := errors.New("synthetic handshake deadline failure")
			inner := &deadlineFailureHandshakeBatchConn{}
			tt.configure(inner, want)
			conn, err := newHandshakeConn(inner, 1500)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			if err := tt.trigger(conn); !errors.Is(err, want) {
				t.Fatalf("handshake error = %v, want %v", err, want)
			}
			if calls := tt.ioCalls(inner); calls != 0 {
				t.Fatalf("I/O calls after deadline failure = %d, want 0", calls)
			}
		})
	}
}

type deadlineFailureHandshakeBatchConn struct {
	mu               sync.Mutex
	readDeadlineErr  error
	writeDeadlineErr error
	readCalls        int
	writeCalls       int
}

func (c *deadlineFailureHandshakeBatchConn) Read([]byte) (int, error) {
	return 0, io.EOF
}
func (c *deadlineFailureHandshakeBatchConn) Write(p []byte) (int, error) { return len(p), nil }
func (*deadlineFailureHandshakeBatchConn) Close() error                  { return nil }
func (*deadlineFailureHandshakeBatchConn) LocalAddr() net.Addr           { return &net.UDPAddr{} }
func (*deadlineFailureHandshakeBatchConn) RemoteAddr() net.Addr          { return &net.UDPAddr{} }
func (*deadlineFailureHandshakeBatchConn) SetDeadline(time.Time) error   { return nil }
func (c *deadlineFailureHandshakeBatchConn) SetReadDeadline(time.Time) error {
	return c.readDeadlineErr
}
func (c *deadlineFailureHandshakeBatchConn) SetWriteDeadline(time.Time) error {
	return c.writeDeadlineErr
}
func (*deadlineFailureHandshakeBatchConn) BatchSize() int { return 1 }
func (c *deadlineFailureHandshakeBatchConn) ReadBatch(ctx context.Context, _ [][]byte, _ []int) (int, error) {
	c.mu.Lock()
	c.readCalls++
	c.mu.Unlock()
	<-ctx.Done()
	return 0, ctx.Err()
}
func (c *deadlineFailureHandshakeBatchConn) WriteBatch(_ context.Context, _ [][]byte, _ []int) (int, error) {
	c.mu.Lock()
	c.writeCalls++
	c.mu.Unlock()
	return 1, nil
}
