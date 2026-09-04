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
	"testing"
	"time"
)

type testQueuedByteBudget struct {
	limit int64
	used  int64
}

func (b *testQueuedByteBudget) ReserveQueuedBytes(n int64) bool {
	if n < 0 || b.used+n > b.limit {
		return false
	}
	b.used += n
	return true
}

func (b *testQueuedByteBudget) ReleaseQueuedBytes(n int64) {
	b.used -= n
}

type retainedBudgetBatchConn struct {
	*scriptedBatchConn
	testQueuedByteBudget
}

type invalidReadCountBatchConn struct {
	*scriptedBatchConn
	released int64
}

func (c *invalidReadCountBatchConn) ReadBatch(_ context.Context, bufs [][]byte, _ []int) (int, error) {
	return len(bufs) + 1, nil
}

func (c *invalidReadCountBatchConn) ReadBatchRetained(_ context.Context, bufs [][]byte, _ []int) (int, int64, error) {
	return len(bufs) + 1, 64, nil
}

func (c *invalidReadCountBatchConn) WriteBatch(_ context.Context, bufs [][]byte, _ []int) (int, error) {
	return len(bufs) + 1, nil
}

func (c *invalidReadCountBatchConn) ReleaseQueuedBytes(n int64) {
	c.released += n
}

func TestSecureWireScratchUsesQueuedByteBudget(t *testing.T) {
	secret := bytes.Repeat([]byte{0x35}, minimumWireSecretSize)
	clientCodec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverCodec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x41}, 64)
	sealed, ok := clientCodec.seal(payload, wireDirectionClient)
	if !ok {
		t.Fatal("failed to seal test packet")
	}

	t.Run("read", func(t *testing.T) {
		inner := &retainedBudgetBatchConn{
			scriptedBatchConn:    &scriptedBatchConn{reads: [][][]byte{{sealed}}},
			testQueuedByteBudget: testQueuedByteBudget{limit: int64(len(sealed) - 1)},
		}
		conn := newWireBatchConn(inner, serverCodec, udptlsModeServer)
		buf := make([]byte, len(payload))
		if n, err := conn.ReadBatch(t.Context(), [][]byte{buf}, []int{0}); n != 0 || !errors.Is(err, errTalariaUDPQueueMemoryLimit) {
			t.Fatalf("ReadBatch() = %d, %v; want 0, %v", n, err, errTalariaUDPQueueMemoryLimit)
		}
		if inner.used != 0 {
			t.Fatalf("read scratch budget after rejection = %d, want 0", inner.used)
		}
	})

	t.Run("retained read", func(t *testing.T) {
		inner := &retainedBudgetBatchConn{
			scriptedBatchConn:    &scriptedBatchConn{reads: [][][]byte{{sealed}}},
			testQueuedByteBudget: testQueuedByteBudget{limit: int64(2*len(sealed) - 1)},
		}
		conn := newWireBatchConn(inner, serverCodec, udptlsModeServer).(*wireBatchConn)
		buf := make([]byte, len(payload))
		n, retained, err := conn.ReadBatchRetained(t.Context(), [][]byte{buf}, []int{0})
		if n != 0 || retained != 0 || err == nil {
			t.Fatalf("ReadBatchRetained() = %d, %d, %v; want 0, 0, error", n, retained, err)
		}
		if inner.used != 0 {
			t.Fatalf("retained read scratch budget after rejection = %d, want 0", inner.used)
		}
	})

	t.Run("write", func(t *testing.T) {
		inner := &retainedBudgetBatchConn{
			scriptedBatchConn:    &scriptedBatchConn{},
			testQueuedByteBudget: testQueuedByteBudget{limit: int64(len(sealed) - 1)},
		}
		conn := newWireBatchConn(inner, clientCodec, udptlsModeClient)
		if n, err := conn.WriteBatch(t.Context(), [][]byte{payload}, []int{len(payload)}); n != 0 || !errors.Is(err, errTalariaUDPQueueMemoryLimit) {
			t.Fatalf("WriteBatch() = %d, %v; want 0, %v", n, err, errTalariaUDPQueueMemoryLimit)
		}
		if inner.used != 0 || len(inner.snapshotWrites()) != 0 {
			t.Fatalf("write after budget rejection = %d bytes reserved, %d packets", inner.used, len(inner.snapshotWrites()))
		}
	})
}

func TestTalariaUDPQueuesAndScratchShareByteBudget(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 1 << 20},
	}
	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wrapped.(*udptlsConn)

	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if inner.used != int64(c.maxCipher) {
		t.Fatalf("write scratch reservation = %d, want %d", inner.used, c.maxCipher)
	}

	encrypted := udptlsEncryptedPacket{buf: make([]byte, c.maxCipher), n: 1}
	if !c.reserveEncryptedPacket(&encrypted) {
		t.Fatal("encrypted queue reservation failed")
	}
	c.releaseEncryptedPacket(encrypted)

	plain := udptlsPlainPacket{buf: make([]byte, c.maxPacket), n: 1}
	if !c.reservePlainPacket(&plain) {
		t.Fatal("plaintext queue reservation failed")
	}
	plainCh := make(chan udptlsPlainPacket, 1)
	plainCh <- plain
	close(plainCh)
	c.readStateMu.Lock()
	c.plainPktCh = plainCh
	c.readStateMu.Unlock()

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after close = %d, want 0", inner.used)
	}
}

func TestTalariaUDPReceiveBufferPoolsRetainAndReleaseSharedBudget(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 1 << 20},
	}
	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wrapped.(*udptlsConn)

	enc, ok := c.getEncBuf()
	if !ok {
		t.Fatal("encrypted buffer reservation failed")
	}
	if got := inner.used; got != int64(c.maxCipher) {
		t.Fatalf("encrypted buffer reservation = %d, want %d", got, c.maxCipher)
	}
	c.putEncBuf(enc)
	if got := inner.used; got != int64(c.maxCipher) {
		t.Fatalf("cached encrypted buffer reservation = %d, want %d", got, c.maxCipher)
	}

	plain, ok := c.getPlainBuf()
	if !ok {
		t.Fatal("plaintext buffer reservation failed")
	}
	c.putPlainBuf(plain)
	if got := inner.used; got != int64(c.maxCipher+c.maxPacket) {
		t.Fatalf("cached receive buffer reservation = %d, want %d", got, c.maxCipher+c.maxPacket)
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after close = %d, want 0", inner.used)
	}
}

func TestTalariaUDPReceiveBufferPoolsTrimIdleCapacityForActiveWork(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 1024},
	}
	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wrapped.(*udptlsConn)

	enc, ok := c.getEncBuf()
	if !ok {
		t.Fatal("encrypted buffer reservation failed")
	}
	c.putEncBuf(enc)
	if !c.reserveQueuedBytes(1024) {
		t.Fatal("idle receive buffer was not trimmed for active work")
	}
	if len(c.encPool) != 0 {
		t.Fatal("trimmed encrypted buffer remained cached")
	}
	c.releaseQueuedBytes(1024)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after close = %d, want 0", inner.used)
	}
}

func TestTalariaUDPPacketReadScratchRetainsSharedBudgetUntilRelease(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 16384},
	}
	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wrapped.(*udptlsConn)

	if _, err := c.ReservePacketReadBufferBytes(16385); !errors.Is(err, errTalariaUDPQueueMemoryLimit) {
		t.Fatalf("oversized packet read scratch error = %v, want %v", err, errTalariaUDPQueueMemoryLimit)
	}
	release, err := c.ReservePacketReadBufferBytes(2048)
	if err != nil {
		t.Fatal(err)
	}
	if got := inner.used; got != 2048 {
		t.Fatalf("packet read scratch reservation = %d, want 2048", got)
	}
	release()
	release()
	if inner.used != 0 {
		t.Fatalf("packet read scratch reservation after release = %d, want 0", inner.used)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTalariaUDPCloseWaitsForPacketReadScratchRelease(t *testing.T) {
	inner := &retainedBudgetBatchConn{
		scriptedBatchConn:    &scriptedBatchConn{},
		testQueuedByteBudget: testQueuedByteBudget{limit: 16384},
	}
	key := bytes.Repeat([]byte{1}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 512, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := wrapped.(*udptlsConn)
	release, err := c.ReservePacketReadBufferBytes(2048)
	if err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before packet read scratch release: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after packet read scratch release")
	}
	if inner.used != 0 {
		t.Fatalf("queued byte budget after close = %d, want 0", inner.used)
	}
}

func (c *retainedBudgetBatchConn) ReadBatchRetained(ctx context.Context, bufs [][]byte, sizes []int) (int, int64, error) {
	n, err := c.ReadBatch(ctx, bufs, sizes)
	if n == 0 {
		return 0, 0, err
	}
	var retained int64
	for i := 0; i < n; i++ {
		retained += int64(sizes[i])
	}
	if !c.ReserveQueuedBytes(retained) {
		return 0, 0, io.ErrShortBuffer
	}
	return n, retained, err
}

func TestRetryWrappersPreserveSharedHandshakeBudget(t *testing.T) {
	binding := bytes.Repeat([]byte{0x51}, retryPacketBindingSize)
	tag := bytes.Repeat([]byte{0x62}, retryCookieTagSize)
	innerPacket := testHandshakeStartPacket([]byte{1, 2, 3})

	tests := []struct {
		name    string
		wrapper func(*retainedBudgetBatchConn) batchConn
		sealDir byte
	}{
		{
			name: "server",
			wrapper: func(inner *retainedBudgetBatchConn) batchConn {
				conn := &retryServerConn{batchConn: inner, maxPacket: 512, bound: true}
				copy(conn.binding[:], binding)
				copy(conn.tag[:], tag)
				return conn
			},
			sealDir: handshakeAuthDirectionClient,
		},
		{
			name: "client",
			wrapper: func(inner *retainedBudgetBatchConn) batchConn {
				conn := newRetryClientConn(inner, 512)
				copy(conn.authBinding[:], binding)
				copy(conn.authTag[:], tag)
				conn.authReady = true
				return conn
			},
			sealDir: handshakeAuthDirectionServer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealed, ok := sealHandshakeAuthPacket(innerPacket, binding, tag, tt.sealDir, 512)
			if !ok {
				t.Fatal("failed to seal test handshake packet")
			}
			budgetInner := &retainedBudgetBatchConn{
				scriptedBatchConn:    &scriptedBatchConn{},
				testQueuedByteBudget: testQueuedByteBudget{limit: 1024},
			}
			budgetWrapper := tt.wrapper(budgetInner)
			handshake, err := newHandshakeConnWithReservedOverhead(budgetWrapper, 512, handshakeAuthOverhead, false)
			if err != nil {
				t.Fatal(err)
			}
			if handshake.budget == nil {
				t.Fatal("retry wrapper hid the shared queued-byte budget")
			}
			_ = handshake.Close()

			if !handshake.budget.ReserveQueuedBytes(32) || budgetInner.used != 32 {
				t.Fatalf("outbound reservation was not forwarded: %d", budgetInner.used)
			}
			handshake.budget.ReleaseQueuedBytes(32)
			if budgetInner.used != 0 {
				t.Fatalf("outbound reservation leaked: %d", budgetInner.used)
			}

			readInner := &retainedBudgetBatchConn{
				scriptedBatchConn:    &scriptedBatchConn{reads: [][][]byte{{sealed}}},
				testQueuedByteBudget: testQueuedByteBudget{limit: 1024},
			}
			readWrapper := tt.wrapper(readInner)
			retainedReader, ok := readWrapper.(retainedBatchConn)
			if !ok {
				t.Fatal("retry wrapper hid retained batch reads")
			}
			buf := make([]byte, 512)
			sizes := []int{0}
			n, retained, err := retainedReader.ReadBatchRetained(t.Context(), [][]byte{buf}, sizes)
			if err != nil || n != 1 || retained != int64(len(sealed)) {
				t.Fatalf("retained read = n=%d retained=%d err=%v", n, retained, err)
			}
			if !bytes.Equal(buf[:sizes[0]], innerPacket) {
				t.Fatalf("authenticated packet = %x, want %x", buf[:sizes[0]], innerPacket)
			}
			if readInner.used != retained {
				t.Fatalf("underlying retained budget = %d, want %d", readInner.used, retained)
			}
			retainedReader.ReleaseQueuedBytes(retained)
			if readInner.used != 0 {
				t.Fatalf("underlying retained budget leaked: %d", readInner.used)
			}
		})
	}
}

func TestHandshakeReceiveCopiesShareAndReleaseGlobalBudget(t *testing.T) {
	budget := &testQueuedByteBudget{limit: 4}
	newConn := func() *handshakeConn {
		return &handshakeConn{
			budget:            budget,
			maxQueuedBytes:    8,
			maxQueuedSegments: 8,
			recvQueued:        make(map[uint64][]byte),
			sendNotify:        make(chan struct{}, 1),
			recvNotify:        make(chan struct{}, 1),
		}
	}
	first := newConn()
	second := newConn()

	if err := first.handleData(0, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if budget.used != 4 {
		t.Fatalf("global handshake budget = %d, want 4", budget.used)
	}
	if err := second.handleData(0, []byte{5}); err != nil {
		t.Fatal(err)
	}
	if second.recvNext != 0 || len(second.recvReady) != 0 || budget.used != 4 {
		t.Fatalf("second handshake bypassed global budget: next=%d ready=%d used=%d",
			second.recvNext, len(second.recvReady), budget.used)
	}

	buf := make([]byte, 4)
	if n, err := first.Read(buf); err != nil || n != 4 {
		t.Fatalf("first handshake read = %d, %v", n, err)
	}
	if budget.used != 0 {
		t.Fatalf("global handshake budget after read = %d, want 0", budget.used)
	}
	if err := second.handleData(0, []byte{5}); err != nil {
		t.Fatal(err)
	}
	if second.recvNext != 1 || budget.used != 1 {
		t.Fatalf("released budget was not reusable: next=%d used=%d", second.recvNext, budget.used)
	}
	if n, err := second.Read(buf); err != nil || n != 1 {
		t.Fatalf("second handshake read = %d, %v", n, err)
	}
	if budget.used != 0 {
		t.Fatalf("global handshake budget leaked: %d", budget.used)
	}
}

func TestHandshakeSendCopiesShareAndReleaseGlobalBudget(t *testing.T) {
	budget := &testQueuedByteBudget{limit: 4}
	newConn := func() *handshakeConn {
		ctx, cancel := context.WithCancel(context.Background())
		return &handshakeConn{
			inner:          &scriptedBatchConn{},
			budget:         budget,
			maxData:        2,
			maxQueuedBytes: 8,
			ctx:            ctx,
			cancel:         cancel,
			sendNotify:     make(chan struct{}, 1),
			recvNotify:     make(chan struct{}, 1),
			recvQueued:     make(map[uint64][]byte),
		}
	}
	first := newConn()
	second := newConn()
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})

	if n, err := first.Write([]byte{1, 2, 3, 4}); err != nil || n != 4 {
		t.Fatalf("first handshake write = %d, %v", n, err)
	}
	if budget.used != 4 || first.sendQueuedBytes != 4 {
		t.Fatalf("handshake send budget = global %d local %d, want 4/4", budget.used, first.sendQueuedBytes)
	}
	if n, err := second.Write([]byte{5}); err == nil || n != 0 {
		t.Fatalf("second handshake bypassed shared budget: n=%d err=%v", n, err)
	}

	first.sendMu.Lock()
	for _, seg := range first.unacked {
		seg.sentAt = time.Now()
	}
	first.sendMu.Unlock()
	first.handleAck(1)
	if budget.used != 4 || first.sendQueuedBytes != 4 {
		t.Fatalf("partial ACK released retained segment bytes: global=%d local=%d", budget.used, first.sendQueuedBytes)
	}
	first.handleAck(4)
	if budget.used != 0 || first.sendQueuedBytes != 0 || len(first.unacked) != 0 {
		t.Fatalf("full ACK did not release send queue: global=%d local=%d segments=%d",
			budget.used, first.sendQueuedBytes, len(first.unacked))
	}

	if n, err := second.Write([]byte{5}); err != nil || n != 1 {
		t.Fatalf("released handshake send budget was not reusable: n=%d err=%v", n, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.used != 0 || second.sendQueuedBytes != 0 || len(second.unacked) != 0 {
		t.Fatalf("close leaked handshake send queue: global=%d local=%d segments=%d",
			budget.used, second.sendQueuedBytes, len(second.unacked))
	}
}

func TestHandshakeSendQueueBoundsSegments(t *testing.T) {
	c := &handshakeConn{
		maxData:           2,
		maxQueuedBytes:    16,
		maxQueuedSegments: 2,
		sendNotify:        make(chan struct{}, 1),
	}

	if n, err := c.Write([]byte{1, 2, 3, 4, 5}); err == nil || n != 0 {
		t.Fatalf("oversized segment write = %d, %v; want 0 and an error", n, err)
	}
	if len(c.unacked) != 0 || c.sendQueuedBytes != 0 {
		t.Fatalf("rejected write changed queue: segments=%d bytes=%d", len(c.unacked), c.sendQueuedBytes)
	}
	if n, err := c.Write([]byte{1, 2, 3, 4}); err != nil || n != 4 {
		t.Fatalf("bounded segment write = %d, %v; want 4, nil", n, err)
	}
}

func TestHandshakeReceiveBufferIncludesReadyBytesInLimit(t *testing.T) {
	c := &handshakeConn{
		maxQueuedBytes: 4,
		recvQueued:     make(map[uint64][]byte),
		sendNotify:     make(chan struct{}, 1),
		recvNotify:     make(chan struct{}, 1),
	}
	if err := c.handleData(0, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleData(4, []byte{5}); err != nil {
		t.Fatal(err)
	}
	if got := len(c.recvReady); got != 4 {
		t.Fatalf("retained ready bytes = %d, want 4", got)
	}
	if c.recvNext != 4 {
		t.Fatalf("receive offset = %d, want 4", c.recvNext)
	}
}

func TestHandshakeReceiveQueueBoundsSegmentsAndRejectsEmptyData(t *testing.T) {
	c := &handshakeConn{
		maxQueuedBytes:    16,
		maxQueuedSegments: 2,
		recvQueued:        make(map[uint64][]byte),
		sendNotify:        make(chan struct{}, 1),
		recvNotify:        make(chan struct{}, 1),
	}
	if err := c.handleData(1, nil); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []uint64{1, 2, 3} {
		if err := c.handleData(offset, []byte{byte(offset)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(c.recvQueued); got != 2 {
		t.Fatalf("queued segments = %d, want 2", got)
	}
	if got := c.recvQueuedBytes; got != 2 {
		t.Fatalf("queued bytes = %d, want 2", got)
	}
	if _, ok := c.recvQueued[3]; ok {
		t.Fatal("segment beyond queue limit was retained")
	}
}

func TestMalformedHandshakePacketDoesNotAdvanceACK(t *testing.T) {
	tests := []struct {
		name   string
		packet func() []byte
	}{
		{
			name: "short DATA carrying ACK",
			packet: func() []byte {
				packet := make([]byte, handshakeAckHeaderSize)
				packet[0] = handshakePacketTypeData
				packet[1] = handshakePacketVersion
				binary.LittleEndian.PutUint64(packet[2:10], 3)
				return packet
			},
		},
		{
			name: "DATA length mismatch carrying ACK",
			packet: func() []byte {
				packet := make([]byte, handshakeDataHeaderSize+1)
				packet[0] = handshakePacketTypeData
				packet[1] = handshakePacketVersion
				binary.LittleEndian.PutUint64(packet[2:10], 3)
				binary.LittleEndian.PutUint32(packet[18:22], 2)
				return packet
			},
		},
		{
			name: "ACK with trailing byte",
			packet: func() []byte {
				packet := make([]byte, handshakeAckHeaderSize+1)
				packet[0] = handshakePacketTypeAck
				packet[1] = handshakePacketVersion
				binary.LittleEndian.PutUint64(packet[2:10], 3)
				return packet
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &handshakeConn{
				unacked: []*handshakeSegment{{
					offset:  0,
					payload: []byte{1, 2, 3},
					sentAt:  time.Now(),
				}},
			}
			if err := conn.handleInboundPacket(tt.packet()); err != nil {
				t.Fatal(err)
			}
			if conn.sendAck != 0 || len(conn.unacked) != 1 {
				t.Fatalf("malformed packet changed send state: ack=%d unacked=%d", conn.sendAck, len(conn.unacked))
			}
		})
	}
}

func TestValidateReadBatchRejectsInvalidMetadata(t *testing.T) {
	bufs := [][]byte{make([]byte, 8)}
	tests := []struct {
		name  string
		n     int
		sizes []int
	}{
		{name: "negative count", n: -1, sizes: []int{0}},
		{name: "large count", n: 2, sizes: []int{0}},
		{name: "missing size", n: 1, sizes: nil},
		{name: "negative size", n: 1, sizes: []int{-1}},
		{name: "large size", n: 1, sizes: []int{9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateReadBatch(tt.n, bufs, tt.sizes); err == nil {
				t.Fatal("invalid batch metadata was accepted")
			}
		})
	}
}

func TestTalariaUDPWrappersRejectInvalidReadBatchCount(t *testing.T) {
	type reader interface {
		ReadBatch(context.Context, [][]byte, []int) (int, error)
		ReadBatchRetained(context.Context, [][]byte, []int) (int, int64, error)
	}
	tests := []struct {
		name string
		wrap func(*invalidReadCountBatchConn) reader
	}{
		{
			name: "client retry",
			wrap: func(inner *invalidReadCountBatchConn) reader {
				return &retryClientConn{inner: inner}
			},
		},
		{
			name: "server retry",
			wrap: func(inner *invalidReadCountBatchConn) reader {
				return &retryServerConn{batchConn: inner}
			},
		},
		{
			name: "wire",
			wrap: func(inner *invalidReadCountBatchConn) reader {
				return &wireBatchConn{inner: inner}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := &invalidReadCountBatchConn{scriptedBatchConn: &scriptedBatchConn{}}
			wrapped := tt.wrap(inner)
			bufs := [][]byte{make([]byte, 8)}
			sizes := make([]int, 1)
			if n, err := wrapped.ReadBatch(t.Context(), bufs, sizes); n != 0 || err == nil {
				t.Fatalf("ReadBatch() = %d, %v; want 0 and an error", n, err)
			}
			if n, retained, err := wrapped.ReadBatchRetained(t.Context(), bufs, sizes); n != 0 || retained != 0 || err == nil {
				t.Fatalf("ReadBatchRetained() = %d, %d, %v; want 0, 0 and an error", n, retained, err)
			}
			if inner.released != 64 {
				t.Fatalf("released retained bytes = %d, want 64", inner.released)
			}
		})
	}
}

func TestTalariaUDPWrappersRejectInvalidWriteBatchCount(t *testing.T) {
	inner := &invalidReadCountBatchConn{scriptedBatchConn: &scriptedBatchConn{}}
	bufs := [][]byte{testHandshakeStartPacket([]byte{1})}
	sizes := []int{len(bufs[0])}
	tests := []struct {
		name string
		conn batchConn
	}{
		{name: "client retry", conn: &retryClientConn{inner: inner}},
		{name: "server retry", conn: &retryServerConn{batchConn: inner, maxPacket: 1500, bound: true}},
		{name: "wire", conn: &wireBatchConn{inner: inner}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if n, err := tt.conn.WriteBatch(t.Context(), bufs, sizes); n != 0 || err == nil {
				t.Fatalf("WriteBatch() = %d, %v; want 0 and an error", n, err)
			}
		})
	}
}

func FuzzHandshakeInboundPacket(f *testing.F) {
	data := make([]byte, handshakeDataHeaderSize+1)
	data[0] = handshakePacketTypeData
	data[1] = handshakePacketVersion
	binary.LittleEndian.PutUint32(data[18:22], 1)
	data[handshakeDataHeaderSize] = 1
	f.Add(data)
	emptyData := make([]byte, handshakeDataHeaderSize)
	emptyData[0] = handshakePacketTypeData
	emptyData[1] = handshakePacketVersion
	f.Add(emptyData)
	f.Add([]byte{})
	f.Add([]byte{handshakePacketTypeAck, handshakePacketVersion})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			t.Skip()
		}
		c := &handshakeConn{
			maxQueuedBytes: defaultHandshakeMaxQueuedBytes,
			recvQueued:     make(map[uint64][]byte),
			sendNotify:     make(chan struct{}, 1),
			recvNotify:     make(chan struct{}, 1),
		}
		_ = c.handleInboundPacket(raw)
		_ = c.handleInboundPacket(raw)
	})
}

func FuzzEncryptedRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{udptlsDataPacketType})
	f.Add(make([]byte, udptlsDataHeaderSize+16))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			t.Skip()
		}
		// Build through the real constructor so the key schedule, AEAD limits
		// and buffer pools match a live connection. A hand-rolled struct leaves
		// them zero and silently skips the paths worth fuzzing.
		conn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
			sendKey: make([]byte, 32),
			recvKey: make([]byte, 32),
		}, tls.TLS_AES_256_GCM_SHA384, defaultMaxPlainPacket, udptlsModeClient, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := conn.(*udptlsConn)
		buf := append([]byte(nil), raw...)
		plain, keep, _ := c.decryptPacket(udptlsEncryptedPacket{buf: buf, n: len(buf)})
		if keep {
			c.putPlainBuf(plain.buf)
		}
	})
}
