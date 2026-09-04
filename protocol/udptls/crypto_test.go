// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

type blockingReadBatchConn struct {
	*scriptedBatchConn
}

type reentrantDeadlineBatchConn struct {
	*scriptedBatchConn
	onDeadline     func()
	onReadDeadline func()
}

func (c *reentrantDeadlineBatchConn) SetDeadline(time.Time) error {
	if callback := c.onDeadline; callback != nil {
		c.onDeadline = nil
		callback()
	}
	return nil
}

func (c *reentrantDeadlineBatchConn) SetReadDeadline(time.Time) error {
	if callback := c.onReadDeadline; callback != nil {
		c.onReadDeadline = nil
		callback()
	}
	return nil
}

func (c *blockingReadBatchConn) ReadBatch(ctx context.Context, _ [][]byte, _ []int) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestSetReadDeadlineWakesStartedReadPipeline(t *testing.T) {
	inner := &blockingReadBatchConn{scriptedBatchConn: &scriptedBatchConn{}}
	key := bytes.Repeat([]byte{0x41}, 32)
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: append([]byte(nil), key...),
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	c := wrapped.(*udptlsConn)

	result := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, c.maxPacket))
		result <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		c.readStateMu.Lock()
		started := c.readStarted
		c.readStateMu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TalariaUDP read pipeline did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("blocked TalariaUDP read error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not wake the TalariaUDP read")
	}
}

func TestDeadlineCallsAllowReentrantStateAccess(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*udptlsConn, time.Time) error
		arm  func(*reentrantDeadlineBatchConn, func())
	}{
		{
			name: "all",
			set:  (*udptlsConn).SetDeadline,
			arm:  func(conn *reentrantDeadlineBatchConn, callback func()) { conn.onDeadline = callback },
		},
		{
			name: "read",
			set:  (*udptlsConn).SetReadDeadline,
			arm:  func(conn *reentrantDeadlineBatchConn, callback func()) { conn.onReadDeadline = callback },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inner := &reentrantDeadlineBatchConn{scriptedBatchConn: &scriptedBatchConn{}}
			conn := &udptlsConn{inner: inner, readDeadlineChanged: make(chan struct{})}
			test.arm(inner, func() { conn.SetTalariaUDPPreAuthMode(true) })
			done := make(chan error, 1)
			go func() { done <- test.set(conn, time.Now().Add(time.Second)) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("deadline call deadlocked after reentrant state access")
			}
		})
	}
}

func TestTalariaUDPConnCloseUnregistersGroupCallback(t *testing.T) {
	_, conn := newTalariaUDPTestPair(t)
	var unregisterCalls int
	conn.setCloseUnregister(func() { unregisterCalls++ })
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if unregisterCalls != 1 {
		t.Fatalf("close unregister calls = %d want 1", unregisterCalls)
	}
}

func TestTalariaUDPConnCloseClearsTrafficKeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	wrapped, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
		sendKey:  append([]byte(nil), key...),
		recvKey:  append([]byte(nil), key...),
		sendSalt: [udptlsNonceSaltSize]byte{1, 2, 3, 4},
		recvSalt: [udptlsNonceSaltSize]byte{5, 6, 7, 8},
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := wrapped.(*udptlsConn)
	sendKey := conn.sendKey
	recvKey := conn.recvKey
	conn.recvNextKey = append([]byte(nil), key...)
	nextKey := conn.recvNextKey
	conn.recvNextAEAD = conn.recvAEAD
	conn.recvPrevAEAD = conn.recvAEAD
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sendKey, make([]byte, len(sendKey))) || !bytes.Equal(recvKey, make([]byte, len(recvKey))) || !bytes.Equal(nextKey, make([]byte, len(nextKey))) {
		t.Fatal("TalariaUDP traffic key bytes were not cleared")
	}
	if conn.sendKey != nil || conn.recvKey != nil || conn.recvNextKey != nil || conn.sendAEAD != nil || conn.recvAEAD != nil || conn.recvPrevAEAD != nil || conn.recvNextAEAD != nil {
		t.Fatal("TalariaUDP connection retained traffic key objects")
	}
	if conn.sendSalt != [udptlsNonceSaltSize]byte{} || conn.recvSalt != [udptlsNonceSaltSize]byte{} {
		t.Fatal("TalariaUDP nonce salts were not cleared")
	}
}

func TestTalariaUDPConnCloseClearsKeysAfterReentrantPanic(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	inner := &panicCloseBatchConn{scriptedBatchConn: &scriptedBatchConn{}}
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: append([]byte(nil), key...),
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := wrapped.(*udptlsConn)
	inner.onClose = func() { _ = conn.Close() }
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("TalariaUDP close error = %v, want extension panic", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TalariaUDP Close deadlocked on inner connection reentry")
	}
	if conn.sendKey != nil || conn.recvKey != nil || conn.sendAEAD != nil || conn.recvAEAD != nil {
		t.Fatal("TalariaUDP retained traffic keys after inner Close panic")
	}
	if conn.sendSalt != [udptlsNonceSaltSize]byte{} || conn.recvSalt != [udptlsNonceSaltSize]byte{} {
		t.Fatal("TalariaUDP retained nonce salts after inner Close panic")
	}
}

func TestTalariaUDPConnCloseContinuesAfterUnregisterPanic(t *testing.T) {
	inner := &scriptedBatchConn{}
	wrapped, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: bytes.Repeat([]byte{0x41}, 32),
		recvKey: bytes.Repeat([]byte{0x42}, 32),
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := wrapped.(*udptlsConn)
	conn.setCloseUnregister(func() { panic("boom") })
	if err := conn.Close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("TalariaUDP unregister panic error = %v, want extension panic", err)
	}
	inner.mu.Lock()
	closed := inner.closed
	inner.mu.Unlock()
	if !closed {
		t.Fatal("TalariaUDP inner connection was not closed after unregister panic")
	}
	if conn.sendKey != nil || conn.recvKey != nil {
		t.Fatal("TalariaUDP retained traffic keys after unregister panic")
	}
}

type panicCloseBatchConn struct {
	*scriptedBatchConn
	onClose func()
}

func (c *panicCloseBatchConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	panic("boom")
}

func TestDeriveSessionMaterialSeparatesDirections(t *testing.T) {
	state := udptlsConnectionState{
		version:           tls.VersionTLS13,
		handshakeComplete: true,
		cipherSuite:       tls.TLS_AES_256_GCM_SHA384,
		exportKeyingMaterial: func(label string, context []byte, length int) ([]byte, error) {
			h := sha256.New()
			_, _ = h.Write([]byte(label))
			_, _ = h.Write(context)
			material := make([]byte, length)
			copy(material, h.Sum(nil))
			return material, nil
		},
	}
	client, err := deriveSessionMaterial(state, udptlsModeClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := deriveSessionMaterial(state, udptlsModeServer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(client.sendKey, server.recvKey) || !bytes.Equal(client.recvKey, server.sendKey) {
		t.Fatal("client/server directional keys do not match")
	}
	if client.sendSalt != server.recvSalt || client.recvSalt != server.sendSalt {
		t.Fatal("client/server directional salts do not match")
	}
	if bytes.Equal(client.sendKey, client.recvKey) || client.sendSalt == client.recvSalt {
		t.Fatal("send and receive material was not separated")
	}
}

func TestDeriveSessionMaterialRequiresTLS13AndSupportedCipher(t *testing.T) {
	base := udptlsConnectionState{
		handshakeComplete: true,
		version:           tls.VersionTLS12,
		cipherSuite:       tls.TLS_AES_256_GCM_SHA384,
		exportKeyingMaterial: func(string, []byte, int) ([]byte, error) {
			return make([]byte, 32), nil
		},
	}
	if _, err := deriveSessionMaterial(base, udptlsModeClient); err == nil {
		t.Fatal("TLS 1.2 was accepted")
	}
	base.version = tls.VersionTLS13
	base.cipherSuite = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	if _, err := deriveSessionMaterial(base, udptlsModeClient); err == nil {
		t.Fatal("non-TLS-1.3 cipher suite was accepted")
	}
	base.cipherSuite = tls.TLS_AES_128_GCM_SHA256
	base.exportKeyingMaterial = func(_ string, _ []byte, length int) ([]byte, error) {
		return make([]byte, length), nil
	}
	material, err := deriveSessionMaterial(base, udptlsModeClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(material.sendKey) != 32 || len(material.recvKey) != 32 {
		t.Fatalf("AES fallback key lengths = %d/%d, want 32/32", len(material.sendKey), len(material.recvKey))
	}
	base.cipherSuite = tls.TLS_AES_256_GCM_SHA384
	base.exportKeyingMaterial = func(string, []byte, int) ([]byte, error) {
		return nil, errors.New("export failed")
	}
	if _, err := deriveSessionMaterial(base, udptlsModeClient); err == nil {
		t.Fatal("exporter failure was ignored")
	}
}

func TestReplayWindowRejectsDuplicatesAndStaleCounters(t *testing.T) {
	var window udptlsReplayWindow
	if window.Accept(0) {
		t.Fatal("counter zero was accepted")
	}
	if !window.Accept(1) || window.Accept(1) {
		t.Fatal("counter one duplicate handling failed")
	}
	high := uint64(udptlsReplayWindowCap + 100)
	if !window.Accept(high) {
		t.Fatal("new high counter was rejected")
	}
	if window.Accept(1) {
		t.Fatal("stale counter outside the replay window was accepted")
	}
	if !window.Accept(high-1) || window.Accept(high-1) {
		t.Fatal("in-window reordered counter handling failed")
	}
}

func TestReplayWindowHandlesCountersNearUint64Limit(t *testing.T) {
	var window udptlsReplayWindow
	if !window.Accept(math.MaxUint64 - 2) {
		t.Fatal("initial high counter was rejected")
	}
	if !window.Accept(math.MaxUint64) {
		t.Fatal("MaxUint64 counter was rejected due to arithmetic overflow")
	}
	if !window.Accept(math.MaxUint64-1) || window.Accept(math.MaxUint64-1) {
		t.Fatal("near-limit reordered counter handling failed")
	}
}

// newTalariaUDPTestPair returns two TalariaUDP connections that share directional
// keys, so one can encrypt what the other decrypts.
func newTalariaUDPTestPair(t *testing.T) (*udptlsConn, *udptlsConn) {
	t.Helper()
	key := bytes.Repeat([]byte{0x4c}, 32)
	salt := [udptlsNonceSaltSize]byte{1, 2, 3, 4}
	senderConn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
		sendKey:  append([]byte(nil), key...),
		recvKey:  bytes.Repeat([]byte{0x5d}, 32),
		sendSalt: salt,
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverConn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
		sendKey:  bytes.Repeat([]byte{0x6e}, 32),
		recvKey:  append([]byte(nil), key...),
		recvSalt: salt,
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	return senderConn.(*udptlsConn), receiverConn.(*udptlsConn)
}

func TestWriteBatchAdvancesEpochInsteadOfFailing(t *testing.T) {
	inner := &scriptedBatchConn{}
	key := bytes.Repeat([]byte{0x7a}, 32)
	conn, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
		sendKey: key,
		recvKey: append([]byte(nil), key...),
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*udptlsConn)

	epoch0Key := append([]byte(nil), c.sendKey...)
	c.writeSeq = udptlsPacketsPerEpoch - 1
	// This batch straddles the boundary: one record in epoch 0, one in epoch 1.
	n, err := c.WriteBatch(context.Background(), [][]byte{{1}, {2}}, []int{1, 1})
	if err != nil || n != 2 {
		t.Fatalf("write across epoch boundary = n=%d err=%v, want 2/nil", n, err)
	}
	if c.sendEpoch != 1 {
		t.Fatalf("send epoch = %d, want 1", c.sendEpoch)
	}
	if bytes.Equal(c.sendKey, epoch0Key) {
		t.Fatal("send key was not ratcheted when the epoch advanced")
	}
	// The sequence restarts, so the epoch field is what distinguishes the records.
	if c.writeSeq != udptlsFirstSequence {
		t.Fatalf("sequence after epoch advance = %d, want %d", c.writeSeq, udptlsFirstSequence)
	}
	writes := inner.snapshotWrites()
	if len(writes) != 2 {
		t.Fatalf("inner writes = %d, want 2", len(writes))
	}
	if got := binary.LittleEndian.Uint32(writes[0][udptlsEpochOffset:]); got != 0 {
		t.Fatalf("first record epoch = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(writes[1][udptlsEpochOffset:]); got != 1 {
		t.Fatalf("second record epoch = %d, want 1", got)
	}

	// The epoch field is 32 bits wide, so its exhaustion is still fatal rather
	// than silently wrapping onto a key that has already been used.
	c.sendEpoch = udptlsMaxEpoch
	c.writeSeq = udptlsPacketsPerEpoch
	if _, err := c.WriteBatch(context.Background(), [][]byte{{3}}, []int{1}); !errors.Is(err, errTalariaUDPKeyUsageExhausted) {
		t.Fatalf("write at epoch exhaustion = %v, want key usage limit", err)
	}
}

func TestEpochRoundTripsAndToleratesReordering(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)

	encrypt := func(payload string) []byte {
		t.Helper()
		epoch, sequence, err := sender.nextSendRecordLocked()
		if err != nil {
			t.Fatal(err)
		}
		encBufs := [][]byte{make([]byte, sender.maxCipher)}
		encSizes := make([]int, 1)
		sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte(payload), epoch, sequence)
		return append([]byte(nil), encBufs[0][:encSizes[0]]...)
	}
	decrypt := func(raw []byte) (string, bool) {
		t.Helper()
		plain, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: raw, n: len(raw)})
		if err != nil {
			t.Fatalf("decrypt error = %v", err)
		}
		if !keep {
			return "", false
		}
		out := string(plain.buf[:plain.n])
		receiver.putPlainBuf(plain.buf)
		return out, true
	}

	// Land on the last record of epoch 0, then cross into epoch 1.
	sender.writeSeq = udptlsPacketsPerEpoch - 1
	epoch0 := encrypt("epoch zero")
	epoch1 := encrypt("epoch one")
	if sender.sendEpoch != 1 {
		t.Fatalf("send epoch = %d, want 1", sender.sendEpoch)
	}

	// The epoch-1 record arrives first and must move the receiver forward.
	if got, ok := decrypt(epoch1); !ok || got != "epoch one" {
		t.Fatalf("epoch 1 record = %q ok=%v", got, ok)
	}
	if receiver.recvEpoch != 1 {
		t.Fatalf("receive epoch = %d, want 1", receiver.recvEpoch)
	}
	// The reordered epoch-0 record must still open under the retained key.
	if got, ok := decrypt(epoch0); !ok || got != "epoch zero" {
		t.Fatalf("reordered epoch 0 record = %q ok=%v", got, ok)
	}
}

func TestReplayWindowSpansEpochs(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)

	record := func(epoch, sequence uint32, payload string) []byte {
		t.Helper()
		// Derive the sender key for the requested epoch.
		for sender.sendEpoch < epoch {
			if err := sender.advanceSendEpochLocked(); err != nil {
				t.Fatal(err)
			}
		}
		encBufs := [][]byte{make([]byte, sender.maxCipher)}
		encSizes := make([]int, 1)
		sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte(payload), epoch, sequence)
		return append([]byte(nil), encBufs[0][:encSizes[0]]...)
	}
	accept := func(raw []byte) bool {
		t.Helper()
		plain, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: raw, n: len(raw)})
		if err != nil {
			t.Fatalf("decrypt error = %v", err)
		}
		if keep {
			receiver.putPlainBuf(plain.buf)
		}
		return keep
	}

	first := record(0, 1, "epoch 0 sequence 1")
	if !accept(first) {
		t.Fatal("first record was rejected")
	}
	if accept(first) {
		t.Fatal("replayed record was accepted")
	}

	// Same sequence number, next epoch: a distinct record, not a replay.
	nextEpoch := record(1, 1, "epoch 1 sequence 1")
	if !accept(nextEpoch) {
		t.Fatal("sequence 1 of the next epoch was rejected as a replay")
	}
	if accept(nextEpoch) {
		t.Fatal("replay across the epoch boundary was accepted")
	}
	// The previous epoch keeps its own window, so its replays stay detected while
	// its key is still accepted.
	if accept(first) {
		t.Fatal("replay from the retired epoch was accepted after the epoch advanced")
	}
}

func TestForgedEpochCannotRetireReceiveKey(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)

	forged := make([]byte, udptlsDataHeaderSize+32)
	forged[0] = udptlsDataPacketType
	binary.LittleEndian.PutUint32(forged[udptlsEpochOffset:], 1)
	binary.LittleEndian.PutUint32(forged[udptlsSequenceOffset:], 1)
	if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: forged, n: len(forged)}); keep || err != nil {
		t.Fatalf("forged next-epoch record = keep=%v err=%v, want dropped", keep, err)
	}
	if receiver.recvEpoch != 0 {
		t.Fatalf("receive epoch = %d after a forged record, want 0", receiver.recvEpoch)
	}
	if len(receiver.recvNextKey) == 0 {
		t.Fatal("next receive key was not retained")
	}
	pendingKey := &receiver.recvNextKey[0]
	if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: forged, n: len(forged)}); keep || err != nil {
		t.Fatalf("second forged next-epoch record = keep=%v err=%v, want dropped", keep, err)
	}
	if &receiver.recvNextKey[0] != pendingKey {
		t.Fatal("forged next-epoch record derived another receive key")
	}

	// A genuine epoch-0 record must still open.
	encBufs := [][]byte{make([]byte, sender.maxCipher)}
	encSizes := make([]int, 1)
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte("still works"), 0, 1)
	plain, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: encBufs[0][:encSizes[0]], n: encSizes[0]})
	if err != nil || !keep {
		t.Fatalf("genuine record after forgery = keep=%v err=%v", keep, err)
	}
	receiver.putPlainBuf(plain.buf)

	if err := sender.advanceSendEpochLocked(); err != nil {
		t.Fatal(err)
	}
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte("next epoch"), 1, 1)
	plain, keep, err = receiver.decryptPacket(udptlsEncryptedPacket{buf: encBufs[0][:encSizes[0]], n: encSizes[0]})
	if err != nil || !keep {
		t.Fatalf("genuine next-epoch record = keep=%v err=%v", keep, err)
	}
	receiver.putPlainBuf(plain.buf)
	if receiver.recvEpoch != 1 || receiver.recvNextKey != nil || receiver.recvNextAEAD != nil {
		t.Fatal("authenticated next epoch was not committed")
	}
	if &receiver.recvKey[0] != pendingKey {
		t.Fatal("authenticated next epoch did not use the retained receive key")
	}
}

func TestDistantEpochIsDroppedWithoutDerivingKeys(t *testing.T) {
	_, receiver := newTalariaUDPTestPair(t)
	baseKey := append([]byte(nil), receiver.recvKey...)

	for _, epoch := range []uint32{2, 100, 1 << 20, udptlsMaxEpoch} {
		if _, _, ok := receiver.recvAEADForEpoch(epoch); ok {
			t.Fatalf("epoch %d beyond the skew bound was accepted", epoch)
		}
	}
	if receiver.recvEpoch != 0 {
		t.Fatalf("receive epoch = %d, want 0", receiver.recvEpoch)
	}
	if !bytes.Equal(receiver.recvKey, baseKey) {
		t.Fatal("receive key changed while rejecting distant epochs")
	}

	// One ahead is the only forward step that may be derived.
	if _, commit, ok := receiver.recvAEADForEpoch(1); !ok || commit == nil {
		t.Fatalf("epoch 1 = ok=%v commit=%v, want acceptable with a pending commit", ok, commit != nil)
	}
}

func TestEpochKeysAreForwardSecret(t *testing.T) {
	sender, _ := newTalariaUDPTestPair(t)

	epoch0 := append([]byte(nil), sender.sendKey...)
	if err := sender.advanceSendEpochLocked(); err != nil {
		t.Fatal(err)
	}
	epoch1 := append([]byte(nil), sender.sendKey...)
	if bytes.Equal(epoch0, epoch1) {
		t.Fatal("epoch 1 key equals epoch 0")
	}

	// Ratcheting is one-way: epoch 1 must not reproduce epoch 0, and the same
	// input must always yield the same next epoch.
	again, err := ratchetKey(sender.spec.hashNew, epoch0, sender.spec.keyLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, epoch1) {
		t.Fatal("ratchet is not deterministic")
	}
	forward, err := ratchetKey(sender.spec.hashNew, epoch1, sender.spec.keyLen)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(forward, epoch0) {
		t.Fatal("ratcheting forward reproduced an earlier epoch key")
	}
}

func TestDecryptPacketUsesPerSuiteIntegrityLimit(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)

	if want := uint64(1) << 52; receiver.maxAuthFailures != want {
		t.Fatalf("AES-GCM integrity limit = %d, want %d", receiver.maxAuthFailures, want)
	}

	encBufs := [][]byte{make([]byte, sender.maxCipher)}
	encSizes := make([]int, 1)
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte("payload"), 0, 1)
	tampered := append([]byte(nil), encBufs[0][:encSizes[0]]...)
	tampered[len(tampered)-1] ^= 0x01

	// Far above the old 2^20 bound, and the tunnel must survive.
	receiver.recvAuthFails = 1 << 21
	if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: tampered, n: len(tampered)}); keep || err != nil {
		t.Fatalf("tampered packet = keep=%v err=%v, want silently dropped", keep, err)
	}

	// At the real limit the key must be retired.
	receiver.recvAuthFails = receiver.maxAuthFailures - 1
	if _, _, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: tampered, n: len(tampered)}); !errors.Is(err, errTalariaUDPAuthFailureLimit) {
		t.Fatalf("decrypt at integrity limit = %v, want authentication failure limit", err)
	}
	if _, err := receiver.Read(make([]byte, receiver.maxPacket)); !errors.Is(err, errTalariaUDPAuthFailureLimit) {
		t.Fatalf("read after integrity limit = %v, want authentication failure limit", err)
	}
}

func TestDecryptPacketAuthenticatesValidRecordAfterFailureBurst(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)

	encBufs := [][]byte{make([]byte, sender.maxCipher)}
	encSizes := make([]int, 1)
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte("payload"), 0, 1)
	valid := append([]byte(nil), encBufs[0][:encSizes[0]]...)
	tampered := append([]byte(nil), encBufs[0][:encSizes[0]]...)
	tampered[len(tampered)-1] ^= 0x01

	const failureBurst = 256
	for range failureBurst {
		if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: tampered, n: len(tampered)}); err != nil || keep {
			t.Fatalf("tampered packet = keep=%v err=%v", keep, err)
		}
	}
	if got := receiver.recvAuthFails; got != failureBurst {
		t.Fatalf("authentication attempts = %d want %d", got, failureBurst)
	}

	plain, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: valid, n: len(valid)})
	if err != nil || !keep {
		t.Fatalf("valid packet after failure burst = keep=%v err=%v", keep, err)
	}
	receiver.putPlainBuf(plain.buf)

	_, other := newTalariaUDPTestPair(t)
	if other.recvAuthFails != 0 {
		t.Fatalf("other session authentication failures = %d, want 0", other.recvAuthFails)
	}
}

func TestDecryptPacketRejectsImpossibleHeaderBeforeKeyDerivation(t *testing.T) {
	sender, receiver := newTalariaUDPTestPair(t)
	originalNewAEAD := receiver.spec.newAEAD
	derivations := 0
	receiver.spec.newAEAD = func(key []byte) (cipher.AEAD, error) {
		derivations++
		return originalNewAEAD(key)
	}

	forged := make([]byte, udptlsDataHeaderSize+udptlsMaxAEADOverhead)
	forged[0] = udptlsDataPacketType
	for _, header := range []struct {
		epoch    uint32
		sequence uint32
	}{
		{epoch: receiver.recvEpoch + 1, sequence: udptlsPacketsPerEpoch + 1},
		{epoch: receiver.recvEpoch + 2, sequence: udptlsFirstSequence},
	} {
		binary.LittleEndian.PutUint32(forged[udptlsEpochOffset:], header.epoch)
		binary.LittleEndian.PutUint32(forged[udptlsSequenceOffset:], header.sequence)
		if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: forged, n: len(forged)}); err != nil || keep {
			t.Fatalf("impossible header = keep=%v err=%v", keep, err)
		}
	}
	if derivations != 0 {
		t.Fatalf("impossible headers triggered %d key derivations", derivations)
	}
	if receiver.recvAuthFails != 0 {
		t.Fatalf("impossible headers reached AEAD: failures = %d", receiver.recvAuthFails)
	}

	encBufs := [][]byte{make([]byte, sender.maxCipher)}
	encSizes := make([]int, 1)
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, []byte("valid"), 0, 1)
	plain, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: encBufs[0], n: encSizes[0]})
	if err != nil || !keep {
		t.Fatalf("valid record after forged headers = keep=%v err=%v", keep, err)
	}
	receiver.putPlainBuf(plain.buf)
}

func TestTamperedCiphertextIsDroppedBeforeReplayStateAdvances(t *testing.T) {
	key := bytes.Repeat([]byte{0x4c}, 32)
	salt := [udptlsNonceSaltSize]byte{1, 2, 3, 4}
	senderConn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
		sendKey:  append([]byte(nil), key...),
		recvKey:  bytes.Repeat([]byte{0x5d}, 32),
		sendSalt: salt,
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverConn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
		sendKey:  bytes.Repeat([]byte{0x6e}, 32),
		recvKey:  append([]byte(nil), key...),
		recvSalt: salt,
	}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	sender := senderConn.(*udptlsConn)
	receiver := receiverConn.(*udptlsConn)
	plain := []byte("protected vpn payload")
	encBufs := [][]byte{make([]byte, sender.maxCipher)}
	encSizes := make([]int, 1)
	sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, plain, 0, 1)
	valid := append([]byte(nil), encBufs[0][:encSizes[0]]...)
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0x01

	if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: tampered, n: len(tampered)}); err != nil || keep {
		t.Fatalf("tampered packet = keep=%v err=%v, want silent drop", keep, err)
	}
	if receiver.replay.highest != 0 {
		t.Fatalf("replay window advanced after failed authentication: %d", receiver.replay.highest)
	}
	activity := receiver.inner.(*scriptedBatchConn)
	if got := activity.snapshotActiveMarks(); got != 0 {
		t.Fatalf("tampered packet committed %d activity marks", got)
	}

	got, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: valid, n: len(valid)})
	if err != nil || !keep {
		t.Fatalf("valid packet = keep=%v err=%v", keep, err)
	}
	if !bytes.Equal(got.buf[:got.n], plain) {
		t.Fatalf("plaintext = %q, want %q", got.buf[:got.n], plain)
	}
	receiver.putPlainBuf(got.buf)
	if marks := activity.snapshotActiveMarks(); marks != 1 {
		t.Fatalf("authenticated packet activity marks = %d want 1", marks)
	}
	if _, keep, err := receiver.decryptPacket(udptlsEncryptedPacket{buf: valid, n: len(valid)}); err != nil || keep {
		t.Fatalf("duplicate packet = keep=%v err=%v, want silent drop", keep, err)
	}
	if marks := activity.snapshotActiveMarks(); marks != 1 {
		t.Fatalf("replayed packet refreshed activity: marks = %d", marks)
	}
}

func TestPreAuthModeIgnoresUnauthenticatedPackets(t *testing.T) {
	handshakeStart := make([]byte, handshakeDataHeaderSize)
	handshakeStart[0] = handshakePacketTypeData
	handshakeStart[1] = handshakePacketVersion
	manyInvalid := make([][]byte, 32)
	for i := range manyInvalid {
		manyInvalid[i] = []byte{handshakePacketTypeData}
	}
	tests := []struct {
		name   string
		prefix [][]byte
	}{
		{name: "none"},
		{name: "forged handshake start", prefix: [][]byte{handshakeStart}},
		{name: "more than old ignored packet limit", prefix: manyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x9d}, 32)
			salt := [udptlsNonceSaltSize]byte{9, 8, 7, 6}
			senderConn, err := newTalariaUDPConn(&scriptedBatchConn{}, udptlsSessionMaterial{
				sendKey:  append([]byte(nil), key...),
				recvKey:  bytes.Repeat([]byte{0x2a}, 32),
				sendSalt: salt,
			}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeServer, nil)
			if err != nil {
				t.Fatal(err)
			}
			sender := senderConn.(*udptlsConn)
			plain := []byte("application auth request")
			encBufs := [][]byte{make([]byte, sender.maxCipher)}
			encSizes := make([]int, 1)
			sender.encryptPacket(sender.sendAEAD, encBufs, encSizes, 0, plain, 0, 1)
			reads := make([][][]byte, 0, len(tt.prefix)+1)
			for _, raw := range tt.prefix {
				reads = append(reads, [][]byte{append([]byte(nil), raw...)})
			}
			reads = append(reads, [][]byte{append([]byte(nil), encBufs[0][:encSizes[0]]...)})
			inner := &scriptedBatchConn{reads: reads}
			receiverConn, err := newTalariaUDPConn(inner, udptlsSessionMaterial{
				sendKey:  bytes.Repeat([]byte{0x3b}, 32),
				recvKey:  append([]byte(nil), key...),
				recvSalt: salt,
			}, tls.TLS_AES_256_GCM_SHA384, 1500, udptlsModeServer, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiver := receiverConn.(*udptlsConn)
			receiver.SetTalariaUDPPreAuthMode(true)
			buf := make([]byte, 1500)
			n, err := receiver.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], plain) {
				t.Fatalf("plaintext = %q, want %q", buf[:n], plain)
			}
			receiver.readStateMu.Lock()
			started := receiver.readStarted
			receiver.readStateMu.Unlock()
			if started {
				t.Fatal("pre-auth read started the regular pipeline")
			}
			if widths := inner.snapshotReadBatchWidths(); len(widths) != len(reads) {
				t.Fatalf("pre-auth reads = %d, want %d", len(widths), len(reads))
			}
		})
	}
}

func TestNonceForRecordLaysOutSaltEpochAndSequence(t *testing.T) {
	salt := [udptlsNonceSaltSize]byte{1, 2, 3, 4}
	nonce := nonceForRecord(salt, 0x04030201, 0x08070605)
	want := [12]byte{1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8}
	if nonce != want {
		t.Fatalf("nonce = %x want %x", nonce, want)
	}

	// A different epoch with the same sequence must produce a different nonce.
	if other := nonceForRecord(salt, 0x04030202, 0x08070605); other == nonce {
		t.Fatal("epoch is not part of the nonce")
	}
	// And the salt must keep the two directions apart.
	otherSalt := [udptlsNonceSaltSize]byte{9, 9, 9, 9}
	if other := nonceForRecord(otherSalt, 0x04030201, 0x08070605); other == nonce {
		t.Fatal("salt is not part of the nonce")
	}
}
