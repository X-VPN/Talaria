// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
)

const (
	handshakeAuthVersion = 1

	handshakeAuthDirectionClient = 1
	handshakeAuthDirectionServer = 2

	handshakeAuthDirectionOffset = 5
	handshakeAuthBindingOffset   = handshakeAuthDirectionOffset + 1
	handshakeAuthPayloadOffset   = handshakeAuthBindingOffset + retryPacketBindingSize
	handshakeAuthTagSize         = 16
	handshakeAuthOverhead        = handshakeAuthPayloadOffset + handshakeAuthTagSize
)

var (
	handshakeAuthMagic = [4]byte{'E', 'V', 'R', 'H'}
	handshakeAuthLabel = []byte("talaria-udp-handshake-auth")
)

type retryServerConn struct {
	batchConn
	gate      *retryCookieGate
	maxPacket int

	mu      sync.RWMutex
	binding [retryPacketBindingSize]byte
	tag     [retryCookieTagSize]byte
	bound   bool
}

// newRetryServerConn validates handshake datagrams against the admitted Retry response.
func newRetryServerConn(inner batchConn, gate *retryCookieGate, maxPacket int) (*retryServerConn, error) {
	if inner == nil || gate == nil {
		return nil, errors.New("TalariaUDP server handshake authentication is unavailable")
	}
	return &retryServerConn{batchConn: inner, gate: gate, maxPacket: maxPacket}, nil
}

// Read exposes only Retry-bound handshake packets and post-handshake AEAD records.
func (c *retryServerConn) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := c.ReadBatch(context.Background(), [][]byte{p}, sizes)
	if n == 0 {
		return 0, err
	}
	return sizes[0], err
}

// Write applies the Retry-bound bearer MAC to a single server handshake datagram.
func (c *retryServerConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// ReadBatch drops unauthenticated handshake input without exposing it to ACK bookkeeping.
func (c *retryServerConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	for {
		n, err := c.batchConn.ReadBatch(ctx, bufs, sizes)
		if validateErr := validateReadBatch(n, bufs, sizes); validateErr != nil {
			return 0, validateErr
		}
		visible := 0
		for i := 0; i < n; i++ {
			size := sizes[i]
			if size < 0 || size > len(bufs[i]) {
				return visible, io.ErrUnexpectedEOF
			}
			packet := bufs[i][:size]
			inner, ok := c.openInbound(packet)
			if !ok {
				continue
			}
			if visible != i {
				copy(bufs[visible], inner)
			} else if len(inner) != len(packet) {
				copy(bufs[visible], inner)
			}
			sizes[visible] = len(inner)
			visible++
		}
		if visible > 0 {
			return visible, nil
		}
		if err != nil {
			return 0, err
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}
}

// ReadBatchRetained preserves udpsession's shared byte reservation while the
// authenticated wrapper validates and hands one packet to the handshake cache.
func (c *retryServerConn) ReadBatchRetained(ctx context.Context, bufs [][]byte, sizes []int) (int, int64, error) {
	retainedReader, ok := c.batchConn.(retainedBatchConn)
	if !ok {
		n, err := c.ReadBatch(ctx, bufs, sizes)
		return n, 0, err
	}
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, 0, nil
	}
	for {
		n, retained, err := retainedReader.ReadBatchRetained(ctx, bufs[:1], sizes[:1])
		if validateErr := validateReadBatch(n, bufs[:1], sizes[:1]); validateErr != nil {
			if retained > 0 {
				retainedReader.ReleaseQueuedBytes(retained)
			}
			return 0, 0, validateErr
		}
		if n == 0 {
			if retained > 0 {
				retainedReader.ReleaseQueuedBytes(retained)
			}
			return 0, 0, err
		}
		size := sizes[0]
		if size < 0 || size > len(bufs[0]) {
			retainedReader.ReleaseQueuedBytes(retained)
			return 0, 0, io.ErrUnexpectedEOF
		}
		inner, valid := c.openInbound(bufs[0][:size])
		if !valid {
			retainedReader.ReleaseQueuedBytes(retained)
			if err != nil {
				return 0, 0, err
			}
			continue
		}
		if len(inner) != size {
			copy(bufs[0], inner)
		}
		sizes[0] = len(inner)
		return 1, retained, nil
	}
}

func (c *retryServerConn) ReserveQueuedBytes(n int64) bool {
	if budget, ok := c.batchConn.(queuedByteBudget); ok {
		return budget.ReserveQueuedBytes(n)
	}
	return true
}

func (c *retryServerConn) ReleaseQueuedBytes(n int64) {
	if budget, ok := c.batchConn.(queuedByteBudget); ok {
		budget.ReleaseQueuedBytes(n)
	}
}

// WriteBatch applies the Retry-bound bearer MAC after Retry admission.
func (c *retryServerConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	binding, tag, ok := c.authState()
	if !ok {
		return 0, errors.New("TalariaUDP server handshake authentication is not established")
	}
	return writeAuthenticatedHandshakeBatch(ctx, c.batchConn, bufs, sizes, c.maxPacket, binding[:], tag[:], handshakeAuthDirectionServer)
}

// openInbound establishes Retry state once, then accepts only matching bearer-MAC frames.
func (c *retryServerConn) openInbound(packet []byte) ([]byte, bool) {
	binding, tag, bound := c.authState()
	if bound {
		if inner, ok := openHandshakeAuthPacket(packet, binding[:], tag[:], handshakeAuthDirectionClient); ok {
			return inner, true
		}
		if len(packet) > 0 && packet[0] == udptlsDataPacketType {
			return packet, true
		}
		return nil, false
	}

	issued, packetBinding, packetTag, inner, ok := parseRetryResponse(packet)
	if !ok || !validHandshakeStartPacket(inner) || !c.gate.verify(issued, packetBinding, packetTag, inner, c.RemoteAddr()) {
		return nil, false
	}
	c.mu.Lock()
	copy(c.binding[:], packetBinding)
	copy(c.tag[:], packetTag)
	c.bound = true
	c.mu.Unlock()
	return inner, true
}

// authState snapshots immutable per-handshake authentication material.
func (c *retryServerConn) authState() ([retryPacketBindingSize]byte, [retryCookieTagSize]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binding, c.tag, c.bound
}

// clearAuthState erases temporary Retry authentication material after the TLS handshake.
func (c *retryServerConn) clearAuthState() {
	c.mu.Lock()
	clear(c.binding[:])
	clear(c.tag[:])
	c.bound = false
	c.mu.Unlock()
}

// writeAuthenticatedHandshakeBatch seals a batch without changing caller-owned buffers.
func writeAuthenticatedHandshakeBatch(ctx context.Context, inner batchConn, bufs [][]byte, sizes []int, maxPacket int, binding, tag []byte, direction byte) (int, error) {
	if len(sizes) < len(bufs) {
		return 0, errors.New("TalariaUDP handshake write sizes too small")
	}
	packets := make([][]byte, len(bufs))
	packetSizes := make([]int, len(bufs))
	for i := range bufs {
		size := sizes[i]
		if size < 0 || size > len(bufs[i]) {
			return 0, errors.New("TalariaUDP handshake write size is invalid")
		}
		packet, ok := sealHandshakeAuthPacket(bufs[i][:size], binding, tag, direction, maxPacket)
		if !ok {
			return 0, errors.New("TalariaUDP handshake packet exceeds authenticated maximum")
		}
		packets[i] = packet
		packetSizes[i] = len(packet)
	}
	return writeBatchValidated(ctx, inner, packets, packetSizes)
}

// sealHandshakeAuthPacket binds one handshake frame to its Retry bearer and direction.
func sealHandshakeAuthPacket(packet, binding, tag []byte, direction byte, maxPacket int) ([]byte, bool) {
	if !isHandshakePacket(packet) || len(binding) != retryPacketBindingSize || len(tag) != retryCookieTagSize {
		return nil, false
	}
	size := handshakeAuthOverhead + len(packet)
	if size > maxPacket {
		return nil, false
	}
	sealed := make([]byte, size)
	copy(sealed[:4], handshakeAuthMagic[:])
	sealed[4] = handshakeAuthVersion
	sealed[handshakeAuthDirectionOffset] = direction
	copy(sealed[handshakeAuthBindingOffset:handshakeAuthPayloadOffset], binding)
	copy(sealed[handshakeAuthPayloadOffset:size-handshakeAuthTagSize], packet)
	sum := handshakeAuthTag(sealed[:size-handshakeAuthTagSize], binding, tag, direction)
	copy(sealed[size-handshakeAuthTagSize:], sum[:handshakeAuthTagSize])
	clear(sum[:])
	return sealed, true
}

// openHandshakeAuthPacket checks the Retry bearer MAC before exposing ACK or payload.
func openHandshakeAuthPacket(packet, binding, tag []byte, direction byte) ([]byte, bool) {
	if len(packet) < handshakeAuthOverhead+handshakeAckHeaderSize ||
		len(binding) != retryPacketBindingSize ||
		len(tag) != retryCookieTagSize ||
		packet[0] != handshakeAuthMagic[0] ||
		packet[1] != handshakeAuthMagic[1] ||
		packet[2] != handshakeAuthMagic[2] ||
		packet[3] != handshakeAuthMagic[3] ||
		packet[4] != handshakeAuthVersion ||
		packet[handshakeAuthDirectionOffset] != direction ||
		!hmac.Equal(packet[handshakeAuthBindingOffset:handshakeAuthPayloadOffset], binding) {
		return nil, false
	}
	tagOffset := len(packet) - handshakeAuthTagSize
	expected := handshakeAuthTag(packet[:tagOffset], binding, tag, direction)
	if !hmac.Equal(packet[tagOffset:], expected[:handshakeAuthTagSize]) {
		clear(expected[:])
		return nil, false
	}
	clear(expected[:])
	inner := packet[handshakeAuthPayloadOffset:tagOffset]
	return inner, isHandshakePacket(inner)
}

// handshakeAuthTag derives a direction-specific bearer key from the public Retry tag.
func handshakeAuthTag(packet, binding, tag []byte, direction byte) [sha256.Size]byte {
	keyMAC := hmac.New(sha256.New, tag)
	_, _ = keyMAC.Write(handshakeAuthLabel)
	_, _ = keyMAC.Write([]byte{direction})
	_, _ = keyMAC.Write(binding)
	key := keyMAC.Sum(nil)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(packet)
	var sum [sha256.Size]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}
