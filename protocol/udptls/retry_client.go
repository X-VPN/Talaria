// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxRetryChallengesPerHandshake = 8
	maxRetryResponsesPerHandshake  = 8
)

var (
	errRetryChallengeLimit = errors.New("TalariaUDP retry challenge limit exceeded")
	errRetryResponseLimit  = errors.New("TalariaUDP retry response limit exceeded")
)

type retryClientConn struct {
	inner     batchConn
	maxPacket int

	mu                  sync.Mutex
	firstPacket         []byte
	retryResponse       []byte
	authBinding         [retryPacketBindingSize]byte
	authTag             [retryCookieTagSize]byte
	authReady           bool
	retryChallenges     [maxRetryChallengesPerHandshake][retryChallengeSize]byte
	retryChallengeCount int
	retryResponses      int
}

// newRetryClientConn adds stateless Retry handling around the client's handshake datagrams.
func newRetryClientConn(inner batchConn, maxPacket int) *retryClientConn {
	return &retryClientConn{inner: inner, maxPacket: maxPacket}
}

func (c *retryClientConn) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := c.ReadBatch(context.Background(), [][]byte{p}, sizes)
	if n == 0 {
		return 0, err
	}
	return sizes[0], err
}

func (c *retryClientConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *retryClientConn) Close() error {
	c.clearRetryState()
	return c.inner.Close()
}

func (c *retryClientConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *retryClientConn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }

func (c *retryClientConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}

func (c *retryClientConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

func (c *retryClientConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

func (c *retryClientConn) BatchSize() int { return c.inner.BatchSize() }

func (c *retryClientConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	for {
		n, err := c.inner.ReadBatch(ctx, bufs, sizes)
		if validateErr := validateReadBatch(n, bufs, sizes); validateErr != nil {
			return 0, validateErr
		}
		visible := 0
		for i := 0; i < n; i++ {
			sz := sizes[i]
			if sz < 0 || sz > len(bufs[i]) {
				return visible, io.ErrUnexpectedEOF
			}
			packet := bufs[i][:sz]
			if len(packet) == retryChallengeSize && isRetryFrame(packet, retryFrameTypeChallenge) {
				response, responseErr := c.responseForChallenge(packet)
				if responseErr != nil {
					return visible, responseErr
				}
				if len(response) > 0 {
					written, writeErr := c.inner.WriteBatch(ctx, [][]byte{response}, []int{len(response)})
					if writeErr != nil {
						return visible, writeErr
					}
					if written != 1 {
						return visible, io.ErrShortWrite
					}
				}
				continue
			}
			binding, tag, authReady := c.authState()
			var inner []byte
			if authReady {
				inner, _ = openHandshakeAuthPacket(packet, binding[:], tag[:], handshakeAuthDirectionServer)
				if inner == nil && len(packet) > 0 && packet[0] == udptlsDataPacketType {
					inner = packet
				}
			}
			if inner == nil {
				continue
			}
			if visible != i || len(inner) != len(packet) {
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

// ReadBatchRetained keeps the underlying queue reservation until the
// authenticated packet has either been dropped or transferred to handshakeConn.
func (c *retryClientConn) ReadBatchRetained(ctx context.Context, bufs [][]byte, sizes []int) (int, int64, error) {
	retainedReader, ok := c.inner.(retainedBatchConn)
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
		packet := bufs[0][:size]
		if len(packet) == retryChallengeSize && isRetryFrame(packet, retryFrameTypeChallenge) {
			response, responseErr := c.responseForChallenge(packet)
			retainedReader.ReleaseQueuedBytes(retained)
			if responseErr != nil {
				return 0, 0, responseErr
			}
			if len(response) > 0 {
				written, writeErr := c.inner.WriteBatch(ctx, [][]byte{response}, []int{len(response)})
				if writeErr != nil {
					return 0, 0, writeErr
				}
				if written != 1 {
					return 0, 0, io.ErrShortWrite
				}
			}
			if err != nil {
				return 0, 0, err
			}
			continue
		}
		binding, tag, authReady := c.authState()
		var inner []byte
		if authReady {
			inner, _ = openHandshakeAuthPacket(packet, binding[:], tag[:], handshakeAuthDirectionServer)
			if inner == nil && len(packet) > 0 && packet[0] == udptlsDataPacketType {
				inner = packet
			}
		}
		if inner == nil {
			retainedReader.ReleaseQueuedBytes(retained)
			if err != nil {
				return 0, 0, err
			}
			continue
		}
		if len(inner) != len(packet) {
			copy(bufs[0], inner)
		}
		sizes[0] = len(inner)
		return 1, retained, nil
	}
}

func (c *retryClientConn) ReserveQueuedBytes(n int64) bool {
	if budget, ok := c.inner.(queuedByteBudget); ok {
		return budget.ReserveQueuedBytes(n)
	}
	return true
}

func (c *retryClientConn) ReleaseQueuedBytes(n int64) {
	if budget, ok := c.inner.(queuedByteBudget); ok {
		budget.ReleaseQueuedBytes(n)
	}
}

func (c *retryClientConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	for i := 0; i < len(bufs) && i < len(sizes); i++ {
		sz := sizes[i]
		if sz < 0 || sz > len(bufs[i]) {
			continue
		}
		if validHandshakeStartPacket(bufs[i][:sz]) {
			c.rememberFirstPacket(bufs[i][:sz])
			break
		}
	}
	firstPacket, retryResponse, binding, tag, authReady := c.writeState()
	if !authReady {
		return writeBatchValidated(ctx, c.inner, bufs, sizes)
	}
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
		packet := bufs[i][:size]
		if bytes.Equal(packet, firstPacket) {
			packets[i] = retryResponse
		} else {
			sealed, ok := sealHandshakeAuthPacket(packet, binding[:], tag[:], handshakeAuthDirectionClient, c.maxPacket)
			if !ok {
				return 0, errors.New("TalariaUDP handshake packet exceeds authenticated maximum")
			}
			packets[i] = sealed
		}
		packetSizes[i] = len(packets[i])
	}
	return writeBatchValidated(ctx, c.inner, packets, packetSizes)
}

func (c *retryClientConn) rememberFirstPacket(packet []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstPacket != nil {
		return
	}
	c.firstPacket = append([]byte(nil), packet...)
}

// responseForChallenge drops unbound input and independently limits distinct challenges and total responses.
func (c *retryClientConn) responseForChallenge(challenge []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstPacket == nil {
		return nil, nil
	}
	response, ok := buildRetryResponse(challenge, c.firstPacket)
	if !ok || len(response) > c.maxPacket {
		return nil, nil
	}
	seen := false
	for i := 0; i < c.retryChallengeCount; i++ {
		if bytes.Equal(challenge, c.retryChallenges[i][:]) {
			seen = true
			break
		}
	}
	if !seen && c.retryChallengeCount >= maxRetryChallengesPerHandshake {
		return nil, errRetryChallengeLimit
	}
	if c.retryResponses >= maxRetryResponsesPerHandshake {
		return nil, errRetryResponseLimit
	}
	if !seen {
		copy(c.retryChallenges[c.retryChallengeCount][:], challenge)
		c.retryChallengeCount++
	}
	c.retryResponses++
	if !c.authReady {
		c.retryResponse = append([]byte(nil), response...)
		copy(c.authBinding[:], challenge[retryFrameBindingOffset:retryFrameTagOffset])
		copy(c.authTag[:], challenge[retryFrameTagOffset:retryChallengeSize])
		c.authReady = true
	}
	return append([]byte(nil), c.retryResponse...), nil
}

// clearRetryState releases the retained initial packet and challenge history after the handshake ends.
func (c *retryClientConn) clearRetryState() {
	c.mu.Lock()
	clear(c.firstPacket)
	clear(c.retryResponse)
	clear(c.authBinding[:])
	clear(c.authTag[:])
	clear(c.retryChallenges[:])
	c.firstPacket = nil
	c.retryResponse = nil
	c.authReady = false
	c.retryChallengeCount = 0
	c.retryResponses = 0
	c.mu.Unlock()
}

// authState snapshots the selected Retry authentication material for inbound verification.
func (c *retryClientConn) authState() ([retryPacketBindingSize]byte, [retryCookieTagSize]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authBinding, c.authTag, c.authReady
}

// writeState snapshots immutable Retry state for one outbound batch.
func (c *retryClientConn) writeState() ([]byte, []byte, [retryPacketBindingSize]byte, [retryCookieTagSize]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.firstPacket...), append([]byte(nil), c.retryResponse...), c.authBinding, c.authTag, c.authReady
}
