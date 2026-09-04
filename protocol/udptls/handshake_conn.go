// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	handshakePacketVersion = 1

	handshakePacketTypeData = 1
	handshakePacketTypeAck  = 2

	handshakeAckHeaderSize  = 1 + 1 + 8
	handshakeDataHeaderSize = 1 + 1 + 8 + 8 + 4

	defaultHandshakePayloadSize    = 1024
	defaultHandshakeReadPoll       = 50 * time.Millisecond
	defaultHandshakeWritePoll      = 50 * time.Millisecond
	defaultHandshakeRetransmit     = 150 * time.Millisecond
	defaultHandshakeSendWindow     = 16 * 1024
	defaultHandshakeMaxQueuedBytes = 1 << 20
	defaultHandshakeMaxSegments    = 1024
	defaultPostHandshakeQueue      = 64
)

type queuedByteBudget interface {
	ReserveQueuedBytes(int64) bool
	ReleaseQueuedBytes(int64)
}

type retainedBatchConn interface {
	ReadBatchRetained(context.Context, [][]byte, []int) (int, int64, error)
	ReleaseQueuedBytes(int64)
}

type handshakeConn struct {
	inner               batchConn
	budget              queuedByteBudget
	retainPostHandshake bool

	maxPacket int
	maxData   int

	retransmitInterval time.Duration
	sendWindowBytes    uint64
	maxQueuedBytes     uint64
	maxQueuedSegments  int
	readPollInterval   time.Duration
	writePollInterval  time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once

	sendNotify chan struct{}
	recvNotify chan struct{}

	sendMu          sync.Mutex
	sendNext        uint64
	sendAck         uint64
	unacked         []*handshakeSegment
	sendQueuedBytes uint64
	sendErr         error

	recvMu          sync.Mutex
	recvNext        uint64
	recvReady       []byte
	recvQueued      map[uint64][]byte
	recvQueuedBytes uint64
	ackDirty        bool
	recvErr         error

	postHandshakeMu      sync.Mutex
	postHandshakePackets []udptlsEncryptedPacket
	postHandshakeBytes   uint64

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	wg sync.WaitGroup
}

type handshakeSegment struct {
	offset  uint64
	payload []byte
	sentAt  time.Time
}

func newHandshakeConn(inner batchConn, maxPacket int) (*handshakeConn, error) {
	return newHandshakeConnWithReservedOverhead(inner, maxPacket, 0, false)
}

func newHandshakeConnWithReservedOverhead(inner batchConn, maxPacket int, reservedOverhead int, retainPostHandshake bool) (*handshakeConn, error) {
	if inner == nil {
		return nil, errors.New("TalariaUDP handshake inner conn is nil")
	}
	if reservedOverhead < 0 {
		return nil, fmt.Errorf("TalariaUDP handshake reserved overhead invalid: %d", reservedOverhead)
	}
	if reservedOverhead == 0 && maxPacket <= handshakeDataHeaderSize {
		maxPacket = 1500
	}
	maxData := maxPacket - handshakeDataHeaderSize - reservedOverhead
	if maxData > defaultHandshakePayloadSize {
		maxData = defaultHandshakePayloadSize
	}
	if maxData <= 0 {
		return nil, fmt.Errorf("TalariaUDP handshake max payload invalid: %d", maxData)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &handshakeConn{
		inner:               inner,
		retainPostHandshake: retainPostHandshake,
		maxPacket:           maxPacket,
		maxData:             maxData,
		retransmitInterval:  defaultHandshakeRetransmit,
		sendWindowBytes:     defaultHandshakeSendWindow,
		maxQueuedBytes:      defaultHandshakeMaxQueuedBytes,
		maxQueuedSegments:   defaultHandshakeMaxSegments,
		readPollInterval:    defaultHandshakeReadPoll,
		writePollInterval:   defaultHandshakeWritePoll,
		ctx:                 ctx,
		cancel:              cancel,
		sendNotify:          make(chan struct{}, 1),
		recvNotify:          make(chan struct{}, 1),
		recvQueued:          make(map[uint64][]byte, 8),
	}
	c.budget, _ = inner.(queuedByteBudget)
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
	return c, nil
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.recvMu.Lock()
		if len(c.recvReady) > 0 {
			n := copy(p, c.recvReady)
			c.recvReady = append(c.recvReady[:0], c.recvReady[n:]...)
			if c.budget != nil {
				c.budget.ReleaseQueuedBytes(int64(n))
			}
			c.recvMu.Unlock()
			return n, nil
		}
		err := c.recvErr
		c.recvMu.Unlock()
		if err != nil {
			return 0, err
		}

		if err := c.waitRecv(); err != nil {
			return 0, err
		}
	}
}

func (c *handshakeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if c.sendErr != nil {
		return 0, c.sendErr
	}
	if c.sendQueuedBytes > c.maxQueuedBytes || uint64(len(p)) > c.maxQueuedBytes-c.sendQueuedBytes {
		return 0, fmt.Errorf("TalariaUDP handshake queued bytes exceeded: queued=%d write=%d limit=%d", c.sendQueuedBytes, len(p), c.maxQueuedBytes)
	}
	segments := len(p) / c.maxData
	if len(p)%c.maxData != 0 {
		segments++
	}
	if len(c.unacked) > c.queueSegmentLimit() || segments > c.queueSegmentLimit()-len(c.unacked) {
		return 0, fmt.Errorf("TalariaUDP handshake queued segments exceeded: queued=%d write=%d limit=%d", len(c.unacked), segments, c.queueSegmentLimit())
	}
	if c.budget != nil && !c.budget.ReserveQueuedBytes(int64(len(p))) {
		return 0, fmt.Errorf("TalariaUDP handshake shared queued bytes exceeded: write=%d", len(p))
	}
	c.sendQueuedBytes += uint64(len(p))

	written := 0
	for written < len(p) {
		chunkLen := len(p) - written
		if chunkLen > c.maxData {
			chunkLen = c.maxData
		}
		payload := make([]byte, chunkLen)
		copy(payload, p[written:written+chunkLen])
		c.unacked = append(c.unacked, &handshakeSegment{
			offset:  c.sendNext,
			payload: payload,
		})
		c.sendNext += uint64(chunkLen)
		written += chunkLen
	}
	c.signalSend()
	return written, nil
}

// Close stops the temporary handshake stream state machine but intentionally
// leaves the underlying datagram transport open so the caller can reuse it for
// post-handshake encrypted packets.
func (c *handshakeConn) Close() error {
	c.close(false)
	return nil
}

func (c *handshakeConn) closeAndTakePostHandshakePackets() []udptlsEncryptedPacket {
	c.close(true)
	return c.takePostHandshakePackets()
}

func (c *handshakeConn) close(preservePostHandshake bool) {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.inner.SetDeadline(time.Now())
		c.setSendErr(net.ErrClosed)
		c.setRecvErr(net.ErrClosed)
		c.signalSend()
		c.signalRecv()
		c.wg.Wait()

		c.sendMu.Lock()
		sendQueuedBytes := c.sendQueuedBytes
		c.sendQueuedBytes = 0
		clear(c.unacked)
		c.unacked = nil
		c.sendMu.Unlock()
		if c.budget != nil {
			c.budget.ReleaseQueuedBytes(int64(sendQueuedBytes))

			c.recvMu.Lock()
			c.budget.ReleaseQueuedBytes(int64(c.recvQueuedBytes) + int64(len(c.recvReady)))
			c.recvQueuedBytes = 0
			c.recvReady = nil
			clear(c.recvQueued)
			c.recvMu.Unlock()
		}
		if !preservePostHandshake {
			releaseEncryptedPacketReservations(c.budget, c.takePostHandshakePackets())
		}
	})
}

func (c *handshakeConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *handshakeConn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }

func (c *handshakeConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.signalSend()
	c.signalRecv()
	return nil
}

func (c *handshakeConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	c.signalRecv()
	return nil
}

func (c *handshakeConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	c.signalSend()
	return nil
}

// Drain waits until every queued handshake byte has been cumulatively
// acknowledged by the peer. The protocol switches to the AEAD data plane only
// after Drain succeeds so late retransmissions from the reliable handshake
// shim do not leak into the packet data phase.
func (c *handshakeConn) Drain(ctx context.Context) error {
	ticker := time.NewTicker(c.retransmitInterval / 2)
	defer ticker.Stop()

	for {
		c.sendMu.Lock()
		sendErr := c.sendErr
		pending := len(c.unacked)
		c.sendMu.Unlock()
		_, ackDirty := c.snapshotAck()
		if sendErr != nil {
			return sendErr
		}
		// Wait for both directions of the temporary reliable shim to quiesce.
		// Returning while ackDirty is still set can close the shim before the
		// peer sees the final cumulative ACK, which leaves it stuck retransmitting
		// the last handshake bytes and timing out under load.
		if pending == 0 && !ackDirty {
			return nil
		}
		c.signalSend()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.ctx.Done():
			c.sendMu.Lock()
			sendErr = c.sendErr
			c.sendMu.Unlock()
			if sendErr != nil {
				return sendErr
			}
			return net.ErrClosed
		case <-ticker.C:
		}
	}
}

func (c *handshakeConn) readLoop() {
	defer c.wg.Done()

	buf := make([]byte, c.maxPacket)
	sizes := []int{0}
	buffers := [][]byte{buf}

	for {
		if err := c.ctx.Err(); err != nil {
			return
		}
		if err := c.inner.SetReadDeadline(time.Now().Add(c.readPollInterval)); err != nil {
			err = fmt.Errorf("TalariaUDP handshake set read deadline: %w", err)
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalSend()
			c.signalRecv()
			return
		}
		retained := int64(0)
		n, err := 0, error(nil)
		retainedReader, retainsBudget := c.inner.(retainedBatchConn)
		if retainsBudget {
			n, retained, err = retainedReader.ReadBatchRetained(c.ctx, buffers, sizes)
		} else {
			n, err = c.inner.ReadBatch(c.ctx, buffers, sizes)
		}
		if err != nil {
			if retained > 0 {
				retainedReader.ReleaseQueuedBytes(retained)
			}
			if c.ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalSend()
			c.signalRecv()
			return
		}
		if err := validateReadBatch(n, buffers, sizes); err != nil {
			if retained > 0 {
				retainedReader.ReleaseQueuedBytes(retained)
			}
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalSend()
			c.signalRecv()
			return
		}
		if n != 1 || sizes[0] <= 0 {
			if retained > 0 {
				retainedReader.ReleaseQueuedBytes(retained)
			}
			continue
		}
		err = c.handleInboundPacket(buf[:sizes[0]])
		if retained > 0 {
			retainedReader.ReleaseQueuedBytes(retained)
		}
		if err != nil {
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalSend()
			c.signalRecv()
			return
		}
	}
}

func (c *handshakeConn) writeLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.retransmitInterval / 2)
	defer ticker.Stop()

	for {
		if err := c.ctx.Err(); err != nil {
			return
		}
		packet, ackUpto, ackIncluded, err := c.nextOutboundPacket()
		if err != nil {
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalRecv()
			return
		}
		if packet == nil {
			select {
			case <-c.ctx.Done():
				return
			case <-c.sendNotify:
			case <-ticker.C:
			}
			continue
		}

		if err := c.inner.SetWriteDeadline(time.Now().Add(c.writePollInterval)); err != nil {
			err = fmt.Errorf("TalariaUDP handshake set write deadline: %w", err)
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalRecv()
			return
		}
		written, err := c.inner.WriteBatch(c.ctx, [][]byte{packet}, []int{len(packet)})
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-c.ctx.Done():
					return
				case <-ticker.C:
				}
				continue
			}
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalRecv()
			return
		}
		if written != 1 {
			err = io.ErrShortWrite
			c.setSendErr(err)
			c.setRecvErr(err)
			c.cancel()
			c.signalRecv()
			return
		}
		if ackIncluded {
			c.clearAckDirty(ackUpto)
		}
	}
}

func (c *handshakeConn) handleInboundPacket(pkt []byte) error {
	if len(pkt) < handshakeAckHeaderSize {
		return nil
	}

	if !isHandshakePacket(pkt) {
		if pkt[0] == handshakePacketTypeData || pkt[0] == handshakePacketTypeAck {
			return nil
		}
		if c.retainPostHandshake {
			c.queuePostHandshakePacket(pkt)
		}
		return nil
	}

	ackUpto := binary.LittleEndian.Uint64(pkt[2:10])
	switch pkt[0] {
	case handshakePacketTypeAck:
		c.handleAck(ackUpto)
		return nil
	case handshakePacketTypeData:
		offset := binary.LittleEndian.Uint64(pkt[10:18])
		c.handleAck(ackUpto)
		return c.handleData(offset, pkt[handshakeDataHeaderSize:])
	default:
		return nil
	}
}

func isHandshakePacket(pkt []byte) bool {
	if len(pkt) < handshakeAckHeaderSize {
		return false
	}
	if pkt[1] != handshakePacketVersion {
		return false
	}
	switch pkt[0] {
	case handshakePacketTypeAck:
		return len(pkt) == handshakeAckHeaderSize
	case handshakePacketTypeData:
		if len(pkt) < handshakeDataHeaderSize {
			return false
		}
		payloadLen := binary.LittleEndian.Uint32(pkt[18:22])
		return uint64(payloadLen) == uint64(len(pkt)-handshakeDataHeaderSize)
	default:
		return false
	}
}

func isHandshakeStartPacket(pkt []byte) bool {
	if len(pkt) < handshakeDataHeaderSize {
		return false
	}
	if !isHandshakePacket(pkt) || pkt[0] != handshakePacketTypeData {
		return false
	}
	return binary.LittleEndian.Uint64(pkt[10:18]) == 0
}

func (c *handshakeConn) queuePostHandshakePacket(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	c.postHandshakeMu.Lock()
	defer c.postHandshakeMu.Unlock()
	if len(c.postHandshakePackets) >= defaultPostHandshakeQueue {
		return
	}
	nextBytes := c.postHandshakeBytes + uint64(len(pkt))
	if nextBytes > c.maxQueuedBytes {
		return
	}
	reserved := int64(0)
	if c.budget != nil {
		reserved = int64(len(pkt))
		if !c.budget.ReserveQueuedBytes(reserved) {
			return
		}
	}
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	c.postHandshakePackets = append(c.postHandshakePackets, udptlsEncryptedPacket{
		buf:      buf,
		n:        len(buf),
		reserved: reserved,
	})
	c.postHandshakeBytes = nextBytes
}

func (c *handshakeConn) takePostHandshakePackets() []udptlsEncryptedPacket {
	c.postHandshakeMu.Lock()
	defer c.postHandshakeMu.Unlock()
	packets := c.postHandshakePackets
	c.postHandshakePackets = nil
	c.postHandshakeBytes = 0
	return packets
}

func (c *handshakeConn) handleAck(ackUpto uint64) {
	c.sendMu.Lock()
	var releasedBytes uint64
	defer func() {
		c.sendMu.Unlock()
		if releasedBytes > 0 && c.budget != nil {
			c.budget.ReleaseQueuedBytes(int64(releasedBytes))
		}
	}()
	if ackUpto > c.highestSentAckLocked() {
		return
	}
	if ackUpto <= c.sendAck {
		return
	}
	c.sendAck = ackUpto
	dropN := 0
	for dropN < len(c.unacked) {
		seg := c.unacked[dropN]
		if seg.offset+uint64(len(seg.payload)) > ackUpto {
			break
		}
		releasedBytes += uint64(len(seg.payload))
		dropN++
	}
	if dropN > 0 {
		copy(c.unacked, c.unacked[dropN:])
		remaining := len(c.unacked) - dropN
		clear(c.unacked[remaining:])
		c.unacked = c.unacked[:remaining]
		c.sendQueuedBytes -= releasedBytes
	}
}

func (c *handshakeConn) handleData(offset uint64, payload []byte) error {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	if len(payload) == 0 {
		c.ackDirty = true
		c.signalSend()
		return nil
	}
	if offset < c.recvNext {
		c.ackDirty = true
		c.signalSend()
		return nil
	}
	if _, ok := c.recvQueued[offset]; ok {
		c.ackDirty = true
		c.signalSend()
		return nil
	}
	if len(c.recvQueued) >= c.queueSegmentLimit() {
		c.ackDirty = true
		c.signalSend()
		return nil
	}

	// Retry binds the temporary carrier to one reachable-source exchange, but the
	// peer is not TLS-authenticated yet. Bound retained bytes and offsets until AEAD.
	if !c.withinRecvWindowLocked(offset, len(payload)) {
		c.ackDirty = true
		c.signalSend()
		return nil
	}
	if c.budget != nil && !c.budget.ReserveQueuedBytes(int64(len(payload))) {
		c.ackDirty = true
		c.signalSend()
		return nil
	}

	segment := make([]byte, len(payload))
	copy(segment, payload)
	c.recvQueued[offset] = segment
	c.recvQueuedBytes += uint64(len(segment))

	for {
		next, ok := c.recvQueued[c.recvNext]
		if !ok {
			break
		}
		delete(c.recvQueued, c.recvNext)
		c.recvQueuedBytes -= uint64(len(next))
		c.recvReady = append(c.recvReady, next...)
		c.recvNext += uint64(len(next))
	}
	c.ackDirty = true
	c.signalSend()
	c.signalRecv()
	return nil
}

func (c *handshakeConn) queueSegmentLimit() int {
	if c.maxQueuedSegments <= 0 {
		return defaultHandshakeMaxSegments
	}
	return c.maxQueuedSegments
}

func (c *handshakeConn) highestSentAckLocked() uint64 {
	highest := c.sendAck
	for _, seg := range c.unacked {
		if seg == nil || seg.sentAt.IsZero() {
			continue
		}
		end := seg.offset + uint64(len(seg.payload))
		if end > highest {
			highest = end
		}
	}
	return highest
}

func (c *handshakeConn) withinRecvWindowLocked(offset uint64, payloadLen int) bool {
	if payloadLen < 0 {
		return false
	}
	payloadLenU64 := uint64(payloadLen)
	if payloadLenU64 > c.maxQueuedBytes {
		return false
	}
	windowEnd := c.recvNext + c.maxQueuedBytes
	if windowEnd < c.recvNext {
		windowEnd = ^uint64(0)
	}
	end := offset + payloadLenU64
	if end < offset {
		return false
	}
	if offset >= windowEnd || end > windowEnd {
		return false
	}
	retainedBytes := c.recvQueuedBytes + uint64(len(c.recvReady))
	if retainedBytes < c.recvQueuedBytes {
		return false
	}
	return retainedBytes <= c.maxQueuedBytes && payloadLenU64 <= c.maxQueuedBytes-retainedBytes
}

func (c *handshakeConn) nextOutboundPacket() (packet []byte, ackUpto uint64, ackIncluded bool, err error) {
	now := time.Now()

	c.sendMu.Lock()
	sendErr := c.sendErr
	var seg *handshakeSegment
	windowEnd := c.sendAck + c.sendWindowBytes
	for _, candidate := range c.unacked {
		if candidate.offset >= windowEnd {
			break
		}
		if candidate.sentAt.IsZero() || now.Sub(candidate.sentAt) >= c.retransmitInterval {
			candidate.sentAt = now
			seg = candidate
			break
		}
	}
	c.sendMu.Unlock()
	if sendErr != nil {
		return nil, 0, false, sendErr
	}

	ackUpto, ackDirty := c.snapshotAck()
	if seg != nil {
		pkt := make([]byte, handshakeDataHeaderSize+len(seg.payload))
		pkt[0] = handshakePacketTypeData
		pkt[1] = handshakePacketVersion
		binary.LittleEndian.PutUint64(pkt[2:10], ackUpto)
		binary.LittleEndian.PutUint64(pkt[10:18], seg.offset)
		binary.LittleEndian.PutUint32(pkt[18:22], uint32(len(seg.payload)))
		copy(pkt[handshakeDataHeaderSize:], seg.payload)
		return pkt, ackUpto, ackDirty, nil
	}
	if ackDirty {
		pkt := make([]byte, handshakeAckHeaderSize)
		pkt[0] = handshakePacketTypeAck
		pkt[1] = handshakePacketVersion
		binary.LittleEndian.PutUint64(pkt[2:10], ackUpto)
		return pkt, ackUpto, true, nil
	}
	return nil, 0, false, nil
}

func (c *handshakeConn) snapshotAck() (uint64, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	return c.recvNext, c.ackDirty
}

func (c *handshakeConn) clearAckDirty(ackUpto uint64) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if c.recvNext == ackUpto {
		c.ackDirty = false
	}
}

func (c *handshakeConn) waitRecv() error {
	deadline := c.readDeadlineValue()
	for {
		if err := c.ctx.Err(); err != nil {
			c.recvMu.Lock()
			err = c.recvErr
			c.recvMu.Unlock()
			if err != nil {
				return err
			}
			return net.ErrClosed
		}
		timer := deadlineTimer(deadline)
		select {
		case <-c.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-c.recvNotify:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-timerChan(timer):
			return deadlineExceededError("TalariaUDP handshake read")
		}
	}
}

func (c *handshakeConn) readDeadlineValue() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *handshakeConn) signalSend() {
	select {
	case c.sendNotify <- struct{}{}:
	default:
	}
}

func (c *handshakeConn) signalRecv() {
	select {
	case c.recvNotify <- struct{}{}:
	default:
	}
}

func (c *handshakeConn) setSendErr(err error) {
	if err == nil {
		return
	}
	c.sendMu.Lock()
	if c.sendErr == nil {
		c.sendErr = err
	}
	c.sendMu.Unlock()
}

func (c *handshakeConn) setRecvErr(err error) {
	if err == nil {
		return
	}
	c.recvMu.Lock()
	if c.recvErr == nil {
		c.recvErr = err
	}
	c.recvMu.Unlock()
}

func deadlineTimer(deadline time.Time) *time.Timer {
	if deadline.IsZero() {
		return nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		d = time.Nanosecond
	}
	return time.NewTimer(d)
}

func timerChan(timer *time.Timer) <-chan time.Time {
	if timer == nil {
		return nil
	}
	return timer.C
}

func deadlineExceededError(op string) error {
	return &net.OpError{Op: op, Err: osDeadlineExceeded{}}
}

type osDeadlineExceeded struct{}

func (osDeadlineExceeded) Error() string   { return "i/o timeout" }
func (osDeadlineExceeded) Timeout() bool   { return true }
func (osDeadlineExceeded) Temporary() bool { return true }
