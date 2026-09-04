// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/udpsession"
)

const (
	udptlsDataPacketType = 16

	// Data record header: type(1) ‖ epoch(4) ‖ sequence(4).
	//
	// The epoch is carried explicitly rather than inferred from the sequence, so
	// the record says which key protects it. That keeps the rekey trigger a
	// policy decision instead of an arithmetic consequence of the packet count,
	// and lets a reader - or an auditor - tell which key is in use without
	// reproducing the sender's counter.
	udptlsEpochOffset    = 1
	udptlsSequenceOffset = 5
	udptlsDataHeaderSize = 1 + 4 + 4
	// Every TLS 1.3 AEAD supported by this carrier uses a 16-byte tag.
	udptlsMaxAEADOverhead = 16

	udptlsReplayWindowCap = 4096
	udptlsPipelineSize    = 64

	// udptlsPacketsPerEpoch is how many records one directional key protects
	// before the sender advances the epoch. It keeps a full bit of margin below
	// the RFC 9001 AES-GCM confidentiality bound for 64 KiB packets, the
	// tightest limit among the supported suites.
	udptlsPacketsPerEpoch = 1 << 22

	// udptlsMaxEpochSkew bounds how far ahead of the current receive epoch a
	// record may claim to be. Deriving the next epoch costs an HKDF expansion and
	// happens before authentication can succeed, so an unbounded window would let
	// a spoofed epoch force arbitrary work. One is all a peer can legitimately be
	// ahead: epochs advance one at a time.
	udptlsMaxEpochSkew = 1

	// udptlsMaxEpoch is the last epoch that fits the 32-bit header field. Total
	// capacity is 2^32 epochs times 2^22 records, about 2^54 records.
	udptlsMaxEpoch = uint32(1<<32 - 1)

	// Sequence numbers start at 1 within every epoch, so a zero replay position
	// is always invalid and needs no special case.
	udptlsFirstSequence = uint32(1)
)

var (
	errTalariaUDPKeyUsageExhausted = errors.New("TalariaUDP key usage limit reached")
	errTalariaUDPAuthFailureLimit  = errors.New("TalariaUDP authentication failure limit reached")
	errTalariaUDPQueueMemoryLimit  = errors.New("TalariaUDP queued memory limit reached")
)

// Replay state is per epoch, mirroring key retention exactly: one window for the
// current receive epoch and one for the previous.
//
// A single window keyed on a combined epoch/sequence position does not work.
// Sequences restart each epoch, so any such position jumps forward when the epoch
// advances - by the epoch's whole budget - which pushes records still in flight
// from the previous epoch outside a fixed-width window. They would be dropped as
// stale even though their key is retained, defeating the retention. Keeping one
// window per epoch also means the rekey trigger can move to a timer without
// silently breaking replay detection across the boundary.

type udptlsConn struct {
	inner          batchConn
	budget         queuedByteBudget
	activityMarker interface{ MarkActive() }

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendSalt [udptlsNonceSaltSize]byte
	recvSalt [udptlsNonceSaltSize]byte

	// Epoch state. spec carries the suite's AEAD limits and HKDF hash. sendKey
	// and recvKey are the keys of the current epoch in each direction, retained
	// only so the next epoch can be ratcheted from them: the exporter root is
	// discarded once epoch 0 exists, so an earlier epoch cannot be recovered from
	// a later one.
	//
	// recvPrevAEAD holds the previous receive epoch for records that were
	// reordered across the boundary. It is the only backwards tolerance; anything
	// older is dropped.
	spec            udptlsCipherSpec
	sendKey         []byte
	sendEpoch       uint32
	recvKey         []byte
	recvEpoch       uint32
	recvPrevAEAD    cipher.AEAD
	recvNextKey     []byte
	recvNextAEAD    cipher.AEAD
	maxAuthFailures uint64

	batchSize    int
	maxPacket    int
	maxCipher    int
	readPipeline bool

	writeMu       sync.Mutex
	writeSeq      uint32
	writeBufs     [][]byte
	writeSizes    []int
	writeReserved int64

	readMu sync.Mutex

	readStartOnce sync.Once
	readStateMu   sync.Mutex
	readStarted   bool
	preAuthMode   bool
	readCancel    context.CancelFunc
	plainPktCh    chan udptlsPlainPacket
	readWG        sync.WaitGroup
	readErrMu     sync.Mutex
	readErr       error
	replay        udptlsReplayWindow
	replayPrev    udptlsReplayWindow
	recvAuthFails uint64
	// A buffer checked out from either receive pool keeps its full shared-budget
	// reservation until it is evicted or the connection closes.
	encPool    chan []byte
	plainPool  chan []byte
	pendingEnc []udptlsEncryptedPacket

	opGate          sync.RWMutex
	closed          bool
	closeState      atomic.Uint32
	closeErrMu      sync.Mutex
	closeErr        error
	opsWG           sync.WaitGroup
	registrationMu  sync.Mutex
	closeUnregister func()

	deadlineMu          sync.RWMutex
	readDeadline        time.Time
	readDeadlineChanged chan struct{}
	writeDeadline       time.Time
}

type udptlsReplayWindow struct {
	highest uint64
	seen    [udptlsReplayWindowCap / 64]uint64
}

type udptlsEncryptedPacket struct {
	buf      []byte
	n        int
	reserved int64
	// pooled means encPool owns the backing array and its maxCipher reservation.
	pooled bool
}

type udptlsPlainPacket struct {
	buf      []byte
	n        int
	reserved int64
	// pooled means plainPool owns the backing array and its maxPacket reservation.
	pooled bool
}

type udptlsDataPath struct {
	batchSize    int
	readPipeline bool
}

func newTalariaUDPConn(inner batchConn, material udptlsSessionMaterial, cipherSuite uint16, maxPacket int, mode udptlsMode, pendingEnc []udptlsEncryptedPacket) (_ batchConn, err error) {
	defer clear(material.sendKey)
	defer clear(material.recvKey)
	defer clear(material.sendSalt[:])
	defer clear(material.recvSalt[:])
	budget, _ := inner.(queuedByteBudget)
	defer func() {
		if err != nil {
			releaseEncryptedPacketReservations(budget, pendingEnc)
		}
	}()
	spec, err := cipherSpecFromSuite(cipherSuite)
	if err != nil {
		return nil, err
	}
	sendAEAD, recvAEAD, err := material.newAEADPair(cipherSuite)
	if err != nil {
		return nil, err
	}
	if maxPacket <= 0 {
		maxPacket = defaultMaxPlainPacket
	}
	maxCipher := maxPacket + udptlsDataHeaderSize + sendAEAD.Overhead()
	if sendAEAD.Overhead() > udptlsMaxAEADOverhead || maxCipher > udpsession.MaxUDPPayloadIPv6 {
		return nil, fmt.Errorf("TalariaUDP max packet %d exceeds UDP wire limit", maxPacket)
	}
	dataPath := resolveTalariaUDPDataPath(mode, runtime.GOOS, inner.BatchSize())
	activityMarker, _ := inner.(interface{ MarkActive() })
	c := &udptlsConn{
		inner:          inner,
		budget:         budget,
		activityMarker: activityMarker,
		sendAEAD:       sendAEAD,
		recvAEAD:       recvAEAD,
		sendSalt:       material.sendSalt,
		recvSalt:       material.recvSalt,
		spec:           spec,
		sendKey:        append([]byte(nil), material.sendKey...),
		recvKey:        append([]byte(nil), material.recvKey...),
		// The integrity limit bounds forged packets that fail authentication.
		// Using the real per-suite RFC 9001 value matters: a much lower bound
		// turns a cryptographic safety margin into a cheap way for anyone who
		// knows the five-tuple to tear down an established tunnel.
		maxAuthFailures:     spec.integrityLimit,
		batchSize:           dataPath.batchSize,
		maxPacket:           maxPacket,
		maxCipher:           maxCipher,
		readPipeline:        dataPath.readPipeline,
		pendingEnc:          pendingEnc,
		readDeadlineChanged: make(chan struct{}),
	}
	poolSize := c.resolvePipelineSize()
	c.encPool = make(chan []byte, poolSize)
	c.plainPool = make(chan []byte, poolSize)
	return c, nil
}

func releaseEncryptedPacketReservations(budget queuedByteBudget, packets []udptlsEncryptedPacket) {
	for i := range packets {
		if budget != nil && packets[i].reserved > 0 {
			budget.ReleaseQueuedBytes(packets[i].reserved)
		}
		packets[i] = udptlsEncryptedPacket{}
	}
}

func (c *udptlsConn) Read(p []byte) (int, error) {
	sizes := [1]int{}
	n, err := c.ReadBatch(context.Background(), [][]byte{p}, sizes[:])
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (c *udptlsConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *udptlsConn) Close() error {
	if c == nil {
		return nil
	}
	if !c.closeState.CompareAndSwap(0, 1) {
		if c.closeState.Load() != 2 {
			return nil
		}
		c.closeErrMu.Lock()
		err := c.closeErr
		c.closeErrMu.Unlock()
		return err
	}
	c.opGate.Lock()
	c.closed = true
	c.opGate.Unlock()
	closeErr := c.unregisterFromCloser()

	c.readStateMu.Lock()
	readCancel := c.readCancel
	c.readStateMu.Unlock()
	if readCancel != nil {
		readCancel()
	}

	if !extension.IsNil(c.inner) {
		closeErr = errors.Join(closeErr, extension.Do("TalariaUDP inner connection close", c.inner.Close))
	}
	c.opsWG.Wait()
	c.readWG.Wait()
	c.releaseEncryptedPackets(c.takePendingEncryptedPackets())
	c.drainPlainPackets()
	c.drainReceiveBufferPools()
	c.releaseQueuedBytes(c.writeReserved)
	c.writeReserved = 0
	c.writeBufs = nil
	c.writeSizes = nil
	clear(c.sendKey)
	clear(c.recvKey)
	clear(c.recvNextKey)
	c.sendKey = nil
	c.recvKey = nil
	c.recvNextKey = nil
	clear(c.sendSalt[:])
	clear(c.recvSalt[:])
	c.sendAEAD = nil
	c.recvAEAD = nil
	c.recvPrevAEAD = nil
	c.recvNextAEAD = nil
	c.spec = udptlsCipherSpec{}
	c.closeErrMu.Lock()
	c.closeErr = closeErr
	c.closeErrMu.Unlock()
	c.closeState.Store(2)
	return closeErr
}

func (c *udptlsConn) setCloseUnregister(unregister func()) {
	if unregister == nil {
		return
	}
	c.registrationMu.Lock()
	c.opGate.RLock()
	closed := c.closed
	c.opGate.RUnlock()
	if !closed {
		c.closeUnregister = unregister
	}
	c.registrationMu.Unlock()
	if closed {
		_ = extension.Run("TalariaUDP close unregister", unregister)
	}
}

func (c *udptlsConn) unregisterFromCloser() error {
	c.registrationMu.Lock()
	unregister := c.closeUnregister
	c.closeUnregister = nil
	c.registrationMu.Unlock()
	if unregister != nil {
		return extension.Run("TalariaUDP close unregister", unregister)
	}
	return nil
}

func (c *udptlsConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *udptlsConn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }

func (c *udptlsConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.setReadDeadlineLocked(t)
	c.writeDeadline = t
	c.deadlineMu.Unlock()

	c.readStateMu.Lock()
	started := c.readStarted
	c.readStateMu.Unlock()
	if started {
		return c.inner.SetWriteDeadline(t)
	}
	err := c.inner.SetDeadline(t)
	c.readStateMu.Lock()
	started = c.readStarted
	c.readStateMu.Unlock()
	if started {
		err = errors.Join(err, c.inner.SetReadDeadline(time.Time{}))
	}
	return err
}

func (c *udptlsConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.setReadDeadlineLocked(t)
	c.deadlineMu.Unlock()

	c.readStateMu.Lock()
	started := c.readStarted
	c.readStateMu.Unlock()
	if started {
		return nil
	}
	err := c.inner.SetReadDeadline(t)
	c.readStateMu.Lock()
	started = c.readStarted
	c.readStateMu.Unlock()
	if started {
		err = errors.Join(err, c.inner.SetReadDeadline(time.Time{}))
	}
	return err
}

func (c *udptlsConn) setReadDeadlineLocked(t time.Time) {
	c.readDeadline = t
	changed := c.readDeadlineChanged
	c.readDeadlineChanged = make(chan struct{})
	if changed != nil {
		close(changed)
	}
}

func (c *udptlsConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return c.inner.SetWriteDeadline(t)
}

func (c *udptlsConn) BatchSize() int { return c.batchSize }

// ReservePacketReadBufferBytes accounts caller-owned batch read scratch for its
// full lifetime. The returned release function is idempotent and keeps Close
// waiting until the caller has dropped those buffers.
func (c *udptlsConn) ReservePacketReadBufferBytes(n int64) (func(), error) {
	if n <= 0 {
		return nil, errors.New("TalariaUDP invalid packet read buffer reservation")
	}
	done, err := c.beginIO()
	if err != nil {
		return nil, err
	}
	if !c.reserveQueuedBytes(n) {
		done()
		return nil, errTalariaUDPQueueMemoryLimit
	}
	// Do not let caller scratch consume the entire per-session allowance. The
	// data path still needs one full write batch plus one encrypted/plain receive
	// pair to make progress. Probe that combined capacity now; those components
	// establish their own reservations when first used.
	workingSet := int64(c.maxCipher)*int64(c.batchSize) + int64(c.maxCipher+c.maxPacket)
	if c.budget != nil && !c.reserveQueuedBytes(workingSet) {
		c.releaseQueuedBytes(n)
		done()
		return nil, errTalariaUDPQueueMemoryLimit
	}
	c.releaseQueuedBytes(workingSet)
	var once sync.Once
	return func() {
		once.Do(func() {
			c.releaseQueuedBytes(n)
			done()
		})
	}, nil
}

// SetTalariaUDPPreAuthMode keeps TalariaUDP application authentication on the
// smallest possible receive path. It must be enabled before the regular read
// pipeline starts and disabled once the caller has authenticated the peer.
func (c *udptlsConn) SetTalariaUDPPreAuthMode(enable bool) {
	c.readStateMu.Lock()
	if !c.readStarted {
		c.preAuthMode = enable
	}
	c.readStateMu.Unlock()
	if inner, ok := c.inner.(interface{ SetCompactReadBuffers(bool) }); ok {
		inner.SetCompactReadBuffers(enable)
	}
}

func (c *udptlsConn) beginIO() (func(), error) {
	c.opGate.RLock()
	if c.closed {
		c.opGate.RUnlock()
		return nil, net.ErrClosed
	}
	c.opsWG.Add(1)
	c.opGate.RUnlock()
	return c.opsWG.Done, nil
}

func (c *udptlsConn) startReadPipeline() {
	c.readStartOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		queueSize := c.resolvePipelineSize()
		readPktCh := make(chan udptlsEncryptedPacket, queueSize)
		plainPktCh := make(chan udptlsPlainPacket, queueSize)

		c.readStateMu.Lock()
		c.readCancel = cancel
		c.readStarted = true
		c.plainPktCh = plainPktCh
		c.readStateMu.Unlock()
		_ = c.inner.SetReadDeadline(time.Time{})

		c.readWG.Add(2)
		go c.readPacketLoop(ctx, readPktCh)
		go c.decryptPacketLoop(ctx, readPktCh, plainPktCh)
	})
}

func (c *udptlsConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(sizes) < len(bufs) {
		return 0, errors.New("TalariaUDP read sizes too small")
	}
	done, err := c.beginIO()
	if err != nil {
		return 0, err
	}
	defer done()
	if err := c.getReadErr(); err != nil {
		return 0, err
	}

	if c.preAuthReadEnabled() {
		return c.readPreAuthBatch(ctx, bufs, sizes)
	}
	c.startReadPipeline()
	batchN := c.limitBatch(len(bufs))
	for i := 0; i < batchN; i++ {
		sizes[i] = 0
	}

	c.readStateMu.Lock()
	plainCh := c.plainPktCh
	c.readStateMu.Unlock()

	c.readMu.Lock()
	defer c.readMu.Unlock()

	pkt, ok, err := c.waitPlainPacket(ctx, plainCh)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, io.EOF
	}
	n, copyErr := c.copyPlainPacket(bufs, sizes, 0, pkt)
	if copyErr != nil {
		return n, copyErr
	}
	n = 1

	for n < batchN {
		select {
		case pkt, ok := <-plainCh:
			if !ok {
				return n, nil
			}
			nextN, err := c.copyPlainPacket(bufs, sizes, n, pkt)
			if err != nil {
				return nextN, err
			}
			n = nextN
		default:
			return n, nil
		}
	}
	return n, nil
}

func (c *udptlsConn) preAuthReadEnabled() bool {
	c.readStateMu.Lock()
	defer c.readStateMu.Unlock()
	return c.preAuthMode && !c.readStarted
}

// readPreAuthBatch waits for one authenticated data packet and ignores unauthenticated datagrams until the deadline.
func (c *udptlsConn) readPreAuthBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	sizes[0] = 0
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if c.readDeadlineExpired() {
			return 0, deadlineExceededError("read")
		}
		pending := c.takePendingEncryptedPackets()
		for i, encrypted := range pending {
			plain, keep, err := c.decryptPacket(encrypted)
			c.releaseEncryptedPacket(encrypted)
			if err != nil {
				c.releaseEncryptedPackets(pending[i+1:])
				return 0, err
			}
			if !keep {
				continue
			}
			c.releaseEncryptedPackets(pending[i+1:])
			if _, err := c.copyPlainPacket(bufs, sizes, 0, plain); err != nil {
				return 0, err
			}
			return 1, nil
		}

		encBuf, ok := c.getEncBuf()
		if !ok {
			return 0, errTalariaUDPQueueMemoryLimit
		}
		innerBufs := [1][]byte{encBuf}
		innerSizes := [1]int{}
		n, err := c.inner.ReadBatch(ctx, innerBufs[:], innerSizes[:])
		if err != nil {
			c.putEncBuf(encBuf)
			return 0, err
		}
		if err := validateReadBatch(n, innerBufs[:], innerSizes[:]); err != nil {
			c.putEncBuf(encBuf)
			return 0, err
		}
		if n == 0 {
			c.putEncBuf(encBuf)
			continue
		}
		encrypted := udptlsEncryptedPacket{buf: encBuf, n: innerSizes[0], pooled: true}
		plain, keep, err := c.decryptPacket(encrypted)
		c.releaseEncryptedPacket(encrypted)
		if err != nil {
			return 0, err
		}
		if !keep {
			continue
		}
		if _, err := c.copyPlainPacket(bufs, sizes, 0, plain); err != nil {
			return 0, err
		}
		return 1, nil
	}
}

func (c *udptlsConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(sizes) < len(bufs) {
		return 0, errors.New("TalariaUDP write sizes too small")
	}
	done, err := c.beginIO()
	if err != nil {
		return 0, err
	}
	defer done()

	batchN := c.limitBatch(len(bufs))
	for i := 0; i < batchN; i++ {
		sz := sizes[i]
		if sz < 0 || sz > len(bufs[i]) {
			return i, fmt.Errorf("TalariaUDP invalid packet size: %d", sz)
		}
		if sz > c.maxPacket {
			return i, fmt.Errorf("TalariaUDP packet too large: %d", sz)
		}
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	writeCtx, cancel := c.withWriteDeadline(ctx)
	defer cancel()
	return c.encryptAndWriteBatch(writeCtx, bufs[:batchN], sizes[:batchN])
}

func (c *udptlsConn) waitPlainPacket(ctx context.Context, plainCh <-chan udptlsPlainPacket) (udptlsPlainPacket, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return udptlsPlainPacket{}, false, err
		}
		deadline, changed := c.readDeadlineState()
		if !deadline.IsZero() && time.Now().After(deadline) {
			return udptlsPlainPacket{}, false, deadlineExceededError("read")
		}
		var timer *time.Timer
		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerCh = timer.C
		}
		select {
		case <-ctx.Done():
			stopTalariaUDPTimer(timer)
			return udptlsPlainPacket{}, false, ctx.Err()
		case <-timerCh:
			return udptlsPlainPacket{}, false, deadlineExceededError("read")
		case <-changed:
			stopTalariaUDPTimer(timer)
			continue
		case pkt, ok := <-plainCh:
			stopTalariaUDPTimer(timer)
			if !ok {
				if err := c.getReadErr(); err != nil {
					return udptlsPlainPacket{}, false, err
				}
				if c.isClosed() {
					return udptlsPlainPacket{}, false, net.ErrClosed
				}
				return udptlsPlainPacket{}, false, io.EOF
			}
			return pkt, true, nil
		}
	}
}

func stopTalariaUDPTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func (c *udptlsConn) readDeadlineState() (time.Time, <-chan struct{}) {
	c.deadlineMu.RLock()
	deadline := c.readDeadline
	changed := c.readDeadlineChanged
	c.deadlineMu.RUnlock()
	return deadline, changed
}

func (c *udptlsConn) readDeadlineExpired() bool {
	deadline, _ := c.readDeadlineState()
	return !deadline.IsZero() && time.Now().After(deadline)
}

func (c *udptlsConn) copyPlainPacket(bufs [][]byte, sizes []int, outIdx int, pkt udptlsPlainPacket) (int, error) {
	defer c.releasePlainPacket(pkt)
	if outIdx >= len(bufs) {
		return outIdx, nil
	}
	if pkt.n > len(bufs[outIdx]) {
		return outIdx, fmt.Errorf("TalariaUDP plaintext too large for buffer: %d", pkt.n)
	}
	copy(bufs[outIdx], pkt.buf[:pkt.n])
	sizes[outIdx] = pkt.n
	return outIdx + 1, nil
}

func (c *udptlsConn) readPacketLoop(ctx context.Context, out chan<- udptlsEncryptedPacket) {
	defer c.readWG.Done()
	defer close(out)

	pending := c.takePendingEncryptedPackets()
	for i, pkt := range pending {
		if !c.reserveEncryptedPacket(&pkt) {
			// Handshake-owned packets are not receive-pool buffers. If their
			// reservation cannot be established, dropping the reference is enough;
			// returning it to the pool would create an unaccounted retained buffer.
			continue
		}
		select {
		case out <- pkt:
		case <-ctx.Done():
			c.releaseEncryptedPacket(pkt)
			for j := i + 1; j < len(pending); j++ {
				c.releaseEncryptedPacket(pending[j])
			}
			return
		}
	}

	batchN := c.limitBatch(c.batchSize)
	bufs := make([][]byte, batchN)
	sizes := make([]int, batchN)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		acquired := 0
		for i := 0; i < batchN; i++ {
			buf, ok := c.getEncBuf()
			if !ok {
				break
			}
			bufs[i] = buf
			sizes[i] = 0
			acquired++
		}
		if acquired == 0 {
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		n, err := c.inner.ReadBatch(ctx, bufs[:acquired], sizes[:acquired])
		if err != nil {
			c.releaseUnreadBuffers(bufs[:acquired])
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			c.setReadErr(err)
			c.cancelReadPipeline()
			return
		}
		if err := validateReadBatch(n, bufs[:acquired], sizes[:acquired]); err != nil {
			c.releaseUnreadBuffers(bufs[:acquired])
			c.setReadErr(err)
			c.cancelReadPipeline()
			return
		}
		if n <= 0 {
			c.releaseUnreadBuffers(bufs[:acquired])
			continue
		}
		for i := n; i < acquired; i++ {
			if bufs[i] != nil {
				c.putEncBuf(bufs[i])
				bufs[i] = nil
			}
		}
		for i := 0; i < n; i++ {
			pkt := udptlsEncryptedPacket{buf: bufs[i], n: sizes[i], pooled: true}
			bufs[i] = nil
			if !c.reserveEncryptedPacket(&pkt) {
				c.putEncBuf(pkt.buf)
				continue
			}
			select {
			case out <- pkt:
			case <-ctx.Done():
				c.releaseEncryptedPacket(pkt)
				c.releaseUnreadBuffers(bufs)
				return
			}
		}
	}
}

func validateReadBatch(n int, bufs [][]byte, sizes []int) error {
	if n < 0 || n > len(bufs) || n > len(sizes) {
		return fmt.Errorf("TalariaUDP invalid read batch count: %d", n)
	}
	for i := 0; i < n; i++ {
		if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
			return fmt.Errorf("TalariaUDP invalid read packet size %d for buffer[%d]", sizes[i], i)
		}
	}
	return nil
}

func writeBatchValidated(ctx context.Context, conn batchConn, bufs [][]byte, sizes []int) (int, error) {
	n, err := conn.WriteBatch(ctx, bufs, sizes)
	if n < 0 || n > len(bufs) {
		return 0, fmt.Errorf("TalariaUDP invalid write batch count: %d", n)
	}
	return n, err
}

func (c *udptlsConn) decryptPacketLoop(ctx context.Context, in <-chan udptlsEncryptedPacket, out chan<- udptlsPlainPacket) {
	defer c.readWG.Done()
	defer close(out)

	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case pkt, ok := <-in:
					if !ok {
						return
					}
					c.releaseEncryptedPacket(pkt)
				default:
					return
				}
			}
		case pkt, ok := <-in:
			if !ok {
				return
			}
			plain, keep, err := c.decryptPacket(pkt)
			c.releaseEncryptedPacket(pkt)
			if err != nil {
				c.setReadErr(err)
				c.cancelReadPipeline()
				return
			}
			if !keep {
				continue
			}
			select {
			case out <- plain:
			case <-ctx.Done():
				c.releasePlainPacket(plain)
				return
			}
		}
	}
}

// recvAEADForEpoch returns the AEAD for the epoch a record claims in its header.
// Only three epochs are ever acceptable, which is what keeps a spoofed epoch from
// costing anything:
//
//   - the current epoch, the common case;
//   - the next epoch, derived by one ratchet, for a peer that has just rekeyed;
//   - the previous epoch, retained, for records reordered across the boundary.
//
// Anything else is dropped without deriving a key. For the next epoch the
// returned commit function installs it, and the caller must invoke that only
// after the record authenticates: committing earlier would let anyone who knows
// the five-tuple retire a key the peer is still using, and would discard the
// previous epoch that in-flight records still need.
func (c *udptlsConn) recvAEADForEpoch(epoch uint32) (cipher.AEAD, func(), bool) {
	switch {
	case epoch == c.recvEpoch:
		return c.recvAEAD, nil, true
	case epoch+1 == c.recvEpoch && c.recvPrevAEAD != nil:
		return c.recvPrevAEAD, nil, true
	case epoch > c.recvEpoch && epoch-c.recvEpoch <= udptlsMaxEpochSkew:
		if c.spec.hashNew == nil || c.spec.newAEAD == nil || len(c.recvKey) == 0 {
			// No key schedule to ratchet with. Drop rather than fault: this path
			// is driven by an attacker-supplied epoch.
			return nil, nil, false
		}
		if c.recvNextAEAD == nil {
			next, err := ratchetKey(c.spec.hashNew, c.recvKey, c.spec.keyLen)
			if err != nil {
				return nil, nil, false
			}
			aead, err := c.spec.newAEAD(next)
			if err != nil {
				clear(next)
				return nil, nil, false
			}
			c.recvNextKey = next
			c.recvNextAEAD = aead
		}
		nextKey := c.recvNextKey
		nextAEAD := c.recvNextAEAD
		commit := func() {
			if c.recvEpoch >= epoch {
				return
			}
			c.recvPrevAEAD = c.recvAEAD
			// Rotate the replay window with the key so the retired epoch keeps
			// rejecting its own replays for as long as its key is accepted.
			c.replayPrev = c.replay
			c.replay = udptlsReplayWindow{}
			clear(c.recvKey)
			c.recvKey = nextKey
			c.recvAEAD = nextAEAD
			c.recvEpoch = epoch
			c.recvNextKey = nil
			c.recvNextAEAD = nil
		}
		return nextAEAD, commit, true
	default:
		return nil, nil, false
	}
}

// decryptPacket authenticates a data record before applying key-use and replay limits.
func (c *udptlsConn) decryptPacket(pkt udptlsEncryptedPacket) (udptlsPlainPacket, bool, error) {
	if pkt.n < udptlsDataHeaderSize {
		return udptlsPlainPacket{}, false, nil
	}
	raw := pkt.buf[:pkt.n]
	if raw[0] != udptlsDataPacketType {
		// Drop stale handshake packets or future control packets from the UDP
		// socket instead of treating them as a fatal protocol error.
		return udptlsPlainPacket{}, false, nil
	}
	epoch := binary.LittleEndian.Uint32(raw[udptlsEpochOffset:])
	sequence := binary.LittleEndian.Uint32(raw[udptlsSequenceOffset:])
	if sequence < udptlsFirstSequence || sequence > udptlsPacketsPerEpoch {
		// The sender cannot emit a sequence outside this range. Reject it before
		// a claimed next epoch can trigger key derivation.
		return udptlsPlainPacket{}, false, nil
	}
	aead, commitEpoch, ok := c.recvAEADForEpoch(epoch)
	if !ok {
		// The claimed epoch is neither live nor one step ahead. Dropping is safe:
		// a real peer advances one epoch at a time and we keep the previous one.
		return udptlsPlainPacket{}, false, nil
	}
	plainBuf, ok := c.getPlainBuf()
	if !ok {
		return udptlsPlainPacket{}, false, nil
	}
	nonce := nonceForRecord(c.recvSalt, epoch, sequence)
	plain, err := aead.Open(plainBuf[:0], nonce[:], raw[udptlsDataHeaderSize:pkt.n], raw[:udptlsDataHeaderSize])
	if err != nil {
		c.putPlainBuf(plainBuf)
		c.recvAuthFails++
		if c.recvAuthFails >= c.maxAuthFailures {
			c.setReadErr(errTalariaUDPAuthFailureLimit)
			return udptlsPlainPacket{}, false, errTalariaUDPAuthFailureLimit
		}
		// Datagram transports must tolerate injected or corrupted ciphertext.
		// Only advance the replay window after authentication succeeds so a
		// forged packet cannot burn a valid sequence number or tear down the
		// whole session. For the same reason the epoch stays uncommitted:
		// a spoofed epoch must not be able to retire the live receive key.
		return udptlsPlainPacket{}, false, nil
	}
	if commitEpoch != nil {
		commitEpoch()
	}
	// After a commit the record's epoch is the current one; a retained record from
	// the previous epoch is checked against that epoch's own window.
	replay := &c.replay
	if epoch != c.recvEpoch {
		replay = &c.replayPrev
	}
	if !replay.Accept(uint64(sequence)) {
		c.putPlainBuf(plainBuf)
		return udptlsPlainPacket{}, false, nil
	}
	if c.activityMarker != nil {
		c.activityMarker.MarkActive()
	}
	plainPkt := udptlsPlainPacket{buf: plainBuf, n: len(plain), pooled: true}
	if !c.reservePlainPacket(&plainPkt) {
		c.putPlainBuf(plainBuf)
		return udptlsPlainPacket{}, false, nil
	}
	return plainPkt, true, nil
}

func (c *udptlsConn) ensureWriteBuffers(n int) ([][]byte, []int, error) {
	if cap(c.writeBufs) < n {
		bufs := make([][]byte, n)
		copy(bufs, c.writeBufs)
		c.writeBufs = bufs
	}
	if cap(c.writeSizes) < n {
		c.writeSizes = make([]int, n)
	}
	bufs := c.writeBufs[:n]
	sizes := c.writeSizes[:n]
	for i := 0; i < n; i++ {
		if cap(bufs[i]) < c.maxCipher {
			if !c.reserveQueuedBytes(int64(c.maxCipher)) {
				return nil, nil, errTalariaUDPQueueMemoryLimit
			}
			bufs[i] = make([]byte, c.maxCipher)
			c.writeReserved += int64(c.maxCipher)
		}
		bufs[i] = bufs[i][:c.maxCipher]
		sizes[i] = 0
	}
	return bufs, sizes, nil
}

func (c *udptlsConn) limitBatch(n int) int {
	if n <= c.batchSize {
		return n
	}
	return c.batchSize
}

func resolveTalariaUDPDataPath(mode udptlsMode, goos string, innerBatchSize int) udptlsDataPath {
	if innerBatchSize <= 0 {
		innerBatchSize = 1
	}
	// macOS and other non-Linux clients do not inherit the UDP plugin's real
	// batch/GSO fast path, so clamp them to a single-packet receive pipeline.
	if mode == udptlsModeClient && goos != "linux" {
		return udptlsDataPath{
			batchSize:    1,
			readPipeline: true,
		}
	}
	// Keep the background reader only for Linux servers where the underlying
	// UDP socket can batch receive and hide decrypt cost behind socket reads.
	if mode == udptlsModeServer && goos == "linux" && innerBatchSize > 1 {
		return udptlsDataPath{
			batchSize:    innerBatchSize,
			readPipeline: true,
		}
	}
	return udptlsDataPath{
		batchSize:    innerBatchSize,
		readPipeline: true,
	}
}

func (c *udptlsConn) resolvePipelineSize() int {
	sz := c.batchSize * 4
	if sz < udptlsPipelineSize {
		sz = udptlsPipelineSize
	}
	if sz > 1024 {
		sz = 1024
	}
	return sz
}

func (c *udptlsConn) setReadErr(err error) {
	if err == nil {
		return
	}
	c.readErrMu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.readErrMu.Unlock()
}

func (c *udptlsConn) getReadErr() error {
	c.readErrMu.Lock()
	defer c.readErrMu.Unlock()
	return c.readErr
}

func (c *udptlsConn) withWriteDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	c.deadlineMu.RUnlock()
	if deadline.IsZero() {
		return ctx, func() {}
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}

func (c *udptlsConn) getEncBuf() ([]byte, bool) {
	select {
	case buf := <-c.encPool:
		return buf[:c.maxCipher], true
	default:
	}
	if !c.reserveQueuedBytes(int64(c.maxCipher)) {
		return nil, false
	}
	return make([]byte, c.maxCipher), true
}

func (c *udptlsConn) putEncBuf(buf []byte) {
	if cap(buf) < c.maxCipher {
		c.releaseQueuedBytes(int64(c.maxCipher))
		return
	}
	buf = buf[:c.maxCipher]
	if !c.isClosed() {
		select {
		case c.encPool <- buf:
			return
		default:
		}
	}
	c.releaseQueuedBytes(int64(c.maxCipher))
}

func (c *udptlsConn) getPlainBuf() ([]byte, bool) {
	select {
	case buf := <-c.plainPool:
		return buf[:c.maxPacket], true
	default:
	}
	if !c.reserveQueuedBytes(int64(c.maxPacket)) {
		return nil, false
	}
	return make([]byte, c.maxPacket), true
}

func (c *udptlsConn) putPlainBuf(buf []byte) {
	if cap(buf) < c.maxPacket {
		c.releaseQueuedBytes(int64(c.maxPacket))
		return
	}
	buf = buf[:c.maxPacket]
	if !c.isClosed() {
		select {
		case c.plainPool <- buf:
			return
		default:
		}
	}
	c.releaseQueuedBytes(int64(c.maxPacket))
}

func (c *udptlsConn) reserveQueuedBytes(n int64) bool {
	if c.budget == nil || c.budget.ReserveQueuedBytes(n) {
		return true
	}
	for c.releaseOneIdleReceiveBuffer() {
		if c.budget.ReserveQueuedBytes(n) {
			return true
		}
	}
	return false
}

func (c *udptlsConn) releaseQueuedBytes(n int64) {
	if c.budget != nil && n > 0 {
		c.budget.ReleaseQueuedBytes(n)
	}
}

func (c *udptlsConn) reserveEncryptedPacket(pkt *udptlsEncryptedPacket) bool {
	if pkt == nil || pkt.buf == nil || pkt.pooled || pkt.reserved > 0 || c.budget == nil {
		return true
	}
	retained := int64(cap(pkt.buf))
	if !c.budget.ReserveQueuedBytes(retained) {
		return false
	}
	pkt.reserved = retained
	return true
}

func (c *udptlsConn) releaseEncryptedPacket(pkt udptlsEncryptedPacket) {
	if pkt.pooled {
		c.putEncBuf(pkt.buf)
		return
	}
	c.releaseQueuedBytes(pkt.reserved)
}

func (c *udptlsConn) reservePlainPacket(pkt *udptlsPlainPacket) bool {
	if pkt == nil || pkt.buf == nil || pkt.pooled || pkt.reserved > 0 || c.budget == nil {
		return true
	}
	retained := int64(cap(pkt.buf))
	if !c.budget.ReserveQueuedBytes(retained) {
		return false
	}
	pkt.reserved = retained
	return true
}

func (c *udptlsConn) releasePlainPacket(pkt udptlsPlainPacket) {
	if pkt.pooled {
		c.putPlainBuf(pkt.buf)
		return
	}
	c.releaseQueuedBytes(pkt.reserved)
}

func (c *udptlsConn) releaseOneIdleReceiveBuffer() bool {
	select {
	case <-c.encPool:
		c.releaseQueuedBytes(int64(c.maxCipher))
		return true
	default:
	}
	select {
	case <-c.plainPool:
		c.releaseQueuedBytes(int64(c.maxPacket))
		return true
	default:
		return false
	}
}

func (c *udptlsConn) drainReceiveBufferPools() {
	for c.releaseOneIdleReceiveBuffer() {
	}
}

func (c *udptlsConn) drainPlainPackets() {
	c.readStateMu.Lock()
	plainCh := c.plainPktCh
	c.readStateMu.Unlock()
	if plainCh == nil {
		return
	}
	for pkt := range plainCh {
		c.releasePlainPacket(pkt)
	}
}

func (c *udptlsConn) cancelReadPipeline() {
	c.readStateMu.Lock()
	cancel := c.readCancel
	c.readStateMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *udptlsConn) takePendingEncryptedPackets() []udptlsEncryptedPacket {
	c.readStateMu.Lock()
	defer c.readStateMu.Unlock()
	pending := c.pendingEnc
	c.pendingEnc = nil
	return pending
}

func (c *udptlsConn) isClosed() bool {
	c.opGate.RLock()
	defer c.opGate.RUnlock()
	return c.closed
}

func (w *udptlsReplayWindow) Accept(counter uint64) bool {
	if !w.CanAccept(counter) {
		return false
	}
	if counter > w.highest && w.highest != 0 {
		advance := counter - w.highest
		if advance >= uint64(udptlsReplayWindowCap) {
			clear(w.seen[:])
		} else {
			for position := w.highest + 1; ; position++ {
				w.clear(position)
				if position == counter {
					break
				}
			}
		}
	}
	word, mask := w.slot(counter)
	w.seen[word] |= mask
	if counter > w.highest {
		w.highest = counter
	}
	return true
}

func (w *udptlsReplayWindow) CanAccept(counter uint64) bool {
	if counter == 0 {
		return false
	}
	if counter > w.highest {
		return true
	}
	if w.highest-counter >= uint64(udptlsReplayWindowCap) {
		return false
	}
	word, mask := w.slot(counter)
	return w.seen[word]&mask == 0
}

func (w *udptlsReplayWindow) clear(counter uint64) {
	word, mask := w.slot(counter)
	w.seen[word] &^= mask
}

func (*udptlsReplayWindow) slot(counter uint64) (int, uint64) {
	bit := counter % uint64(udptlsReplayWindowCap)
	return int(bit / 64), uint64(1) << (bit % 64)
}

// nonceForRecord builds the 12-byte AEAD nonce as salt(4) ‖ epoch(4) ‖
// sequence(4). The salt separates the two directions and the epoch/sequence pair
// never repeats within a direction, so a nonce is never reused under one key even
// though sequences restart each epoch.
func nonceForRecord(salt [udptlsNonceSaltSize]byte, epoch, sequence uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:udptlsNonceSaltSize], salt[:])
	binary.LittleEndian.PutUint32(nonce[udptlsNonceSaltSize:], epoch)
	binary.LittleEndian.PutUint32(nonce[udptlsNonceSaltSize+4:], sequence)
	return nonce
}

func (c *udptlsConn) encryptPacket(aead cipher.AEAD, encBufs [][]byte, encSizes []int, idx int, plain []byte, epoch, sequence uint32) {
	nonce := nonceForRecord(c.sendSalt, epoch, sequence)
	enc := encBufs[idx][:udptlsDataHeaderSize]
	enc[0] = udptlsDataPacketType
	binary.LittleEndian.PutUint32(enc[udptlsEpochOffset:], epoch)
	binary.LittleEndian.PutUint32(enc[udptlsSequenceOffset:], sequence)
	// The whole header is the additional data, so the epoch a record claims is
	// authenticated: an attacker cannot retarget a record at another key.
	enc = aead.Seal(enc, nonce[:], plain, enc)
	encBufs[idx] = enc
	encSizes[idx] = len(enc)
}

// advanceSendEpochLocked ratchets the send key to the next epoch and restarts the
// sequence. Callers hold writeMu.
//
// The new key is derived from the current one, never from a retained root, so
// the material that protected earlier epochs is gone once this returns.
func (c *udptlsConn) advanceSendEpochLocked() error {
	if c.sendEpoch == udptlsMaxEpoch {
		return errTalariaUDPKeyUsageExhausted
	}
	next, err := ratchetKey(c.spec.hashNew, c.sendKey, c.spec.keyLen)
	if err != nil {
		return err
	}
	aead, err := c.spec.newAEAD(next)
	if err != nil {
		clear(next)
		return fmt.Errorf("TalariaUDP send key update: %w", err)
	}
	clear(c.sendKey)
	c.sendKey = next
	c.sendAEAD = aead
	c.sendEpoch++
	c.writeSeq = 0
	return nil
}

// nextSendRecordLocked reserves the epoch and sequence for one outbound record,
// advancing the epoch first when the current key has protected its budget.
// Callers hold writeMu.
func (c *udptlsConn) nextSendRecordLocked() (epoch, sequence uint32, err error) {
	// The rekey decision lives here rather than in the nonce arithmetic, so the
	// trigger can become time- or volume-based without touching the record format.
	if c.writeSeq >= udptlsPacketsPerEpoch {
		if err := c.advanceSendEpochLocked(); err != nil {
			return 0, 0, err
		}
	}
	c.writeSeq++
	return c.sendEpoch, c.writeSeq, nil
}

func (c *udptlsConn) encryptAndWriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	encBufs, encSizes, err := c.ensureWriteBuffers(len(bufs))
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(bufs); i++ {
		epoch, sequence, err := c.nextSendRecordLocked()
		if err != nil {
			return 0, err
		}
		c.encryptPacket(c.sendAEAD, encBufs, encSizes, i, bufs[i][:sizes[i]], epoch, sequence)
	}
	return writeBatchValidated(ctx, c.inner, encBufs, encSizes)
}

func (c *udptlsConn) releaseUnreadBuffers(bufs [][]byte) {
	for i := range bufs {
		if bufs[i] != nil {
			c.putEncBuf(bufs[i])
			bufs[i] = nil
		}
	}
}

func (c *udptlsConn) releaseEncryptedPackets(packets []udptlsEncryptedPacket) {
	for _, packet := range packets {
		c.releaseEncryptedPacket(packet)
	}
}
