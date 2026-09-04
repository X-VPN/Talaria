// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type NewClientConnReq struct {
	MaxPacket int
	IOTimeout time.Duration
	BatchSize int
	Stats     Stats
}

// clientBatchPacketConn is the common x/net batch surface.
// ipv4.Message and ipv6.Message alias the same socket message type.
type clientBatchPacketConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type clientConn struct {
	conn      *net.UDPConn
	maxPacket int
	ioTimeout time.Duration
	batchSize int
	stats     Stats

	// readDeadline and writeDeadline hold the deadlines supplied by the caller
	// through SetDeadline and friends. ioReadDeadline and ioWriteDeadline hold
	// the shorter deadline this connection arms on its own to keep a blocking
	// syscall bounded by ioTimeout. They are kept apart so that an internal
	// refresh never extends or discards what the caller asked for; the deadline
	// actually armed on the socket is the earlier of the two. They are guarded
	// by readDeadlineMu and writeMu respectively.
	readDeadline    time.Time
	ioReadDeadline  time.Time
	writeDeadline   time.Time
	ioWriteDeadline time.Time
	udpGSO          bool
	udpGRO          bool
	gsoOOB          []byte
	gsoWriteBuf     []byte
	groReadBuf      []byte
	groReadOOB      []byte
	groSegSize      int
	groPendingN     int
	groPendingOff   int

	batchEnabled bool
	batchIPv6    bool
	batchV4      clientBatchPacketConn
	batchV6      clientBatchPacketConn

	readMsgs4  []ipv4.Message
	readVecs4  [][1][]byte
	writeMsgs4 []ipv4.Message
	writeVecs4 [][1][]byte

	readMsgs6  []ipv6.Message
	readVecs6  [][1][]byte
	writeMsgs6 []ipv6.Message
	writeVecs6 [][1][]byte

	readMu         sync.Mutex
	readDeadlineMu sync.Mutex
	writeMu        sync.Mutex
}

func NewClientConn(conn *net.UDPConn, req NewClientConnReq) BatchConn {
	wireMaxPacket := MaxUDPPayloadForAddr(conn.RemoteAddr())
	maxPacket := req.MaxPacket
	if maxPacket <= 0 {
		maxPacket = wireMaxPacket
	} else if maxPacket > wireMaxPacket {
		maxPacket = wireMaxPacket
	}
	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	} else if batchSize > maxBatchSize {
		batchSize = maxBatchSize
	}
	s := &clientConn{
		conn:      conn,
		maxPacket: maxPacket,
		ioTimeout: req.IOTimeout,
		batchSize: batchSize,
		stats:     req.Stats,
	}
	s.udpGSO = enableUDPGSO(conn)
	s.udpGRO = enableUDPGRO(conn)
	if s.udpGSO {
		s.gsoOOB = make([]byte, 0, udpControlSize())
	}
	if s.udpGRO {
		s.groReadBuf = make([]byte, maxPacket)
		s.groReadOOB = make([]byte, udpControlSize())
	}
	if runtime.GOOS == "linux" {
		if isIPv6UDPAddr(conn.RemoteAddr()) {
			s.batchIPv6 = true
			if batchV6 := ipv6.NewPacketConn(conn); batchV6 != nil {
				s.batchV6 = batchV6
			}
		} else {
			if batchV4 := ipv4.NewPacketConn(conn); batchV4 != nil {
				s.batchV4 = batchV4
			}
		}
		s.batchEnabled = s.batchV4 != nil || s.batchV6 != nil
		if s.udpGRO {
			// GRO data needs control-message parsing and cannot share the batch read path.
			s.batchEnabled = false
		}
		if s.batchEnabled {
			bs := s.batchSize
			s.readMsgs4 = make([]ipv4.Message, bs)
			s.readVecs4 = make([][1][]byte, bs)
			s.writeMsgs4 = make([]ipv4.Message, bs)
			s.writeVecs4 = make([][1][]byte, bs)
			s.readMsgs6 = make([]ipv6.Message, bs)
			s.readVecs6 = make([][1][]byte, bs)
			s.writeMsgs6 = make([]ipv6.Message, bs)
			s.writeVecs6 = make([][1][]byte, bs)
		}
	}
	_ = tuneUDPSocketBuffer(conn)
	return s
}

func (s *clientConn) Read(p []byte) (int, error) {
	sz := [1]int{}
	n, err := s.ReadBatch(context.Background(), [][]byte{p}, sz[:])
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sz[0], nil
}

func (s *clientConn) Write(p []byte) (int, error) {
	n, err := s.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (s *clientConn) Close() error {
	if s.stats != nil {
		s.stats.Close()
	}
	return s.conn.Close()
}

func (s *clientConn) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *clientConn) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *clientConn) SetDeadline(t time.Time) error {
	s.readDeadlineMu.Lock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	defer s.readDeadlineMu.Unlock()
	s.readDeadline = t
	s.writeDeadline = t
	if err := s.conn.SetReadDeadline(s.combinedReadDeadlineLocked()); err != nil {
		return err
	}
	return s.conn.SetWriteDeadline(s.combinedWriteDeadlineLocked())
}

func (s *clientConn) SetReadDeadline(t time.Time) error {
	s.readDeadlineMu.Lock()
	defer s.readDeadlineMu.Unlock()
	s.readDeadline = t
	return s.conn.SetReadDeadline(s.combinedReadDeadlineLocked())
}

func (s *clientConn) SetWriteDeadline(t time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.writeDeadline = t
	return s.conn.SetWriteDeadline(s.combinedWriteDeadlineLocked())
}

// combinedReadDeadlineLocked reports the earlier of the caller's read deadline
// and the internally armed ioTimeout deadline. A zero value means no deadline,
// so it never wins over a deadline that is actually set. Callers must hold readDeadlineMu.
func (s *clientConn) combinedReadDeadlineLocked() time.Time {
	return earlierDeadline(s.readDeadline, s.ioReadDeadline)
}

// combinedWriteDeadlineLocked is the write-side counterpart of
// combinedReadDeadlineLocked. Callers must hold writeMu.
func (s *clientConn) combinedWriteDeadlineLocked() time.Time {
	return earlierDeadline(s.writeDeadline, s.ioWriteDeadline)
}

// refreshReadDeadline re-arms the ioTimeout read deadline when it is due,
// leaving the caller's own deadline untouched.
func (s *clientConn) refreshReadDeadline(now time.Time) error {
	if s.ioTimeout <= 0 {
		return nil
	}
	s.readDeadlineMu.Lock()
	defer s.readDeadlineMu.Unlock()
	if !shouldRefreshDeadline(now, s.ioReadDeadline, s.ioTimeout) {
		return nil
	}
	next := now.Add(s.ioTimeout)
	if err := s.conn.SetReadDeadline(earlierDeadline(s.readDeadline, next)); err != nil {
		return err
	}
	s.ioReadDeadline = next
	return nil
}

// refreshWriteDeadline is the write-side counterpart of refreshReadDeadline.
// Callers already hold writeMu.
func (s *clientConn) refreshWriteDeadlineLocked(now time.Time) error {
	if s.ioTimeout <= 0 {
		return nil
	}
	if !shouldRefreshDeadline(now, s.ioWriteDeadline, s.ioTimeout) {
		return nil
	}
	next := now.Add(s.ioTimeout)
	if err := s.conn.SetWriteDeadline(earlierDeadline(s.writeDeadline, next)); err != nil {
		return err
	}
	s.ioWriteDeadline = next
	return nil
}

// earlierDeadline returns whichever deadline elapses first, treating the zero
// value as "no deadline" rather than as the distant past.
func earlierDeadline(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}

func (s *clientConn) BatchSize() int { return s.batchSize }

// ReadBatch reads non-empty UDP datagrams without exposing empty datagrams as connection errors.
func (s *clientConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	batchN := minInt(len(bufs), len(sizes), s.batchSize)
	if batchN == 0 {
		return 0, nil
	}
	for i := 0; i < batchN; i++ {
		sizes[i] = 0
		if len(bufs[i]) < s.maxPacket {
			return 0, fmt.Errorf("read buffer too small: %d", len(bufs[i]))
		}
	}
	if s.udpGRO {
		return s.readBatchGRO(ctx, bufs, sizes, batchN)
	}
	if s.batchEnabled {
		for {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			if err := s.refreshReadDeadline(time.Now()); err != nil {
				return 0, err
			}
			if s.batchIPv6 {
				msgs := s.readMsgs6[:batchN]
				vecs := s.readVecs6[:batchN]
				for i := 0; i < batchN; i++ {
					vecs[i][0] = bufs[i][:s.maxPacket]
					msgs[i].Buffers = vecs[i][:]
					msgs[i].Addr = nil
					msgs[i].N = 0
				}
				n, err := s.batchV6.ReadBatch(msgs, 0)
				if err != nil {
					return 0, err
				}
				if n < 0 || n > batchN {
					return 0, fmt.Errorf("udp batch count out of range: %d", n)
				}
				for i := 0; i < n; i++ {
					sizes[i] = msgs[i].N
				}
				n, err = compactReadBatch(bufs, sizes, n, s.maxPacket)
				if err != nil {
					return 0, err
				}
				if n == 0 {
					continue
				}
				if s.stats != nil {
					s.stats.AddRX(n, sumPacketSizes(sizes[:n]))
				}
				return n, nil
			}
			msgs := s.readMsgs4[:batchN]
			vecs := s.readVecs4[:batchN]
			for i := 0; i < batchN; i++ {
				vecs[i][0] = bufs[i][:s.maxPacket]
				msgs[i].Buffers = vecs[i][:]
				msgs[i].Addr = nil
				msgs[i].N = 0
			}
			n, err := s.batchV4.ReadBatch(msgs, 0)
			if err != nil {
				return 0, err
			}
			if n < 0 || n > batchN {
				return 0, fmt.Errorf("udp batch count out of range: %d", n)
			}
			for i := 0; i < n; i++ {
				sizes[i] = msgs[i].N
			}
			n, err = compactReadBatch(bufs, sizes, n, s.maxPacket)
			if err != nil {
				return 0, err
			}
			if n == 0 {
				continue
			}
			if s.stats != nil {
				s.stats.AddRX(n, sumPacketSizes(sizes[:n]))
			}
			return n, nil
		}
	}

	count := 0
	for count < batchN {
		if count == 0 {
			if err := s.refreshReadDeadline(time.Now()); err != nil {
				return 0, err
			}
		}
		if count > 0 {
			restoreDeadline, ok := s.armReadDrainDeadline()
			if !ok {
				break
			}
			n, err := s.conn.Read(bufs[count][:s.maxPacket])
			restoreDeadline()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return count, err
			}
			if n == 0 {
				continue
			}
			sizes[count] = n
			count++
			continue
		}
		n, err := s.conn.Read(bufs[count][:s.maxPacket])
		if err != nil {
			return count, err
		}
		if n == 0 {
			continue
		}
		sizes[count] = n
		count++
	}
	if s.stats != nil {
		s.stats.AddRX(count, sumPacketSizes(sizes[:count]))
	}
	return count, nil
}

// compactReadBatch validates batch metadata and removes empty datagrams while preserving packet order.
func compactReadBatch(bufs [][]byte, sizes []int, n int, maxPacket int) (int, error) {
	if n < 0 || n > len(bufs) || n > len(sizes) {
		return 0, fmt.Errorf("udp batch count out of range: %d", n)
	}
	count := 0
	for i := 0; i < n; i++ {
		sz := sizes[i]
		if sz < 0 || sz > maxPacket || sz > len(bufs[i]) {
			return 0, fmt.Errorf("udp packet size out of range: %d", sz)
		}
		if sz == 0 {
			continue
		}
		if sz > len(bufs[count]) {
			return 0, fmt.Errorf("udp packet size out of range: %d", sz)
		}
		count++
	}
	out := 0
	for i := 0; i < n; i++ {
		sz := sizes[i]
		if sz == 0 {
			continue
		}
		if out != i {
			copy(bufs[out], bufs[i][:sz])
		}
		sizes[out] = sz
		out++
	}
	clear(sizes[out:n])
	return out, nil
}

func (s *clientConn) readBatchGRO(ctx context.Context, bufs [][]byte, sizes []int, batchN int) (int, error) {
	count := 0
	restoreReadDeadline := func() {}
	drainDeadlineArmed := false
	defer func() {
		if drainDeadlineArmed {
			restoreReadDeadline()
		}
	}()
	for count < batchN {
		if s.groPendingN == 0 {
			if count == 0 {
				if err := s.refreshReadDeadline(time.Now()); err != nil {
					return count, err
				}
			}
			if count > 0 && !drainDeadlineArmed {
				var ok bool
				restoreReadDeadline, ok = s.armReadDrainDeadline()
				if !ok {
					return count, nil
				}
				drainDeadlineArmed = true
			}
			n, oobn, _, _, err := s.conn.ReadMsgUDP(s.groReadBuf, s.groReadOOB)
			if err != nil {
				if count > 0 {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						return count, nil
					}
				}
				return count, err
			}
			if n <= 0 {
				continue
			}
			segSize := parseUDPGROSegmentSize(s.groReadOOB[:oobn])
			if segSize <= 0 || segSize > n {
				segSize = n
			}
			if segCount := groSegmentCount(n, segSize); segCount > 1 && s.stats != nil {
				s.stats.AddGRO(1, segCount, n)
			}
			s.groSegSize = segSize
			s.groPendingN = n
			s.groPendingOff = 0
		}

		sz := s.groSegSize
		if s.groPendingN < sz {
			sz = s.groPendingN
		}
		if sz <= 0 {
			s.groPendingN = 0
			continue
		}
		if sz > s.maxPacket {
			return count, fmt.Errorf("udp packet size out of range: %d", sz)
		}
		copy(bufs[count], s.groReadBuf[s.groPendingOff:s.groPendingOff+sz])
		sizes[count] = sz
		s.groPendingOff += sz
		s.groPendingN -= sz
		count++
	}
	if s.stats != nil {
		s.stats.AddRX(count, sumPacketSizes(sizes[:count]))
	}
	return count, nil
}

func (s *clientConn) armReadDrainDeadline() (func(), bool) {
	s.readDeadlineMu.Lock()
	restoreDeadline := s.combinedReadDeadlineLocked()
	s.readDeadlineMu.Unlock()
	if err := s.conn.SetReadDeadline(time.Now()); err != nil {
		return nil, false
	}
	return func() {
		s.readDeadlineMu.Lock()
		defer s.readDeadlineMu.Unlock()
		// A caller may have changed the deadline while the drain read was in
		// progress; restore the current value rather than the stale snapshot.
		if current := s.combinedReadDeadlineLocked(); current != restoreDeadline {
			restoreDeadline = current
		}
		_ = s.conn.SetReadDeadline(restoreDeadline)
	}, true
}

func (s *clientConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(sizes) < len(bufs) {
		return 0, fmt.Errorf("write sizes too small: %d for %d buffers", len(sizes), len(bufs))
	}
	batchN := minInt(len(bufs), len(sizes), s.batchSize)
	if batchN == 0 {
		return 0, nil
	}
	for i := 0; i < batchN; i++ {
		sz := sizes[i]
		if sz < 0 || sz > len(bufs[i]) {
			return 0, fmt.Errorf("invalid packet size %d for buffer[%d]", sz, i)
		}
		if sz > s.maxPacket {
			return 0, fmt.Errorf("udp packet too large: %d", sz)
		}
	}
	if err := s.refreshWriteDeadlineLocked(time.Now()); err != nil {
		return 0, err
	}
	if s.udpGSO {
		n, err := s.writeBatchWithGSO(bufs, sizes, batchN, nil)
		if s.stats != nil {
			s.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
		}
		return n, err
	}

	if s.batchEnabled {
		if s.batchIPv6 {
			msgs := s.writeMsgs6[:batchN]
			vecs := s.writeVecs6[:batchN]
			outN := 0
			for i := 0; i < batchN; i++ {
				sz := sizes[i]
				if sz == 0 {
					continue
				}
				vecs[outN][0] = bufs[i][:sz]
				msgs[outN].Buffers = vecs[outN][:]
				msgs[outN].Addr = nil
				outN++
			}
			if outN == 0 {
				return 0, nil
			}
			n, err := s.batchV6.WriteBatch(msgs[:outN], 0)
			if s.stats != nil {
				s.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
			}
			return n, err
		}
		msgs := s.writeMsgs4[:batchN]
		vecs := s.writeVecs4[:batchN]
		outN := 0
		for i := 0; i < batchN; i++ {
			sz := sizes[i]
			if sz == 0 {
				continue
			}
			vecs[outN][0] = bufs[i][:sz]
			msgs[outN].Buffers = vecs[outN][:]
			msgs[outN].Addr = nil
			outN++
		}
		if outN == 0 {
			return 0, nil
		}
		n, err := s.batchV4.WriteBatch(msgs[:outN], 0)
		if s.stats != nil {
			s.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
		}
		return n, err
	}

	count := 0
	writtenBytes := 0
	for i := 0; i < batchN; i++ {
		sz := sizes[i]
		if sz == 0 {
			continue
		}
		if _, err := s.conn.Write(bufs[i][:sz]); err != nil {
			if s.stats != nil {
				s.stats.AddTX(count, writtenBytes)
			}
			return count, err
		}
		count++
		writtenBytes += sz
	}
	if s.stats != nil {
		s.stats.AddTX(count, writtenBytes)
	}
	return count, nil
}

func (s *clientConn) writeBatchWithGSO(bufs [][]byte, sizes []int, batchN int, remote *net.UDPAddr) (int, error) {
	count, unsupported, err := writeBatchWithUDPGSO(s.conn, remote, bufs, sizes, batchN, s.maxPacket, &s.gsoOOB, &s.gsoWriteBuf, s.stats)
	if unsupported {
		s.udpGSO = false
		s.gsoOOB = nil
		s.gsoWriteBuf = nil
	}
	return count, err
}
