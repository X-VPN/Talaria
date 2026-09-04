// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/X-VPN/Talaria/internal/sourceip"
)

const (
	defaultIdleTimeout               = time.Minute
	defaultBatchSize                 = 32
	defaultInboundQueue              = 256
	defaultMaxSessions               = 4096
	defaultMaxSessionsPerIP          = 512
	defaultMaxQueuedBytes            = 512 << 20
	defaultMaxQueuedPerSession       = 16 << 20
	defaultReadBufSize               = 64 * 1024
	defaultUDPSocketBuffer           = 4 << 20
	preferredUDPSocketBuffer         = 64 << 20
	defaultUDPDeadlineRefresh        = 50 * time.Millisecond
	defaultUDPGSOMaxPayload          = 65507
	defaultUDPGSOMaxSegments         = 64
	defaultUDPReadWorkersMax         = 1
	MaxUDPPayloadIPv4                = 65507
	MaxUDPPayloadIPv6                = 65527
	defaultMaxPacket                 = MaxUDPPayloadIPv4
	defaultMaxIdleReadBuffers        = 1024
	maxBatchSize                     = 256
	maxQueueSize                     = 1 << 16
	maxSessionLimit                  = 1 << 20
	maxQueuedBytesLimit        int64 = 8 << 30
	maxReadBufferSize                = 1 << 20
	maxIdleReadBuffers               = 1 << 16
)

var udpSocketBufferCandidates = [...]int{
	preferredUDPSocketBuffer,
	32 << 20,
	16 << 20,
	8 << 20,
	defaultUDPSocketBuffer,
}

var udpGOMAXPROCS = runtime.GOMAXPROCS
var udpGSOMaxPayload = defaultUDPGSOMaxPayload
var udpGSOMaxSegments = defaultUDPGSOMaxSegments

type BatchConn interface {
	net.Conn
	BatchSize() int
	ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error)
	WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error)
}

type batchConnWrapper struct {
	net.Conn
}

func (w batchConnWrapper) BatchSize() int {
	return 1
}

func (w batchConnWrapper) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	n, err := w.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	if n == 0 {
		return 0, nil
	}
	return 1, nil
}

func (w batchConnWrapper) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(sizes) < len(bufs) {
		return 0, errors.New("TalariaUDP session: write sizes too small")
	}
	count := 0
	for i := range bufs {
		sz := sizes[i]
		if sz < 0 || sz > len(bufs[i]) {
			return count, fmt.Errorf("TalariaUDP session: invalid packet size %d for buffer[%d]", sz, i)
		}
		if sz == 0 {
			continue
		}
		n, err := w.Write(bufs[i][:sz])
		if err != nil {
			return count, err
		}
		if n != sz {
			return count, io.ErrShortWrite
		}
		count++
	}
	return count, nil
}

func WrapBatchConn(conn net.Conn) BatchConn {
	if c, ok := conn.(BatchConn); ok {
		return c
	}
	return batchConnWrapper{Conn: conn}
}

type Stats interface {
	Close()
	AddRX(packets int, bytes int)
	AddTX(packets int, bytes int)
	AddGSO(msgs int, segments int, wireBytes int)
	AddGSOFallback(groups int)
	AddGRO(msgs int, segments int, wireBytes int)
	AddQueueDrops(packets int)
}

type StatsFactory func(name string, local net.Addr, remote net.Addr) Stats

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type readBufferPool struct {
	size int
	idle chan []byte
}

func newReadBufferPool(size int, maxIdle int) *readBufferPool {
	if maxIdle < 0 {
		maxIdle = 0
	}
	return &readBufferPool{
		size: size,
		idle: make(chan []byte, maxIdle),
	}
}

func (p *readBufferPool) Get() []byte {
	if p == nil {
		return nil
	}
	select {
	case buf := <-p.idle:
		return buf
	default:
		return make([]byte, p.size)
	}
}

func (p *readBufferPool) Put(buf []byte) {
	if p == nil || buf == nil || len(buf) != p.size {
		return
	}
	select {
	case p.idle <- buf:
	default:
	}
}

func (p *readBufferPool) idleLen() int {
	if p == nil {
		return 0
	}
	return len(p.idle)
}

type packet struct {
	buf  []byte
	n    int
	pool *readBufferPool
}

func (p packet) retainedBytes() int64 {
	return int64(cap(p.buf))
}

func (p packet) release() {
	if p.pool != nil && p.buf != nil {
		p.pool.Put(p.buf)
	}
}

func (p *packet) compact() {
	if p == nil || p.n <= 0 || p.n >= cap(p.buf) {
		return
	}
	buf := make([]byte, p.n)
	copy(buf, p.buf[:p.n])
	p.release()
	p.buf = buf
	p.pool = nil
}

type sessionKey struct {
	raw   string
	zone  string
	port  int
	ip    [16]byte
	ipLen uint8
}

type sourceKey struct {
	raw   string
	zone  string
	ip    [16]byte
	ipLen uint8
}

func sessionKeyFromAddr(addr net.Addr) sessionKey {
	key := sessionKey{}
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		if addr != nil {
			key.raw = addr.String()
		}
		return key
	}
	key.port = ua.Port
	key.zone = ua.Zone
	if ip4 := ua.IP.To4(); ip4 != nil {
		copy(key.ip[:4], ip4)
		key.ipLen = 4
		return key
	}
	if ip16 := ua.IP.To16(); ip16 != nil {
		copy(key.ip[:], ip16)
		key.ipLen = 16
		return key
	}
	key.raw = ua.String()
	return key
}

func sourceKeyFromAddr(addr net.Addr, ipv6PrefixBits int) sourceKey {
	key := sourceKey{}
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		if addr != nil {
			raw := addr.String()
			if host, _, err := net.SplitHostPort(raw); err == nil {
				key.raw = host
			} else {
				key.raw = raw
			}
		}
		return key
	}
	key.zone = ua.Zone
	if ip4 := ua.IP.To4(); ip4 != nil {
		copy(key.ip[:4], ip4)
		key.ipLen = 4
		return key
	}
	if ip16 := ua.IP.To16(); ip16 != nil {
		copy(key.ip[:], ip16)
		sourceip.MaskIPv6(&key.ip, ipv6PrefixBits)
		key.ipLen = 16
		return key
	}
	key.raw = ua.IP.String()
	return key
}

type udpSocketBufferTuner interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

func tuneUDPSocketBuffer(conn udpSocketBufferTuner) int {
	for _, size := range udpSocketBufferCandidates {
		rerr := conn.SetReadBuffer(size)
		werr := conn.SetWriteBuffer(size)
		if rerr == nil && werr == nil {
			return size
		}
	}
	return 0
}

func shouldRefreshDeadline(now time.Time, deadline time.Time, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	if deadline.IsZero() {
		return true
	}
	refreshBefore := timeout / 4
	if refreshBefore < defaultUDPDeadlineRefresh {
		refreshBefore = defaultUDPDeadlineRefresh
	}
	return !now.Before(deadline.Add(-refreshBefore))
}

func minInt(v int, rest ...int) int {
	m := v
	for _, x := range rest {
		if x < m {
			m = x
		}
	}
	return m
}

// MaxUDPPayloadForAddr returns the largest non-jumbogram UDP payload for addr's
// IP family. Unknown address types use the conservative IPv4 limit.
func MaxUDPPayloadForAddr(addr net.Addr) int {
	if isIPv6Addr(addr) {
		return MaxUDPPayloadIPv6
	}
	return MaxUDPPayloadIPv4
}

func sumPacketSizes(sizes []int) int {
	total := 0
	for _, sz := range sizes {
		if sz > 0 {
			total += sz
		}
	}
	return total
}

func sumBatchWriteSizes(bufs [][]byte, sizes []int, count int) int {
	total := 0
	used := 0
	for i := 0; i < len(sizes) && i < len(bufs) && used < count; i++ {
		sz := sizes[i]
		if sz <= 0 {
			continue
		}
		if sz > len(bufs[i]) {
			break
		}
		total += sz
		used++
	}
	return total
}

func groSegmentCount(totalBytes, segSize int) int {
	if totalBytes <= 0 || segSize <= 0 {
		return 0
	}
	return (totalBytes + segSize - 1) / segSize
}

func resolveUDPReadWorkers(batchReadEnabled bool, udpGRO bool) int {
	// GRO parser keeps per-reader state, so keep a single reader when GRO is enabled.
	if udpGRO {
		return 1
	}
	// Plain per-packet reads can reorder packets when multiple goroutines call
	// ReadFrom on the same socket. Keep this path single-threaded and reserve
	// multi-reader fan-out for the real batch read path.
	if !batchReadEnabled {
		return 1
	}
	workers := udpGOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > defaultUDPReadWorkersMax {
		return defaultUDPReadWorkersMax
	}
	return workers
}

func writeSingleUDPPacket(conn *net.UDPConn, remote *net.UDPAddr, payload []byte) error {
	if remote == nil {
		_, err := conn.Write(payload)
		return err
	}
	_, err := conn.WriteToUDP(payload, remote)
	return err
}

func classifyUDPGSOWriteError(err error) (fallbackToSingle bool, disableGSO bool) {
	if err == nil {
		return false, false
	}
	if isUDPSegmentUnsupported(err) {
		return true, true
	}
	if isUDPSegmentRecoverable(err) {
		return true, false
	}
	return false, false
}

func isUDPSegmentRecoverable(err error) bool {
	var errno syscall.Errno
	if errorAs(err, &errno) {
		return errno == syscall.EINVAL || errno == syscall.EMSGSIZE
	}
	var opErr *net.OpError
	if errorAs(err, &opErr) {
		return isUDPSegmentRecoverable(opErr.Err)
	}
	var sysErr *os.SyscallError
	if errorAs(err, &sysErr) {
		return isUDPSegmentRecoverable(sysErr.Err)
	}
	return false
}

func writeBatchWithUDPGSO(
	conn *net.UDPConn,
	remote *net.UDPAddr,
	bufs [][]byte,
	sizes []int,
	batchN int,
	maxPacket int,
	gsoOOB *[]byte,
	scratch *[]byte,
	stats Stats,
) (count int, unsupported bool, err error) {
	if conn == nil {
		return 0, false, net.ErrClosed
	}
	for i := 0; i < batchN; {
		sz := sizes[i]
		if sz <= 0 {
			i++
			continue
		}
		if sz > len(bufs[i]) {
			return count, false, fmt.Errorf("invalid packet size %d for buffer[%d]", sz, i)
		}
		if sz > maxPacket {
			return count, false, fmt.Errorf("udp packet too large: %d", sz)
		}

		groupEnd := i + 1
		total := sz
		for groupEnd < batchN {
			next := sizes[groupEnd]
			if next != sz || next <= 0 {
				break
			}
			if next > len(bufs[groupEnd]) || next > maxPacket {
				break
			}
			if groupEnd-i >= udpGSOMaxSegments {
				break
			}
			if total+next > udpGSOMaxPayload {
				break
			}
			total += next
			groupEnd++
		}

		if groupEnd-i > 1 {
			if cap(*scratch) < total {
				*scratch = make([]byte, total)
			}
			agg := (*scratch)[:total]
			off := 0
			for j := i; j < groupEnd; j++ {
				copy(agg[off:off+sz], bufs[j][:sz])
				off += sz
			}
			oob := buildUDPSegmentOOB(sz, *gsoOOB)
			*gsoOOB = oob
			if _, _, werr := conn.WriteMsgUDP(agg, oob, remote); werr != nil {
				fallback, disableGSO := classifyUDPGSOWriteError(werr)
				if fallback {
					if disableGSO {
						unsupported = true
					}
					if stats != nil {
						stats.AddGSOFallback(1)
					}
					for j := i; j < groupEnd; j++ {
						if werr = writeSingleUDPPacket(conn, remote, bufs[j][:sz]); werr != nil {
							return count, unsupported, werr
						}
						count++
					}
					i = groupEnd
					continue
				}
				return count, unsupported, werr
			}
			if stats != nil {
				stats.AddGSO(1, groupEnd-i, total)
			}
			count += groupEnd - i
			i = groupEnd
			continue
		}

		if werr := writeSingleUDPPacket(conn, remote, bufs[i][:sz]); werr != nil {
			return count, unsupported, werr
		}
		count++
		i++
	}
	return count, unsupported, nil
}

func errorAs(err error, target any) bool {
	return err != nil && target != nil && errors.As(err, target)
}

func isIPv6Addr(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a != nil && a.IP != nil && a.IP.To4() == nil
	case *net.TCPAddr:
		return a != nil && a.IP != nil && a.IP.To4() == nil
	default:
		return false
	}
}

func isIPv6UDPAddr(addr net.Addr) bool {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil || ua.IP == nil {
		return false
	}
	return ua.IP.To4() == nil
}
