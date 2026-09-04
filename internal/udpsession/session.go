// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package udpsession multiplexes many logical connections over one UDP listener
// and bounds the memory each one can hold.
//
// A single socket receives every client, so admission has to happen before state
// is created: the listener enforces global and per-source session limits, a
// bounded accept queue, per-session packet queues, and a cap on retained buffer
// bytes. Batched reads and writes, and the Linux segmentation offload paths,
// exist to keep syscall counts down at high packet rates.
package udpsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/sourceip"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var listenerSessionID uint64

const (
	readErrorInitialBackoff       = 10 * time.Millisecond
	readErrorMaxBackoff           = time.Second
	readErrorLimit                = 3
	defaultNewSessionReplyQueue   = 64
	defaultNewSessionRepliesPerIP = 2
	defaultNewSessionReplyBytes   = 1 << 20
	defaultNewSessionReplyTimeout = 100 * time.Millisecond
	maximumNewSessionReplyTimeout = time.Second
)

var (
	ErrSessionLimit       = errors.New("TalariaUDP session: session limit reached")
	ErrSourceSessionLimit = errors.New("TalariaUDP session: source session limit reached")
	ErrAcceptQueueFull    = errors.New("TalariaUDP session: accept queue full")
	ErrInboundQueueFull   = errors.New("TalariaUDP session: inbound queue full")
	ErrQueueMemoryLimit   = errors.New("TalariaUDP session: queued memory limit reached")
	ErrPacketTooLarge     = errors.New("TalariaUDP session: packet too large")
)

type NewListenerReq struct {
	ListenAddr                string
	ListenPacket              func(network, address string) (net.PacketConn, error)
	PacketConn                net.PacketConn
	ManualReceive             bool
	IdleTimeout               time.Duration
	BatchSize                 int
	InboundQueue              int
	AcceptQueue               int
	SessionQueue              int
	MaxSessions               int
	MaxSessionsPerSourceIP    int
	MaxQueuedBytes            int64
	MaxQueuedBytesPerSourceIP int64
	MaxQueuedBytesPerSession  int64
	ReadBufferSize            int
	MaxPacket                 int
	EnableBatchRead           bool
	MaxIdleReadBuffers        int
	IOTimeout                 time.Duration
	StatsFactory              StatsFactory
	NewSessionGate            NewSessionGate
	NewSessionReplyQueue      int
	NewSessionRepliesPerIP    int
	NewSessionReplyMaxBytes   int64
	NewSessionReplyTimeout    time.Duration
	CompactReadBuffers        bool
	DeferInboundActivity      bool
	IPv6SourcePrefixBits      int
}

// NewSessionGate decides whether an unknown remote may allocate session state.
// Implementations must treat packet and remote as untrusted input.
type NewSessionGate interface {
	EvaluateNewSession(packet []byte, remote net.Addr) NewSessionDecision
}

type NewSessionDecision struct {
	Admit   bool
	Payload []byte
	Reply   []byte
	State   any
	Commit  func() (func(), bool)
}

type Listener struct {
	pc            net.PacketConn
	udpConn       *net.UDPConn
	acceptCh      chan *Conn
	acceptSlots   chan struct{}
	closeCh       chan struct{}
	closeState    atomic.Uint32
	closeErrMu    sync.Mutex
	closeErr      error
	manualReceive bool

	idleTimeout               time.Duration
	ioTimeout                 time.Duration
	batchSize                 int
	queueSize                 int
	maxSessions               int
	maxSessionsPerSourceIP    int
	maxQueuedBytes            int64
	maxQueuedBytesPerSourceIP int64
	maxQueuedBytesPerSession  int64
	maxPacket                 int
	readBufferSize            int
	statsFactory              StatsFactory
	newSessionGate            NewSessionGate
	compactReadBuffers        bool
	deferInboundActivity      bool
	ipv6SourcePrefixBits      int

	mu                sync.Mutex
	sessions          map[sessionKey]*Conn
	sessionsBySource  map[sourceKey]*sourceUsage
	queuedBytes       atomic.Int64
	writeMu           sync.Mutex
	writeStateMu      sync.Mutex
	activeWriter      *Conn
	activeWriteCtx    context.Context
	replyMu           sync.Mutex
	replyQueue        chan newSessionReply
	replyDone         chan struct{}
	replyPending      int
	replyPendingBytes int64
	repliesBySource   map[sourceKey]int
	replyLimit        int
	replyPerSource    int
	replyByteLimit    int64
	replyTimeout      time.Duration
	replyClosed       bool

	readDeadline     time.Time
	udpGSO           bool
	udpGRO           bool
	readWorkers      int
	batchReadEnabled bool
	batchV4          *ipv4.PacketConn
	batchV6          *ipv6.PacketConn

	bufPool *readBufferPool

	terminalMu  sync.Mutex
	terminalErr error
}

type Conn struct {
	listener    *Listener
	remote      net.Addr
	sessionID   string
	key         sessionKey
	source      sourceKey
	sourceUsage *sourceUsage
	inbound     chan packet
	inboundMu   sync.RWMutex
	closeCh     chan struct{}
	closeSignal sync.Once
	closeOnce   sync.Once
	releaseGate func()
	gateState   any
	stats       Stats

	lastActive atomic.Int64

	batchEnabled bool
	batchIPv6    bool
	batchV4      *ipv4.PacketConn
	batchV6      *ipv6.PacketConn
	writeMsgs4   []ipv4.Message
	writeVecs4   [][1][]byte
	writeMsgs6   []ipv6.Message
	writeVecs6   [][1][]byte

	udpGSO      bool
	gsoOOB      []byte
	gsoWriteBuf []byte

	droppedPackets atomic.Uint64
	queuedBytes    atomic.Int64
	compactReads   atomic.Bool
	writeMu        sync.Mutex

	deadlineMu          sync.RWMutex
	readDeadline        time.Time
	readDeadlineChanged chan struct{}
	writeDeadline       time.Time
}

type sourceUsage struct {
	sessions    int
	queuedBytes atomic.Int64
}

type newSessionReply struct {
	packet []byte
	addr   net.Addr
	source sourceKey
}

func NewListener(req NewListenerReq) (*Listener, error) {
	if req.InboundQueue < 0 || req.AcceptQueue < 0 || req.SessionQueue < 0 || req.NewSessionReplyQueue < 0 || req.NewSessionRepliesPerIP < 0 {
		return nil, errors.New("TalariaUDP session: queue limits cannot be negative")
	}
	if req.MaxSessions < 0 || req.MaxSessionsPerSourceIP < 0 {
		return nil, errors.New("TalariaUDP session: session limits cannot be negative")
	}
	if req.MaxQueuedBytes < 0 || req.MaxQueuedBytesPerSourceIP < 0 || req.MaxQueuedBytesPerSession < 0 || req.NewSessionReplyMaxBytes < 0 {
		return nil, errors.New("TalariaUDP session: queued byte limits cannot be negative")
	}
	if req.IdleTimeout < 0 || req.IOTimeout < 0 || req.NewSessionReplyTimeout < 0 {
		return nil, errors.New("TalariaUDP session: timeouts cannot be negative")
	}
	if req.BatchSize > maxBatchSize {
		return nil, fmt.Errorf("TalariaUDP session: batch size %d exceeds maximum %d", req.BatchSize, maxBatchSize)
	}
	if req.InboundQueue > maxQueueSize || req.AcceptQueue > maxQueueSize || req.SessionQueue > maxQueueSize {
		return nil, fmt.Errorf("TalariaUDP session: queue size exceeds maximum %d", maxQueueSize)
	}
	if req.NewSessionReplyQueue > maxQueueSize {
		return nil, fmt.Errorf("TalariaUDP session: new-session reply queue exceeds maximum %d", maxQueueSize)
	}
	if req.NewSessionReplyTimeout > maximumNewSessionReplyTimeout {
		return nil, fmt.Errorf("TalariaUDP session: new-session reply timeout exceeds maximum %s", maximumNewSessionReplyTimeout)
	}
	if req.MaxSessions > maxSessionLimit || req.MaxSessionsPerSourceIP > maxSessionLimit {
		return nil, fmt.Errorf("TalariaUDP session: session limit exceeds maximum %d", maxSessionLimit)
	}
	if req.MaxQueuedBytes > maxQueuedBytesLimit || req.MaxQueuedBytesPerSourceIP > maxQueuedBytesLimit || req.MaxQueuedBytesPerSession > maxQueuedBytesLimit || req.NewSessionReplyMaxBytes > maxQueuedBytesLimit {
		return nil, fmt.Errorf("TalariaUDP session: queued byte limit exceeds maximum %d", maxQueuedBytesLimit)
	}
	if req.ReadBufferSize > maxReadBufferSize {
		return nil, fmt.Errorf("TalariaUDP session: read buffer size %d exceeds maximum %d", req.ReadBufferSize, maxReadBufferSize)
	}
	if req.MaxPacket > MaxUDPPayloadIPv6 {
		return nil, fmt.Errorf("TalariaUDP session: max packet %d exceeds UDP maximum %d", req.MaxPacket, MaxUDPPayloadIPv6)
	}
	if req.MaxIdleReadBuffers > maxIdleReadBuffers {
		return nil, fmt.Errorf("TalariaUDP session: idle read buffer limit %d exceeds maximum %d", req.MaxIdleReadBuffers, maxIdleReadBuffers)
	}
	if req.ListenPacket == nil {
		req.ListenPacket = net.ListenPacket
	}
	if req.IdleTimeout <= 0 {
		req.IdleTimeout = defaultIdleTimeout
	}
	if req.BatchSize <= 0 {
		req.BatchSize = defaultBatchSize
	}
	if req.AcceptQueue == 0 {
		req.AcceptQueue = req.InboundQueue
		if req.AcceptQueue == 0 {
			req.AcceptQueue = defaultInboundQueue
		}
	}
	if req.SessionQueue == 0 {
		req.SessionQueue = req.InboundQueue
		if req.SessionQueue == 0 {
			req.SessionQueue = defaultInboundQueue
		}
	}
	if req.MaxSessions == 0 {
		req.MaxSessions = defaultMaxSessions
	}
	if req.MaxSessionsPerSourceIP == 0 {
		req.MaxSessionsPerSourceIP = min(defaultMaxSessionsPerIP, req.MaxSessions/2)
	}
	if req.MaxSessionsPerSourceIP == 0 || req.MaxSessionsPerSourceIP >= req.MaxSessions {
		return nil, errors.New("TalariaUDP session: source session limit must be less than global limit")
	}
	if req.MaxQueuedBytes == 0 {
		req.MaxQueuedBytes = defaultMaxQueuedBytes
	}
	if req.MaxQueuedBytesPerSourceIP == 0 {
		req.MaxQueuedBytesPerSourceIP = req.MaxQueuedBytes / 2
	}
	if req.MaxQueuedBytesPerSourceIP == 0 || req.MaxQueuedBytesPerSourceIP >= req.MaxQueuedBytes {
		return nil, errors.New("TalariaUDP session: source queued byte limit must be less than global limit")
	}
	if req.MaxQueuedBytesPerSession == 0 {
		req.MaxQueuedBytesPerSession = min(int64(defaultMaxQueuedPerSession), req.MaxQueuedBytes/2)
	}
	if req.MaxQueuedBytesPerSession == 0 || req.MaxQueuedBytesPerSession >= req.MaxQueuedBytes {
		return nil, errors.New("TalariaUDP session: session queued byte limit must be less than global limit")
	}
	if req.ReadBufferSize <= 0 {
		req.ReadBufferSize = defaultReadBufSize
	}
	if req.MaxPacket <= 0 {
		req.MaxPacket = defaultMaxPacket
	}
	if req.ReadBufferSize < req.MaxPacket {
		return nil, fmt.Errorf("TalariaUDP session: read buffer size %d is smaller than max packet %d", req.ReadBufferSize, req.MaxPacket)
	}
	if req.MaxIdleReadBuffers <= 0 {
		req.MaxIdleReadBuffers = defaultMaxIdleReadBuffers
	}
	if req.NewSessionReplyQueue == 0 {
		req.NewSessionReplyQueue = defaultNewSessionReplyQueue
	}
	if req.NewSessionRepliesPerIP == 0 {
		req.NewSessionRepliesPerIP = min(defaultNewSessionRepliesPerIP, req.NewSessionReplyQueue)
	}
	if req.NewSessionRepliesPerIP > req.NewSessionReplyQueue {
		return nil, errors.New("TalariaUDP session: source reply limit exceeds global reply limit")
	}
	if req.NewSessionReplyMaxBytes == 0 {
		req.NewSessionReplyMaxBytes = defaultNewSessionReplyBytes
	}
	if req.NewSessionReplyTimeout == 0 {
		req.NewSessionReplyTimeout = defaultNewSessionReplyTimeout
	}
	if req.IOTimeout > 0 && req.IOTimeout < req.NewSessionReplyTimeout {
		req.NewSessionReplyTimeout = req.IOTimeout
	}
	ipv6PrefixBits, err := sourceip.NormalizePrefixBits(req.IPv6SourcePrefixBits)
	if err != nil {
		return nil, fmt.Errorf("TalariaUDP session: %w", err)
	}
	req.IPv6SourcePrefixBits = ipv6PrefixBits
	if req.PacketConn != nil && extension.IsNil(req.PacketConn) {
		return nil, errors.New("TalariaUDP session: packet connection is typed nil")
	}
	pc := req.PacketConn
	ownedPacketConn := false
	if pc == nil {
		pc, err = req.ListenPacket("udp", req.ListenAddr)
		if err != nil {
			if !extension.IsNil(pc) {
				_ = extension.Do("TalariaUDP session failed packet listener close", pc.Close)
			}
			return nil, err
		}
		ownedPacketConn = true
	}
	if extension.IsNil(pc) {
		return nil, errors.New("TalariaUDP session: packet listener returned a nil connection")
	}
	if wireMax := MaxUDPPayloadForAddr(pc.LocalAddr()); req.MaxPacket > wireMax {
		if ownedPacketConn {
			_ = pc.Close()
		}
		return nil, fmt.Errorf("TalariaUDP session: max packet %d exceeds %s payload maximum %d", req.MaxPacket, pc.LocalAddr().Network(), wireMax)
	}
	l := &Listener{
		pc:                        pc,
		acceptCh:                  make(chan *Conn, req.AcceptQueue),
		acceptSlots:               make(chan struct{}, req.AcceptQueue),
		closeCh:                   make(chan struct{}),
		manualReceive:             req.ManualReceive,
		idleTimeout:               req.IdleTimeout,
		ioTimeout:                 req.IOTimeout,
		batchSize:                 req.BatchSize,
		queueSize:                 req.SessionQueue,
		maxSessions:               req.MaxSessions,
		maxSessionsPerSourceIP:    req.MaxSessionsPerSourceIP,
		maxQueuedBytes:            req.MaxQueuedBytes,
		maxQueuedBytesPerSourceIP: req.MaxQueuedBytesPerSourceIP,
		maxQueuedBytesPerSession:  req.MaxQueuedBytesPerSession,
		maxPacket:                 req.MaxPacket,
		readBufferSize:            req.ReadBufferSize,
		statsFactory:              req.StatsFactory,
		newSessionGate:            req.NewSessionGate,
		compactReadBuffers:        req.CompactReadBuffers,
		deferInboundActivity:      req.DeferInboundActivity,
		ipv6SourcePrefixBits:      req.IPv6SourcePrefixBits,
		sessions:                  map[sessionKey]*Conn{},
		sessionsBySource:          map[sourceKey]*sourceUsage{},
		bufPool:                   newReadBufferPool(req.ReadBufferSize, req.MaxIdleReadBuffers),
	}
	if req.NewSessionGate != nil {
		l.replyQueue = make(chan newSessionReply, req.NewSessionReplyQueue)
		l.replyDone = make(chan struct{})
		l.repliesBySource = make(map[sourceKey]int)
		l.replyLimit = req.NewSessionReplyQueue
		l.replyPerSource = req.NewSessionRepliesPerIP
		l.replyByteLimit = req.NewSessionReplyMaxBytes
		l.replyTimeout = req.NewSessionReplyTimeout
	}
	if udpConn, ok := pc.(*net.UDPConn); ok {
		l.udpConn = udpConn
		_ = tuneUDPSocketBuffer(udpConn)
		l.udpGSO = enableUDPGSO(udpConn)
		if req.EnableBatchRead && runtime.GOOS == "linux" {
			if isIPv6Addr(pc.LocalAddr()) {
				l.batchV6 = ipv6.NewPacketConn(udpConn)
				l.batchReadEnabled = true
			} else {
				l.batchV4 = ipv4.NewPacketConn(udpConn)
				l.batchReadEnabled = true
			}
		}
	}
	l.readWorkers = resolveUDPReadWorkers(l.batchReadEnabled, l.udpGRO)
	if l.replyQueue != nil {
		go l.runNewSessionReplyWriter()
	}
	if !req.ManualReceive {
		go l.readLoop()
	}
	go l.gcLoop()
	return l, nil
}

func (l *Listener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.closeCh:
			return nil, l.acceptError()
		case conn := <-l.acceptCh:
			<-l.acceptSlots
			select {
			case <-l.closeCh:
				return nil, l.acceptError()
			default:
			}
			if conn == nil || conn.isClosed() {
				continue
			}
			return conn, nil
		}
	}
}

func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	if !l.closeState.CompareAndSwap(0, 1) {
		if l.closeState.Load() != 2 {
			return nil
		}
		l.closeErrMu.Lock()
		err := l.closeErr
		l.closeErrMu.Unlock()
		return err
	}
	l.mu.Lock()
	l.replyMu.Lock()
	l.replyClosed = true
	l.replyMu.Unlock()
	close(l.closeCh)
	sessions := make([]*Conn, 0, len(l.sessions))
	for _, conn := range l.sessions {
		sessions = append(sessions, conn)
	}
	l.sessions = map[sessionKey]*Conn{}
	l.sessionsBySource = map[sourceKey]*sourceUsage{}
	l.mu.Unlock()
	for _, conn := range sessions {
		conn.signalClose()
	}
	var closeErr error
	if !extension.IsNil(l.pc) {
		closeErr = extension.Do("TalariaUDP session packet connection close", l.pc.Close)
	}
	for _, conn := range sessions {
		_ = extension.Do("TalariaUDP session connection close", func() error {
			return conn.close(false)
		})
	}
	l.closeErrMu.Lock()
	l.closeErr = closeErr
	l.closeErrMu.Unlock()
	l.closeState.Store(2)
	return closeErr
}

func (l *Listener) acceptError() error {
	l.terminalMu.Lock()
	defer l.terminalMu.Unlock()
	if l.terminalErr != nil {
		return l.terminalErr
	}
	return net.ErrClosed
}

func (l *Listener) isClosed() bool {
	select {
	case <-l.closeCh:
		return true
	default:
		return false
	}
}

func (l *Listener) terminate(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	l.terminalMu.Lock()
	if l.terminalErr == nil {
		l.terminalErr = fmt.Errorf("TalariaUDP session listener read failed: %w", err)
	}
	l.terminalMu.Unlock()
	_ = l.Close()
}

func (l *Listener) handleReadError(err error, consecutive *int) bool {
	select {
	case <-l.closeCh:
		return false
	default:
	}
	// Timeout is the only portable retry classification; Temporary is
	// deprecated because non-timeout temporary errors are ill-defined.
	var timeoutErr interface{ Timeout() bool }
	if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
		*consecutive = 0
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		l.terminate(err)
		return false
	}
	(*consecutive)++
	if *consecutive >= readErrorLimit {
		l.terminate(err)
		return false
	}
	shift := *consecutive - 1
	if shift > 20 {
		shift = 20
	}
	backoff := readErrorInitialBackoff << shift
	if backoff > readErrorMaxBackoff {
		backoff = readErrorMaxBackoff
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-l.closeCh:
		return false
	case <-timer.C:
		return true
	}
}

func (l *Listener) ReceivePacket(b []byte, addr net.Addr) error {
	if addr == nil {
		return errors.New("TalariaUDP session: nil remote addr")
	}
	if len(b) > l.maxPacket {
		key := sessionKeyFromAddr(addr)
		l.mu.Lock()
		conn := l.sessions[key]
		l.mu.Unlock()
		if conn != nil {
			conn.recordDrop()
		}
		return ErrPacketTooLarge
	}
	buf := l.bufPool.Get()
	if len(b) > len(buf) {
		l.bufPool.Put(buf)
		buf = make([]byte, len(b))
	}
	copy(buf[:len(b)], b)
	return l.dispatchPacket(packet{
		buf:  buf,
		n:    len(b),
		pool: l.bufPool,
	}, addr)
}

func (l *Listener) readLoop() {
	if l.batchReadEnabled {
		if l.batchV6 != nil {
			l.runReadWorkers(l.readLoopBatchV6)
			return
		}
		l.runReadWorkers(l.readLoopBatchV4)
		return
	}
	l.runReadWorkers(l.readLoopSimple)
}

func (l *Listener) runReadWorkers(loopFn func()) {
	if l.readWorkers <= 1 {
		loopFn()
		return
	}
	var wg sync.WaitGroup
	wg.Add(l.readWorkers)
	for i := 0; i < l.readWorkers; i++ {
		go func() {
			defer wg.Done()
			loopFn()
		}()
	}
	wg.Wait()
}

func (l *Listener) readLoopSimple() {
	var lastKey sessionKey
	var lastConn *Conn
	var hasLast bool
	readFailures := 0
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		buf := l.bufPool.Get()
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.bufPool.Put(buf)
			if !l.handleReadError(err, &readFailures) {
				return
			}
			continue
		}
		if n < 0 || n > len(buf) || (n > 0 && addr == nil) {
			l.bufPool.Put(buf)
			l.terminate(fmt.Errorf("invalid ReadFrom result: n=%d buffer=%d addr=%v", n, len(buf), addr))
			return
		}
		readFailures = 0
		if n <= 0 {
			l.bufPool.Put(buf)
			continue
		}
		now := time.Now()
		key := sessionKeyFromAddr(addr)
		conn := lastConn
		created := false
		pkt := packet{buf: buf, n: n, pool: l.bufPool}
		if !hasLast || key != lastKey || conn == nil || conn.isClosed() {
			var admitted bool
			conn, created, admitted, err = l.getOrCreateConnForPacket(key, addr, &pkt)
			lastKey = key
			lastConn = conn
			hasLast = err == nil && admitted
			if !admitted {
				pkt.release()
				continue
			}
		}
		if err != nil {
			pkt.release()
			continue
		}
		if err := l.dispatchToConn(conn, created, pkt, now); err != nil && errors.Is(err, net.ErrClosed) {
			continue
		}
	}
}

func (l *Listener) readLoopGRO() {
	var lastKey sessionKey
	var lastConn *Conn
	var hasLast bool
	readFailures := 0
	oob := make([]byte, udpControlSize())
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		buf := l.bufPool.Get()
		if l.ioTimeout > 0 {
			now := time.Now()
			if shouldRefreshDeadline(now, l.readDeadline, l.ioTimeout) {
				l.readDeadline = now.Add(l.ioTimeout)
				_ = l.udpConn.SetReadDeadline(l.readDeadline)
			}
		}
		n, oobn, _, addr, err := l.udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			l.bufPool.Put(buf)
			if !l.handleReadError(err, &readFailures) {
				return
			}
			continue
		}
		readFailures = 0
		if n <= 0 {
			l.bufPool.Put(buf)
			continue
		}
		now := time.Now()
		if oobn == 0 {
			pkt := packet{buf: buf, n: n, pool: l.bufPool}
			key := sessionKeyFromAddr(addr)
			conn := lastConn
			created := false
			if !hasLast || key != lastKey || conn == nil || conn.isClosed() {
				var admitted bool
				conn, created, admitted, err = l.getOrCreateConnForPacket(key, addr, &pkt)
				lastKey = key
				lastConn = conn
				hasLast = err == nil && admitted
				if !admitted {
					pkt.release()
					continue
				}
			}
			if err != nil {
				pkt.release()
				continue
			}
			if err := l.dispatchToConn(conn, created, pkt, now); err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		segSize := parseUDPGROSegmentSize(oob[:oobn])
		if segSize <= 0 || segSize > n {
			segSize = n
		}
		segCount := groSegmentCount(n, segSize)
		for off := 0; off < n; off += segSize {
			sz := segSize
			if left := n - off; left < sz {
				sz = left
			}
			if sz <= 0 {
				continue
			}
			out := l.bufPool.Get()
			if sz > len(out) {
				l.bufPool.Put(out)
				out = make([]byte, sz)
			}
			copy(out[:sz], buf[off:off+sz])
			pkt := packet{buf: out, n: sz, pool: l.bufPool}
			key := sessionKeyFromAddr(addr)
			conn := lastConn
			created := false
			if !hasLast || key != lastKey || conn == nil || conn.isClosed() {
				var admitted bool
				conn, created, admitted, err = l.getOrCreateConnForPacket(key, addr, &pkt)
				lastKey = key
				lastConn = conn
				hasLast = err == nil && admitted
				if !admitted {
					pkt.release()
					continue
				}
			}
			if err != nil {
				pkt.release()
				continue
			}
			if segCount > 1 && conn.stats != nil {
				conn.stats.AddGRO(1, segCount, n)
				segCount = 0
			}
			if err := l.dispatchToConn(conn, created, pkt, now); err != nil && errors.Is(err, net.ErrClosed) {
				l.bufPool.Put(buf)
				return
			}
		}
		l.bufPool.Put(buf)
	}
}

func (l *Listener) readLoopBatchV4() {
	batchN := l.batchSize
	msgs := make([]ipv4.Message, batchN)
	vecs := make([][1][]byte, batchN)
	pkts := make([]packet, batchN)
	var lastKey sessionKey
	var lastConn *Conn
	var hasLast bool
	readFailures := 0
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		for i := 0; i < batchN; i++ {
			buf := l.bufPool.Get()
			pkts[i] = packet{buf: buf, pool: l.bufPool}
			vecs[i][0] = buf
			msgs[i].Buffers = vecs[i][:]
			msgs[i].Addr = nil
			msgs[i].N = 0
		}
		n, err := l.batchV4.ReadBatch(msgs, 0)
		if err != nil {
			for i := 0; i < batchN; i++ {
				pkts[i].release()
			}
			if !l.handleReadError(err, &readFailures) {
				return
			}
			continue
		}
		readFailures = 0
		for i := n; i < batchN; i++ {
			pkts[i].release()
		}
		now := time.Now()
		for i := 0; i < n; i++ {
			if msgs[i].N <= 0 {
				pkts[i].release()
				continue
			}
			pkts[i].n = msgs[i].N
			key := sessionKeyFromAddr(msgs[i].Addr)
			conn := lastConn
			created := false
			if !hasLast || key != lastKey || conn == nil || conn.isClosed() {
				var admitted bool
				conn, created, admitted, err = l.getOrCreateConnForPacket(key, msgs[i].Addr, &pkts[i])
				lastKey = key
				lastConn = conn
				hasLast = err == nil && admitted
				if !admitted {
					pkts[i].release()
					continue
				}
			}
			if err != nil {
				pkts[i].release()
				continue
			}
			if err := l.dispatchToConn(conn, created, pkts[i], now); err != nil && errors.Is(err, net.ErrClosed) {
				continue
			}
		}
	}
}

func (l *Listener) readLoopBatchV6() {
	batchN := l.batchSize
	msgs := make([]ipv6.Message, batchN)
	vecs := make([][1][]byte, batchN)
	pkts := make([]packet, batchN)
	var lastKey sessionKey
	var lastConn *Conn
	var hasLast bool
	readFailures := 0
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		for i := 0; i < batchN; i++ {
			buf := l.bufPool.Get()
			pkts[i] = packet{buf: buf, pool: l.bufPool}
			vecs[i][0] = buf
			msgs[i].Buffers = vecs[i][:]
			msgs[i].Addr = nil
			msgs[i].N = 0
		}
		n, err := l.batchV6.ReadBatch(msgs, 0)
		if err != nil {
			for i := 0; i < batchN; i++ {
				pkts[i].release()
			}
			if !l.handleReadError(err, &readFailures) {
				return
			}
			continue
		}
		readFailures = 0
		for i := n; i < batchN; i++ {
			pkts[i].release()
		}
		now := time.Now()
		for i := 0; i < n; i++ {
			if msgs[i].N <= 0 {
				pkts[i].release()
				continue
			}
			pkts[i].n = msgs[i].N
			key := sessionKeyFromAddr(msgs[i].Addr)
			conn := lastConn
			created := false
			if !hasLast || key != lastKey || conn == nil || conn.isClosed() {
				var admitted bool
				conn, created, admitted, err = l.getOrCreateConnForPacket(key, msgs[i].Addr, &pkts[i])
				lastKey = key
				lastConn = conn
				hasLast = err == nil && admitted
				if !admitted {
					pkts[i].release()
					continue
				}
			}
			if err != nil {
				pkts[i].release()
				continue
			}
			if err := l.dispatchToConn(conn, created, pkts[i], now); err != nil && errors.Is(err, net.ErrClosed) {
				continue
			}
		}
	}
}

func (l *Listener) dispatchPacket(pkt packet, addr net.Addr) error {
	key := sessionKeyFromAddr(addr)
	conn, created, admitted, err := l.getOrCreateConnForPacket(key, addr, &pkt)
	if err != nil {
		pkt.release()
		return err
	}
	if !admitted {
		pkt.release()
		return nil
	}
	return l.dispatchToConn(conn, created, pkt, time.Now())
}

func (l *Listener) getOrCreateConnForPacket(key sessionKey, addr net.Addr, pkt *packet) (*Conn, bool, bool, error) {
	l.mu.Lock()
	conn := l.sessions[key]
	l.mu.Unlock()
	if conn != nil {
		return conn, false, true, nil
	}

	var commit func() (func(), bool)
	var gateState any
	if l.newSessionGate != nil {
		decision := l.newSessionGate.EvaluateNewSession(pkt.buf[:pkt.n], addr)
		if len(decision.Reply) > 0 {
			if len(decision.Reply) > pkt.n || len(decision.Reply) > min(l.maxPacket, MaxUDPPayloadForAddr(addr)) {
				return nil, false, false, errors.New("TalariaUDP session: new-session reply exceeds request size")
			}
			l.enqueueNewSessionReply(decision.Reply, addr)
		}
		if !decision.Admit {
			return nil, false, false, nil
		}
		payload := decision.Payload
		if payload == nil {
			payload = pkt.buf[:pkt.n]
		}
		if len(payload) == 0 || len(payload) > l.maxPacket || len(payload) > len(pkt.buf) {
			return nil, false, false, errors.New("TalariaUDP session: invalid admitted packet size")
		}
		copy(pkt.buf, payload)
		pkt.n = len(payload)
		commit = decision.Commit
		gateState = decision.State
	}

	conn, created, admitted, err := l.getOrCreateConn(key, addr, commit, gateState)
	return conn, created, admitted, err
}

func (l *Listener) enqueueNewSessionReply(packet []byte, addr net.Addr) {
	if len(packet) == 0 || addr == nil || l.replyQueue == nil {
		return
	}
	source := sourceKeyFromAddr(addr, l.ipv6SourcePrefixBits)
	l.replyMu.Lock()
	defer l.replyMu.Unlock()
	replyBytes := int64(len(packet))
	if l.replyClosed || l.replyPending >= l.replyLimit || l.repliesBySource[source] >= l.replyPerSource || replyBytes > l.replyByteLimit-l.replyPendingBytes {
		return
	}
	reply := newSessionReply{
		packet: append([]byte(nil), packet...),
		addr:   cloneNewSessionReplyAddr(addr),
		source: source,
	}
	select {
	case l.replyQueue <- reply:
		l.replyPending++
		l.replyPendingBytes += int64(len(reply.packet))
		l.repliesBySource[source]++
	default:
	}
}

func cloneNewSessionReplyAddr(addr net.Addr) net.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return addr
	}
	clone := *udpAddr
	clone.IP = append(net.IP(nil), udpAddr.IP...)
	return &clone
}

func (l *Listener) runNewSessionReplyWriter() {
	defer close(l.replyDone)
	defer l.drainNewSessionReplies()
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}
		select {
		case <-l.closeCh:
			return
		case reply := <-l.replyQueue:
			_ = extension.Do("TalariaUDP session new-session reply write", func() error {
				return l.writeNewSessionReply(reply)
			})
			l.releaseNewSessionReply(reply)
		}
	}
}

func (l *Listener) writeNewSessionReply(reply newSessionReply) error {
	if len(reply.packet) == 0 || reply.addr == nil {
		return nil
	}
	select {
	case <-l.closeCh:
		return net.ErrClosed
	default:
	}
	if !l.writeMu.TryLock() {
		return nil
	}
	defer l.writeMu.Unlock()
	deadline := time.Now().Add(l.replyTimeout)
	err := extension.Do("TalariaUDP session new-session reply deadline", func() error {
		return l.pc.SetWriteDeadline(deadline)
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = extension.Do("TalariaUDP session new-session reply deadline reset", func() error {
			return l.pc.SetWriteDeadline(time.Time{})
		})
	}()
	n, err := l.pc.WriteTo(reply.packet, reply.addr)
	if err != nil {
		return err
	}
	if n != len(reply.packet) {
		return io.ErrShortWrite
	}
	return nil
}

func (l *Listener) releaseNewSessionReply(reply newSessionReply) {
	l.replyMu.Lock()
	l.replyPending--
	l.replyPendingBytes -= int64(len(reply.packet))
	if l.repliesBySource[reply.source] <= 1 {
		delete(l.repliesBySource, reply.source)
	} else {
		l.repliesBySource[reply.source]--
	}
	l.replyMu.Unlock()
}

func (l *Listener) drainNewSessionReplies() {
	for {
		select {
		case reply := <-l.replyQueue:
			l.releaseNewSessionReply(reply)
		default:
			return
		}
	}
}

func (l *Listener) dispatchToConn(conn *Conn, created bool, pkt packet, now time.Time) error {
	if conn == nil {
		pkt.release()
		return net.ErrClosed
	}
	err := l.dispatchExistingConnAt(conn, pkt, now)
	if err != nil && created {
		_ = conn.Close()
	}
	return err
}

func (l *Listener) dispatchExistingConn(conn *Conn, pkt packet) error {
	return l.dispatchExistingConnAt(conn, pkt, time.Now())
}

func (l *Listener) dispatchExistingConnAt(conn *Conn, pkt packet, now time.Time) error {
	if conn == nil {
		pkt.release()
		return net.ErrClosed
	}
	if pkt.n > conn.listener.maxPacket {
		conn.recordDrop()
		pkt.release()
		return ErrPacketTooLarge
	}
	conn.inboundMu.RLock()
	defer conn.inboundMu.RUnlock()
	select {
	case <-conn.closeCh:
		pkt.release()
		return net.ErrClosed
	default:
	}
	if conn.stats != nil {
		conn.stats.AddRX(1, pkt.n)
	}
	if conn.compactReads.Load() {
		pkt.compact()
	}
	retained := pkt.retainedBytes()
	if !conn.reserveQueuedBytes(retained) {
		conn.recordDrop()
		pkt.release()
		return ErrQueueMemoryLimit
	}
	select {
	case <-conn.closeCh:
		conn.releaseQueuedBytes(retained)
		pkt.release()
		return net.ErrClosed
	case <-l.closeCh:
		conn.releaseQueuedBytes(retained)
		pkt.release()
		return net.ErrClosed
	case conn.inbound <- pkt:
		if !l.deferInboundActivity {
			conn.touch(now)
		}
		return nil
	default:
		conn.releaseQueuedBytes(retained)
		conn.recordDrop()
		pkt.release()
		return ErrInboundQueueFull
	}
}

func (l *Listener) getOrCreateConn(key sessionKey, addr net.Addr, commit func() (func(), bool), gateState any) (*Conn, bool, bool, error) {
	l.mu.Lock()
	select {
	case <-l.closeCh:
		l.mu.Unlock()
		return nil, false, false, net.ErrClosed
	default:
	}
	if conn := l.sessions[key]; conn != nil {
		l.mu.Unlock()
		return conn, false, true, nil
	}
	if len(l.sessions) >= l.maxSessions {
		l.mu.Unlock()
		return nil, false, false, ErrSessionLimit
	}
	source := sourceKeyFromAddr(addr, l.ipv6SourcePrefixBits)
	usage := l.sessionsBySource[source]
	if usage != nil && usage.sessions >= l.maxSessionsPerSourceIP {
		l.mu.Unlock()
		return nil, false, false, ErrSourceSessionLimit
	}
	select {
	case l.acceptSlots <- struct{}{}:
	default:
		l.mu.Unlock()
		return nil, false, false, ErrAcceptQueueFull
	}
	var releaseGate func()
	if commit != nil {
		var committed bool
		releaseGate, committed = commit()
		if !committed {
			<-l.acceptSlots
			l.mu.Unlock()
			return nil, false, false, nil
		}
	}
	if usage == nil {
		usage = &sourceUsage{}
		l.sessionsBySource[source] = usage
	}
	id := atomic.AddUint64(&listenerSessionID, 1)
	conn := &Conn{
		listener:            l,
		remote:              addr,
		sessionID:           fmt.Sprintf("udp-session-%d", id),
		key:                 key,
		source:              source,
		sourceUsage:         usage,
		inbound:             make(chan packet, l.queueSize),
		closeCh:             make(chan struct{}),
		releaseGate:         releaseGate,
		gateState:           gateState,
		readDeadlineChanged: make(chan struct{}),
		udpGSO:              l.udpGSO,
	}
	conn.compactReads.Store(l.compactReadBuffers)
	if l.statsFactory != nil {
		conn.stats = l.statsFactory(conn.sessionID, l.pc.LocalAddr(), addr)
	}
	if conn.udpGSO {
		conn.gsoOOB = make([]byte, 0, udpControlSize())
	}
	if runtime.GOOS == "linux" {
		if isIPv6Addr(addr) {
			if l.batchV6 != nil {
				conn.batchEnabled = true
				conn.batchIPv6 = true
				conn.batchV6 = l.batchV6
				conn.writeMsgs6 = make([]ipv6.Message, l.batchSize)
				conn.writeVecs6 = make([][1][]byte, l.batchSize)
			}
		} else if l.batchV4 != nil {
			conn.batchEnabled = true
			conn.batchV4 = l.batchV4
			conn.writeMsgs4 = make([]ipv4.Message, l.batchSize)
			conn.writeVecs4 = make([][1][]byte, l.batchSize)
		}
	}
	conn.touch(time.Now())
	l.sessions[key] = conn
	usage.sessions++
	l.acceptCh <- conn
	l.mu.Unlock()
	return conn, true, true, nil
}

func (l *Listener) removeSession(conn *Conn) {
	if l == nil || conn == nil {
		return
	}
	l.mu.Lock()
	l.removeSessionLocked(conn)
	l.mu.Unlock()
}

func (l *Listener) removeSessionLocked(conn *Conn) {
	if l.sessions[conn.key] != conn {
		return
	}
	delete(l.sessions, conn.key)
	usage := conn.sourceUsage
	usage.sessions--
	if usage.sessions == 0 && usage.queuedBytes.Load() == 0 {
		delete(l.sessionsBySource, conn.source)
	}
}

func (l *Listener) cleanupSourceUsage(source sourceKey, usage *sourceUsage) {
	l.mu.Lock()
	if current := l.sessionsBySource[source]; current == usage && usage.sessions == 0 && usage.queuedBytes.Load() == 0 {
		delete(l.sessionsBySource, source)
	}
	l.mu.Unlock()
}

func (l *Listener) gcLoop() {
	if l.idleTimeout <= 0 {
		return
	}
	interval := l.idleTimeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-l.closeCh:
			return
		case <-ticker.C:
		}
		deadline := time.Now().Add(-l.idleTimeout).UnixNano()
		l.mu.Lock()
		expired := make([]*Conn, 0, len(l.sessions))
		for _, conn := range l.sessions {
			if conn.lastActive.Load() >= deadline {
				continue
			}
			expired = append(expired, conn)
			l.removeSessionLocked(conn)
		}
		l.mu.Unlock()
		for _, conn := range expired {
			_ = conn.close(false)
		}
	}
}

func (c *Conn) IsManagedUDPSession() bool {
	return true
}

func (c *Conn) NewSessionState() any {
	if c == nil {
		return nil
	}
	return c.gateState
}

func (c *Conn) LocalAddr() net.Addr {
	return c.listener.pc.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Conn) BatchSize() int {
	return c.listener.batchSize
}

func (c *Conn) Read(p []byte) (int, error) {
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

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *Conn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	n, _, err := c.readBatch(ctx, bufs, sizes, false)
	return n, err
}

func (c *Conn) ReadBatchRetained(ctx context.Context, bufs [][]byte, sizes []int) (int, int64, error) {
	return c.readBatch(ctx, bufs, sizes, true)
}

func (c *Conn) readBatch(ctx context.Context, bufs [][]byte, sizes []int, retainBudget bool) (int, int64, error) {
	batchN := minInt(len(bufs), len(sizes), c.listener.batchSize)
	if batchN == 0 {
		return 0, 0, nil
	}
	for i := 0; i < batchN; i++ {
		sizes[i] = 0
	}
	pkt, err := c.waitPacket(ctx)
	if err != nil {
		return 0, 0, err
	}
	retained := pkt.retainedBytes()
	if pkt.n > len(bufs[0]) {
		c.releaseQueuedBytes(retained)
		pkt.release()
		return 0, 0, io.ErrShortBuffer
	}
	copy(bufs[0], pkt.buf[:pkt.n])
	sizes[0] = pkt.n
	pkt.release()
	if !retainBudget {
		c.releaseQueuedBytes(retained)
		retained = 0
	}
	count := 1
	for i := 1; i < batchN; i++ {
		select {
		case pkt = <-c.inbound:
			pktRetained := pkt.retainedBytes()
			if pkt.n > len(bufs[i]) {
				c.releaseQueuedBytes(pktRetained)
				pkt.release()
				return count, retained, io.ErrShortBuffer
			}
			copy(bufs[i], pkt.buf[:pkt.n])
			sizes[i] = pkt.n
			pkt.release()
			if retainBudget {
				retained += pktRetained
			} else {
				c.releaseQueuedBytes(pktRetained)
			}
			count++
		default:
			return count, retained, nil
		}
	}
	return count, retained, nil
}

func (c *Conn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (written int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-c.listener.closeCh:
		return 0, net.ErrClosed
	default:
	}
	batchN := minInt(len(bufs), len(sizes), c.listener.batchSize)
	if batchN == 0 {
		return 0, nil
	}
	for {
		c.listener.writeMu.Lock()
		if c.writeMu.TryLock() {
			break
		}
		c.listener.writeMu.Unlock()
		c.writeMu.Lock()
		c.writeMu.Unlock()
	}
	defer c.listener.writeMu.Unlock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-c.listener.closeCh:
		return 0, net.ErrClosed
	default:
	}
	maxPacket := min(c.listener.maxPacket, MaxUDPPayloadForAddr(c.remote))
	if err := c.listener.beginConnWrite(c, ctx); err != nil {
		return 0, err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.listener.refreshActiveWriteDeadline(c)
	})
	defer func() {
		stopCancel()
		c.listener.endConnWrite(c)
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if c.udpGSO && c.listener.udpConn != nil {
		if ua, ok := c.remote.(*net.UDPAddr); ok && ua != nil {
			n, err := c.writeBatchWithGSO(bufs, sizes, batchN, ua, maxPacket)
			if n > 0 {
				c.touch(time.Now())
				if c.stats != nil {
					c.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
				}
			}
			return n, err
		}
	}
	if c.batchEnabled {
		if c.batchIPv6 {
			msgs := c.writeMsgs6[:batchN]
			vecs := c.writeVecs6[:batchN]
			outN := 0
			for i := 0; i < batchN; i++ {
				sz := sizes[i]
				if sz < 0 || sz > len(bufs[i]) {
					return outN, io.ErrShortBuffer
				}
				if sz == 0 {
					continue
				}
				if sz > maxPacket {
					return outN, fmt.Errorf("udp packet too large: %d", sz)
				}
				vecs[outN][0] = bufs[i][:sz]
				msgs[outN].Buffers = vecs[outN][:]
				msgs[outN].Addr = c.remote
				outN++
			}
			if outN == 0 {
				return 0, nil
			}
			n, err := c.batchV6.WriteBatch(msgs[:outN], 0)
			if n > 0 {
				c.touch(time.Now())
				if c.stats != nil {
					c.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
				}
			}
			return n, err
		}
		msgs := c.writeMsgs4[:batchN]
		vecs := c.writeVecs4[:batchN]
		outN := 0
		for i := 0; i < batchN; i++ {
			sz := sizes[i]
			if sz < 0 || sz > len(bufs[i]) {
				return outN, io.ErrShortBuffer
			}
			if sz == 0 {
				continue
			}
			if sz > maxPacket {
				return outN, fmt.Errorf("udp packet too large: %d", sz)
			}
			vecs[outN][0] = bufs[i][:sz]
			msgs[outN].Buffers = vecs[outN][:]
			msgs[outN].Addr = c.remote
			outN++
		}
		if outN == 0 {
			return 0, nil
		}
		n, err := c.batchV4.WriteBatch(msgs[:outN], 0)
		if n > 0 {
			c.touch(time.Now())
			if c.stats != nil {
				c.stats.AddTX(n, sumBatchWriteSizes(bufs, sizes, n))
			}
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
		if sz < 0 || sz > len(bufs[i]) {
			return count, io.ErrShortBuffer
		}
		if sz > maxPacket {
			return count, fmt.Errorf("udp packet too large: %d", sz)
		}
		n, err := c.listener.pc.WriteTo(bufs[i][:sz], c.remote)
		if err != nil {
			if c.stats != nil {
				c.stats.AddTX(count, writtenBytes)
			}
			return count, err
		}
		if n != sz {
			if c.stats != nil {
				c.stats.AddTX(count, writtenBytes)
			}
			return count, io.ErrShortWrite
		}
		c.touch(time.Now())
		count++
		writtenBytes += sz
	}
	if c.stats != nil {
		c.stats.AddTX(count, writtenBytes)
	}
	return count, nil
}

func (l *Listener) beginConnWrite(c *Conn, ctx context.Context) error {
	l.writeStateMu.Lock()
	defer l.writeStateMu.Unlock()
	if c.isClosed() || l.isClosed() {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	l.activeWriter = c
	l.activeWriteCtx = ctx
	deadline := c.effectiveWriteDeadline(ctx)
	if !deadline.IsZero() && time.Now().After(deadline) {
		l.activeWriter = nil
		l.activeWriteCtx = nil
		return timeoutError{}
	}
	if err := l.pc.SetWriteDeadline(deadline); err != nil {
		l.activeWriter = nil
		l.activeWriteCtx = nil
		return err
	}
	return nil
}

func (l *Listener) endConnWrite(c *Conn) {
	l.writeStateMu.Lock()
	defer l.writeStateMu.Unlock()
	if l.activeWriter != c {
		return
	}
	l.activeWriter = nil
	l.activeWriteCtx = nil
	_ = l.pc.SetWriteDeadline(time.Time{})
}

func (l *Listener) refreshActiveWriteDeadline(c *Conn) error {
	l.writeStateMu.Lock()
	defer l.writeStateMu.Unlock()
	if l.activeWriter != c {
		return nil
	}
	return l.pc.SetWriteDeadline(c.effectiveWriteDeadline(l.activeWriteCtx))
}

func (c *Conn) writeBatchWithGSO(bufs [][]byte, sizes []int, batchN int, remote *net.UDPAddr, maxPacket int) (int, error) {
	count, unsupported, err := writeBatchWithUDPGSO(c.listener.udpConn, remote, bufs, sizes, batchN, maxPacket, &c.gsoOOB, &c.gsoWriteBuf, c.stats)
	if unsupported {
		c.udpGSO = false
		c.gsoOOB = nil
		c.gsoWriteBuf = nil
	}
	return count, err
}

func (c *Conn) Close() error {
	return c.close(true)
}

func (c *Conn) close(removeFromListener bool) error {
	c.closeOnce.Do(func() {
		c.signalClose()
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		c.inboundMu.Lock()
		if removeFromListener {
			c.listener.removeSession(c)
		}
		for {
			select {
			case pkt := <-c.inbound:
				c.releaseQueuedBytes(pkt.retainedBytes())
				pkt.release()
			default:
				c.inboundMu.Unlock()
				if c.stats != nil {
					c.stats.Close()
				}
				return
			}
		}
	})
	return nil
}

func (c *Conn) signalClose() {
	if c == nil {
		return
	}
	c.closeSignal.Do(func() {
		close(c.closeCh)
		if c.releaseGate != nil {
			c.releaseGate()
			c.releaseGate = nil
		}
		_ = c.listener.refreshActiveWriteDeadline(c)
	})
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	changed := c.readDeadlineChanged
	c.readDeadlineChanged = make(chan struct{})
	if changed != nil {
		close(changed)
	}
	c.deadlineMu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return c.listener.refreshActiveWriteDeadline(c)
}

func (c *Conn) effectiveWriteDeadline(ctx context.Context) time.Time {
	if c.isClosed() || (ctx != nil && ctx.Err() != nil) {
		return time.Now()
	}
	deadline := c.getWriteDeadline()
	if ctx != nil {
		if ctxDeadline, ok := ctx.Deadline(); ok {
			deadline = earlierDeadline(deadline, ctxDeadline)
		}
	}
	return deadline
}

func (c *Conn) waitPacket(ctx context.Context) (packet, error) {
	for {
		deadline, changed := c.readDeadlineState()
		if time.Now().After(deadline) {
			if !deadline.IsZero() {
				return packet{}, timeoutError{}
			}
		}
		var timer *time.Timer
		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerCh = timer.C
		}
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return packet{}, ctx.Err()
		case <-c.closeCh:
			stopTimer(timer)
			return packet{}, net.ErrClosed
		case <-c.listener.closeCh:
			stopTimer(timer)
			return packet{}, net.ErrClosed
		case <-timerCh:
			return packet{}, timeoutError{}
		case <-changed:
			stopTimer(timer)
			continue
		case pkt := <-c.inbound:
			stopTimer(timer)
			if !c.listener.deferInboundActivity {
				c.touch(time.Now())
			}
			return pkt, nil
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func (c *Conn) readDeadlineState() (time.Time, <-chan struct{}) {
	c.deadlineMu.RLock()
	deadline := c.readDeadline
	changed := c.readDeadlineChanged
	c.deadlineMu.RUnlock()
	return deadline, changed
}

// MarkActive commits activity after a protocol layered above udpsession has
// authenticated an inbound packet.
func (c *Conn) MarkActive() {
	if c != nil {
		c.touch(time.Now())
	}
}

func (c *Conn) touch(now time.Time) {
	c.lastActive.Store(now.UnixNano())
}

func (c *Conn) getReadDeadline() time.Time {
	c.deadlineMu.RLock()
	deadline := c.readDeadline
	c.deadlineMu.RUnlock()
	return deadline
}

func (c *Conn) getWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	deadline := c.writeDeadline
	c.deadlineMu.RUnlock()
	return deadline
}

func (c *Conn) DroppedPackets() uint64 {
	return c.droppedPackets.Load()
}

func (c *Conn) reserveQueuedBytes(n int64) bool {
	if n < 0 {
		return false
	}
	for {
		current := c.queuedBytes.Load()
		if n > c.listener.maxQueuedBytesPerSession-current {
			return false
		}
		if c.queuedBytes.CompareAndSwap(current, current+n) {
			break
		}
	}
	for {
		current := c.sourceUsage.queuedBytes.Load()
		if n > c.listener.maxQueuedBytesPerSourceIP-current {
			c.queuedBytes.Add(-n)
			return false
		}
		if c.sourceUsage.queuedBytes.CompareAndSwap(current, current+n) {
			break
		}
	}
	for {
		current := c.listener.queuedBytes.Load()
		if n > c.listener.maxQueuedBytes-current {
			c.sourceUsage.queuedBytes.Add(-n)
			c.queuedBytes.Add(-n)
			return false
		}
		if c.listener.queuedBytes.CompareAndSwap(current, current+n) {
			return true
		}
	}
}

func (c *Conn) ReserveQueuedBytes(n int64) bool {
	c.inboundMu.RLock()
	defer c.inboundMu.RUnlock()
	if c.isClosed() {
		return false
	}
	return c.reserveQueuedBytes(n)
}

func (c *Conn) SetCompactReadBuffers(enable bool) {
	c.compactReads.Store(enable)
}

func (c *Conn) ReleaseQueuedBytes(n int64) {
	c.releaseQueuedBytes(n)
}

func (c *Conn) releaseQueuedBytes(n int64) {
	if n <= 0 {
		return
	}
	c.queuedBytes.Add(-n)
	c.listener.queuedBytes.Add(-n)
	if c.sourceUsage.queuedBytes.Add(-n) == 0 {
		c.listener.cleanupSourceUsage(c.source, c.sourceUsage)
	}
}

func (c *Conn) recordDrop() {
	c.droppedPackets.Add(1)
	if c.stats != nil {
		c.stats.AddQueueDrops(1)
	}
}
