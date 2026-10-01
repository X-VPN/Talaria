// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package udptls implements TalariaUDP: a standard TLS 1.3 handshake
// whose exporter material keys a custom AEAD datagram channel. It is not DTLS.
//
// Before any per-connection state is allocated, a stateless Retry exchange binds
// a challenge to the source address, the initial packet and the time, so a
// spoofed source cannot make the server allocate a session. The challenge is
// capped so the response is never larger than the request.
//
// After the handshake, TLS exporter output is expanded with HKDF into
// independent per-direction keys and nonce salts. Each datagram carries a
// monotonic counter that forms the nonce and is authenticated as additional
// data; packets are authenticated before they are parsed or forwarded, and a
// replay window rejects duplicates and stale records. Keys ratchet forward at a
// fixed counter interval, so a long-lived tunnel never reaches an AEAD usage
// limit, and an earlier generation cannot be derived from a later one.
package udptls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/netdial"
	"github.com/X-VPN/Talaria/internal/sourceip"
	"github.com/X-VPN/Talaria/internal/udpsession"
	"github.com/X-VPN/Talaria/lifecycle"
)

const (
	TunnelTLSALPN      = "talaria-udp"
	udptlsWireOverhead = udptlsDataHeaderSize + udptlsMaxAEADOverhead
	// SecureDataPacketOverhead covers the authenticated data record and the
	// mandatory secure wire envelope, excluding the VPN payload and IP/UDP
	// carrier headers.
	SecureDataPacketOverhead      = udptlsWireOverhead + wireEnvelopeOverhead
	defaultMaxPlainPacket         = udpsession.MaxUDPPayloadIPv4 - udptlsWireOverhead - wireEnvelopeOverhead
	maxPlainPacket                = udpsession.MaxUDPPayloadIPv6 - udptlsWireOverhead - wireEnvelopeOverhead
	defaultDialTimeout            = 5 * time.Second
	defaultHandshakeDelay         = 2 * time.Second
	defaultServerHandshakeTimeout = 5 * time.Second
	HandshakeCount                = 2
	maxIOTimeoutMS                = 24 * 60 * 60 * 1000
)

func GetDialTimeout(udpDialTimeout time.Duration, oneHandshakeTimeout time.Duration) time.Duration {
	return udpDialTimeout + oneHandshakeTimeout*HandshakeCount
}

type NewDialerReq struct {
	ParentDial                  func(network, address string) (net.Conn, error)
	ParentDialTimeout           time.Duration
	ParentDialAlreadyHasTimeout bool
	Closer                      lifecycle.Closer
	// TLSConfig is cloned when NewDialer is called; TalariaUDP rejects
	// InsecureSkipVerify and forces TLS 1.3, its carrier ALPN, and disabled tickets.
	TLSConfig *tls.Config
	// WireSecret authenticates and encrypts the outer UDP framing. Secure is the
	// default profile and requires at least 32 bytes.
	WireSecret   []byte
	WireIdentity string
	WireProfile  WireProfile
	// MaxPacket is the largest plaintext packet; TalariaUDP reserves its record
	// header and AEAD tag separately within the UDP payload limit.
	MaxPacket   int
	IOTimeoutMS int
	wire        *wireCodec
}

type NewListenerReq struct {
	ListenAddr               string
	ListenPacket             func(network, address string) (net.PacketConn, error)
	PacketConn               net.PacketConn
	GetCertificate           func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	FallbackCertificate      *tls.Certificate
	CacheGetCertificate      bool
	CachePureGetCertificate  bool
	CertificateCacheScope    []byte
	AllowCertificateFallback bool
	CertPEM                  string
	KeyPEM                   string
	// MaxPacket is the largest plaintext packet; TalariaUDP reserves its record
	// header and AEAD tag separately within the UDP payload limit.
	MaxPacket       int
	IOTimeoutMS     int
	InboundQueue    int
	AdmissionLimits AdmissionLimits
	// WireSecret must match the dialer.
	WireSecret   []byte
	WireIdentity string
	WireProfile  WireProfile
}

type Listener struct {
	inner                    *udpsession.Listener
	getCertificate           func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	acceptResults            chan udptlsAcceptResult
	acceptDone               chan struct{}
	terminalMu               sync.Mutex
	terminalErr              error
	handshakeMu              sync.Mutex
	handshakes               int
	handshakesBySource       map[handshakeSourceKey]int
	handshakeWorkersBySource map[handshakeSourceKey]int
	maxHandshakes            int
	maxHandshakesPerSource   int
	ipv6SourcePrefixBits     int
	closeCh                  chan struct{}
	closeState               atomic.Uint32
	closeErrMu               sync.Mutex
	acceptWG                 sync.WaitGroup
	handshakeWG              sync.WaitGroup
	handshakeWorkerSlots     chan struct{}
	closeErr                 error
	retryGate                *retryCookieGate
	wire                     *wireCodec
	maxPacket                int
	maxWirePacket            int
}

type udptlsAcceptResult struct {
	conn net.Conn
	err  error
}

type handshakeSourceKey struct {
	raw   string
	zone  string
	ip    [16]byte
	ipLen uint8
}

func handshakeSourceKeyFromAddr(addr net.Addr, ipv6PrefixBits int) handshakeSourceKey {
	var key handshakeSourceKey
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		if addr != nil {
			key.raw = addr.Network() + "\x00" + addr.String()
		}
		return key
	}
	key.zone = udpAddr.Zone
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		copy(key.ip[:4], ip4)
		key.ipLen = 4
		return key
	}
	if ip16 := udpAddr.IP.To16(); ip16 != nil {
		copy(key.ip[:], ip16)
		sourceip.MaskIPv6(&key.ip, ipv6PrefixBits)
		key.ipLen = 16
		return key
	}
	key.raw = udpAddr.IP.String()
	return key
}

func NewDialer(req NewDialerReq) func(network, address string) (net.Conn, error) {
	if extension.IsNil(req.Closer) {
		req.Closer = lifecycle.NewCloser()
	}
	if req.ParentDialTimeout <= 0 {
		req.ParentDialTimeout = GetDialTimeout(defaultDialTimeout, defaultHandshakeDelay)
	}
	if req.MaxPacket <= 0 {
		req.MaxPacket = defaultMaxPlainPacket
	}
	if req.IOTimeoutMS <= 0 {
		req.IOTimeoutMS = 5000
	}
	tlsConfig, tlsConfigErr := newClientTLSConfig(req)
	if tlsConfigErr == nil {
		req.TLSConfig = tlsConfig
	}
	var configErr error
	wire, wireErr := newWireCodec(req.WireProfile, req.WireSecret, req.WireIdentity, rand.Reader)
	req.wire = wire
	if req.MaxPacket > maxPlainPacket {
		configErr = fmt.Errorf("TalariaUDP max plaintext packet exceeds UDP maximum: %d", req.MaxPacket)
	} else if err := validateRetryMaxPacket(udptlsWirePacketSize(req.MaxPacket)); err != nil {
		configErr = err
	} else if req.IOTimeoutMS > maxIOTimeoutMS {
		configErr = fmt.Errorf("TalariaUDP I/O timeout is too large: %dms", req.IOTimeoutMS)
	} else if req.ParentDial == nil {
		configErr = errors.New("TalariaUDP parent dialer is required")
	} else if tlsConfigErr != nil {
		configErr = tlsConfigErr
	} else if wireErr != nil {
		configErr = wireErr
	} else if !req.ParentDialAlreadyHasTimeout {
		req.ParentDial = netdial.WrapTimeout(netdial.WrapTimeoutReq{
			Dial:                req.ParentDial,
			Timeout:             req.ParentDialTimeout,
			Closer:              req.Closer,
			DoNotRegisterResult: true,
		})
	}
	if configErr == nil && wire != nil {
		registered, err := udptlsCloserAdd(req.Closer, wire.Close)
		if err != nil {
			configErr = err
		} else if registered == nil {
			configErr = net.ErrClosed
		}
	}
	if configErr != nil && wire != nil {
		wire.Close()
	}
	return func(network, address string) (net.Conn, error) {
		if network != "udp" {
			return nil, fmt.Errorf("TalariaUDP dialer only supports udp, got %s", network)
		}
		if configErr != nil {
			return nil, configErr
		}
		closed, err := udptlsCloserIsClosed(req.Closer)
		if err != nil {
			return nil, err
		}
		if closed {
			return nil, net.ErrClosed
		}
		var rawConn net.Conn
		err = extension.Do("TalariaUDP parent dialer", func() error {
			var dialErr error
			rawConn, dialErr = req.ParentDial("udp", address)
			return dialErr
		})
		if err != nil {
			if !extension.IsNil(rawConn) {
				_ = extension.Do("TalariaUDP failed parent dial connection close", rawConn.Close)
			}
			return nil, err
		}
		if extension.IsNil(rawConn) {
			return nil, errors.New("TalariaUDP parent dialer returned a nil connection")
		}
		unregisterSetupConn, err := udptlsCloserAdd(req.Closer, func() {
			_ = extension.Do("TalariaUDP setup connection close", rawConn.Close)
		})
		if err != nil || unregisterSetupConn == nil {
			_ = extension.Do("TalariaUDP setup connection close", rawConn.Close)
			if err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		}
		defer func() { _ = extension.Run("TalariaUDP setup connection unregister", unregisterSetupConn) }()
		udpConn, ok := rawConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			_ = extension.Do("TalariaUDP unexpected connection close", rawConn.Close)
			return nil, fmt.Errorf("unexpected udp conn type %T", rawConn)
		}
		wireMaxPacket := udptlsWirePacketSize(req.MaxPacket)
		carrierMaxPacket := req.wire.packetSize(wireMaxPacket)
		if carrierMaxPacket > udpsession.MaxUDPPayloadForAddr(udpConn.RemoteAddr()) {
			_ = extension.Do("TalariaUDP oversized connection close", udpConn.Close)
			return nil, fmt.Errorf("TalariaUDP max plaintext packet %d exceeds %s UDP payload limit", req.MaxPacket, udpConn.RemoteAddr().Network())
		}
		baseConn := udpsession.NewClientConn(udpConn, udpsession.NewClientConnReq{
			MaxPacket: carrierMaxPacket,
			IOTimeout: time.Duration(req.IOTimeoutMS) * time.Millisecond,
			Stats:     newUDPSharedStats(udpDebugEnabled(), "udp-client", udpConn.LocalAddr(), udpConn.RemoteAddr()),
		})
		wrapped, err := newClientConn(baseConn, req)
		if err != nil {
			_ = extension.Do("TalariaUDP failed client connection close", baseConn.Close)
			return nil, err
		}
		if err := registerDialedConn(req.Closer, wrapped); err != nil {
			return nil, err
		}
		return wrapped, nil
	}
}

func registerDialedConn(closer lifecycle.Closer, conn net.Conn) error {
	if extension.IsNil(closer) || extension.IsNil(conn) {
		if !extension.IsNil(conn) {
			_ = extension.Do("TalariaUDP unregistered connection close", conn.Close)
		}
		return net.ErrClosed
	}
	unregister, err := udptlsCloserAdd(closer, func() {
		_ = extension.Do("TalariaUDP registered connection close", conn.Close)
	})
	if err != nil || unregister == nil {
		_ = extension.Do("TalariaUDP unregistered connection close", conn.Close)
		if err != nil {
			return err
		}
		return net.ErrClosed
	}
	closed, err := udptlsCloserIsClosed(closer)
	if err != nil || closed {
		_ = extension.Run("TalariaUDP connection unregister", unregister)
		_ = extension.Do("TalariaUDP closed lifecycle connection close", conn.Close)
		if err != nil {
			return err
		}
		return net.ErrClosed
	}
	if udptlsConn, ok := conn.(*udptlsConn); ok {
		udptlsConn.setCloseUnregister(unregister)
	}
	return nil
}

func udptlsCloserIsClosed(closer lifecycle.Closer) (closed bool, err error) {
	err = extension.Run("TalariaUDP lifecycle closed check", func() {
		closed = closer.IsClose()
	})
	return closed, err
}

func udptlsCloserAdd(closer lifecycle.Closer, callback func()) (unregister func(), err error) {
	err = extension.Run("TalariaUDP lifecycle registration", func() {
		unregister = closer.AddOnClose(callback)
	})
	return unregister, err
}

func NewListener(req NewListenerReq) (*Listener, error) {
	if req.GetCertificate != nil {
		return nil, errors.New("TalariaUDP dynamic certificate callbacks are not supported")
	}
	if req.FallbackCertificate != nil || req.CacheGetCertificate || req.CachePureGetCertificate ||
		len(req.CertificateCacheScope) != 0 || req.AllowCertificateFallback {
		return nil, errors.New("TalariaUDP dynamic certificate options are not supported")
	}
	if req.PacketConn != nil && extension.IsNil(req.PacketConn) {
		return nil, errors.New("TalariaUDP packet connection is typed nil")
	}
	if req.PacketConn != nil {
		protected, err := protectPacketConn(req.PacketConn)
		if err != nil {
			return nil, err
		}
		req.PacketConn = protected
	}
	if req.ListenPacket != nil {
		listenPacket := req.ListenPacket
		req.ListenPacket = func(network, address string) (pc net.PacketConn, err error) {
			err = extension.Do("TalariaUDP listen packet callback", func() error {
				var listenErr error
				pc, listenErr = listenPacket(network, address)
				return listenErr
			})
			if err != nil {
				if !extension.IsNil(pc) {
					_ = extension.Do("TalariaUDP failed packet listener close", pc.Close)
				}
				return nil, err
			}
			if extension.IsNil(pc) {
				return nil, errors.New("TalariaUDP listen packet callback returned a nil connection")
			}
			protected, protectErr := protectPacketConn(pc)
			if protectErr != nil {
				_ = extension.Do("TalariaUDP invalid packet listener close", pc.Close)
				return nil, protectErr
			}
			return protected, nil
		}
	}
	limits, err := normalizeAdmissionLimits(req.AdmissionLimits, req.InboundQueue)
	if err != nil {
		return nil, err
	}
	if req.MaxPacket <= 0 {
		req.MaxPacket = defaultMaxPlainPacket
	}
	if req.IOTimeoutMS <= 0 {
		req.IOTimeoutMS = 5000
	}
	if req.MaxPacket > maxPlainPacket {
		return nil, fmt.Errorf("TalariaUDP max plaintext packet exceeds UDP maximum: %d", req.MaxPacket)
	}
	if err := validateRetryMaxPacket(udptlsWirePacketSize(req.MaxPacket)); err != nil {
		return nil, err
	}
	if req.IOTimeoutMS > maxIOTimeoutMS {
		return nil, fmt.Errorf("TalariaUDP I/O timeout is too large: %dms", req.IOTimeoutMS)
	}
	wireMaxPacket := udptlsWirePacketSize(req.MaxPacket)
	wire, err := newWireCodec(req.WireProfile, req.WireSecret, req.WireIdentity, rand.Reader)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		wire.Close()
		return nil, fmt.Errorf("TalariaUDP certificate: %w", err)
	}
	getCertificate := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &certificate, nil }
	carrierMaxPacket := wire.packetSize(wireMaxPacket)
	wire.limitReceiverStatesBySource(limits.IPv6SourcePrefixBits)
	retryGate, err := newRetryCookieGateWithWire(wireMaxPacket, rand.Reader, time.Now, wire)
	if err != nil {
		wire.Close()
		return nil, fmt.Errorf("TalariaUDP retry cookie key: %w", err)
	}
	inner, err := udpsession.NewListener(udpsession.NewListenerReq{
		ListenAddr:                req.ListenAddr,
		ListenPacket:              req.ListenPacket,
		PacketConn:                req.PacketConn,
		IdleTimeout:               0,
		BatchSize:                 defaultUDPBatchSize,
		AcceptQueue:               limits.AcceptQueue,
		SessionQueue:              limits.SessionQueue,
		MaxSessions:               limits.MaxSessions,
		MaxSessionsPerSourceIP:    limits.MaxSessionsPerSourceIP,
		MaxQueuedBytes:            limits.MaxQueuedBytes,
		MaxQueuedBytesPerSourceIP: limits.MaxQueuedBytesPerSourceIP,
		MaxQueuedBytesPerSession:  limits.MaxQueuedBytesPerSession,
		IPv6SourcePrefixBits:      limits.IPv6SourcePrefixBits,
		ReadBufferSize:            carrierMaxPacket,
		MaxPacket:                 carrierMaxPacket,
		EnableBatchRead:           true,
		IOTimeout:                 time.Duration(req.IOTimeoutMS) * time.Millisecond,
		NewSessionGate:            retryGate,
		CompactReadBuffers:        true,
		DeferInboundActivity:      true,
		StatsFactory: func(name string, local net.Addr, remote net.Addr) udpsession.Stats {
			return newUDPSharedStats(udpDebugEnabled(), name, local, remote)
		},
	})
	if err != nil {
		retryGate.Close()
		return nil, err
	}
	l := &Listener{
		inner:                    inner,
		getCertificate:           getCertificate,
		acceptResults:            make(chan udptlsAcceptResult, limits.AcceptQueue),
		acceptDone:               make(chan struct{}),
		handshakesBySource:       make(map[handshakeSourceKey]int),
		handshakeWorkersBySource: make(map[handshakeSourceKey]int),
		maxHandshakes:            limits.MaxPendingHandshakes,
		maxHandshakesPerSource:   limits.MaxPendingHandshakesPerSourceIP,
		handshakeWorkerSlots:     make(chan struct{}, limits.MaxPendingHandshakes),
		ipv6SourcePrefixBits:     limits.IPv6SourcePrefixBits,
		closeCh:                  make(chan struct{}),
		retryGate:                retryGate,
		wire:                     wire,
		maxPacket:                req.MaxPacket,
		maxWirePacket:            wireMaxPacket,
	}
	l.acceptWG.Add(1)
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) Accept(ctx context.Context) (net.Conn, error) {
	if l == nil || l.inner == nil || l.acceptResults == nil {
		return nil, net.ErrClosed
	}
	for {
		if err := l.terminalAcceptError(); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.closeCh:
			return nil, l.acceptError()
		case <-l.acceptDone:
			return nil, l.acceptError()
		case result, ok := <-l.acceptResults:
			if !ok {
				return nil, net.ErrClosed
			}
			if l.isClosed() {
				if result.conn != nil {
					_ = result.conn.Close()
				}
				return nil, net.ErrClosed
			}
			if result.err != nil {
				return nil, result.err
			}
			return result.conn, nil
		}
	}
}

func (l *Listener) Addr() net.Addr {
	if l == nil || l.inner == nil {
		return nil
	}
	return l.inner.Addr()
}

func (l *Listener) Close() error {
	if l == nil || l.inner == nil {
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
	close(l.closeCh)
	closeErr := extension.Do("TalariaUDP session listener close", l.inner.Close)
	l.retryGate.Close()
	l.closeErrMu.Lock()
	l.closeErr = closeErr
	l.closeErrMu.Unlock()
	l.closeState.Store(2)
	go l.finishClose()
	return closeErr
}

func (l *Listener) finishClose() {
	l.acceptWG.Wait()
	l.handshakeWG.Wait()
	l.closePendingAcceptResults()
	close(l.acceptResults)
}

func (l *Listener) closePendingAcceptResults() {
	for {
		select {
		case result, ok := <-l.acceptResults:
			if !ok {
				return
			}
			if !extension.IsNil(result.conn) {
				_ = extension.Do("TalariaUDP pending accepted connection close", result.conn.Close)
			}
		default:
			return
		}
	}
}

func (l *Listener) acceptLoop() {
	defer l.acceptWG.Done()
	defer close(l.acceptDone)
	for {
		baseConn, err := l.inner.Accept(context.Background())
		if err != nil {
			if l.isClosed() {
				return
			}
			l.setTerminalAcceptError(err)
			go func() { _ = l.Close() }()
			return
		}
		source, ok := l.acquireHandshakeSlot(baseConn)
		if !ok {
			if l.isClosed() {
				return
			}
			continue
		}
		l.handshakeWG.Add(1)
		go l.serverHandshake(baseConn, source)
	}
}

func (l *Listener) setTerminalAcceptError(err error) {
	if err == nil {
		return
	}
	l.terminalMu.Lock()
	if l.terminalErr == nil {
		l.terminalErr = err
	}
	l.terminalMu.Unlock()
}

func (l *Listener) terminalAcceptError() error {
	l.terminalMu.Lock()
	defer l.terminalMu.Unlock()
	return l.terminalErr
}

func (l *Listener) acceptError() error {
	if err := l.terminalAcceptError(); err != nil {
		return err
	}
	return net.ErrClosed
}

func (l *Listener) acquireHandshakeSlot(baseConn net.Conn) (handshakeSourceKey, bool) {
	source := handshakeSourceKeyFromAddr(baseConn.RemoteAddr(), l.ipv6SourcePrefixBits)
	select {
	case <-l.closeCh:
		_ = baseConn.Close()
		return handshakeSourceKey{}, false
	default:
	}

	l.handshakeMu.Lock()
	if l.handshakes >= l.maxHandshakes ||
		l.handshakesBySource[source] >= l.maxHandshakesPerSource {
		l.handshakeMu.Unlock()
		_ = baseConn.Close()
		return handshakeSourceKey{}, false
	}
	l.handshakes++
	l.handshakesBySource[source]++
	l.handshakeMu.Unlock()
	return source, true
}

func (l *Listener) releaseHandshakeSlot(source handshakeSourceKey) {
	l.handshakeMu.Lock()
	defer l.handshakeMu.Unlock()
	if l.handshakesBySource[source] <= 1 {
		delete(l.handshakesBySource, source)
	} else {
		l.handshakesBySource[source]--
	}
	l.handshakes--
}

func (l *Listener) serverHandshake(baseConn net.Conn, source handshakeSourceKey) {
	defer l.handshakeWG.Done()
	defer l.releaseHandshakeSlot(source)

	conn, err := l.awaitServerHandshake(baseConn, source, defaultServerHandshakeTimeout, func() (net.Conn, error) {
		return newConnForServerWithCertificateTimeout(baseConn, l.retryGate, l.wire, l.getCertificate, defaultServerHandshakeTimeout, l.maxPacket, l.maxWirePacket)
	})
	if err != nil {
		return
	}
	if !l.publishAcceptResult(udptlsAcceptResult{conn: conn}) {
		_ = conn.Close()
	}
}

func (l *Listener) awaitServerHandshake(baseConn net.Conn, source handshakeSourceKey, timeout time.Duration, handshake func() (net.Conn, error)) (net.Conn, error) {
	if timeout <= 0 {
		timeout = defaultServerHandshakeTimeout
	}
	select {
	case <-l.closeCh:
		_ = baseConn.Close()
		return nil, net.ErrClosed
	default:
	}
	if !l.acquireHandshakeWorker(source) {
		_ = baseConn.Close()
		return nil, errors.New("TalariaUDP handshake worker capacity reached")
	}
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		defer l.releaseHandshakeWorker(source)
		var conn net.Conn
		err := extension.Do("TalariaUDP server handshake", func() error {
			var handshakeErr error
			conn, handshakeErr = handshake()
			return handshakeErr
		})
		select {
		case resultCh <- result{conn: conn, err: err}:
		case <-abandoned:
			if !extension.IsNil(conn) {
				_ = extension.Do("TalariaUDP abandoned handshake connection close", conn.Close)
			}
		}
	}()
	defer close(abandoned)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-l.closeCh:
		_ = baseConn.Close()
		return nil, net.ErrClosed
	case <-timer.C:
		_ = baseConn.Close()
		return nil, context.DeadlineExceeded
	case result := <-resultCh:
		if result.err != nil {
			_ = baseConn.Close()
		}
		return result.conn, result.err
	}
}

func (l *Listener) acquireHandshakeWorker(source handshakeSourceKey) bool {
	l.handshakeMu.Lock()
	defer l.handshakeMu.Unlock()
	if source != (handshakeSourceKey{}) && l.maxHandshakesPerSource > 0 &&
		l.handshakeWorkersBySource[source] >= l.maxHandshakesPerSource {
		return false
	}
	select {
	case l.handshakeWorkerSlots <- struct{}{}:
		if source != (handshakeSourceKey{}) {
			if l.handshakeWorkersBySource == nil {
				l.handshakeWorkersBySource = make(map[handshakeSourceKey]int)
			}
			l.handshakeWorkersBySource[source]++
		}
		return true
	default:
		return false
	}
}

func (l *Listener) releaseHandshakeWorker(source handshakeSourceKey) {
	l.handshakeMu.Lock()
	<-l.handshakeWorkerSlots
	if count := l.handshakeWorkersBySource[source]; count <= 1 {
		delete(l.handshakeWorkersBySource, source)
	} else {
		l.handshakeWorkersBySource[source] = count - 1
	}
	l.handshakeMu.Unlock()
}

func (l *Listener) publishAcceptResult(result udptlsAcceptResult) bool {
	select {
	case <-l.closeCh:
		return false
	case l.acceptResults <- result:
		return true
	}
}

func (l *Listener) isClosed() bool {
	select {
	case <-l.closeCh:
		return true
	default:
		return false
	}
}

// newConnForServerWithCertificateTimeout performs a Retry-bound TLS handshake.
func newConnForServerWithCertificateTimeout(baseConn net.Conn, retryGate *retryCookieGate, wire *wireCodec, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), timeout time.Duration, maxPacket, maxWirePacket int) (net.Conn, error) {
	if timeout <= 0 {
		timeout = defaultServerHandshakeTimeout
	}
	if baseConn == nil {
		return nil, errors.New("nil base conn")
	}
	inner := wrapBatchConn(baseConn)
	if maxPacket <= 0 {
		maxPacket = defaultMaxPlainPacket
	}
	if maxWirePacket <= 0 {
		maxWirePacket = udptlsWirePacketSize(maxPacket)
	}
	inner = newWireBatchConn(inner, wire, udptlsModeServer)
	retryConn, err := newRetryServerConn(inner, retryGate, maxWirePacket)
	if err != nil {
		return nil, err
	}
	defer retryConn.clearAuthState()
	// Keep AEAD packets that race ahead of the final reliable-handshake ACK so
	// the data plane can authenticate them after the shim is drained.
	handshakeConn, err := newHandshakeConnWithReservedOverhead(retryConn, maxWirePacket, handshakeAuthOverhead, true)
	if err != nil {
		return nil, err
	}

	tlsConn, err := newServerTLSConnWithCertificate(handshakeConn, getCertificate)
	if err != nil {
		_ = handshakeConn.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = handshakeConn.Close()
		return nil, fmt.Errorf("TalariaUDP tls handshake: %w", err)
	}
	if err := validateNegotiatedProtocol(tlsConn.ConnectionState()); err != nil {
		_ = handshakeConn.Close()
		return nil, err
	}
	if err := handshakeConn.Drain(ctx); err != nil {
		_ = handshakeConn.Close()
		return nil, fmt.Errorf("TalariaUDP handshake drain: %w", err)
	}
	state := newConnectionStateFromTLS(tlsConn.ConnectionState())
	material, err := deriveSessionMaterial(state, udptlsModeServer)
	if err != nil {
		_ = handshakeConn.Close()
		return nil, err
	}
	pendingEnc := handshakeConn.closeAndTakePostHandshakePackets()
	// The temporary reliable handshake shim leaves short polling deadlines on the
	// shared datagram conn. Clear them before switching to the data plane or the
	// first post-handshake packet can fail with a stale timeout.
	if err := resetPostHandshakeDeadline(inner, pendingEnc); err != nil {
		return nil, err
	}
	return newTalariaUDPConn(inner, material, state.cipherSuite, maxPacket, udptlsModeServer, pendingEnc)
}

func newClientConn(baseConn batchConn, req NewDialerReq) (net.Conn, error) {
	maxPacket := req.MaxPacket
	if maxPacket <= 0 {
		maxPacket = defaultMaxPlainPacket
	}
	if err := validateRetryMaxPacket(udptlsWirePacketSize(maxPacket)); err != nil {
		return nil, err
	}
	maxWirePacket := udptlsWirePacketSize(maxPacket)
	inner := newWireBatchConn(baseConn, req.wire, udptlsModeClient)
	retryConn := newRetryClientConn(inner, maxWirePacket)
	defer retryConn.clearRetryState()
	handshakeConn, err := newHandshakeConnWithReservedOverhead(retryConn, maxWirePacket, retryChallengeSize, true)
	if err != nil {
		return nil, err
	}

	state, err := performClientHandshake(handshakeConn, req)
	if err != nil {
		_ = handshakeConn.Close()
		return nil, err
	}
	material, err := deriveSessionMaterial(state, udptlsModeClient)
	if err != nil {
		_ = handshakeConn.Close()
		return nil, err
	}
	pendingEnc := handshakeConn.closeAndTakePostHandshakePackets()
	// The handshake shim leaves short-lived deadlines on the shared UDP conn.
	// Reset them before handing the socket to the steady-state data path.
	if err := resetPostHandshakeDeadline(inner, pendingEnc); err != nil {
		return nil, err
	}
	return newTalariaUDPConn(inner, material, state.cipherSuite, maxPacket, udptlsModeClient, pendingEnc)
}

func resetPostHandshakeDeadline(inner batchConn, pendingEnc []udptlsEncryptedPacket) error {
	if err := inner.SetDeadline(time.Time{}); err != nil {
		budget, _ := inner.(queuedByteBudget)
		releaseEncryptedPacketReservations(budget, pendingEnc)
		return fmt.Errorf("TalariaUDP reset post-handshake deadline: %w", err)
	}
	return nil
}

// validateRetryMaxPacket ensures the initial packet can carry a non-amplifying Retry challenge.
func validateRetryMaxPacket(maxPacket int) error {
	if maxPacket < minimumRetryMaxPacket {
		return fmt.Errorf("TalariaUDP max packet too small for retry cookie: %d", maxPacket)
	}
	return nil
}

func udptlsWirePacketSize(maxPlainPacket int) int {
	return maxPlainPacket + udptlsWireOverhead
}

func performClientHandshake(handshakeConn *handshakeConn, req NewDialerReq) (udptlsConnectionState, error) {
	timeout := req.ParentDialTimeout
	if timeout <= 0 {
		timeout = GetDialTimeout(defaultDialTimeout, defaultHandshakeDelay)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tlsConn := tls.Client(handshakeConn, req.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return udptlsConnectionState{}, fmt.Errorf("TalariaUDP tls handshake: %w", err)
	}
	if err := validateNegotiatedProtocol(tlsConn.ConnectionState()); err != nil {
		return udptlsConnectionState{}, err
	}
	if err := handshakeConn.Drain(ctx); err != nil {
		return udptlsConnectionState{}, fmt.Errorf("TalariaUDP handshake drain: %w", err)
	}
	return newConnectionStateFromTLS(tlsConn.ConnectionState()), nil
}

func newServerTLSConn(conn net.Conn, certPEM, keyPEM string) (*tls.Conn, error) {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return tls.Server(conn, serverTLSConfigWithCertificate(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	})), nil
}

// newClientTLSConfig preserves caller verification policy and enforces TalariaUDP invariants.
func newClientTLSConfig(req NewDialerReq) (*tls.Config, error) {
	if req.TLSConfig == nil {
		return nil, fmt.Errorf("TalariaUDP tls_config is required")
	}
	if req.TLSConfig.Rand != nil || req.TLSConfig.Time != nil || req.TLSConfig.KeyLogWriter != nil {
		return nil, fmt.Errorf("TalariaUDP tls Rand, Time, and KeyLogWriter hooks are not supported")
	}
	serverName := strings.TrimSpace(req.TLSConfig.ServerName)
	if serverName == "" {
		return nil, fmt.Errorf("TalariaUDP server_name is required")
	}
	if req.TLSConfig.RootCAs == nil {
		return nil, fmt.Errorf("TalariaUDP root_ca_pool is required")
	}
	if req.TLSConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("TalariaUDP certificate verification cannot be disabled")
	}
	if req.TLSConfig.MaxVersion != 0 && req.TLSConfig.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("TalariaUDP max TLS version must allow TLS 1.3")
	}
	if req.TLSConfig.MinVersion > tls.VersionTLS13 {
		return nil, fmt.Errorf("TalariaUDP min TLS version must allow TLS 1.3")
	}
	tlsCfg := req.TLSConfig.Clone()
	tlsCfg.ServerName = serverName
	tlsCfg.RootCAs = req.TLSConfig.RootCAs.Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.SessionTicketsDisabled = true
	tlsCfg.NextProtos = []string{TunnelTLSALPN}
	return tlsCfg, nil
}

func newServerTLSConnWithCertificate(conn net.Conn, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*tls.Conn, error) {
	if getCertificate == nil {
		return nil, fmt.Errorf("TalariaUDP get_certificate callback is required")
	}
	return tls.Server(conn, serverTLSConfigWithCertificate(getCertificate)), nil
}

func serverTLSConfigWithCertificate(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			for i, suite := range hello.CipherSuites {
				if suite == tls.TLS_AES_128_GCM_SHA256 {
					hello.CipherSuites[i] = 0xffff
				}
			}
			return nil, nil
		},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			var cert *tls.Certificate
			err := extension.Do("TalariaUDP certificate callback", func() error {
				var callbackErr error
				cert, callbackErr = getCertificate(info)
				return callbackErr
			})
			if err != nil {
				return nil, err
			}
			if cert == nil {
				return nil, fmt.Errorf("TalariaUDP get_certificate returned nil")
			}
			return cert, nil
		},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		NextProtos:             []string{TunnelTLSALPN},
	}
}

func validateNegotiatedProtocol(state tls.ConnectionState) error {
	if state.CipherSuite == tls.TLS_AES_128_GCM_SHA256 {
		return errors.New("TalariaUDP TLS AES-128-GCM is disabled")
	}
	if state.NegotiatedProtocol != TunnelTLSALPN {
		return fmt.Errorf("TalariaUDP negotiated unexpected TLS ALPN %q", state.NegotiatedProtocol)
	}
	return nil
}

func newConnectionStateFromTLS(state tls.ConnectionState) udptlsConnectionState {
	return udptlsConnectionState{
		version:              state.Version,
		handshakeComplete:    state.HandshakeComplete,
		cipherSuite:          state.CipherSuite,
		exportKeyingMaterial: state.ExportKeyingMaterial,
	}
}
