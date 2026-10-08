// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/ippacket"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

const (
	defaultAuthTimeout       = 5 * time.Second
	defaultDownlinkQueueSize = 8192
	maxDownlinkQueueSize     = 1 << 16
	defaultUplinkQueueSize   = 4096
	maxUplinkQueueSize       = 1 << 16
	defaultKeepAliveInterval = time.Second
	defaultKeepAliveTimeout  = 5 * time.Second
	wireVersion              = 1
)

var errInvalidTunPacket = errors.New("Talaria client: invalid TUN packet buffer")

type downlinkTunItem struct {
	pkt  *dataplane.PacketBuffer
	pool *dataplane.Pool
	n    int
}

type downlinkTunWriter struct {
	ctx   context.Context
	tun   platform.Tun
	stats StatsSink
	onErr func(error)
	queue chan downlinkTunItem
	done  chan struct{}

	errMu sync.RWMutex
	err   error
}

func newDownlinkTunWriter(ctx context.Context, tun platform.Tun, queueSize int, stats StatsSink, onErr func(error)) *downlinkTunWriter {
	if queueSize <= 0 {
		queueSize = defaultDownlinkQueueSize
	}
	w := &downlinkTunWriter{
		ctx:   ctx,
		tun:   tun,
		stats: stats,
		onErr: onErr,
		queue: make(chan downlinkTunItem, queueSize),
		done:  make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *downlinkTunWriter) writeBuffer(pkt *dataplane.PacketBuffer, pool *dataplane.Pool) error {
	if pkt == nil || pkt.Start < 0 || pkt.End <= pkt.Start || pkt.End > len(pkt.Raw) {
		return errInvalidTunPacket
	}
	if err := w.getErr(); err != nil {
		return err
	}
	select {
	case w.queue <- downlinkTunItem{pkt: pkt, pool: pool, n: pkt.Len()}:
		return nil
	case <-w.done:
		if err := w.getErr(); err != nil {
			return err
		}
		return io.ErrClosedPipe
	case <-w.ctx.Done():
		return w.ctx.Err()
	default:
		// Drop the newest packet when the TUN writer falls behind. Keeping the
		// transport reader moving lets it continue to process control messages
		// and avoids terminating the whole VPN session on a transient burst.
		if pool != nil {
			pool.Put(pkt)
		}
		return nil
	}
}

type uplinkConnItem struct {
	pkt  *dataplane.PacketBuffer
	pool *dataplane.Pool
	n    int
}

type uplinkConnWriter struct {
	ctx   context.Context
	conn  net.Conn
	stats StatsSink
	onErr func(error)
	queue chan uplinkConnItem
	done  chan struct{}

	errMu sync.RWMutex
	err   error
}

func newUplinkConnWriter(ctx context.Context, conn net.Conn, queueSize int, stats StatsSink, onErr func(error)) *uplinkConnWriter {
	if queueSize <= 0 {
		queueSize = defaultUplinkQueueSize
	}
	w := &uplinkConnWriter{
		ctx:   ctx,
		conn:  conn,
		stats: stats,
		onErr: onErr,
		queue: make(chan uplinkConnItem, queueSize),
		done:  make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *uplinkConnWriter) writeBuffer(pkt *dataplane.PacketBuffer, pool *dataplane.Pool, payloadLen int) error {
	if pkt == nil || pkt.Len() <= 0 {
		return nil
	}
	if err := w.getErr(); err != nil {
		return err
	}
	select {
	case w.queue <- uplinkConnItem{pkt: pkt, pool: pool, n: payloadLen}:
		return nil
	case <-w.done:
		if err := w.getErr(); err != nil {
			return err
		}
		return io.ErrClosedPipe
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}

func (w *uplinkConnWriter) close() {
	close(w.queue)
	<-w.done
	for item := range w.queue {
		if item.pool != nil && item.pkt != nil {
			item.pool.Put(item.pkt)
		}
	}
}

func (w *uplinkConnWriter) run() {
	defer func() {
		if recovered := recover(); recovered != nil {
			err := extension.PanicError("Talaria client uplink writer extension", recovered)
			w.setErr(err)
			if w.onErr != nil {
				_ = extension.Run("Talaria client uplink error callback", func() { w.onErr(err) })
			}
		}
		close(w.done)
	}()
	for item := range w.queue {
		if item.pkt == nil || item.pkt.Len() <= 0 {
			continue
		}
		if err := writeConnFrame(w.conn, item.pkt.Bytes()); err != nil {
			if item.pool != nil {
				item.pool.Put(item.pkt)
			}
			w.setErr(err)
			if w.onErr != nil {
				if callbackErr := extension.Run("Talaria client uplink error callback", func() { w.onErr(err) }); callbackErr != nil {
					w.setErr(callbackErr)
				}
			}
			return
		}
		if item.pool != nil {
			item.pool.Put(item.pkt)
		}
		w.stats.OnUploadBytes(w.ctx, item.n)
	}
}

func (w *uplinkConnWriter) getErr() error {
	w.errMu.RLock()
	err := w.err
	w.errMu.RUnlock()
	return err
}

func (w *uplinkConnWriter) setErr(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.errMu.Unlock()
}

func (w *downlinkTunWriter) close() {
	close(w.queue)
	<-w.done
	for item := range w.queue {
		if item.pool != nil && item.pkt != nil {
			item.pool.Put(item.pkt)
		}
	}
}

func (w *downlinkTunWriter) run() {
	defer func() {
		if recovered := recover(); recovered != nil {
			err := extension.PanicError("Talaria client downlink writer extension", recovered)
			w.setErr(err)
			if w.onErr != nil {
				_ = extension.Run("Talaria client downlink error callback", func() { w.onErr(err) })
			}
		}
		close(w.done)
	}()
	for item := range w.queue {
		if item.pkt == nil || item.n <= 0 {
			if item.pool != nil && item.pkt != nil {
				item.pool.Put(item.pkt)
			}
			continue
		}
		err := func() error {
			if item.pool != nil {
				defer item.pool.Put(item.pkt)
			}
			n, err := writeTunPacketBuffer(w.ctx, w.tun, item.pkt)
			if err != nil || n == 0 {
				return err
			}
			w.stats.OnDownloadBytes(w.ctx, n)
			w.stats.OnTunWrite(w.ctx, n)
			return nil
		}()
		if err != nil {
			w.setErr(err)
			if w.onErr != nil {
				if callbackErr := extension.Run("Talaria client downlink error callback", func() { w.onErr(err) }); callbackErr != nil {
					w.setErr(callbackErr)
				}
			}
			return
		}
	}
}

func (w *downlinkTunWriter) getErr() error {
	w.errMu.RLock()
	err := w.err
	w.errMu.RUnlock()
	return err
}

func (w *downlinkTunWriter) setErr(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.errMu.Unlock()
}

type session struct {
	cfg       Config
	secretKey []byte
	deps      Deps

	mu            sync.RWMutex
	state         State
	conn          net.Conn
	endpoint      EndpointConn
	tun           platform.Tun
	cancel        context.CancelFunc
	stopOnCancel  func() bool
	done          chan struct{}
	closeState    atomic.Uint32
	closeErrMu    sync.Mutex
	closeErr      error
	loopsStarted  bool
	failErr       error
	clientID      uint64
	remoteVersion byte
	dataSeq       uint32
	keepAliveSeq  uint32
	lastReceiveNs int64
}

// NewSession validates cfg and constructs an idle VPN session without starting I/O.
func NewSession(cfg Config, deps Deps) (Session, error) {
	protocol, err := ParseProtocol(string(cfg.Protocol))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedProtocol, err)
	}
	cfg.Protocol = protocol
	if extension.IsNil(deps.Endpoint) {
		deps.Endpoint = nil
	}
	if extension.IsNil(deps.Dialer) {
		deps.Dialer = nil
	}
	if deps.Endpoint == nil && deps.Dialer == nil {
		return nil, fmt.Errorf("%w: missing endpoint or dialer", ErrInvalidConfig)
	}
	if extension.IsNil(deps.Tun) {
		return nil, fmt.Errorf("%w: missing tun provider", ErrInvalidConfig)
	}
	if extension.IsNil(deps.PacketCodec) {
		deps.PacketCodec = dataplane.WireCodec{}
	}
	if extension.IsNil(deps.Events) {
		deps.Events = noopEventSink{}
	}
	if extension.IsNil(deps.Stats) {
		deps.Stats = noopStatsSink{}
	}
	if !ProtocolSupportedOnCurrentPlatform(cfg.Protocol) {
		return nil, fmt.Errorf("%w: %s is not supported on this platform", ErrUnsupportedProtocol, cfg.Protocol)
	}
	if cfg.MTU < 0 {
		return nil, fmt.Errorf("%w: MTU cannot be negative", ErrInvalidConfig)
	}
	if cfg.MTU > dataplane.MaxMTU {
		return nil, fmt.Errorf("%w: MTU %d exceeds maximum %d", ErrInvalidConfig, cfg.MTU, dataplane.MaxMTU)
	}
	if cfg.UplinkQueueSize < 0 {
		return nil, fmt.Errorf("%w: uplink queue size cannot be negative", ErrInvalidConfig)
	}
	if cfg.UplinkQueueSize > maxUplinkQueueSize {
		return nil, fmt.Errorf("%w: uplink queue size %d exceeds maximum %d", ErrInvalidConfig, cfg.UplinkQueueSize, maxUplinkQueueSize)
	}
	if cfg.DownlinkQueueSize < 0 {
		return nil, fmt.Errorf("%w: downlink queue size cannot be negative", ErrInvalidConfig)
	}
	if cfg.DownlinkQueueSize > maxDownlinkQueueSize {
		return nil, fmt.Errorf("%w: downlink queue size %d exceeds maximum %d", ErrInvalidConfig, cfg.DownlinkQueueSize, maxDownlinkQueueSize)
	}
	if cfg.AuthTimeout < 0 {
		return nil, fmt.Errorf("%w: auth timeout cannot be negative", ErrInvalidConfig)
	}
	if cfg.KeepAliveDuration < 0 {
		return nil, fmt.Errorf("%w: keepalive duration cannot be negative", ErrInvalidConfig)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("%w: missing client ID", ErrInvalidConfig)
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("%w: missing secret key", ErrInvalidConfig)
	}
	if len(cfg.ClientID) > 255 || len(cfg.SecretKey) > 255 {
		return nil, fmt.Errorf("%w: credentials exceed wire-format limit", ErrInvalidConfig)
	}
	if cfg.MTU == 0 {
		cfg.MTU = dataplane.EffectiveTunMTUForProtocol(string(cfg.Protocol))
	}
	if cfg.UplinkQueueSize == 0 {
		cfg.UplinkQueueSize = defaultUplinkQueueSize
	}
	if cfg.DownlinkQueueSize == 0 {
		cfg.DownlinkQueueSize = defaultDownlinkQueueSize
	}
	if cfg.AuthTimeout <= 0 {
		cfg.AuthTimeout = defaultAuthTimeout
	}
	if cfg.KeepAliveDuration <= 0 {
		cfg.KeepAliveDuration = defaultKeepAliveTimeout
	}
	if cfg.KeepAliveDuration < defaultKeepAliveTimeout {
		cfg.KeepAliveDuration = defaultKeepAliveTimeout
	}
	secretKey := []byte(cfg.SecretKey)
	cfg.SecretKey = ""
	return &session{
		cfg:           cfg,
		secretKey:     secretKey,
		deps:          deps,
		state:         StateIdle,
		done:          make(chan struct{}),
		remoteVersion: wireVersion,
	}, nil
}

func (s *session) Start(ctx context.Context) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = extension.PanicError("Talaria client start extension", recovered)
			s.fail(ctx, err)
		}
	}()
	s.mu.Lock()
	if s.state != StateIdle {
		s.mu.Unlock()
		return fmt.Errorf("%w: state %s", ErrAlreadyStarted, s.state)
	}
	parent := ctx
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.state = StateDialing
	// Blocking TUN and connection reads do not observe context cancellation on
	// their own, so cancelling the caller's context must close the session
	// explicitly. Registering on the parent keeps Close from re-entering
	// itself through the cancellation this session owns.
	s.stopOnCancel = context.AfterFunc(parent, func() { _ = s.Close() })
	s.mu.Unlock()
	s.deps.Events.OnStateChange(ctx, StateDialing)

	if s.deps.Endpoint != nil {
		return s.startEndpoint(ctx)
	}
	return s.startRawConn(ctx)
}

func (s *session) startEndpoint(ctx context.Context) error {
	secretKey := s.takeSecretKey()
	defer clear(secretKey)
	endpoint, err := s.deps.Endpoint.DialEndpoint(ctx, EndpointDialRequest{
		Protocol:            s.cfg.Protocol,
		ClientID:            s.cfg.ClientID,
		SecretKey:           string(secretKey),
		EntranceIP:          s.cfg.EntranceIP,
		ExitIP:              s.cfg.ExitIP,
		ServerIP:            s.cfg.ServerIP,
		Domain:              s.cfg.Domain,
		ServerPort:          s.cfg.ServerPort,
		MTU:                 s.cfg.MTU,
		KeepAliveDuration:   s.cfg.KeepAliveDuration,
		AuthTimeout:         s.cfg.AuthTimeout,
		RSTWhenReconnecting: s.cfg.RSTWhenReconnecting,
	})
	if err != nil {
		if !extension.IsNil(endpoint) {
			_ = extension.Do("Talaria client failed endpoint close", endpoint.Close)
		}
		s.fail(ctx, err)
		return err
	}
	if extension.IsNil(endpoint) {
		err = errors.New("Talaria client: endpoint provider returned nil endpoint")
		s.fail(ctx, err)
		return err
	}
	var clientID uint64
	if err := extension.Run("Talaria client endpoint client ID", func() {
		clientID = endpoint.ClientID()
	}); err != nil {
		_ = extension.Do("Talaria client invalid endpoint close", endpoint.Close)
		s.fail(ctx, err)
		return err
	}
	if clientID == 0 {
		err = errors.New("Talaria client: endpoint returned zero client ID")
		_ = extension.Do("Talaria client invalid endpoint close", endpoint.Close)
		s.fail(ctx, err)
		return err
	}
	if err := s.installEndpoint(ctx, endpoint, clientID); err != nil {
		_ = extension.Do("Talaria client endpoint close", endpoint.Close)
		s.fail(ctx, err)
		return err
	}

	tun, err := s.deps.Tun.Establish(ctx, TunConfig{
		Protocol:      string(s.cfg.Protocol),
		SourceIP:      s.cfg.EntranceIP,
		DestinationIP: s.cfg.ExitIP,
		MTU:           s.cfg.MTU,
	})
	if err != nil {
		if !extension.IsNil(tun) {
			_ = extension.Do("Talaria client failed tun close", tun.Close)
		}
		s.fail(ctx, err)
		return err
	}
	if extension.IsNil(tun) {
		err = errors.New("Talaria client: tun provider returned nil device")
		s.fail(ctx, err)
		return err
	}
	if err := s.installTun(ctx, tun); err != nil {
		_ = extension.Do("Talaria client tun close", tun.Close)
		s.fail(ctx, err)
		return err
	}
	if err := s.markConnected(ctx); err != nil {
		s.fail(ctx, err)
		return err
	}
	s.markReceive()
	go s.runEndpointLoops(ctx, tun, endpoint)
	s.deps.Events.OnConnectStage(ctx, "connected", map[string]string{
		"protocol": string(s.cfg.Protocol),
	})
	return nil
}

func (s *session) startRawConn(ctx context.Context) error {
	conn, err := s.deps.Dialer.Dial(ctx, DialRequest{
		Protocol:   s.cfg.Protocol,
		ServerIP:   s.cfg.ServerIP,
		Domain:     s.cfg.Domain,
		ServerPort: s.cfg.ServerPort,
	})
	if err != nil {
		if !extension.IsNil(conn) {
			_ = extension.Do("Talaria client failed connection close", conn.Close)
		}
		s.fail(ctx, err)
		return err
	}
	if extension.IsNil(conn) {
		err = errors.New("Talaria client: dialer returned nil connection")
		s.fail(ctx, err)
		return err
	}
	if err := s.installConn(ctx, conn); err != nil {
		_ = extension.Do("Talaria client connection close", conn.Close)
		s.fail(ctx, err)
		return err
	}

	if err := s.auth(ctx, conn); err != nil {
		s.fail(ctx, err)
		return err
	}

	tun, err := s.deps.Tun.Establish(ctx, TunConfig{
		Protocol:      string(s.cfg.Protocol),
		SourceIP:      s.cfg.EntranceIP,
		DestinationIP: s.cfg.ExitIP,
		MTU:           s.cfg.MTU,
	})
	if err != nil {
		if !extension.IsNil(tun) {
			_ = extension.Do("Talaria client failed tun close", tun.Close)
		}
		s.fail(ctx, err)
		return err
	}
	if extension.IsNil(tun) {
		err = errors.New("Talaria client: tun provider returned nil device")
		s.fail(ctx, err)
		return err
	}
	if err := s.installTun(ctx, tun); err != nil {
		_ = extension.Do("Talaria client tun close", tun.Close)
		s.fail(ctx, err)
		return err
	}
	if err := s.markConnected(ctx); err != nil {
		s.fail(ctx, err)
		return err
	}
	s.markReceive()
	go s.runLoops(ctx, tun, conn)
	s.deps.Events.OnConnectStage(ctx, "connected", map[string]string{
		"protocol": string(s.cfg.Protocol),
	})
	return nil
}

func (s *session) installEndpoint(ctx context.Context, endpoint EndpointConn, clientID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateDialing {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.endpoint = endpoint
	s.clientID = clientID
	return nil
}

func (s *session) installConn(ctx context.Context, conn net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateDialing {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *session) installTun(ctx context.Context, tun platform.Tun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateDialing {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.tun = tun
	return nil
}

func (s *session) markConnected(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StateDialing {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = StateConnected
	s.mu.Unlock()
	if err := extension.Run("Talaria client connected state event", func() {
		s.deps.Events.OnStateChange(ctx, StateConnected)
	}); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateConnected {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.loopsStarted = true
	return nil
}

func (s *session) Close() error {
	if !s.closeState.CompareAndSwap(0, 1) {
		if s.closeState.Load() != 2 {
			return nil
		}
		s.closeErrMu.Lock()
		err := s.closeErr
		s.closeErrMu.Unlock()
		return err
	}
	s.mu.Lock()
	cancel := s.cancel
	stopOnCancel := s.stopOnCancel
	conn := s.conn
	endpoint := s.endpoint
	tun := s.tun
	loopsStarted := s.loopsStarted
	clear(s.secretKey)
	s.secretKey = nil
	s.state = StateClosed
	if !loopsStarted {
		close(s.done)
	}
	s.mu.Unlock()

	if stopOnCancel != nil {
		stopOnCancel()
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if conn != nil {
		closeErr = errors.Join(closeErr, extension.Do("Talaria client connection close", conn.Close))
	}
	if endpoint != nil {
		closeErr = errors.Join(closeErr, extension.Do("Talaria client endpoint close", endpoint.Close))
	}
	if tun != nil {
		closeErr = errors.Join(closeErr, extension.Do("Talaria client tun close", tun.Close))
	}
	s.closeErrMu.Lock()
	s.closeErr = closeErr
	s.closeErrMu.Unlock()
	s.closeState.Store(2)
	return closeErr
}

func (s *session) Done() <-chan struct{} {
	return s.done
}

func (s *session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Err reports why the session terminated. fail records the cause before Done is
// closed, so a caller that waits on Done always observes it.
func (s *session) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failErr
}

func (s *session) LocalAddr() (addr string) {
	s.mu.RLock()
	endpoint := s.endpoint
	conn := s.conn
	s.mu.RUnlock()
	if endpoint != nil {
		_ = extension.Run("Talaria client endpoint local address", func() { addr = endpoint.LocalAddr() })
		return addr
	}
	var local net.Addr
	if conn == nil || extension.Run("Talaria client connection local address", func() { local = conn.LocalAddr() }) != nil || extension.IsNil(local) {
		return ""
	}
	_ = extension.Run("Talaria client connection local address string", func() { addr = local.String() })
	return addr
}

// auth validates credentials and waits until the server confirms the session data path is ready.
func (s *session) auth(ctx context.Context, conn net.Conn) error {
	secretKey := s.takeSecretKey()
	defer clear(secretKey)
	s.deps.Events.OnConnectStage(ctx, "auth_start", map[string]string{
		"protocol": string(s.cfg.Protocol),
	})
	authCtx, cancel := context.WithTimeout(ctx, s.cfg.AuthTimeout)
	defer cancel()
	deadline, _ := authCtx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("Talaria client: set auth deadline: %w", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return fmt.Errorf("Talaria client: set auth write deadline: %w", err)
	}
	deadlineCleared := false
	defer func() {
		if !deadlineCleared {
			_ = conn.SetReadDeadline(time.Time{})
			_ = conn.SetWriteDeadline(time.Time{})
		}
	}()

	authPacket := &vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      s.cfg.ClientID,
		Sk:      string(secretKey),
		Version: wireVersion,
	}
	raw, err := s.deps.PacketCodec.Encode(authPacket)
	authPacket.Sk = ""
	if err != nil {
		return fmt.Errorf("Talaria client: encode auth: %w", err)
	}
	defer clear(raw)
	if err := writeConnFrame(conn, raw); err != nil {
		return fmt.Errorf("Talaria client: write auth: %w", err)
	}
	clear(raw)
	raw = nil
	if err := authCtx.Err(); err != nil {
		return fmt.Errorf("Talaria client: authentication deadline: %w", err)
	}

	buf := make([]byte, s.connReadBufferSize())
	authenticated := false
	sessionReady := false
	var readyClientID uint64
	for !authenticated || !sessionReady {
		n, err := readConnFrame(conn, buf)
		if err != nil {
			return fmt.Errorf("Talaria client: read session response: %w", err)
		}
		packet, _, err := s.deps.PacketCodec.Decode(buf[:n])
		if err != nil {
			return fmt.Errorf("Talaria client: decode session response: %w", err)
		}
		switch packet.Cmd {
		case vpnpacket.CmdAuthSuccess:
			if authenticated || packet.NewClientId == 0 {
				return fmt.Errorf("%w: invalid authentication success", ErrProtocolViolation)
			}
			if sessionReady && readyClientID != packet.NewClientId {
				return fmt.Errorf("%w: ready client id does not match authentication", ErrProtocolViolation)
			}
			s.clientID = packet.NewClientId
			if packet.Version != 0 {
				s.remoteVersion = packet.Version
			}
			authenticated = true
			s.deps.Events.OnConnectStage(ctx, "auth_success", nil)
		case vpnpacket.CmdSessionReady:
			if sessionReady {
				return fmt.Errorf("%w: duplicate session ready", ErrProtocolViolation)
			}
			if authenticated && packet.ClientId != s.clientID {
				return fmt.Errorf("%w: ready client id does not match authentication", ErrProtocolViolation)
			}
			readyClientID = packet.ClientId
			sessionReady = true
		case vpnpacket.CmdErr:
			return fmt.Errorf("%w: %s", ErrAuthRejected, packet.ErrorMessage)
		default:
			return fmt.Errorf("%w: unexpected session response cmd=%d", ErrProtocolViolation, packet.Cmd)
		}
		if err := authCtx.Err(); err != nil {
			return fmt.Errorf("Talaria client: authentication deadline: %w", err)
		}
	}
	if err := authCtx.Err(); err != nil {
		return fmt.Errorf("Talaria client: authentication deadline: %w", err)
	}
	readResetErr := conn.SetReadDeadline(time.Time{})
	writeResetErr := conn.SetWriteDeadline(time.Time{})
	if err := errors.Join(readResetErr, writeResetErr); err != nil {
		return fmt.Errorf("Talaria client: reset auth deadlines: %w", err)
	}
	deadlineCleared = true
	return nil
}

func (s *session) takeSecretKey() []byte {
	s.mu.Lock()
	secretKey := s.secretKey
	s.secretKey = nil
	s.mu.Unlock()
	return secretKey
}

func (s *session) runLoops(ctx context.Context, tun platform.Tun, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		s.runLoop(ctx, "Talaria client tun-to-connection extension", func() error { return s.runTunToConn(ctx, tun, conn) })
	}()
	go func() {
		defer wg.Done()
		s.runLoop(ctx, "Talaria client connection-to-tun extension", func() error { return s.runConnToTun(ctx, tun, conn) })
	}()
	go func() {
		defer wg.Done()
		s.runLoop(ctx, "Talaria client keepalive extension", func() error { return s.runKeepAlive(ctx, conn) })
	}()
	wg.Wait()
	close(s.done)
}

func (s *session) runEndpointLoops(ctx context.Context, tun platform.Tun, endpoint EndpointConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.runLoop(ctx, "Talaria client tun-to-endpoint extension", func() error { return s.runEndpointTunToConn(ctx, tun, endpoint) })
	}()
	go func() {
		defer wg.Done()
		s.runLoop(ctx, "Talaria client endpoint-to-tun extension", func() error { return s.runEndpointConnToTun(ctx, tun, endpoint) })
	}()
	wg.Wait()
	close(s.done)
}

func (s *session) runLoop(ctx context.Context, scope string, fn func() error) {
	err := extension.Do(scope, fn)
	if err != nil && !isExpectedClose(ctx, err) {
		s.fail(ctx, err)
	}
}

func (s *session) runEndpointTunToConn(ctx context.Context, tun platform.Tun, endpoint EndpointConn) error {
	pool := dataplane.NewPool(dataplane.TunReadPacketBufferSize(s.cfg.MTU), dataplane.DefaultHeadroom)
	buffered, hasBufferedWrite := endpoint.(interface {
		WriteDataBuffer(*dataplane.PacketBuffer) error
	})
	for {
		pkt := pool.Get()
		n, err := readTunPacketToBuffer(tun, pkt)
		if err != nil {
			pool.Put(pkt)
			return err
		}
		if n <= 0 {
			pool.Put(pkt)
			continue
		}
		pkt.End = pkt.Start + n
		s.deps.Stats.OnTunRead(ctx, n)
		if hasBufferedWrite {
			err = buffered.WriteDataBuffer(pkt)
		} else {
			err = endpoint.WriteData(pkt.Bytes())
		}
		pool.Put(pkt)
		if err != nil {
			return fmt.Errorf("Talaria client: endpoint write data: %w", err)
		}
		s.deps.Stats.OnUploadBytes(ctx, n)
	}
}

func (s *session) runEndpointConnToTun(ctx context.Context, tun platform.Tun, endpoint EndpointConn) (err error) {
	writerCtx, cancelWriter := context.WithCancel(ctx)
	downlinkWriter := newDownlinkTunWriter(writerCtx, tun, s.cfg.DownlinkQueueSize, s.deps.Stats, func(error) {
		_ = endpoint.Close()
	})
	defer func() {
		cancelWriter()
		downlinkWriter.close()
		if writeErr := downlinkWriter.getErr(); writeErr != nil {
			err = errors.Join(err, fmt.Errorf("Talaria client: write tun: %w", writeErr))
		}
	}()
	if borrowed, ok := endpoint.(BorrowedPayloadEndpointConn); ok {
		return s.runBorrowedEndpointConnToTun(borrowed, downlinkWriter)
	}
	if buffered, ok := endpoint.(interface {
		ReadPacketBuffer(*dataplane.PacketBuffer) (*vpnpacket.VpnPacket, bool, error)
	}); ok {
		return s.runBufferedEndpointConnToTun(buffered, endpoint, downlinkWriter)
	}
	pool := dataplane.NewPool(dataplane.EndpointReadPacketBufferSize(s.cfg.MTU, string(s.cfg.Protocol)), dataplane.DefaultHeadroom)
	for {
		packet, err := endpoint.ReadPacket()
		if err != nil {
			return err
		}
		if packet == nil {
			return errors.New("Talaria client: endpoint returned nil packet")
		}
		s.markReceive()
		switch packet.Cmd {
		case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
			if len(packet.Data) == 0 {
				continue
			}
			pkt := pool.Get()
			if err := copyTunPayload(pkt, packet.Data); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: copy tun payload: %w", err)
			}
			if err := downlinkWriter.writeBuffer(pkt, pool); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: write tun: %w", err)
			}
		case vpnpacket.CmdKeepAlive:
			continue
		case vpnpacket.CmdServerKeepAlive:
			if err := s.replyEndpointKeepAlive(endpoint, packet); err != nil {
				return err
			}
		case vpnpacket.CmdErr:
			return fmt.Errorf("%w: %s", ErrServerRejected, packet.ErrorMessage)
		}
	}
}

func (s *session) runBorrowedEndpointConnToTun(borrowed BorrowedPayloadEndpointConn, downlinkWriter *downlinkTunWriter) error {
	pool := dataplane.NewPool(dataplane.EndpointReadPacketBufferSize(s.cfg.MTU, string(s.cfg.Protocol)), dataplane.DefaultHeadroom)
	for {
		payload, release, err := borrowed.ReadPayloadBorrowed()
		if err != nil {
			return errors.Join(err, releaseBorrowedPayload(release))
		}
		s.markReceive()
		if len(payload) == 0 {
			if err := releaseBorrowedPayload(release); err != nil {
				return err
			}
			continue
		}
		pkt := pool.Get()
		copyErr := copyTunPayload(pkt, payload)
		releaseErr := releaseBorrowedPayload(release)
		if copyErr != nil || releaseErr != nil {
			pool.Put(pkt)
			return errors.Join(copyErr, releaseErr)
		}
		if err := downlinkWriter.writeBuffer(pkt, pool); err != nil {
			pool.Put(pkt)
			return fmt.Errorf("Talaria client: write tun: %w", err)
		}
	}
}

func (s *session) runBufferedEndpointConnToTun(buffered interface {
	ReadPacketBuffer(*dataplane.PacketBuffer) (*vpnpacket.VpnPacket, bool, error)
}, endpoint EndpointConn, downlinkWriter *downlinkTunWriter) error {
	pool := dataplane.NewPool(dataplane.EndpointReadPacketBufferSize(s.cfg.MTU, string(s.cfg.Protocol)), dataplane.DefaultHeadroom)
	for {
		pkt := pool.Get()
		packet, dataReady, err := buffered.ReadPacketBuffer(pkt)
		if err != nil {
			pool.Put(pkt)
			return err
		}
		if packet == nil {
			pool.Put(pkt)
			return errors.New("Talaria client: buffered endpoint returned nil packet")
		}
		if pkt.Start < 0 || pkt.End < pkt.Start || pkt.End > len(pkt.Raw) {
			pool.Put(pkt)
			return errInvalidTunPacket
		}
		s.markReceive()
		switch packet.Cmd {
		case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
			if dataReady && pkt.Len() > 0 {
				if err := downlinkWriter.writeBuffer(pkt, pool); err != nil {
					pool.Put(pkt)
					return fmt.Errorf("Talaria client: write tun: %w", err)
				}
				continue
			}
			if len(packet.Data) == 0 {
				pool.Put(pkt)
				continue
			}
			if err := copyTunPayload(pkt, packet.Data); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: copy tun payload: %w", err)
			}
			if err := downlinkWriter.writeBuffer(pkt, pool); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: write tun: %w", err)
			}
		case vpnpacket.CmdKeepAlive:
			pool.Put(pkt)
			continue
		case vpnpacket.CmdServerKeepAlive:
			pool.Put(pkt)
			if err := s.replyEndpointKeepAlive(endpoint, packet); err != nil {
				return err
			}
		case vpnpacket.CmdErr:
			pool.Put(pkt)
			return fmt.Errorf("%w: %s", ErrServerRejected, packet.ErrorMessage)
		default:
			pool.Put(pkt)
		}
	}
}

func (s *session) runTunToConn(ctx context.Context, tun platform.Tun, conn net.Conn) error {
	pool := dataplane.NewPool(dataplane.TunReadPacketBufferSize(s.cfg.MTU), dataplane.DefaultHeadroom)
	uplinkWriter := newUplinkConnWriter(ctx, conn, s.cfg.UplinkQueueSize, s.deps.Stats, func(err error) {
		s.fail(ctx, fmt.Errorf("Talaria client: write data: %w", err))
	})
	defer uplinkWriter.close()
	entranceIP := ipv4Bytes(s.cfg.EntranceIP)
	exitIP := ipv4Bytes(s.cfg.ExitIP)
	for {
		pkt := pool.Get()
		n, err := readTunPacketToBuffer(tun, pkt)
		if err != nil {
			pool.Put(pkt)
			return err
		}
		if n <= 0 {
			pool.Put(pkt)
			continue
		}
		pkt.End = pkt.Start + n
		s.deps.Stats.OnTunRead(ctx, n)
		seq := atomic.AddUint32(&s.dataSeq, 1)
		if err := dataplane.WriteDataHeader(pkt, s.clientID, seq, s.remoteVersion, entranceIP, exitIP); err != nil {
			pool.Put(pkt)
			return fmt.Errorf("Talaria client: encode data: %w", err)
		}
		if err := uplinkWriter.writeBuffer(pkt, pool, n); err != nil {
			pool.Put(pkt)
			return fmt.Errorf("Talaria client: write data: %w", err)
		}
	}
}

func (s *session) runConnToTun(ctx context.Context, tun platform.Tun, conn net.Conn) error {
	pool := dataplane.NewPool(dataplane.ConnReadPacketBufferSize(s.cfg.MTU), dataplane.DefaultHeadroom)
	writerCtx, cancelWriter := context.WithCancel(ctx)
	downlinkWriter := newDownlinkTunWriter(writerCtx, tun, s.cfg.DownlinkQueueSize, s.deps.Stats, func(error) {
		_ = conn.Close()
	})
	defer func() {
		cancelWriter()
		downlinkWriter.close()
	}()
	var packet vpnpacket.VpnPacket
	for {
		pkt := pool.Get()
		n, err := readConnFrame(conn, pkt.Raw[pkt.Start:])
		if err != nil {
			pool.Put(pkt)
			if writeErr := downlinkWriter.getErr(); writeErr != nil {
				return fmt.Errorf("Talaria client: write tun: %w", writeErr)
			}
			return err
		}
		pkt.End = pkt.Start + n
		payloadOffset, decodeErr := s.decodePacketInto(&packet, pkt.Bytes())
		if decodeErr != nil {
			pool.Put(pkt)
			return fmt.Errorf("Talaria client: decode packet: %w", decodeErr)
		}
		s.markReceive()
		switch packet.Cmd {
		case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
			if payloadOffset > 0 && pkt.ConsumeHead(payloadOffset) && pkt.Len() > 0 {
				if err := downlinkWriter.writeBuffer(pkt, pool); err == nil {
					continue
				} else {
					pool.Put(pkt)
					return fmt.Errorf("Talaria client: write tun: %w", err)
				}
			}
			if len(packet.Data) == 0 {
				pool.Put(pkt)
				continue
			}
			if err := copyTunPayload(pkt, packet.Data); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: copy tun payload: %w", err)
			}
			if err := downlinkWriter.writeBuffer(pkt, pool); err != nil {
				pool.Put(pkt)
				return fmt.Errorf("Talaria client: write tun: %w", err)
			}
		case vpnpacket.CmdKeepAlive, vpnpacket.CmdServerKeepAlive:
			pool.Put(pkt)
			if s.isClientKeepAliveReply(&packet) {
				continue
			}
			if err := s.replyKeepAlive(conn, &packet); err != nil {
				return err
			}
		case vpnpacket.CmdErr:
			pool.Put(pkt)
			return fmt.Errorf("%w: %s", ErrServerRejected, packet.ErrorMessage)
		default:
			pool.Put(pkt)
		}
	}
}

func (s *session) decodePacketInto(packet *vpnpacket.VpnPacket, raw []byte) (int, error) {
	if reusable, ok := s.deps.PacketCodec.(dataplane.ReusableCodec); ok {
		return reusable.DecodeInto(packet, raw)
	}
	decoded, payloadOffset, err := s.deps.PacketCodec.Decode(raw)
	if err != nil {
		return 0, err
	}
	if decoded == nil {
		return 0, errors.New("nil decoded packet")
	}
	*packet = *decoded
	return payloadOffset, nil
}

func (s *session) runKeepAlive(ctx context.Context, conn net.Conn) error {
	ticker := time.NewTicker(defaultKeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if age := s.lastReceiveAge(now); age >= s.cfg.KeepAliveDuration {
				return fmt.Errorf("%w after %s", ErrKeepAliveTimeout, age.Truncate(time.Millisecond))
			}
			id := atomic.AddUint32(&s.keepAliveSeq, 1)
			packet := &vpnpacket.VpnPacket{
				ClientId:    s.clientID,
				Cmd:         vpnpacket.CmdKeepAlive,
				KeepAliveId: id,
				SendTime:    now.UnixNano(),
				IsPing:      true,
			}
			raw, err := s.deps.PacketCodec.Encode(packet)
			if err != nil {
				return fmt.Errorf("Talaria client: encode keepalive: %w", err)
			}
			if err := writeConnFrame(conn, raw); err != nil {
				return fmt.Errorf("Talaria client: write keepalive: %w", err)
			}
		}
	}
}

func (s *session) isClientKeepAliveReply(packet *vpnpacket.VpnPacket) bool {
	if packet == nil || packet.Cmd != vpnpacket.CmdKeepAlive {
		return false
	}
	return !packet.IsPing
}

func (s *session) replyKeepAlive(conn net.Conn, packet *vpnpacket.VpnPacket) error {
	reply := &vpnpacket.VpnPacket{
		ClientId:    s.clientID,
		Cmd:         packet.Cmd,
		KeepAliveId: packet.KeepAliveId,
		SendTime:    packet.SendTime,
	}
	raw, err := s.deps.PacketCodec.Encode(reply)
	if err != nil {
		return fmt.Errorf("Talaria client: encode keepalive reply: %w", err)
	}
	if err := writeConnFrame(conn, raw); err != nil {
		return fmt.Errorf("Talaria client: write keepalive reply: %w", err)
	}
	return nil
}

func (s *session) replyEndpointKeepAlive(endpoint EndpointConn, packet *vpnpacket.VpnPacket) error {
	if err := endpoint.WritePacket(&vpnpacket.VpnPacket{
		ClientId:    endpoint.ClientID(),
		Cmd:         vpnpacket.CmdServerKeepAlive,
		KeepAliveId: packet.KeepAliveId,
	}); err != nil {
		return fmt.Errorf("Talaria client: endpoint keepalive reply: %w", err)
	}
	return nil
}

func (s *session) markReceive() {
	atomic.StoreInt64(&s.lastReceiveNs, time.Now().UnixNano())
}

func (s *session) lastReceiveAge(now time.Time) time.Duration {
	last := atomic.LoadInt64(&s.lastReceiveNs)
	if last == 0 {
		return 0
	}
	age := now.Sub(time.Unix(0, last))
	if age < 0 {
		return 0
	}
	return age
}

func (s *session) fail(ctx context.Context, err error) {
	s.mu.Lock()
	if s.state == StateClosed {
		s.mu.Unlock()
		return
	}
	s.state = StateFailed
	// Record the cause before Close runs, so a caller that observes Done or
	// StateFailed can always retrieve it through Err. Keep the first cause: a
	// failing session tends to produce follow-on errors from the other loops,
	// and the first one is the diagnostic.
	if s.failErr == nil {
		s.failErr = err
	}
	s.mu.Unlock()
	_ = extension.Run("Talaria client state event", func() { s.deps.Events.OnStateChange(ctx, StateFailed) })
	_ = extension.Run("Talaria client error event", func() { s.deps.Events.OnError(ctx, err) })
	_ = s.Close()
}

func (s *session) tunReadBufferSize() int {
	return dataplane.TunReadBufferSize(s.cfg.MTU)
}

func (s *session) connReadBufferSize() int {
	return dataplane.ConnReadBufferSize(s.cfg.MTU)
}

func ipv4Bytes(s string) []byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return make([]byte, 4)
	}
	return []byte(ip)
}

func isExpectedClose(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	return ctx.Err() != nil
}

func readTunPacketToBuffer(tun platform.Tun, pkt *dataplane.PacketBuffer) (int, error) {
	if tun == nil || pkt == nil {
		return 0, io.ErrUnexpectedEOF
	}
	var n int
	var err error
	if offTun, ok := tun.(platform.PacketOffsetReader); ok {
		n, err = offTun.ReadPacketOffset(pkt.Raw, pkt.Start)
	} else {
		n, err = tun.Read(pkt.Raw[pkt.Start:])
	}
	if err != nil {
		return n, err
	}
	available := len(pkt.Raw) - pkt.Start
	if n < 0 || n > available {
		return 0, fmt.Errorf("Talaria client: TUN returned invalid read size %d for %d-byte buffer", n, available)
	}
	return n, nil
}

// writeTunPacketBuffer returns (0, nil) for non-IPv4 payloads or parse failures.
func writeTunPacketBuffer(ctx context.Context, tun platform.Tun, pkt *dataplane.PacketBuffer) (int, error) {
	if tun == nil || pkt == nil {
		return 0, io.ErrUnexpectedEOF
	}
	if pkt.Start < 0 || pkt.End < pkt.Start || pkt.End > len(pkt.Raw) {
		return 0, errInvalidTunPacket
	}
	if pkt.Len() <= 0 {
		return 0, nil
	}
	if ipPacket, err := ippacket.ParseIPPacket(pkt.Bytes()); err != nil || !ipPacket.IsIPv4() {
		return 0, nil
	}
	expected := pkt.Len()
	var n int
	var err error
	if offTun, ok := tun.(platform.PacketOffsetWriter); ok {
		n, err = offTun.WritePacketOffset(ctx, pkt.Raw, pkt.Start, expected)
	} else {
		n, err = tun.WriteContext(ctx, pkt.Bytes())
	}
	if err == nil && n != expected {
		return n, io.ErrShortWrite
	}
	return n, err
}

func copyTunPayload(pkt *dataplane.PacketBuffer, payload []byte) error {
	if pkt == nil || pkt.Start < 0 || pkt.End < pkt.Start || pkt.End > len(pkt.Raw) {
		return errInvalidTunPacket
	}
	if len(payload) > len(pkt.Raw)-pkt.Start {
		return io.ErrShortBuffer
	}
	copy(pkt.Raw[pkt.Start:], payload)
	pkt.End = pkt.Start + len(payload)
	return nil
}

func writeConnFrame(conn net.Conn, frame []byte) error {
	if extension.IsNil(conn) {
		return net.ErrClosed
	}
	n, err := conn.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func readConnFrame(conn net.Conn, frame []byte) (int, error) {
	n, err := conn.Read(frame)
	if n < 0 || n > len(frame) {
		return 0, fmt.Errorf("Talaria client: connection returned invalid read size %d for %d-byte buffer", n, len(frame))
	}
	return n, err
}

func releaseBorrowedPayload(release func()) error {
	if release == nil {
		return nil
	}
	return extension.Run("Talaria client borrowed payload release", release)
}
