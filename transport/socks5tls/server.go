// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package socks5tls implements the TalariaTCP carrier and its SOCKS5 session
// layer.
//
// TalariaTCP requires TLS 1.3 and verified certificates. It wraps the full TLS
// stream in a deployment-keyed transform with a randomized, authenticated
// preamble.
//
// The connection's role is selected after the TLS handshake, inside the
// encrypted stream, so an observer cannot tell a control connection from a data
// connection. Data streams are SOCKS5 CONNECT only: no-auth, BIND and UDP
// ASSOCIATE are rejected, and a stream may not target the Talaria listener
// itself.
package socks5tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/internal/controlframe"
	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const (
	defaultHandshakeTimeout      = 10 * time.Second
	defaultSessionCleanupWorkers = 256
	defaultFlowReclaimWorkers    = 8
	defaultFlowReclaimQueue      = 256
)

var defaultServerHandshakeWorkerSlots = make(chan struct{}, defaultMaxPendingHandshakes)

type Server struct {
	listener                     net.Listener
	tlsConfig                    *tls.Config
	wireKey                      *wireKey
	wireKeyMu                    sync.RWMutex
	wireReplay                   *wireReplayCache
	handshakeTimeout             time.Duration
	now                          func() time.Time
	registry                     *coretransport.SessionRegistry
	admission                    *admissionLimiter
	handshakeWorkers             chan struct{}
	handshakeWorkerMu            sync.Mutex
	handshakeWorkersBySource     map[string]int
	maxHandshakeWorkersPerSource int
	cleanupMu                    sync.Mutex
	cleanupSlots                 chan struct{}
	cleanupByClient              map[uint64]struct{}
	reclaimMu                    sync.Mutex
	reclaimQueue                 chan flowReclaimTask
	reclaimSlots                 chan struct{}
	reclaimStop                  chan struct{}
	reclaimStart                 sync.Once
	reclaimWG                    sync.WaitGroup
	reclaimStopped               bool

	serveMu       sync.Mutex
	streamHandler coretransport.StreamHandler
	socksServer   *gosocks5.Server
	serving       bool

	sessionMu   sync.Mutex
	connMu      sync.Mutex
	conns       map[net.Conn]struct{}
	flows       map[coretransport.SessionRef]map[*streamFlow]struct{}
	expiry      map[coretransport.SessionRef]*time.Timer
	workerMu    sync.Mutex
	workersDone bool
	wg          sync.WaitGroup

	closeState atomic.Uint32
	closeErrMu sync.Mutex
	closeErr   error
	closed     chan struct{}
}

type streamFlow struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	cancelOnce  sync.Once
	closeDone   chan struct{}
	client      net.Conn
	target      net.Conn
	closed      bool
	closing     atomic.Bool
	reclaimOnce sync.Once
	reclaimDone func()
	reclaim     func(net.Conn)
}

type flowReclaimTask struct {
	flow        *streamFlow
	conn        net.Conn
	reclaimDone func()
}

func NewServer(cfg ServerConfig) (server *Server, err error) {
	defer extension.Recover("SOCKS5 TLS server configuration extension", &err)
	tlsConfig, err := normalizeServerTLSConfig(cfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	if cfg.CacheTLSConfig {
		return nil, errors.New("SOCKS5 TLS dynamic config options are not supported")
	}
	if cfg.CachePureTLSConfig || len(cfg.TLSConfigCacheScope) != 0 || cfg.AllowTLSConfigFallback {
		return nil, errors.New("SOCKS5 TLS dynamic config options are not supported")
	}
	wireKey, err := newWireKey(cfg.WireSecret, cfg.WireIdentity)
	if err != nil {
		return nil, err
	}
	defer func() {
		if server == nil && wireKey != nil {
			clear(wireKey[:])
		}
	}()
	tlsConfig.NextProtos = nil
	if cfg.HandshakeTimeout < 0 {
		return nil, errors.New("SOCKS5 TLS handshake timeout cannot be negative")
	}
	if cfg.HandshakeTimeout > 5*time.Minute {
		return nil, errors.New("SOCKS5 TLS handshake timeout exceeds maximum 5m")
	}
	if cfg.Now != nil {
		return nil, errors.New("SOCKS5 TLS custom clock is not supported")
	}
	listener := cfg.Listener
	if extension.IsNil(listener) {
		listen := cfg.Listen
		if listen == "" {
			listen = "127.0.0.1:0"
		}
		listener, err = net.Listen("tcp", listen)
		if err != nil {
			return nil, fmt.Errorf("listen SOCKS5 TLS: %w", err)
		}
	}
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	admissionLimits, err := normalizeAdmissionLimits(cfg.AdmissionLimits)
	if err != nil {
		_ = extension.Do("SOCKS5 TLS invalid server listener close", listener.Close)
		return nil, err
	}
	wireReplay := newWireReplayCache(defaultWireReplayCacheSize, defaultWireReplayPerSource)
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		disableAES128GCM(hello)
		return nil, nil
	}
	return &Server{
		listener:                     listener,
		tlsConfig:                    tlsConfig,
		wireKey:                      wireKey,
		wireReplay:                   wireReplay,
		handshakeTimeout:             handshakeTimeout,
		now:                          now,
		registry:                     coretransport.NewSessionRegistry(),
		admission:                    newAdmissionLimiter(admissionLimits),
		handshakeWorkers:             make(chan struct{}, admissionLimits.MaxPendingHandshakes),
		handshakeWorkersBySource:     make(map[string]int),
		maxHandshakeWorkersPerSource: admissionLimits.MaxPendingPerSourceIP,
		cleanupSlots:                 make(chan struct{}, defaultSessionCleanupWorkers),
		cleanupByClient:              make(map[uint64]struct{}),
		reclaimQueue:                 make(chan flowReclaimTask, admissionLimits.MaxConnections),
		reclaimSlots:                 make(chan struct{}, admissionLimits.MaxConnections),
		reclaimStop:                  make(chan struct{}),
		conns:                        make(map[net.Conn]struct{}),
		flows:                        make(map[coretransport.SessionRef]map[*streamFlow]struct{}),
		expiry:                       make(map[coretransport.SessionRef]*time.Timer),
		closed:                       make(chan struct{}),
	}, nil
}

func (s *Server) Addr() (addr net.Addr) {
	if s == nil || s.listener == nil {
		return nil
	}
	_ = extension.Run("SOCKS5 TLS listener address", func() { addr = s.listener.Addr() })
	return addr
}

func (s *Server) Activate(ctx context.Context, grant coretransport.SessionGrant) error {
	defer clear(grant.DataToken[:])
	if err := s.Prepare(ctx, grant); err != nil {
		return err
	}
	if err := s.Commit(ctx, grant.SessionRef); err != nil {
		_ = s.Revoke(ctx, grant.SessionRef)
		return err
	}
	if err := s.Finalize(ctx, grant.SessionRef); err != nil {
		_ = s.Revoke(ctx, grant.SessionRef)
		return err
	}
	return nil
}

func (s *Server) Prepare(_ context.Context, grant coretransport.SessionGrant) error {
	defer clear(grant.DataToken[:])
	if s == nil {
		return net.ErrClosed
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.isClosed() {
		return net.ErrClosed
	}
	return s.registry.Prepare(grant, now)
}

func (s *Server) Commit(_ context.Context, session coretransport.SessionRef) error {
	if s == nil {
		return net.ErrClosed
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	s.sessionMu.Lock()
	if s.isClosed() {
		s.sessionMu.Unlock()
		return net.ErrClosed
	}
	_, _, expiresAt, err := s.registry.Commit(session, now)
	if err != nil {
		s.sessionMu.Unlock()
		return err
	}
	if !expiresAt.IsZero() && !s.scheduleSessionExpiry(session, expiresAt, now) {
		s.registry.Revoke(session)
		s.sessionMu.Unlock()
		s.closeSessionFlows(session)
		return net.ErrClosed
	}
	s.sessionMu.Unlock()
	return nil
}

func (s *Server) Finalize(_ context.Context, session coretransport.SessionRef) error {
	if s == nil {
		return net.ErrClosed
	}
	releaseCleanup, ok := s.acquireSessionCleanup(session.ClientID)
	if !ok {
		return errors.New("SOCKS5 TLS session cleanup capacity reached")
	}
	defer releaseCleanup()
	s.sessionMu.Lock()
	if s.isClosed() {
		s.sessionMu.Unlock()
		return net.ErrClosed
	}
	old, hadOld, err := s.registry.Finalize(session)
	if err != nil {
		s.sessionMu.Unlock()
		return err
	}
	if hadOld && old != session {
		s.stopSessionExpiry(old)
	}
	s.sessionMu.Unlock()
	if hadOld && old != session {
		flows := s.detachSessionFlows(old)
		releaseCleanup()
		s.reclaimFlows(flows)
	}
	return nil
}

func (s *Server) acquireSessionCleanup(clientID uint64) (func(), bool) {
	if clientID == 0 {
		return nil, false
	}
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	if s.cleanupSlots == nil {
		s.cleanupSlots = make(chan struct{}, defaultSessionCleanupWorkers)
	}
	if s.cleanupByClient == nil {
		s.cleanupByClient = make(map[uint64]struct{})
	}
	if _, exists := s.cleanupByClient[clientID]; exists {
		return nil, false
	}
	select {
	case s.cleanupSlots <- struct{}{}:
		s.cleanupByClient[clientID] = struct{}{}
	default:
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.cleanupMu.Lock()
			delete(s.cleanupByClient, clientID)
			<-s.cleanupSlots
			s.cleanupMu.Unlock()
		})
	}, true
}

func (s *Server) currentTime() (now time.Time, err error) {
	err = extension.Run("SOCKS5 TLS clock", func() {
		now = s.now()
	})
	return now, err
}

func (s *Server) Revoke(_ context.Context, session coretransport.SessionRef) error {
	if s == nil {
		return nil
	}
	s.sessionMu.Lock()
	revoked := s.registry.Revoke(session)
	if revoked {
		s.stopSessionExpiry(session)
	}
	s.sessionMu.Unlock()
	if revoked {
		s.closeSessionFlows(session)
	}
	return nil
}

func (s *Server) Serve(ctx context.Context, control coretransport.ControlHandler, streams coretransport.StreamHandler) (err error) {
	defer extension.Recover("SOCKS5 TLS server extension", &err)
	if s == nil || s.listener == nil {
		return net.ErrClosed
	}
	if extension.IsNil(control) {
		return errors.New("control handler is required")
	}
	if extension.IsNil(streams) {
		return errors.New("stream handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("SOCKS5 TLS server is already serving")
	}
	s.serving = true
	s.streamHandler = streams
	s.socksServer = gosocks5.NewServer(
		gosocks5.WithResolver(noResolveResolver{}),
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			sessionAuthenticator{server: s},
		}),
		gosocks5.WithConnectHandle(s.handleConnect),
		gosocks5.WithBindHandle(rejectUnsupportedCommand),
		gosocks5.WithAssociateHandle(rejectUnsupportedCommand),
	)
	s.serveMu.Unlock()
	defer s.waitWorkers()
	serveDone := make(chan struct{})
	defer close(serveDone)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closed:
		case <-serveDone:
		}
	}()

	for {
		var raw net.Conn
		err := extension.Do("SOCKS5 TLS listener accept", func() error {
			var acceptErr error
			raw, acceptErr = s.listener.Accept()
			return acceptErr
		})
		if err != nil {
			if !extension.IsNil(raw) {
				_ = extension.Do("SOCKS5 TLS failed accepted connection close", raw.Close)
			}
			if ctx.Err() != nil || s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			_ = s.Close()
			return err
		}
		if extension.IsNil(raw) {
			_ = s.Close()
			return errors.New("SOCKS5 TLS listener returned a nil connection")
		}
		var remote net.Addr
		if err := extension.Run("SOCKS5 TLS accepted connection remote address", func() {
			remote = raw.RemoteAddr()
		}); err != nil {
			_ = extension.Do("SOCKS5 TLS invalid accepted connection close", raw.Close)
			_ = s.Close()
			return err
		}
		var lease *admissionLease
		var admitted bool
		if err := extension.Run("SOCKS5 TLS accepted connection admission", func() {
			lease, admitted = s.admission.acquire(remote)
		}); err != nil {
			_ = extension.Do("SOCKS5 TLS invalid accepted connection close", raw.Close)
			_ = s.Close()
			return err
		}
		if !admitted {
			_ = extension.Do("SOCKS5 TLS rejected connection close", raw.Close)
			continue
		}
		if !s.trackConn(raw, true) {
			lease.release()
			_ = extension.Do("SOCKS5 TLS accepted connection close after shutdown", raw.Close)
			return nil
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer lease.release()
			defer s.trackConn(raw, false)
			defer func() { _ = extension.Do("SOCKS5 TLS connection close", raw.Close) }()
			_ = s.serveConn(ctx, raw, control, lease)
		}()
	}
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if !s.closeState.CompareAndSwap(0, 1) {
		if s.closeState.Load() != 2 {
			return nil
		}
		s.closeErrMu.Lock()
		err := s.closeErr
		s.closeErrMu.Unlock()
		return err
	}
	close(s.closed)
	s.wireReplay.close()
	s.wireKeyMu.Lock()
	if s.wireKey != nil {
		clear(s.wireKey[:])
		s.wireKey = nil
	}
	s.wireKeyMu.Unlock()
	var closeErr error
	if s.listener != nil {
		closeErr = extension.Do("SOCKS5 TLS listener close", s.listener.Close)
	}
	s.sessionMu.Lock()
	s.registry.Close()
	s.connMu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	flows := make([]*streamFlow, 0)
	for _, sessionFlows := range s.flows {
		for flow := range sessionFlows {
			flows = append(flows, flow)
		}
	}
	for _, flow := range flows {
		flow.cancelFlow()
	}
	clear(s.flows)
	timers := make([]*time.Timer, 0, len(s.expiry))
	for _, timer := range s.expiry {
		timers = append(timers, timer)
	}
	clear(s.expiry)
	s.connMu.Unlock()
	s.sessionMu.Unlock()
	for _, timer := range timers {
		timer.Stop()
	}
	s.reclaimFlows(flows)
	for _, conn := range conns {
		_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
	}
	s.serveMu.Lock()
	serving := s.serving
	s.serveMu.Unlock()
	if !serving {
		s.stopFlowReclaimer()
	}
	s.closeErrMu.Lock()
	s.closeErr = closeErr
	s.closeErrMu.Unlock()
	s.closeState.Store(2)
	return closeErr
}

func (s *Server) serveConn(ctx context.Context, raw net.Conn, control coretransport.ControlHandler, lease *admissionLease) (err error) {
	defer extension.Recover("SOCKS5 TLS control handler", &err)
	defer lease.releasePending()
	deadline := time.Now().Add(s.handshakeTimeout)
	if err := raw.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set TLS negotiation deadline: %w", err)
	}
	source := ""
	if lease != nil {
		source = lease.source
	}
	conn, err := s.handshakeConn(ctx, raw, source)
	if err != nil {
		return err
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return errors.New("unexpected TLS version")
	}
	if err := validateNegotiatedCipherSuite(state.CipherSuite); err != nil {
		return err
	}
	if err := validateNegotiatedProtocol(state.NegotiatedProtocol); err != nil {
		return err
	}
	role, err := readConnectionRole(conn)
	if err != nil {
		return fmt.Errorf("read TLS connection role: %w", err)
	}
	switch role {
	case connectionRoleControl:
		lease.releasePending()
		if err := raw.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clear TLS control negotiation deadline: %w", err)
		}
		return control.HandleControl(ctx, controlframe.New(conn))
	case connectionRoleStream:
		s.serveMu.Lock()
		socksServer := s.socksServer
		s.serveMu.Unlock()
		if socksServer == nil {
			return net.ErrClosed
		}
		return socksServer.ServeConn(&admittedConn{Conn: conn, lease: lease})
	default:
		return errors.New("unsupported TLS connection role")
	}
}

func (s *Server) handshakeConn(ctx context.Context, raw net.Conn, source string) (*tls.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slots := s.handshakeWorkers
	if slots == nil {
		slots = defaultServerHandshakeWorkerSlots
	}
	if !s.acquireHandshakeWorker(slots, source) {
		_ = raw.Close()
		return nil, errors.New("SOCKS5 TLS handshake worker capacity reached")
	}
	type result struct {
		conn *tls.Conn
		err  error
	}
	resultCh := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		defer s.releaseHandshakeWorker(slots, source)
		s.wireKeyMu.RLock()
		wireConn := wrapServerWire(raw, s.wireKey, s.wireReplay, source, s.now)
		s.wireKeyMu.RUnlock()
		conn := tls.Server(wireConn, s.tlsConfig)
		handshakeCtx, cancel := context.WithTimeout(ctx, s.handshakeTimeout)
		err := extension.Do("SOCKS5 TLS server handshake", func() error {
			return conn.HandshakeContext(handshakeCtx)
		})
		cancel()
		select {
		case resultCh <- result{conn: conn, err: err}:
		case <-abandoned:
			_ = extension.Do("SOCKS5 TLS abandoned handshake close", conn.Close)
		}
	}()
	defer close(abandoned)
	timer := time.NewTimer(s.handshakeTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		_ = raw.Close()
		return nil, ctx.Err()
	case <-s.closed:
		_ = raw.Close()
		return nil, net.ErrClosed
	case <-timer.C:
		_ = raw.Close()
		return nil, context.DeadlineExceeded
	case result := <-resultCh:
		if result.err != nil {
			_ = raw.Close()
		}
		return result.conn, result.err
	}
}

func (s *Server) acquireHandshakeWorker(slots chan struct{}, source string) bool {
	s.handshakeWorkerMu.Lock()
	defer s.handshakeWorkerMu.Unlock()
	if source != "" && s.maxHandshakeWorkersPerSource > 0 &&
		s.handshakeWorkersBySource[source] >= s.maxHandshakeWorkersPerSource {
		return false
	}
	select {
	case slots <- struct{}{}:
		if source != "" {
			if s.handshakeWorkersBySource == nil {
				s.handshakeWorkersBySource = make(map[string]int)
			}
			s.handshakeWorkersBySource[source]++
		}
		return true
	default:
		return false
	}
}

func (s *Server) releaseHandshakeWorker(slots chan struct{}, source string) {
	s.handshakeWorkerMu.Lock()
	<-slots
	if count := s.handshakeWorkersBySource[source]; count <= 1 {
		delete(s.handshakeWorkersBySource, source)
	} else {
		s.handshakeWorkersBySource[source] = count - 1
	}
	s.handshakeWorkerMu.Unlock()
}

func (s *Server) handleConnect(ctx context.Context, writer io.Writer, request *gosocks5.Request) (err error) {
	defer extension.Recover("SOCKS5 TLS stream handler", &err)
	clientConn, ok := writer.(net.Conn)
	if !ok {
		return errors.New("SOCKS5 stream is not a network connection")
	}
	if admitted, ok := clientConn.(interface{ finishAdmission() }); ok {
		admitted.finishAdmission()
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear SOCKS5 stream negotiation deadline: %w", err)
	}
	session, ok := s.authenticateRequest(request)
	if !ok {
		_ = gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
		return errors.New("SOCKS5 session is not active")
	}

	target, err := destinationFromRequest(request)
	if err != nil {
		_ = gosocks5.SendReply(writer, statute.RepAddrTypeNotSupported, nil)
		return err
	}
	flowCtx, cancel := context.WithCancel(ctx)
	reclaimDone, ok := s.acquireFlowReclaim()
	if !ok {
		cancel()
		_ = gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return errors.New("SOCKS5 TLS flow cleanup capacity reached")
	}
	flow := &streamFlow{cancel: cancel, client: clientConn, reclaimDone: reclaimDone, reclaim: s.reclaimConn}
	now, err := s.currentTime()
	if err != nil {
		flow.cancelFlow()
		defer s.reclaimFlow(flow)
		return err
	}
	if !s.trackCurrentFlow(session, flow, now) {
		flow.cancelFlow()
		defer s.reclaimFlow(flow)
		_ = gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
		return errors.New("SOCKS5 session was revoked")
	}
	defer s.trackFlow(session, flow, false)
	defer s.reclaimFlow(flow)

	s.serveMu.Lock()
	handler := s.streamHandler
	s.serveMu.Unlock()
	remote, err := handler.OpenStream(flowCtx, coretransport.StreamRequest{
		Session: session,
		Target:  target,
		Source:  clientConn.RemoteAddr(),
		Local:   clientConn.LocalAddr(),
	})
	if err != nil {
		if !extension.IsNil(remote) {
			s.reclaimConn(remote)
		}
		_ = gosocks5.SendReply(writer, replyForDialError(err), nil)
		return err
	}
	if extension.IsNil(remote) {
		_ = gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return errors.New("stream handler returned a nil connection")
	}
	if !flow.setTarget(remote) {
		return net.ErrClosed
	}
	if err := gosocks5.SendReply(writer, statute.RepSuccess, socksReplyAddr(remote.LocalAddr())); err != nil {
		return err
	}
	return coretransport.Relay(flowCtx, &bufferedConn{Conn: clientConn, reader: request.Reader}, remote)
}

func (s *Server) authenticateRequest(request *gosocks5.Request) (coretransport.SessionRef, bool) {
	if request == nil || request.AuthContext == nil || request.AuthContext.Method != statute.MethodUserPassAuth {
		return coretransport.SessionRef{}, false
	}
	payload := request.AuthContext.Payload
	clientIDText := payload[authClientIDKey]
	generationText := payload[authGenerationKey]
	clear(payload)
	request.AuthContext = nil
	clientID, err := strconv.ParseUint(clientIDText, 10, 64)
	if err != nil || clientID == 0 {
		return coretransport.SessionRef{}, false
	}
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 {
		return coretransport.SessionRef{}, false
	}
	session := coretransport.SessionRef{ClientID: clientID, Generation: generation}
	current, ok := s.registry.Current(clientID, s.now())
	return session, ok && current == session
}

func (s *Server) trackConn(conn net.Conn, add bool) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if add {
		if s.isClosed() {
			return false
		}
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
	return true
}

func (s *Server) trackFlow(session coretransport.SessionRef, flow *streamFlow, add bool) {
	s.connMu.Lock()
	if add {
		flows := s.flows[session]
		if flows == nil {
			flows = make(map[*streamFlow]struct{})
			s.flows[session] = flows
		}
		flows[flow] = struct{}{}
	} else if flows := s.flows[session]; flows != nil {
		delete(flows, flow)
		if len(flows) == 0 {
			delete(s.flows, session)
		}
	}
	s.connMu.Unlock()
}

func (s *Server) trackCurrentFlow(session coretransport.SessionRef, flow *streamFlow, now time.Time) bool {
	if s == nil || flow == nil {
		return false
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.isClosed() {
		return false
	}
	current, active := s.registry.Current(session.ClientID, now)
	if !active || current != session {
		return false
	}
	s.trackFlow(session, flow, true)
	return true
}

func (s *Server) closeSessionFlows(session coretransport.SessionRef) {
	s.reclaimFlows(s.detachSessionFlows(session))
}

func (s *Server) detachSessionFlows(session coretransport.SessionRef) []*streamFlow {
	s.connMu.Lock()
	flowsBySession := s.flows[session]
	flows := make([]*streamFlow, 0, len(flowsBySession))
	for flow := range flowsBySession {
		flows = append(flows, flow)
	}
	for _, flow := range flows {
		flow.cancelFlow()
	}
	delete(s.flows, session)
	s.connMu.Unlock()
	return flows
}

func (s *Server) reclaimFlows(flows []*streamFlow) {
	for _, flow := range flows {
		s.reclaimFlow(flow)
	}
}

func (s *Server) reclaimFlow(flow *streamFlow) {
	if flow == nil {
		return
	}
	flow.cancelFlow()
	flow.reclaimOnce.Do(func() {
		if flow.reclaimDone == nil {
			reclaimDone, ok := s.acquireFlowReclaim()
			if !ok {
				flow.close()
				return
			}
			flow.reclaimDone = reclaimDone
		}
		s.enqueueFlowReclaim(flowReclaimTask{flow: flow})
	})
}

func (s *Server) reclaimConn(conn net.Conn) {
	if extension.IsNil(conn) {
		return
	}
	reclaimDone, ok := s.acquireFlowReclaim()
	if !ok {
		_ = extension.Do("SOCKS5 TLS detached connection close", conn.Close)
		return
	}
	s.enqueueFlowReclaim(flowReclaimTask{conn: conn, reclaimDone: reclaimDone})
}

func (s *Server) acquireFlowReclaim() (func(), bool) {
	if s == nil {
		return nil, false
	}
	s.reclaimMu.Lock()
	defer s.reclaimMu.Unlock()
	if s.reclaimStopped {
		return nil, false
	}
	if s.reclaimQueue == nil {
		s.reclaimQueue = make(chan flowReclaimTask, defaultFlowReclaimQueue)
	}
	if s.reclaimSlots == nil {
		s.reclaimSlots = make(chan struct{}, cap(s.reclaimQueue))
	}
	select {
	case s.reclaimSlots <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() { <-s.reclaimSlots })
	}, true
}

func (s *Server) enqueueFlowReclaim(task flowReclaimTask) {
	if s == nil {
		return
	}
	s.reclaimMu.Lock()
	if s.reclaimStopped {
		s.reclaimMu.Unlock()
		task.run()
		return
	}
	if s.reclaimQueue == nil {
		s.reclaimQueue = make(chan flowReclaimTask, defaultFlowReclaimQueue)
	}
	if s.reclaimStop == nil {
		s.reclaimStop = make(chan struct{})
	}
	s.reclaimStart.Do(func() {
		for range defaultFlowReclaimWorkers {
			s.reclaimWG.Add(1)
			go func() {
				defer s.reclaimWG.Done()
				s.runFlowReclaimer()
			}()
		}
	})
	s.reclaimQueue <- task
	s.reclaimMu.Unlock()
}

func (s *Server) runFlowReclaimer() {
	for {
		select {
		case task := <-s.reclaimQueue:
			task.run()
		case <-s.reclaimStop:
			for {
				select {
				case task := <-s.reclaimQueue:
					task.run()
				default:
					return
				}
			}
		}
	}
}

func (s *Server) stopFlowReclaimer() {
	if s == nil {
		return
	}
	s.reclaimMu.Lock()
	if !s.reclaimStopped {
		s.reclaimStopped = true
		if s.reclaimStop != nil {
			close(s.reclaimStop)
		}
	}
	s.reclaimMu.Unlock()
}

func (task flowReclaimTask) run() {
	if task.reclaimDone != nil {
		defer task.reclaimDone()
	}
	if task.flow != nil {
		task.flow.close()
		return
	}
	if !extension.IsNil(task.conn) {
		_ = extension.Do("SOCKS5 TLS detached connection close", task.conn.Close)
	}
}

func (s *Server) scheduleSessionExpiry(session coretransport.SessionRef, expiresAt, now time.Time) bool {
	delay := expiresAt.Sub(now)
	if delay <= 0 {
		return false
	}
	s.connMu.Lock()
	select {
	case <-s.closed:
		s.connMu.Unlock()
		return false
	default:
	}
	timer := time.AfterFunc(delay, func() {
		if !s.startWorker() {
			return
		}
		defer s.wg.Done()
		_ = s.Revoke(context.Background(), session)
	})
	s.expiry[session] = timer
	s.connMu.Unlock()
	return true
}

func (s *Server) stopSessionExpiry(session coretransport.SessionRef) {
	s.connMu.Lock()
	timer := s.expiry[session]
	delete(s.expiry, session)
	s.connMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

func (s *Server) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Server) startWorker() bool {
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workersDone {
		return false
	}
	s.wg.Add(1)
	return true
}

func (s *Server) waitWorkers() {
	s.workerMu.Lock()
	s.workersDone = true
	s.workerMu.Unlock()
	s.wg.Wait()
	s.stopFlowReclaimer()
	s.reclaimWG.Wait()
}

func (f *streamFlow) setTarget(target net.Conn) bool {
	if f == nil || target == nil {
		return false
	}
	f.mu.Lock()
	if f.closed {
		reclaim := f.reclaim
		f.mu.Unlock()
		if reclaim != nil {
			reclaim(target)
		} else {
			_ = target.Close()
		}
		return false
	}
	f.target = target
	f.mu.Unlock()
	return true
}

func (f *streamFlow) close() {
	if f == nil {
		return
	}
	done := f.closeSignal()
	f.cancelFlow()
	if !f.closing.CompareAndSwap(false, true) {
		return
	}
	reclaimDone := f.reclaimDone
	defer func() {
		if reclaimDone != nil {
			reclaimDone()
		}
		close(done)
	}()
	f.mu.Lock()
	client := f.client
	target := f.target
	f.client = nil
	f.target = nil
	f.mu.Unlock()
	if client != nil {
		_ = extension.Do("SOCKS5 TLS client flow close", client.Close)
	}
	if target != nil {
		_ = extension.Do("SOCKS5 TLS target flow close", target.Close)
	}
}

func (f *streamFlow) closeSignal() chan struct{} {
	f.mu.Lock()
	if f.closeDone == nil {
		f.closeDone = make(chan struct{})
	}
	done := f.closeDone
	f.mu.Unlock()
	return done
}

func (f *streamFlow) cancelFlow() {
	if f == nil {
		return
	}
	f.cancelOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		cancel := f.cancel
		f.cancel = nil
		f.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
}

const (
	authClientIDKey   = "client_id"
	authGenerationKey = "session_generation"
)

type sessionAuthenticator struct {
	server *Server
}

func (a sessionAuthenticator) GetCode() uint8 { return statute.MethodUserPassAuth }

func (a sessionAuthenticator) Authenticate(reader io.Reader, writer io.Writer, _ string) (*gosocks5.AuthContext, error) {
	if _, err := writeAllCount(writer, []byte{statute.VersionSocks5, statute.MethodUserPassAuth}); err != nil {
		return nil, err
	}
	credentials, err := statute.ParseUserPassRequest(reader)
	defer clear(credentials.User)
	defer clear(credentials.Pass)
	if err != nil {
		return nil, err
	}
	var token [coretransport.DataTokenSize]byte
	clientID, ok := decodeCredentialsBytes(credentials.User, credentials.Pass, &token)
	defer clear(token[:])
	if !ok || a.server == nil {
		return nil, rejectCredentials(writer)
	}
	session, ok := a.server.registry.AuthenticateBytes(clientID, token[:], a.server.now())
	if !ok {
		return nil, rejectCredentials(writer)
	}
	if _, err := writeAllCount(writer, []byte{statute.UserPassAuthVersion, statute.AuthSuccess}); err != nil {
		return nil, err
	}
	return &gosocks5.AuthContext{
		Method: statute.MethodUserPassAuth,
		Payload: map[string]string{
			authClientIDKey:   strconv.FormatUint(session.ClientID, 10),
			authGenerationKey: strconv.FormatUint(session.Generation, 10),
		},
	}, nil
}

func rejectCredentials(writer io.Writer) error {
	if _, err := writeAllCount(writer, []byte{statute.UserPassAuthVersion, statute.AuthFailure}); err != nil {
		return err
	}
	return statute.ErrUserAuthFailed
}

func decodeCredentialsBytes(user, password []byte, token *[coretransport.DataTokenSize]byte) (uint64, bool) {
	if token == nil {
		return 0, false
	}
	clear(token[:])
	if len(password) != base64.RawURLEncoding.EncodedLen(len(token)) {
		return 0, false
	}
	clientID, err := strconv.ParseUint(string(user), 10, 64)
	if err != nil || clientID == 0 || string(user) != strconv.FormatUint(clientID, 10) {
		return 0, false
	}
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(password)))
	defer clear(raw)
	n, err := base64.RawURLEncoding.Strict().Decode(raw, password)
	if err != nil || n != len(token) {
		return 0, false
	}
	copy(token[:], raw[:n])
	return clientID, true
}

func destinationFromRequest(request *gosocks5.Request) (coretransport.Destination, error) {
	if request == nil || request.RawDestAddr == nil {
		return coretransport.Destination{}, errors.New("SOCKS5 destination is missing")
	}
	host := request.RawDestAddr.FQDN
	if host == "" && request.RawDestAddr.IP != nil {
		host = request.RawDestAddr.IP.String()
	}
	if request.RawDestAddr.Port <= 0 || request.RawDestAddr.Port > 65535 {
		return coretransport.Destination{}, errors.New("SOCKS5 destination port is invalid")
	}
	target := coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    host,
		Port:    uint16(request.RawDestAddr.Port),
	}
	return target, target.Validate()
}

func rejectUnsupportedCommand(_ context.Context, writer io.Writer, _ *gosocks5.Request) error {
	if err := gosocks5.SendReply(writer, statute.RepCommandNotSupported, nil); err != nil {
		return err
	}
	return errors.New("SOCKS5 command is not supported")
}

func replyForDialError(err error) uint8 {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "refused"):
		return statute.RepConnectionRefused
	case strings.Contains(message, "network is unreachable"):
		return statute.RepNetworkUnreachable
	default:
		return statute.RepHostUnreachable
	}
}

func socksReplyAddr(addr net.Addr) net.Addr {
	switch addr.(type) {
	case *net.TCPAddr, *net.UDPAddr:
		return addr
	default:
		return &net.TCPAddr{IP: net.IPv4zero}
	}
}

type noResolveResolver struct{}

func (noResolveResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	closeWrite, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	return closeWrite.CloseWrite()
}

var _ coretransport.Server = (*Server)(nil)
