// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/udptls"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
	"github.com/X-VPN/Talaria/transport/socks5tls"
)

const (
	defaultMTUBufferSize       = 64 * 1024
	defaultAuthTimeout         = 6 * time.Second
	defaultSessionIdleTimeout  = 2 * time.Minute
	defaultSessionWriteTimeout = 10 * time.Second
	maxServerAuthTimeout       = time.Minute
)

// Start validates cfg before allocating server resources or starting a listener.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	protocol, err := client.ParseProtocol(string(cfg.Protocol))
	if err != nil {
		return nil, fmt.Errorf("Talaria server: %w", err)
	}
	cfg.Protocol = protocol
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateBoundedOutboundConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.GetCertificate != nil || cfg.CacheGetCertificate || cfg.CachePureGetCertificate ||
		len(cfg.CertificateCacheScope) != 0 || cfg.AllowCertificateFallback {
		return nil, errors.New("Talaria server: dynamic certificate callbacks are not supported")
	}
	cfg = normalizeConfig(cfg)
	resourceLimits, err := normalizeResourceLimits(cfg.ResourceLimits)
	if err != nil {
		return nil, err
	}
	cfg.ResourceLimits = resourceLimits
	if !client.ProtocolSupportedOnCurrentPlatform(cfg.Protocol) {
		return nil, fmt.Errorf("Talaria server: protocol %s is not supported on this platform", cfg.Protocol)
	}
	if extension.IsNil(cfg.Auth) {
		return nil, errors.New("Talaria server: missing auth provider")
	}
	cfg.Auth, err = normalizeBoundedAuthProvider(cfg.Auth)
	if err != nil {
		return nil, err
	}
	if extension.IsNil(cfg.PacketHandler) {
		return nil, errors.New("Talaria server: missing packet handler")
	}
	needsCertificate := cfg.Protocol == client.ProtocolTalariaUDP || cfg.Transport == nil
	if needsCertificate && (cfg.CertPEM == "" || cfg.KeyPEM == "") {
		return nil, errors.New("Talaria server: missing certificate PEM")
	}
	if err := sealBoundedPacketHandler(cfg.PacketHandler); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	s := &Server{
		protocol:            cfg.Protocol,
		codec:               cfg.PacketCodec,
		auth:                cfg.Auth,
		handler:             cfg.PacketHandler,
		cancel:              cancel,
		logErr:              cfg.ErrorLog,
		errorLogs:           newErrorLogLimiter(0, 0),
		errorLogQueue:       make(chan serverErrorLog, defaultErrorLogQueue),
		errorLogStop:        make(chan struct{}),
		dial:                cfg.DialContext,
		ttl:                 cfg.SessionTTL,
		writeTimeout:        cfg.SessionWriteTimeout,
		forward:             cfg.ForwardHandler,
		policy:              cfg.TargetPolicy,
		resources:           newResourceLimiter(cfg.ResourceLimits),
		authSlots:           make(chan struct{}, cfg.ResourceLimits.MaxPendingAuth),
		outboundSlots:       make(chan struct{}, cfg.ResourceLimits.MaxPendingDials),
		boundedOutbound:     true,
		lookupIP:            cfg.LookupNetIP,
		closeDone:           make(chan struct{}),
		done:                make(chan struct{}),
		sessionReclaimQueue: make(chan sessionReclaimTask, cfg.ResourceLimits.MaxSessions*4),
		sessionReclaimSlots: make(chan struct{}, cfg.ResourceLimits.MaxSessions*4),
		sessionReclaimStop:  make(chan struct{}),
	}
	var startErr error
	switch cfg.Protocol {
	case client.ProtocolTalariaTCP:
		startErr = s.startTalariaTCP(runCtx, cfg)
	case client.ProtocolTalariaUDP:
		startErr = s.startTalariaUDP(runCtx, cfg)
	default:
		startErr = errors.New("Talaria server: unsupported normalized protocol")
	}
	if startErr != nil {
		_ = s.Close()
		return nil, startErr
	}
	s.runWG.Add(1)
	go func() {
		defer s.runWG.Done()
		<-runCtx.Done()
		_ = s.Close()
		<-s.closeDone
	}()
	go func() {
		s.runWG.Wait()
		s.waitSessionReclaimer()
		if handler, ok := s.handler.(*TunPacketHandler); ok {
			handler.waitWorkers()
		}
		s.waitErrorLogger()
		close(s.done)
	}()
	return s, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if extension.IsNil(cfg.PacketCodec) {
		cfg.PacketCodec = dataplane.WireCodec{}
	}
	if cfg.ReadBufferSize <= 0 {
		cfg.ReadBufferSize = defaultMTUBufferSize
	}
	if cfg.AuthTimeout <= 0 {
		cfg.AuthTimeout = defaultAuthTimeout
	}
	if cfg.SessionIdleTimeout <= 0 {
		cfg.SessionIdleTimeout = defaultSessionIdleTimeout
	}
	if cfg.SessionWriteTimeout <= 0 {
		cfg.SessionWriteTimeout = defaultSessionWriteTimeout
	}
	if cfg.DialContext == nil {
		dialer := &net.Dialer{}
		cfg.DialContext = dialer.DialContext
	}
	if cfg.LookupNetIP == nil {
		resolver := &net.Resolver{PreferGo: true}
		cfg.LookupNetIP = resolver.LookupNetIP
	}
	if extension.IsNil(cfg.TargetPolicy) {
		cfg.TargetPolicy = ReferenceTargetPolicy()
	}
	if extension.IsNil(cfg.ForwardHandler) {
		cfg.ForwardHandler = nil
	}
	if extension.IsNil(cfg.Transport) {
		cfg.Transport = nil
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if cfg.Port < 0 || cfg.Port > 65535 {
		return fmt.Errorf("Talaria server: invalid listen port %d", cfg.Port)
	}
	if cfg.ReadBufferSize < 0 {
		return errors.New("Talaria server: read buffer size cannot be negative")
	}
	if cfg.ReadBufferSize > maxServeReadBufferSize {
		return fmt.Errorf("Talaria server: read buffer size %d exceeds maximum %d", cfg.ReadBufferSize, maxServeReadBufferSize)
	}
	if cfg.AuthTimeout < 0 {
		return errors.New("Talaria server: auth timeout cannot be negative")
	}
	if cfg.AuthTimeout > maxServerAuthTimeout {
		return fmt.Errorf("Talaria server: auth timeout %s exceeds maximum %s", cfg.AuthTimeout, maxServerAuthTimeout)
	}
	if cfg.SessionIdleTimeout < 0 {
		return errors.New("Talaria server: session idle timeout cannot be negative")
	}
	if cfg.SessionWriteTimeout < 0 {
		return errors.New("Talaria server: session write timeout cannot be negative")
	}
	if cfg.SessionWriteTimeout > 5*time.Minute {
		return fmt.Errorf("Talaria server: session write timeout %s exceeds maximum %s", cfg.SessionWriteTimeout, 5*time.Minute)
	}
	if cfg.SessionTTL < 0 {
		return errors.New("Talaria server: session TTL cannot be negative")
	}
	return nil
}

func validateBoundedOutboundConfig(cfg Config) error {
	if !extension.IsNil(cfg.ForwardHandler) {
		return errors.New("Talaria server: ForwardHandler callbacks are not supported")
	}
	if cfg.LookupNetIP != nil {
		return errors.New("Talaria server: LookupNetIP callbacks are not supported")
	}
	if cfg.DialContext != nil {
		return errors.New("Talaria server: DialContext callbacks are not supported")
	}
	if !extension.IsNil(cfg.TargetPolicy) {
		if _, ok := cfg.TargetPolicy.(*referenceTargetPolicy); !ok {
			return errors.New("Talaria server: TargetPolicy must use NewReferenceTargetPolicy")
		}
	}
	return nil
}

func sealBoundedPacketHandler(handler PacketHandler) error {
	switch value := handler.(type) {
	case EchoPacketHandler:
		return nil
	case *EchoPacketHandler:
		if value != nil {
			return nil
		}
	case *TunPacketHandler:
		return value.sealBoundedPolicy()
	}
	return errors.New("Talaria server: PacketHandler must use EchoPacketHandler or TunPacketHandler")
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if !s.closeState.CompareAndSwap(0, 1) {
		if s.closeState.Load() != 2 {
			// A reentrant or concurrent Close must not wait for an external
			// callback that may be the caller itself.
			return nil
		}
		s.closeErrMu.Lock()
		err := s.closeErr
		s.closeErrMu.Unlock()
		return err
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.closeAllSessions("")
	var closeErr error
	if s.talariaUDPListener != nil {
		closeErr = errors.Join(closeErr, extension.Do("TalariaUDP listener close", s.talariaUDPListener.Close))
	}
	if s.streamServer != nil {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP transport close", s.streamServer.Close))
	}
	if closer, ok := s.handler.(interface{ Close() error }); ok {
		closeErr = errors.Join(closeErr, extension.Do("packet handler close", closer.Close))
	}
	s.stopErrorLogger()
	if s.done == nil {
		s.stopSessionReclaimer()
	}
	s.closeErrMu.Lock()
	s.closeErr = closeErr
	s.closeErrMu.Unlock()
	s.closeState.Store(2)
	if s.closeDone != nil {
		close(s.closeDone)
	}
	return closeErr
}

// Done closes after all listener and per-connection goroutines started by
// Server have exited. Close remains non-blocking; callers that need bounded
// shutdown should call Wait with their own deadline.
func (s *Server) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

// Wait waits for all goroutines owned by Server to exit.
func (s *Server) Wait(ctx context.Context) error {
	if s == nil || s.done == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	return s.addr
}

func (s *Server) Port() uint16 {
	return uint16(addrPortString(s.Addr()))
}

func (s *Server) startTalariaUDP(ctx context.Context, cfg Config) error {
	listenAddr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	maxPacket := dataplane.ConnReadBufferSize(dataplane.MaxMTU)
	if cfg.ReadBufferSize > maxPacket {
		cfg.ReadBufferSize = maxPacket
	}
	listener, err := udptls.NewListener(udptls.NewListenerReq{
		ListenAddr:      listenAddr,
		CertPEM:         cfg.CertPEM,
		KeyPEM:          cfg.KeyPEM,
		MaxPacket:       maxPacket,
		AdmissionLimits: cfg.TalariaUDPAdmissionLimits,
		WireSecret:      []byte(cfg.TalariaUDPWireSecret),
		WireIdentity:    cfg.TalariaUDPWireIdentity,
		WireProfile:     udptls.WireProfileSecure,
	})
	if err != nil {
		return err
	}
	s.talariaUDPListener = listener
	s.addr = listener.Addr().String()
	s.runWG.Add(1)
	go func() {
		defer s.runWG.Done()
		s.runTalariaUDPAcceptLoop(ctx, listener, cfg)
	}()
	return nil
}

type talariaUDPAcceptor interface {
	Accept(context.Context) (net.Conn, error)
}

func (s *Server) runTalariaUDPAcceptLoop(ctx context.Context, listener talariaUDPAcceptor, cfg Config) {
	for {
		var conn net.Conn
		acceptErr := extension.Do("TalariaUDP listener accept", func() error {
			var err error
			conn, err = listener.Accept(ctx)
			return err
		})
		if acceptErr != nil {
			if !extension.IsNil(conn) {
				_ = extension.Do("TalariaUDP failed accepted connection close", conn.Close)
			}
			s.logError("TalariaUDP accept", acceptErr)
			if !isExpectedClose(ctx, acceptErr) {
				_ = s.Close()
			}
			return
		}
		if extension.IsNil(conn) {
			s.logError("TalariaUDP accept", errors.New("TalariaUDP listener returned a nil connection"))
			_ = s.Close()
			return
		}
		s.runWG.Add(1)
		go func(conn net.Conn) {
			defer s.runWG.Done()
			err := s.ServePacketConn(ctx, conn, ServeOptions{
				Protocol:       cfg.Protocol,
				ReadBufferSize: cfg.ReadBufferSize,
				AuthTimeout:    cfg.AuthTimeout,
				IdleTimeout:    cfg.SessionIdleTimeout,
			})
			s.logError("TalariaUDP serve packet conn", err)
		}(conn)
	}
}

func (s *Server) startTalariaTCP(ctx context.Context, cfg Config) error {
	streamServer := cfg.Transport
	if streamServer == nil {
		var err error
		tlsConfig := &tls.Config{}
		if cfg.CertPEM != "" || cfg.KeyPEM != "" {
			certificate, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
			if err != nil {
				return fmt.Errorf("load TalariaTCP certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
		streamServer, err = socks5tls.NewServer(socks5tls.ServerConfig{
			Listen:          net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
			AdmissionLimits: cfg.TalariaTCPAdmissionLimits,
			TLSConfig:       tlsConfig,
			WireIdentity:    cfg.TalariaTCPWireIdentity,
			WireSecret:      []byte(cfg.TalariaTCPWireSecret),
		})
		if err != nil {
			return err
		}
	}
	s.streamServer = streamServer
	var transportAddr net.Addr
	if err := extension.Do("TalariaTCP transport address", func() error {
		transportAddr = streamServer.Addr()
		return nil
	}); err != nil {
		return err
	}
	if extension.IsNil(transportAddr) {
		return errors.New("Talaria server: transport has no listen address")
	}
	stagedTransport, ok := streamServer.(coretransport.StagedServer)
	if !ok {
		return errors.New("Talaria server: TalariaTCP transport does not support staged session activation")
	}
	var transportAddress string
	if err := extension.Run("TalariaTCP transport address string", func() {
		transportAddress = transportAddr.String()
	}); err != nil {
		return err
	}
	s.addr = transportAddress
	sessions := &streamControlSessions{server: s, transport: stagedTransport}
	s.runWG.Add(1)
	go func() {
		defer s.runWG.Done()
		err := extension.Do("TalariaTCP transport serve", func() error {
			return streamServer.Serve(ctx,
				coretransport.ControlHandlerFunc(func(controlCtx context.Context, conn net.Conn) error {
					return s.ServeControlConn(controlCtx, conn, ServeOptions{
						Protocol:       cfg.Protocol,
						ReadBufferSize: cfg.ReadBufferSize,
						AuthTimeout:    cfg.AuthTimeout,
						IdleTimeout:    cfg.SessionIdleTimeout,
						Sessions:       sessions,
					})
				}),
				coretransport.StreamHandlerFunc(s.openStream),
			)
		})
		s.logError("TalariaTCP transport serve", err)
		_ = s.Close()
	}()
	return nil
}

func (s *Server) openStream(ctx context.Context, req coretransport.StreamRequest) (conn net.Conn, err error) {
	defer s.recoverExtensionPanic("stream request", &err)
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.getActiveSessions().awaitCurrent(ctx, req.Session) {
		return nil, errors.New("stream session is not current")
	}
	lease, err := s.resources.acquireStream(req.Session.ClientID)
	if err != nil {
		return nil, err
	}
	releaseLease := true
	defer func() {
		if releaseLease {
			lease.release()
		}
	}()
	operationCtx, cancelOperation := context.WithTimeout(ctx, s.resources.dialTimeout())
	defer cancelOperation()
	target := req.Target
	session := SessionContext{
		Protocol:   s.protocol,
		ClientID:   req.Session.ClientID,
		Generation: req.Session.Generation,
		RemoteAddr: addrString(req.Source),
		RemoteIP:   hostFromAddr(req.Source),
		LocalAddr:  addrString(req.Local),
	}
	if s.forward != nil {
		decision, err := callBoundedExtension(operationCtx, s.outboundSlots, s.resources, session.ClientID, "Talaria forward handler", func() (ForwardDecision, error) {
			return s.forward.Forward(operationCtx, ForwardRequest{
				Session: session,
				Target:  target,
				Source:  req.Source,
				Local:   req.Local,
			})
		}, nil)
		if err != nil {
			return nil, err
		}
		if decision.Block {
			return nil, errors.New("stream target is blocked")
		}
		if decision.Target.Host != "" || decision.Target.Port != 0 || decision.Target.Network != "" {
			target = decision.Target
		}
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if !s.getActiveSessions().isCurrent(req.Session) {
		return nil, errors.New("stream session was replaced before policy evaluation")
	}
	addresses, err := s.resolveStreamTarget(operationCtx, session, target, req.Local)
	if err != nil {
		return nil, err
	}
	conn, err = s.dialResolvedTarget(operationCtx, session.ClientID, target, addresses)
	lease.dialDone()
	if err != nil {
		return nil, err
	}
	if extension.IsNil(conn) {
		return nil, errors.New("Talaria server: outbound dial returned a nil connection")
	}
	if operationCtx.Err() != nil || !s.getActiveSessions().isCurrent(req.Session) {
		_ = extension.Do("Talaria server stale outbound connection close", conn.Close)
		if operationCtx.Err() != nil {
			return nil, operationCtx.Err()
		}
		return nil, errors.New("stream session was replaced during outbound dial")
	}
	releaseLease = false
	return &resourceLimitedConn{Conn: conn, release: lease.release}, nil
}

type boundedExtensionResult[T any] struct {
	value   T
	err     error
	release func()
}

func callBoundedExtension[T any](ctx context.Context, slots chan struct{}, resources *resourceLimiter, clientID uint64, scope string, call func() (T, error), discard func(T)) (T, error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if slots == nil {
		slots = defaultOutboundCallbackSlots
	}
	var releaseWorker func()
	var ok bool
	if resources != nil && clientID != 0 {
		releaseWorker, ok = resources.acquireOutboundWorker(clientID, slots)
	} else {
		select {
		case slots <- struct{}{}:
			releaseWorker = func() { <-slots }
			ok = true
		default:
		}
	}
	if !ok {
		return zero, errResourceLimit
	}
	discardResult := func(value T) {
		if discard != nil {
			_ = extension.Run(scope+" discarded result", func() { discard(value) })
		}
	}
	resultCh := make(chan boundedExtensionResult[T])
	go func() {
		var value T
		err := extension.Do(scope, func() error {
			var callbackErr error
			value, callbackErr = call()
			return callbackErr
		})
		select {
		case resultCh <- boundedExtensionResult[T]{value: value, err: err, release: releaseWorker}:
		case <-ctx.Done():
			defer releaseWorker()
			discardResult(value)
		}
	}()
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case result := <-resultCh:
		defer result.release()
		if err := ctx.Err(); err != nil {
			discardResult(result.value)
			return zero, err
		}
		if result.err != nil && discard != nil {
			discardResult(result.value)
			return zero, result.err
		}
		return result.value, result.err
	}
}

var defaultOutboundCallbackSlots = make(chan struct{}, defaultMaxPendingDials)

type streamControlSessions struct {
	server    *Server
	transport coretransport.StagedServer
}

func (s *streamControlSessions) ActivateControlSession(ctx context.Context, conn net.Conn, session SessionContext, write PacketWriter, onRevoke func()) (func() error, func() error, func(), error) {
	return s.activateControlSession(ctx, conn, session, write, nil, onRevoke)
}

func (s *streamControlSessions) activateControlSession(ctx context.Context, conn net.Conn, session SessionContext, write PacketWriter, cancelData, revokeData func()) (func() error, func() error, func(), error) {
	if s == nil || s.server == nil || s.transport == nil {
		return nil, nil, nil, net.ErrClosed
	}
	if write == nil {
		return nil, nil, nil, errors.New("Talaria server: control session writer is required")
	}
	if session.Generation == 0 {
		return nil, nil, nil, errors.New("Talaria server: control session generation is required")
	}
	grant, err := coretransport.NewSessionGrant(session.ClientID, session.Generation, time.Now(), s.server.ttl)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(grant.DataToken[:])
	ref := grant.SessionRef
	var transportPrepared atomic.Bool
	var transportRevoked atomic.Bool
	revokeTransport := func(scope string) error {
		if !transportRevoked.CompareAndSwap(false, true) {
			return nil
		}
		return extension.Do(scope, func() error {
			return s.transport.Revoke(context.Background(), ref)
		})
	}
	cancelSessionData := func() {
		if cancelData != nil {
			if err := extension.Run("TalariaTCP control session cancel", cancelData); err != nil {
				s.server.logError("TalariaTCP control session cancel", err)
			}
		}
		if transportPrepared.Load() {
			if err := revokeTransport("TalariaTCP transport revoke session"); err != nil {
				s.server.logError("TalariaTCP transport revoke session", err)
			}
		}
	}
	var cleanupSessionData func()
	if revokeData != nil {
		cleanupSessionData = func() {
			if err := extension.Run("TalariaTCP control session revoke", revokeData); err != nil {
				s.server.logError("TalariaTCP control session revoke", err)
			}
		}
	}
	unlockSession := s.server.sessionLocks.lock(session.ClientID)
	resourceLease, err := s.server.resources.acquireSession(session.ClientID)
	if err != nil {
		unlockSession()
		return nil, nil, nil, err
	}
	binding, err := s.server.prepareSession(activeServerSessionConfig{
		Ref:        ref,
		Context:    session,
		Conn:       conn,
		Write:      write,
		Resources:  resourceLease,
		ExpiresAt:  grant.ExpiresAt,
		CancelData: cancelSessionData,
		RevokeData: cleanupSessionData,
	})
	if err != nil {
		resourceLease.rollback()
		unlockSession()
		return nil, nil, nil, err
	}
	releaseBinding := true
	defer func() {
		if releaseBinding {
			s.server.releaseSession(binding)
		}
	}()
	unlockSession()
	prepareErr := extension.Do("TalariaTCP transport prepare session", func() error {
		return s.transport.Prepare(ctx, grant)
	})
	if prepareErr != nil {
		rollbackErr := revokeTransport("TalariaTCP transport revoke failed preparation")
		return nil, nil, nil, errors.Join(prepareErr, rollbackErr)
	}
	transportPrepared.Store(true)
	if binding.closed.Load() || !s.server.getActiveSessions().isPending(ref) {
		_ = revokeTransport("TalariaTCP transport revoke abandoned session")
		return nil, nil, nil, errors.New("Talaria server: session was revoked while preparing the TalariaTCP transport")
	}
	expiresAtUnix := int64(0)
	if !grant.ExpiresAt.IsZero() {
		expiresAtUnix = grant.ExpiresAt.Unix()
	}
	token := append([]byte(nil), grant.DataToken[:]...)
	defer clear(token)
	writeErr := write(&vpnpacket.VpnPacket{
		Cmd:               vpnpacket.CmdSessionGrant,
		ClientId:          grant.ClientID,
		SessionGeneration: grant.Generation,
		SessionExpiresAt:  expiresAtUnix,
		SessionDataToken:  token,
	})
	if writeErr != nil {
		return nil, nil, nil, writeErr
	}
	commit := func() error {
		if err := extension.Do("TalariaTCP transport commit session", func() error {
			return s.transport.Commit(ctx, ref)
		}); err != nil {
			return err
		}
		if err := s.server.commitSession(binding); err != nil {
			_ = revokeTransport("TalariaTCP transport rollback session")
			return err
		}
		return nil
	}
	finalize := func() error {
		if err := extension.Do("TalariaTCP transport finalize session", func() error {
			return s.transport.Finalize(ctx, ref)
		}); err != nil {
			return err
		}
		if err := s.server.finalizeSession(binding); err != nil {
			s.server.RevokeClient(ref.ClientID, peerSessionSetupErrorMessage)
			return err
		}
		return nil
	}
	releaseBinding = false
	return commit, finalize, func() {
		s.server.releaseSession(binding)
	}, nil
}

func (s *Server) logError(scope string, err error) {
	if s == nil || s.logErr == nil || err == nil {
		return
	}
	if s.cancel == nil && errors.Is(err, net.ErrClosed) {
		return
	}
	suppressed, allowed := s.errorLogs.admit(scope, time.Now())
	if suppressed > 0 {
		s.enqueueErrorLog(scope, fmt.Errorf("suppressed %d repeated errors in the previous interval", suppressed))
	}
	if !allowed {
		return
	}
	s.enqueueErrorLog(scope, err)
}

func writePacket(codec dataplane.Codec, conn net.Conn, packet *vpnpacket.VpnPacket) error {
	raw, err := codec.Encode(packet)
	if err != nil {
		return err
	}
	return writeConnFrame(conn, raw)
}

func writeErr(codec dataplane.Codec, conn net.Conn, msg string) error {
	return writePacket(codec, conn, &vpnpacket.VpnPacket{
		Cmd:          vpnpacket.CmdErr,
		ErrorMessage: msg,
	})
}

func writeAuthenticationError(codec dataplane.Codec, conn net.Conn) error {
	return writeErr(codec, conn, errAuthenticationFailed.Error())
}

func addrPortString(addr string) int {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0
	}
	return port
}
