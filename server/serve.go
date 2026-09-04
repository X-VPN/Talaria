// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

type ServeOptions struct {
	Protocol       client.Protocol
	ReadBufferSize int
	AuthTimeout    time.Duration
	IdleTimeout    time.Duration
	Sessions       ControlSessionActivator
}

const (
	connReadBatchNoProgressLimit          = 32
	connReadBatchNoProgressInitialBackoff = 100 * time.Microsecond
	connReadBatchNoProgressMaxBackoff     = 2 * time.Millisecond
	maxAuthCredentialBytes                = 255
	maxServeReadBufferSize                = 1 << 20
	maxServePacketBatchSize               = 256
	maxServePacketBatchBytes              = 16 << 20
	peerSessionSetupErrorMessage          = "session setup failed"
	peerPacketHandlingErrorMessage        = "packet handling failed"
	maxPacketHandlerResponses             = 64
	maxPacketHandlerResponseBytes         = 1 << 20
)

var (
	errAuthenticationFailed    = errors.New("authentication failed")
	errAuthenticationRateLimit = errors.New("authentication rate limit reached")
	defaultAuthProviderSlots   = make(chan struct{}, defaultMaxPendingAuth)
)

type packetBatchReader interface {
	net.Conn
	BatchSize() int
	ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error)
}

type packetBatchBufferBudget interface {
	ReservePacketReadBufferBytes(int64) (func(), error)
}

type rawFrameHandlerResult struct {
	handled   bool
	responses []*vpnpacket.VpnPacket
}

func packetHandlerCallsAreBounded(handler PacketHandler) bool {
	switch handler.(type) {
	case EchoPacketHandler, *EchoPacketHandler, *TunPacketHandler:
		return true
	default:
		return false
	}
}

func normalizeServeOptions(opt ServeOptions, protocol client.Protocol, defaultReadBufferSize int) (ServeOptions, error) {
	if opt.Protocol == "" {
		opt.Protocol = protocol
	}
	normalizedProtocol, err := client.ParseProtocol(string(opt.Protocol))
	if err != nil {
		return ServeOptions{}, fmt.Errorf("Talaria server: %w", err)
	}
	opt.Protocol = normalizedProtocol
	if opt.ReadBufferSize < 0 {
		return ServeOptions{}, errors.New("Talaria server: read buffer size cannot be negative")
	}
	if opt.ReadBufferSize > maxServeReadBufferSize {
		return ServeOptions{}, fmt.Errorf("Talaria server: read buffer size %d exceeds maximum %d", opt.ReadBufferSize, maxServeReadBufferSize)
	}
	if opt.AuthTimeout < 0 {
		return ServeOptions{}, errors.New("Talaria server: auth timeout cannot be negative")
	}
	if opt.AuthTimeout > maxServerAuthTimeout {
		return ServeOptions{}, fmt.Errorf("Talaria server: auth timeout %s exceeds maximum %s", opt.AuthTimeout, maxServerAuthTimeout)
	}
	if opt.IdleTimeout < 0 {
		return ServeOptions{}, errors.New("Talaria server: session idle timeout cannot be negative")
	}
	if opt.ReadBufferSize == 0 {
		opt.ReadBufferSize = defaultReadBufferSize
	}
	if opt.AuthTimeout == 0 {
		opt.AuthTimeout = defaultAuthTimeout
	}
	if opt.IdleTimeout == 0 {
		opt.IdleTimeout = defaultSessionIdleTimeout
	}
	return opt, nil
}

func (s *Server) ServePacketConn(ctx context.Context, conn net.Conn, opt ServeOptions) (err error) {
	defer s.recoverExtensionPanic("packet session", &err)
	if s == nil {
		return net.ErrClosed
	}
	if extension.IsNil(conn) {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opt, err = normalizeServeOptions(opt, s.protocol, defaultMTUBufferSize)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopCloseOnContext := closeOnContext(ctx, conn)
	defer stopCloseOnContext()

	var pendingAuthLease *pendingAuthResourceLease
	if s.resources != nil {
		pendingAuthLease, err = s.resources.acquirePendingAuth(hostFromAddr(conn.RemoteAddr()))
		if err != nil {
			return err
		}
		defer pendingAuthLease.release()
	}
	setTalariaUDPPreAuthMode(conn, true)
	session, err := s.authenticatePacketConn(ctx, conn, opt)
	setTalariaUDPPreAuthMode(conn, false)
	pendingAuthLease.release()
	if err != nil {
		if shouldWriteAuthenticationError(err) {
			_ = s.writeAuthenticationError(conn, opt.AuthTimeout)
		}
		return err
	}
	batchConn, batchSize, err := preparePacketBatch(conn, opt)
	if err != nil {
		_ = writeErr(s.codec, conn, peerSessionSetupErrorMessage)
		return err
	}
	session.Generation = s.sessionGeneration.Add(1)
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	unlockSession := s.sessionLocks.lock(session.ClientID)
	var resourceLease *sessionResourceLease
	if s.resources != nil {
		resourceLease, err = s.resources.acquireSession(session.ClientID)
		if err != nil {
			unlockSession()
			_ = writeErr(s.codec, conn, peerSessionSetupErrorMessage)
			return err
		}
	}
	writers := s.newSessionWriters(sessionCtx, conn)
	writerGate, handlerWriters := newSessionWriterGate(writers, func() bool {
		return s.getActiveSessions().isCurrent(session.Ref())
	}, session.ClientID)
	responseWriters := writerGate.responseWriters(handlerWriters)
	writeSessionPacket := writers.Packet
	detachGuard := newSessionDetachGuard()
	defer detachGuard.detachNow()
	var expiresAt time.Time
	if s.ttl > 0 {
		expiresAt = time.Now().Add(s.ttl)
	}
	binding, err := s.prepareSession(activeServerSessionConfig{
		Ref:       session.Ref(),
		Context:   session,
		Conn:      conn,
		Write:     writeSessionPacket,
		Resources: resourceLease,
		ExpiresAt: expiresAt,
		CancelData: func() {
			cancelSession()
			detachGuard.revoke()
		},
	})
	if err != nil {
		resourceLease.rollback()
		unlockSession()
		_ = writeErr(s.codec, conn, peerSessionSetupErrorMessage)
		return err
	}
	unlockSession()
	defer s.releaseSession(binding)
	attachCtx, cancelAttach := context.WithTimeout(sessionCtx, opt.AuthTimeout)
	detach, attachErr := s.attachPacketSession(attachCtx, sessionCtx, session, handlerWriters)
	cancelAttach()
	if attachErr != nil {
		_ = writeErr(s.codec, conn, peerSessionSetupErrorMessage)
		return attachErr
	}
	detachGuard.setDetach(detach)
	if err := s.commitSession(binding); err != nil {
		return err
	}
	if err := s.finalizeSession(binding); err != nil {
		return err
	}
	if !s.beginSessionReady(session.Ref()) {
		return errors.New("Talaria server: packet session was revoked before readiness")
	}
	if err := writerGate.markReady(session.ClientID); err != nil {
		return err
	}
	if !s.markSessionReady(session.Ref()) {
		return errors.New("Talaria server: packet session was revoked before readiness")
	}
	if batchConn != nil {
		return s.servePacketBatchDataLoop(sessionCtx, batchConn, batchSize, opt, session, responseWriters)
	}
	return s.servePacketDataLoop(sessionCtx, conn, opt, session, responseWriters)
}

func (s *Server) ServeControlConn(ctx context.Context, conn net.Conn, opt ServeOptions) (err error) {
	defer s.recoverExtensionPanic("control session", &err)
	if s == nil {
		return net.ErrClosed
	}
	if extension.IsNil(conn) {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opt, err = normalizeServeOptions(opt, s.protocol, 2048)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopCloseOnContext := closeOnContext(ctx, conn)
	defer stopCloseOnContext()

	var pendingAuthLease *pendingAuthResourceLease
	if s.resources != nil {
		pendingAuthLease, err = s.resources.acquirePendingAuth(hostFromAddr(conn.RemoteAddr()))
		if err != nil {
			return err
		}
		defer pendingAuthLease.release()
	}
	session, err := s.authenticateControlConn(ctx, conn, opt)
	pendingAuthLease.release()
	if err != nil {
		if shouldWriteAuthenticationError(err) {
			_ = s.writeAuthenticationError(conn, opt.AuthTimeout)
		}
		return err
	}
	session.Generation = s.sessionGeneration.Add(1)
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	writers := s.newSessionWriters(sessionCtx, conn)
	writerGate, handlerWriters := newSessionWriterGate(writers, func() bool {
		return s.getActiveSessions().isCurrent(session.Ref())
	}, session.ClientID)
	responseWriters := writerGate.responseWriters(handlerWriters)
	writeSessionPacket := writers.Packet
	if bindConn, ok := conn.(interface{ BindClientID(uint64) error }); ok {
		if err := bindConn.BindClientID(session.ClientID); err != nil {
			return err
		}
	}
	detachGuard := newSessionDetachGuard()
	defer detachGuard.detachNow()
	onRevoke := func() {
		detachGuard.revoke()
	}
	var commit func() error
	var finalize func() error
	if opt.Sessions != nil {
		var revoke func()
		if sessions, ok := opt.Sessions.(*streamControlSessions); ok {
			commit, finalize, revoke, err = sessions.activateControlSession(
				sessionCtx, conn, session, writeSessionPacket, func() {
					cancelSession()
					onRevoke()
				}, nil,
			)
		} else {
			commit, finalize, revoke, err = opt.Sessions.ActivateControlSession(sessionCtx, conn, session, writeSessionPacket, func() {
				cancelSession()
				onRevoke()
			})
		}
		if revoke != nil {
			revokeCallback := revoke
			revoke = onceFunc(func() {
				if callbackErr := extension.Run("control session activator revoke", revokeCallback); callbackErr != nil {
					s.logError("control session activator revoke", callbackErr)
				}
			})
		}
		if err != nil {
			if revoke != nil {
				revoke()
			}
			_ = writeSessionPacket(peerErrorPacket(peerSessionSetupErrorMessage))
			return err
		}
		if revoke != nil {
			defer revoke()
		}
	} else {
		// Without an activator nothing else registers this session, so register
		// it here. Otherwise the control session would be invisible to
		// RevokeClient and RevokeSession while still carrying packet traffic.
		unlockSession := s.sessionLocks.lock(session.ClientID)
		var resourceLease *sessionResourceLease
		if s.resources != nil {
			resourceLease, err = s.resources.acquireSession(session.ClientID)
			if err != nil {
				unlockSession()
				_ = writeSessionPacket(peerErrorPacket(peerSessionSetupErrorMessage))
				return err
			}
		}
		var expiresAt time.Time
		if s.ttl > 0 {
			expiresAt = time.Now().Add(s.ttl)
		}
		binding, activateErr := s.prepareSession(activeServerSessionConfig{
			Ref:       session.Ref(),
			Context:   session,
			Conn:      conn,
			Write:     writeSessionPacket,
			Resources: resourceLease,
			ExpiresAt: expiresAt,
			CancelData: func() {
				cancelSession()
				onRevoke()
			},
		})
		if activateErr != nil {
			err = activateErr
			resourceLease.rollback()
			unlockSession()
			_ = writeSessionPacket(peerErrorPacket(peerSessionSetupErrorMessage))
			return err
		}
		unlockSession()
		defer s.releaseSession(binding)
		commit = func() error { return s.commitSession(binding) }
		finalize = func() error { return s.finalizeSession(binding) }
	}
	attachCtx, cancelAttach := context.WithTimeout(sessionCtx, opt.AuthTimeout)
	detach, attachErr := s.attachPacketSession(attachCtx, sessionCtx, session, handlerWriters)
	cancelAttach()
	if attachErr != nil {
		_ = writeSessionPacket(peerErrorPacket(peerSessionSetupErrorMessage))
		return attachErr
	}
	detachGuard.setDetach(detach)
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}
	if finalize != nil {
		if err := finalize(); err != nil {
			return err
		}
	}
	if !s.beginSessionReady(session.Ref()) {
		return errors.New("Talaria server: control session was revoked before readiness")
	}
	if err := writerGate.markReady(session.ClientID); err != nil {
		return err
	}
	if !s.markSessionReady(session.Ref()) {
		return errors.New("Talaria server: control session was revoked before readiness")
	}

	buf := make([]byte, opt.ReadBufferSize)
	defer conn.SetReadDeadline(time.Time{})
	for {
		if err := conn.SetReadDeadline(time.Now().Add(opt.IdleTimeout)); err != nil {
			if isExpectedClose(sessionCtx, err) {
				return nil
			}
			return fmt.Errorf("Talaria server: set control idle deadline: %w", err)
		}
		n, err := readConnFrame(conn, buf)
		if err != nil {
			if isExpectedClose(sessionCtx, err) {
				return nil
			}
			return err
		}
		packet, _, err := s.codec.Decode(buf[:n])
		if err != nil {
			return fmt.Errorf("Talaria server: decode control packet: %w", err)
		}
		if packet.Cmd == vpnpacket.CmdClientClose {
			return nil
		}
		if err := s.handleAndWriteResponsesWithWriters(sessionCtx, responseWriters, session, packet); err != nil {
			return err
		}
	}
}

func (s *Server) newSessionWriters(ctx context.Context, conn net.Conn) SessionWriters {
	writeMu := new(sync.Mutex)
	writeTimeout := s.writeTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultSessionWriteTimeout
	}
	useWriteDeadline := s.protocol == client.ProtocolTalariaTCP
	write := func(fn func() error) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if useWriteDeadline {
			if err := extension.Do("Talaria server session write deadline", func() error {
				return conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			}); err != nil {
				return err
			}
			writeErr := extension.Do("Talaria server session connection write", fn)
			resetErr := extension.Do("Talaria server session write deadline reset", func() error {
				return conn.SetWriteDeadline(time.Time{})
			})
			if writeErr == nil && isExpectedClose(ctx, resetErr) {
				resetErr = nil
			}
			return errors.Join(writeErr, resetErr)
		}
		return extension.Do("Talaria server session connection write", fn)
	}
	packetWriter := func(packet *vpnpacket.VpnPacket) error {
		var raw []byte
		err := extension.Do("Talaria server session packet encode", func() error {
			var encodeErr error
			raw, encodeErr = s.codec.Encode(packet)
			return encodeErr
		})
		if err != nil {
			return err
		}
		if len(raw) > maxPacketHandlerResponseBytes {
			return fmt.Errorf("Talaria server: encoded session packet exceeds %d bytes", maxPacketHandlerResponseBytes)
		}
		return write(func() error {
			return writeConnFrame(conn, raw)
		})
	}
	rawWriter := func(raw []byte) error {
		if len(raw) == 0 {
			return nil
		}
		return write(func() error {
			return writeConnFrame(conn, raw)
		})
	}
	rawBatchWriter := func(bufs [][]byte, sizes []int) (int, error) {
		var written int
		err := write(func() error {
			var err error
			written, err = writeRawPacketBatch(ctx, conn, bufs, sizes)
			return err
		})
		return written, err
	}
	return SessionWriters{
		Packet:   packetWriter,
		Raw:      rawWriter,
		RawBatch: rawBatchWriter,
		Close: func() {
			_ = extension.Do("Talaria server session connection close", func() error {
				return conn.Close()
			})
		},
	}
}

type sessionWriterGate struct {
	open     atomic.Bool
	writers  SessionWriters
	current  func() bool
	clientID uint64
}

// newSessionWriterGate drops handler output until the server commits SessionReady.
func newSessionWriterGate(writers SessionWriters, current func() bool, clientID uint64) (*sessionWriterGate, SessionWriters) {
	gate := &sessionWriterGate{writers: writers, current: current, clientID: clientID}
	return gate, SessionWriters{
		Packet: func(packet *vpnpacket.VpnPacket) error {
			if !gate.canWrite() {
				return nil
			}
			if packet == nil {
				return errors.New("Talaria server: packet handler wrote a nil packet")
			}
			if !allowedServerResponseCommand(packet.Cmd) {
				return fmt.Errorf("Talaria server: packet handler output command %d is not allowed", packet.Cmd)
			}
			normalizeServerResponse(packet, gate.clientID)
			if err := validatePacketHandlerPayloadSize(packet, maxPacketHandlerResponseBytes); err != nil {
				return err
			}
			return writers.Packet(packet)
		},
		Raw: func(raw []byte) error {
			if !gate.canWrite() {
				return nil
			}
			if err := normalizeHandlerRawOutput(raw, gate.clientID); err != nil {
				return err
			}
			return writers.Raw(raw)
		},
		RawBatch: func(bufs [][]byte, sizes []int) (int, error) {
			if !gate.canWrite() {
				return len(bufs), nil
			}
			if len(bufs) > maxServePacketBatchSize || len(sizes) < len(bufs) {
				return 0, errors.New("Talaria server: packet handler raw batch is invalid")
			}
			totalBytes := 0
			for i := range bufs {
				if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
					return 0, fmt.Errorf("Talaria server: packet handler raw batch size %d is invalid", sizes[i])
				}
				if sizes[i] > maxServePacketBatchBytes-totalBytes {
					return 0, fmt.Errorf("Talaria server: packet handler raw batch exceeds %d bytes", maxServePacketBatchBytes)
				}
				if err := normalizeHandlerRawOutput(bufs[i][:sizes[i]], gate.clientID); err != nil {
					return 0, err
				}
				totalBytes += sizes[i]
			}
			return writers.RawBatch(bufs, sizes)
		},
		Close: writers.Close,
	}
}

func (g *sessionWriterGate) responseWriters(handlerWriters SessionWriters) SessionWriters {
	writers := SessionWriters{Packet: handlerWriters.Packet}
	if g != nil && g.writers.Raw != nil {
		writers.Raw = g.writeEncodedResponse
	}
	return writers
}

func (g *sessionWriterGate) writeEncodedResponse(raw []byte) error {
	if !g.canWrite() {
		return nil
	}
	return g.writers.Raw(raw)
}

func normalizeHandlerRawOutput(raw []byte, clientID uint64) error {
	if len(raw) > maxPacketHandlerResponseBytes {
		return fmt.Errorf("Talaria server: packet handler raw output exceeds %d bytes", maxPacketHandlerResponseBytes)
	}
	if len(raw) < 9 {
		return errors.New("Talaria server: packet handler raw output is truncated")
	}
	cmd := raw[8]
	switch {
	case cmd == vpnpacket.CmdData || cmd == vpnpacket.CmdDataReturn:
		if len(raw) < vpnpacket.RawCmdDataHeaderLen() {
			return errors.New("Talaria server: packet handler raw data output is truncated")
		}
	case vpnpacket.IsFixedV4DataWireCmd(cmd):
		if len(raw) < vpnpacket.FixedV4PayloadOffset() {
			return errors.New("Talaria server: packet handler fixed-v4 output is truncated")
		}
	default:
		return fmt.Errorf("Talaria server: packet handler raw output command %d is not allowed", cmd)
	}
	binary.LittleEndian.PutUint64(raw[:8], clientID)
	return nil
}

func (g *sessionWriterGate) canWrite() bool {
	return g != nil && g.open.Load() && (g.current == nil || g.current())
}

// markReady commits the final readiness barrier before enabling handler output.
func (g *sessionWriterGate) markReady(clientID uint64) error {
	if g == nil || g.writers.Packet == nil {
		return errors.New("Talaria server: session writer is unavailable")
	}
	if err := g.writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdSessionReady, ClientId: clientID}); err != nil {
		return err
	}
	g.open.Store(true)
	return nil
}

func (s *Server) attachPacketSession(attachCtx, sessionCtx context.Context, session SessionContext, writers SessionWriters) (func(), error) {
	if attachCtx == nil {
		attachCtx = context.Background()
	}
	if sessionCtx == nil {
		sessionCtx = context.Background()
	}
	ref := session.Ref()
	if !s.getActiveSessions().isPending(ref) {
		return nil, errors.New("Talaria server: packet session is not pending")
	}
	reclaimDone, ok := s.acquireSessionReclaim()
	if !ok {
		return nil, errResourceLimit
	}
	reclaimOwned := true
	defer func() {
		if reclaimOwned {
			reclaimDone()
		}
	}()

	detach, releaseWorker, err := s.callPacketSessionAttach(attachCtx, sessionCtx, session, writers)
	if releaseWorker != nil {
		releaseWorker()
	}
	if detach != nil {
		switch handler := s.handler.(type) {
		case *TunPacketHandler:
			detach = onceFunc(func() {
				s.reclaimOwnedSession(handler.detachSessionRefForReclaim(ref), reclaimDone)
			})
		default:
			detachCallback := detach
			detach = onceFunc(func() {
				s.reclaimOwnedSession(func() {
					s.runPacketSessionDetach("packet handler detach", detachCallback)
				}, reclaimDone)
			})
		}
		reclaimOwned = false
	}
	if err != nil {
		if detach != nil {
			detach()
		}
		return nil, err
	}
	if err := attachCtx.Err(); err != nil {
		if detach != nil {
			detach()
		}
		return nil, err
	}
	if !s.getActiveSessions().isPending(ref) {
		if detach != nil {
			detach()
		}
		return nil, errors.New("Talaria server: packet session was revoked while attaching")
	}
	return detach, nil
}

type packetSessionAttachResult struct {
	detach func()
	err    error
}

func (s *Server) callPacketSessionAttach(attachCtx, sessionCtx context.Context, session SessionContext, writers SessionWriters) (func(), func(), error) {
	if err := attachCtx.Err(); err != nil {
		return nil, nil, err
	}
	switch handler := s.handler.(type) {
	case *TunPacketHandler:
		detach, err := handler.AttachSessionWriters(sessionCtx, session, writers)
		return detach, nil, err
	}
	_, hasWritersAttach := s.handler.(SessionWritersHandler)
	_, hasPacketAttach := s.handler.(SessionPacketHandler)
	if !hasWritersAttach && !hasPacketAttach {
		return nil, nil, nil
	}
	slots := s.authSlots
	if slots == nil {
		slots = defaultAuthProviderSlots
	}
	releaseWorker, ok := s.acquireAuthWorker(session.RemoteIP, slots)
	if !ok {
		return nil, nil, errResourceLimit
	}
	resultCh := make(chan packetSessionAttachResult)
	go func() {
		var detach func()
		err := extension.Do("Talaria packet session attach", func() error {
			var attachErr error
			if attached, ok := s.handler.(SessionWritersHandler); ok {
				detach, attachErr = attached.AttachSessionWriters(sessionCtx, session, writers)
			} else if attached, ok := s.handler.(SessionPacketHandler); ok {
				detach, attachErr = attached.AttachSession(sessionCtx, session, writers.Packet)
			}
			return attachErr
		})
		result := packetSessionAttachResult{detach: detach, err: err}
		select {
		case resultCh <- result:
		case <-attachCtx.Done():
			releaseWorker()
			s.reclaimSession(func() {
				s.runPacketSessionDetach("abandoned packet session detach", detach)
			})
		}
	}()
	select {
	case <-attachCtx.Done():
		return nil, nil, attachCtx.Err()
	case result := <-resultCh:
		return result.detach, releaseWorker, result.err
	}
}

func (s *Server) runPacketSessionDetach(scope string, detach func()) {
	if detach == nil {
		return
	}
	if err := extension.Run(scope, detach); err != nil {
		s.logError(scope, err)
	}
}

func (s *Server) recoverExtensionPanic(scope string, err *error) {
	if recovered := recover(); recovered != nil {
		panicErr := extension.PanicError("Talaria server "+scope, recovered)
		if err != nil {
			*err = panicErr
		}
		s.logError(scope, panicErr)
	}
}

func onceFunc(fn func()) func() {
	if fn == nil {
		return nil
	}
	var called atomic.Bool
	return func() {
		if called.CompareAndSwap(false, true) {
			fn()
		}
	}
}

type sessionDetachGuard struct {
	mu      sync.Mutex
	revoked bool
	detach  func()
}

func newSessionDetachGuard() *sessionDetachGuard {
	return new(sessionDetachGuard)
}

func (g *sessionDetachGuard) setDetach(detach func()) {
	if g == nil || detach == nil {
		return
	}
	detach = onceFunc(detach)
	g.mu.Lock()
	if !g.revoked {
		g.detach = detach
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	detach()
}

func (g *sessionDetachGuard) revoke() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.revoked = true
	detach := g.detach
	g.mu.Unlock()
	if detach != nil {
		detach()
	}
}

func (g *sessionDetachGuard) detachNow() {
	if g == nil {
		return
	}
	g.mu.Lock()
	detach := g.detach
	g.mu.Unlock()
	if detach != nil {
		detach()
	}
}

// authenticatePacketConn authenticates the first protected packet on a packet transport.
func (s *Server) authenticatePacketConn(ctx context.Context, conn net.Conn, opt ServeOptions) (session SessionContext, err error) {
	if s.resources != nil && !s.resources.allowAuthAttempt(hostFromAddr(conn.RemoteAddr()), time.Now()) {
		return SessionContext{}, errAuthenticationRateLimit
	}
	authCtx, cancel := context.WithTimeout(ctx, opt.AuthTimeout)
	defer cancel()
	buf := make([]byte, opt.ReadBufferSize)
	defer clear(buf)
	deadline, _ := authCtx.Deadline()
	if err := setAuthDeadlines(conn, deadline, "packet"); err != nil {
		return SessionContext{}, err
	}
	defer func() {
		if resetErr := clearAuthDeadlines(conn, "packet"); resetErr != nil {
			session = SessionContext{}
			err = errors.Join(err, resetErr)
		}
	}()
	n, err := readConnFrame(conn, buf)
	if err != nil {
		return SessionContext{}, fmt.Errorf("Talaria server: read auth: %w", err)
	}
	packet, _, err := s.codec.Decode(buf[:n])
	if err != nil {
		return SessionContext{}, fmt.Errorf("Talaria server: decode auth: %w", err)
	}
	return s.authenticatePacket(authCtx, conn, opt.Protocol, packet)
}

type talariaUDPPreAuthModeConn interface {
	SetTalariaUDPPreAuthMode(bool)
}

func setTalariaUDPPreAuthMode(conn net.Conn, enable bool) {
	if conn == nil {
		return
	}
	if udptlsConn, ok := conn.(talariaUDPPreAuthModeConn); ok {
		udptlsConn.SetTalariaUDPPreAuthMode(enable)
	}
}

// preparePacketBatch fixes and validates deterministic batch-loop parameters before readiness.
func preparePacketBatch(conn net.Conn, opt ServeOptions) (packetBatchReader, int, error) {
	batchConn, ok := conn.(packetBatchReader)
	if !ok {
		return nil, 0, nil
	}
	batchSize := 1
	if connBatchSize := batchConn.BatchSize(); connBatchSize > 0 {
		batchSize = connBatchSize
	}
	if batchSize > maxServePacketBatchSize {
		return nil, 0, fmt.Errorf("Talaria server: packet batch size %d exceeds maximum %d", batchSize, maxServePacketBatchSize)
	}
	if opt.ReadBufferSize > maxServePacketBatchBytes/batchSize {
		return nil, 0, fmt.Errorf("Talaria server: packet batch buffers exceed maximum %d bytes", maxServePacketBatchBytes)
	}
	return batchConn, batchSize, nil
}

// servePacketDataLoop reads and handles packets from a non-batching transport.
func (s *Server) servePacketDataLoop(ctx context.Context, conn net.Conn, opt ServeOptions, session SessionContext, writers SessionWriters) error {
	buf := make([]byte, opt.ReadBufferSize)
	defer conn.SetReadDeadline(time.Time{})
	for {
		if err := conn.SetReadDeadline(time.Now().Add(opt.IdleTimeout)); err != nil {
			if isExpectedClose(ctx, err) {
				return nil
			}
			return fmt.Errorf("Talaria server: set packet idle deadline: %w", err)
		}
		n, err := readConnFrame(conn, buf)
		if err != nil {
			if isExpectedClose(ctx, err) {
				return nil
			}
			return err
		}
		if err := s.handleRawPacketFrameWithWriters(ctx, writers, session, buf[:n]); err != nil {
			if isExpectedClose(ctx, err) {
				return nil
			}
			return err
		}
	}
}

// servePacketBatchDataLoop reads and handles packet batches using preflighted limits.
func (s *Server) servePacketBatchDataLoop(ctx context.Context, conn packetBatchReader, batchSize int, opt ServeOptions, session SessionContext, writers SessionWriters) error {
	if budget, ok := conn.(packetBatchBufferBudget); ok {
		for {
			retainedBytes := int64(batchSize) * int64(opt.ReadBufferSize)
			release, err := budget.ReservePacketReadBufferBytes(retainedBytes)
			if err == nil {
				defer release()
				break
			}
			if batchSize == 1 {
				return err
			}
			// Preserve batching when the shared memory budget allows it, but
			// degrade to a smaller fixed scratch set under pressure.
			batchSize = max(1, batchSize/2)
		}
	}
	frames := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range frames {
		frames[i] = make([]byte, opt.ReadBufferSize)
	}
	emptyReads := 0
	emptyReadBackoff := connReadBatchNoProgressInitialBackoff
	for {
		if err := conn.SetReadDeadline(time.Now().Add(opt.IdleTimeout)); err != nil {
			if isExpectedClose(ctx, err) {
				return nil
			}
			return fmt.Errorf("Talaria server: set packet batch idle deadline: %w", err)
		}
		n, err := conn.ReadBatch(ctx, frames, sizes)
		if err != nil {
			if isExpectedClose(ctx, err) {
				return nil
			}
			return err
		}
		if n < 0 || n > len(frames) || n > len(sizes) {
			return fmt.Errorf("Talaria server: invalid packet batch count: %d", n)
		}
		if n == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			emptyReads++
			if emptyReads >= connReadBatchNoProgressLimit {
				return errors.New("Talaria server: packet batch read made no progress")
			}
			timer := time.NewTimer(emptyReadBackoff)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return ctx.Err()
			case <-timer.C:
			}
			if emptyReadBackoff < connReadBatchNoProgressMaxBackoff {
				emptyReadBackoff *= 2
				if emptyReadBackoff > connReadBatchNoProgressMaxBackoff {
					emptyReadBackoff = connReadBatchNoProgressMaxBackoff
				}
			}
			continue
		}
		emptyReads = 0
		emptyReadBackoff = connReadBatchNoProgressInitialBackoff
		for i := 0; i < n && i < len(frames) && i < len(sizes); i++ {
			size := sizes[i]
			if size < 0 {
				return fmt.Errorf("Talaria server: invalid negative packet frame size: %d", size)
			}
			if size == 0 {
				continue
			}
			if size > len(frames[i]) {
				return fmt.Errorf("Talaria server: packet frame size overflows buffer: %d", size)
			}
			raw := frames[i][:size]
			if !s.getActiveSessions().isCurrent(session.Ref()) {
				return net.ErrClosed
			}
			if err := normalizeInboundRawFrame(raw, session); err != nil {
				return err
			}
			if tunHandler, ok := s.handler.(*TunPacketHandler); ok {
				if err := s.validateBuiltinRawFrameTarget(ctx, session, raw); err != nil {
					return err
				}
				handled, borrowed, responses, err := tunHandler.HandleBorrowedRawFrame(ctx, session, raw)
				if borrowed {
					frames[i] = make([]byte, opt.ReadBufferSize)
				}
				if err != nil {
					if isExpectedClose(ctx, err) {
						return nil
					}
					return err
				}
				if handled {
					if err := s.writeResponsesWithWriters(writers, session, responses); err != nil {
						if isExpectedClose(ctx, err) {
							return nil
						}
						return err
					}
					continue
				}
			}
			if err := s.handleRawPacketFrameWithWriters(ctx, writers, session, raw); err != nil {
				if isExpectedClose(ctx, err) {
					return nil
				}
				return err
			}
		}
	}
}

func (s *Server) handleRawPacketFrame(ctx context.Context, write PacketWriter, session SessionContext, raw []byte) error {
	return s.handleRawPacketFrameWithWriters(ctx, SessionWriters{Packet: write}, session, raw)
}

func (s *Server) handleRawPacketFrameWithWriters(ctx context.Context, writers SessionWriters, session SessionContext, raw []byte) error {
	write := writers.Packet
	if !s.getActiveSessions().isCurrent(session.Ref()) {
		return net.ErrClosed
	}
	if err := normalizeInboundRawFrame(raw, session); err != nil {
		return err
	}
	if err := s.validateBuiltinRawFrameTarget(ctx, session, raw); err != nil {
		if write != nil {
			_ = write(peerErrorPacket(peerPacketHandlingErrorMessage))
		}
		return err
	}
	if rawHandler, ok := s.handler.(RawFrameHandler); ok {
		var handled bool
		var responses []*vpnpacket.VpnPacket
		var err error
		if packetHandlerCallsAreBounded(s.handler) {
			handled, responses, err = rawHandler.HandleRawFrame(ctx, session, raw)
		} else {
			result, callErr := callBoundedExtension(ctx, s.outboundSlots, s.resources, session.ClientID, "Talaria raw frame handler", func() (rawFrameHandlerResult, error) {
				handled, responses, handlerErr := rawHandler.HandleRawFrame(ctx, session, raw)
				return rawFrameHandlerResult{handled: handled, responses: responses}, handlerErr
			}, nil)
			handled, responses, err = result.handled, result.responses, callErr
		}
		if !s.getActiveSessions().isCurrent(session.Ref()) {
			return net.ErrClosed
		}
		if err != nil {
			if write != nil {
				_ = write(peerErrorPacket(peerPacketHandlingErrorMessage))
			}
			return err
		}
		if handled {
			return s.writeResponsesWithWriters(writers, session, responses)
		}
	}
	packet, _, err := s.codec.Decode(raw)
	if err != nil {
		return fmt.Errorf("Talaria server: decode packet: %w", err)
	}
	if err := normalizeInboundPacket(packet, session); err != nil {
		return err
	}
	if packet.Cmd == vpnpacket.CmdClientClose {
		return net.ErrClosed
	}
	return s.handleAndWriteResponsesWithWriters(ctx, writers, session, packet)
}

// authenticateControlConn authenticates the first protected frame on a control transport.
func (s *Server) authenticateControlConn(ctx context.Context, conn net.Conn, opt ServeOptions) (session SessionContext, err error) {
	if s.resources != nil && !s.resources.allowAuthAttempt(hostFromAddr(conn.RemoteAddr()), time.Now()) {
		return SessionContext{}, errAuthenticationRateLimit
	}
	authCtx, cancel := context.WithTimeout(ctx, opt.AuthTimeout)
	defer cancel()
	buf := make([]byte, opt.ReadBufferSize)
	defer clear(buf)
	deadline, _ := authCtx.Deadline()
	if err := setAuthDeadlines(conn, deadline, "control"); err != nil {
		return SessionContext{}, err
	}
	defer func() {
		if resetErr := clearAuthDeadlines(conn, "control"); resetErr != nil {
			session = SessionContext{}
			err = errors.Join(err, resetErr)
		}
	}()
	n, err := readConnFrame(conn, buf)
	if err != nil {
		return SessionContext{}, fmt.Errorf("Talaria server: read control auth: %w", err)
	}
	packet, _, err := s.codec.Decode(buf[:n])
	if err != nil {
		return SessionContext{}, fmt.Errorf("Talaria server: decode control auth: %w", err)
	}
	return s.authenticatePacket(authCtx, conn, opt.Protocol, packet)
}

// authenticatePacket validates one decoded authentication request and calls the configured provider.
func (s *Server) authenticatePacket(ctx context.Context, conn net.Conn, protocol client.Protocol, packet *vpnpacket.VpnPacket) (SessionContext, error) {
	if packet == nil || packet.Cmd != vpnpacket.CmdAuthRequest {
		return SessionContext{}, errors.New("expected auth request")
	}
	defer func() {
		packet.Id = ""
		packet.Sk = ""
	}()
	if !validAuthCredential(packet.Id) || !validAuthCredential(packet.Sk) {
		return SessionContext{}, errAuthenticationFailed
	}
	req := AuthRequest{
		Protocol:          protocol,
		Packet:            packet,
		RequestedClientID: packet.ClientId,
		ClientID:          packet.Id,
		SecretKey:         packet.Sk,
		Version:           packet.Version,
		EntranceIP:        packet.EntranceIp,
		ExitIP:            packet.ExitIp,
		RemoteAddr:        addrString(conn.RemoteAddr()),
		RemoteIP:          hostFromAddr(conn.RemoteAddr()),
		LocalAddr:         addrString(conn.LocalAddr()),
	}
	result, err := s.callAuthProvider(ctx, req)
	if err != nil {
		if errors.Is(err, extension.ErrPanic) || errors.Is(err, errResourceLimit) {
			return SessionContext{}, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return SessionContext{}, fmt.Errorf("%w: %w", errAuthenticationFailed, ctxErr)
		}
		return SessionContext{}, errAuthenticationFailed
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return SessionContext{}, fmt.Errorf("%w: %w", errAuthenticationFailed, ctxErr)
	}
	if result.ClientID == 0 {
		return SessionContext{}, errAuthenticationFailed
	}
	if result.Version == 0 {
		result.Version = DefaultAuthVersion
	}
	authSuccess, err := s.codec.Encode(&vpnpacket.VpnPacket{
		ClientId:      packet.ClientId,
		Cmd:           vpnpacket.CmdAuthSuccess,
		NewClientId:   result.ClientID,
		Version:       result.Version,
		RemoteVersion: packet.Version,
	})
	if err != nil {
		return SessionContext{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return SessionContext{}, fmt.Errorf("%w: %w", errAuthenticationFailed, ctxErr)
	}
	if err := writeConnFrame(conn, authSuccess); err != nil {
		return SessionContext{}, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return SessionContext{}, fmt.Errorf("%w: %w", errAuthenticationFailed, ctxErr)
	}
	return SessionContext{
		Protocol:   protocol,
		ClientID:   result.ClientID,
		RemoteAddr: req.RemoteAddr,
		RemoteIP:   req.RemoteIP,
		LocalAddr:  req.LocalAddr,
	}, nil
}

type authProviderResult struct {
	result AuthResult
	err    error
}

func (s *Server) callAuthProvider(ctx context.Context, req AuthRequest) (AuthResult, error) {
	if err := ctx.Err(); err != nil {
		return AuthResult{}, err
	}
	if provider, ok := s.auth.(boundedAuthProvider); ok {
		return provider.Authenticate(ctx, req)
	}
	slots := s.authSlots
	if slots == nil {
		slots = defaultAuthProviderSlots
	}
	releaseWorker, ok := s.acquireAuthWorker(req.RemoteIP, slots)
	if !ok {
		return AuthResult{}, errResourceLimit
	}
	providerReq := req
	packet := *req.Packet
	providerReq.Packet = &packet
	resultCh := make(chan authProviderResult, 1)
	go func() {
		defer releaseWorker()
		var result AuthResult
		err := extension.Do("Talaria server auth provider", func() error {
			var authErr error
			result, authErr = s.auth.Authenticate(ctx, providerReq)
			return authErr
		})
		resultCh <- authProviderResult{result: result, err: err}
	}()
	select {
	case <-ctx.Done():
		return AuthResult{}, ctx.Err()
	case result := <-resultCh:
		return result.result, result.err
	}
}

func (s *Server) acquireAuthWorker(source string, slots chan struct{}) (func(), bool) {
	if s.resources != nil {
		return s.resources.acquireAuthWorker(source, slots)
	}
	select {
	case slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }, true
	default:
		return nil, false
	}
}

func setAuthDeadlines(conn net.Conn, deadline time.Time, scope string) error {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("Talaria server: set %s auth read deadline: %w", scope, err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return fmt.Errorf("Talaria server: set %s auth write deadline: %w", scope, err)
	}
	return nil
}

func clearAuthDeadlines(conn net.Conn, scope string) error {
	readErr := conn.SetReadDeadline(time.Time{})
	writeErr := conn.SetWriteDeadline(time.Time{})
	if readErr == nil && writeErr == nil {
		return nil
	}
	return fmt.Errorf("Talaria server: reset %s auth deadlines: %w", scope, errors.Join(readErr, writeErr))
}

func shouldWriteAuthenticationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr net.Error
	return !errors.As(err, &netErr) || !netErr.Timeout()
}

func (s *Server) writeAuthenticationError(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 || timeout > sessionCloseWriteTimeout {
		timeout = sessionCloseWriteTimeout
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	return writeAuthenticationError(s.codec, conn)
}

func validAuthCredential(value string) bool {
	return len(value) > 0 && len(value) <= maxAuthCredentialBytes && utf8.ValidString(value)
}

func (s *Server) handleAndWriteResponses(ctx context.Context, write PacketWriter, session SessionContext, packet *vpnpacket.VpnPacket) error {
	return s.handleAndWriteResponsesWithWriters(ctx, SessionWriters{Packet: write}, session, packet)
}

func (s *Server) handleAndWriteResponsesWithWriters(ctx context.Context, writers SessionWriters, session SessionContext, packet *vpnpacket.VpnPacket) error {
	write := writers.Packet
	if !s.getActiveSessions().isCurrent(session.Ref()) {
		return net.ErrClosed
	}
	if err := normalizeInboundPacket(packet, session); err != nil {
		return err
	}
	if err := s.validateBuiltinPacketTarget(ctx, session, packet); err != nil {
		if write != nil {
			_ = write(peerErrorPacket(peerPacketHandlingErrorMessage))
		}
		return err
	}
	var responses []*vpnpacket.VpnPacket
	var err error
	if packetHandlerCallsAreBounded(s.handler) {
		responses, err = s.handler.HandlePacket(ctx, session, packet)
	} else {
		responses, err = callBoundedExtension(ctx, s.outboundSlots, s.resources, session.ClientID, "Talaria packet handler", func() ([]*vpnpacket.VpnPacket, error) {
			return s.handler.HandlePacket(ctx, session, packet)
		}, nil)
	}
	if !s.getActiveSessions().isCurrent(session.Ref()) {
		return net.ErrClosed
	}
	if err != nil {
		if write != nil {
			_ = write(peerErrorPacket(peerPacketHandlingErrorMessage))
		}
		return err
	}
	return s.writeResponsesWithWriters(writers, session, responses)
}

func (s *Server) validateBuiltinPacketTarget(ctx context.Context, session SessionContext, packet *vpnpacket.VpnPacket) error {
	if packet == nil || (packet.Cmd != vpnpacket.CmdData && packet.Cmd != vpnpacket.CmdDataReturn) {
		return nil
	}
	return s.validateBuiltinRawIPTarget(ctx, session, packet.Data)
}

func (s *Server) validateBuiltinRawFrameTarget(ctx context.Context, session SessionContext, raw []byte) error {
	if _, ok := s.handler.(*TunPacketHandler); !ok || !vpnpacket.IsFixedV4DataCmd(raw, len(raw)) {
		return nil
	}
	return s.validateBuiltinRawIPTarget(ctx, session, vpnpacket.GetFixedV4Payload(raw, len(raw)))
}

func (s *Server) writeResponses(_ context.Context, write PacketWriter, session SessionContext, responses []*vpnpacket.VpnPacket) error {
	return s.writeResponsesWithWriters(SessionWriters{Packet: write}, session, responses)
}

func (s *Server) writeResponsesWithWriters(writers SessionWriters, session SessionContext, responses []*vpnpacket.VpnPacket) error {
	if len(responses) > maxPacketHandlerResponses {
		return fmt.Errorf("Talaria server: packet handler returned %d responses, maximum is %d", len(responses), maxPacketHandlerResponses)
	}
	codec := s.codec
	if extension.IsNil(codec) {
		codec = dataplane.WireCodec{}
	}
	totalBytes := 0
	encoded := make([][]byte, len(responses))
	for i, response := range responses {
		if !s.getActiveSessions().isCurrent(session.Ref()) {
			return net.ErrClosed
		}
		if response == nil {
			continue
		}
		if !allowedServerResponseCommand(response.Cmd) {
			return fmt.Errorf("Talaria server: packet handler response command %d is not allowed", response.Cmd)
		}
		normalizeServerResponse(response, session.ClientID)
		if err := validatePacketHandlerPayloadSize(response, maxPacketHandlerResponseBytes-totalBytes); err != nil {
			return err
		}
		raw, err := codec.Encode(response)
		if err != nil {
			return fmt.Errorf("Talaria server: encode packet handler response: %w", err)
		}
		if len(raw) > maxPacketHandlerResponseBytes-totalBytes {
			return fmt.Errorf("Talaria server: packet handler responses exceed %d bytes", maxPacketHandlerResponseBytes)
		}
		totalBytes += len(raw)
		encoded[i] = raw
	}
	for i, response := range responses {
		if response == nil || (writers.Raw == nil && writers.Packet == nil) {
			continue
		}
		if !s.getActiveSessions().isCurrent(session.Ref()) {
			return net.ErrClosed
		}
		if writers.Raw != nil {
			if err := writers.Raw(encoded[i]); err != nil {
				return err
			}
		} else if err := writers.Packet(response); err != nil {
			return err
		}
	}
	return nil
}

func validatePacketHandlerPayloadSize(packet *vpnpacket.VpnPacket, remaining int) error {
	if packet == nil || remaining < 0 {
		return errors.New("Talaria server: invalid packet handler response")
	}
	var payloadBytes int
	switch packet.Cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
		payloadBytes = len(packet.Data)
	case vpnpacket.CmdErr:
		payloadBytes = len(packet.ErrorMessage)
	}
	if payloadBytes > remaining {
		return fmt.Errorf("Talaria server: packet handler responses exceed %d bytes", maxPacketHandlerResponseBytes)
	}
	return nil
}

func normalizeInboundRawFrame(raw []byte, session SessionContext) error {
	if len(raw) < 9 {
		return fmt.Errorf("Talaria server: client packet length %d is less than 9", len(raw))
	}
	cmd := raw[8]
	switch {
	case cmd == vpnpacket.CmdData || cmd == vpnpacket.CmdDataReturn:
		if len(raw) < vpnpacket.RawCmdDataHeaderLen() {
			return errors.New("Talaria server: client data packet is truncated")
		}
	case vpnpacket.IsFixedV4DataWireCmd(cmd):
		if len(raw) < vpnpacket.FixedV4PayloadOffset() {
			return errors.New("Talaria server: client fixed-v4 data packet is truncated")
		}
		clear(raw[13:21])
	case cmd == vpnpacket.CmdKeepAlive || cmd == vpnpacket.CmdServerKeepAlive:
		if len(raw) < 13 {
			return errors.New("Talaria server: client keepalive packet is truncated")
		}
	case cmd == vpnpacket.CmdClientClose:
	default:
		return fmt.Errorf("Talaria server: client packet command %d is not allowed", cmd)
	}
	binary.LittleEndian.PutUint64(raw[:8], session.ClientID)
	return nil
}

func normalizeInboundPacket(packet *vpnpacket.VpnPacket, session SessionContext) error {
	if packet == nil {
		return errors.New("Talaria server: packet codec returned nil packet")
	}
	switch packet.Cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn, vpnpacket.CmdKeepAlive, vpnpacket.CmdServerKeepAlive, vpnpacket.CmdClientClose:
	default:
		return fmt.Errorf("Talaria server: client packet command %d is not allowed", packet.Cmd)
	}
	normalized := vpnpacket.VpnPacket{
		Cmd:      packet.Cmd,
		WireCmd:  packet.Cmd,
		ClientId: session.ClientID,
	}
	switch packet.Cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
		normalized.DataSequenceId = packet.DataSequenceId
		normalized.Data = packet.Data
	case vpnpacket.CmdKeepAlive:
		normalized.KeepAliveId = packet.KeepAliveId
		normalized.SendTime = packet.SendTime
		normalized.LastTimeOffset = packet.LastTimeOffset
		normalized.IsPing = packet.IsPing
		normalized.KeepAliveRemoteIpv4 = packet.KeepAliveRemoteIpv4
	case vpnpacket.CmdServerKeepAlive:
		normalized.KeepAliveId = packet.KeepAliveId
	}
	*packet = normalized
	return nil
}

func normalizeServerResponse(packet *vpnpacket.VpnPacket, clientID uint64) {
	normalized := vpnpacket.VpnPacket{Cmd: packet.Cmd, WireCmd: packet.Cmd, ClientId: clientID}
	switch packet.Cmd {
	case vpnpacket.CmdData:
		normalized.RemoteVersion = packet.RemoteVersion
		normalized.DataSequenceId = packet.DataSequenceId
		normalized.EntranceIp = packet.EntranceIp
		normalized.ExitIp = packet.ExitIp
		normalized.Data = packet.Data
	case vpnpacket.CmdDataReturn:
		normalized.DataSequenceId = packet.DataSequenceId
		normalized.Data = packet.Data
	case vpnpacket.CmdKeepAlive:
		normalized.KeepAliveId = packet.KeepAliveId
		normalized.SendTime = packet.SendTime
		normalized.LastTimeOffset = packet.LastTimeOffset
		normalized.IsPing = packet.IsPing
		normalized.KeepAliveRemoteIpv4 = packet.KeepAliveRemoteIpv4
	case vpnpacket.CmdServerKeepAlive:
		normalized.KeepAliveId = packet.KeepAliveId
	case vpnpacket.CmdErr:
		normalized.ErrorMessage = packet.ErrorMessage
	}
	*packet = normalized
}

func allowedServerResponseCommand(cmd byte) bool {
	switch cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn, vpnpacket.CmdKeepAlive, vpnpacket.CmdServerKeepAlive, vpnpacket.CmdErr:
		return true
	default:
		return false
	}
}

func peerErrorPacket(message string) *vpnpacket.VpnPacket {
	return &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdErr, ErrorMessage: message}
}

func writeRawPacketBatch(ctx context.Context, conn net.Conn, bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(sizes) < len(bufs) {
		return 0, errors.New("Talaria server: raw batch sizes too small")
	}
	for i := range bufs {
		if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
			return 0, fmt.Errorf("Talaria server: invalid raw packet size %d for buffer[%d]", sizes[i], i)
		}
	}
	if batchConn, ok := conn.(interface {
		WriteBatch(context.Context, [][]byte, []int) (int, error)
	}); ok {
		return batchConn.WriteBatch(ctx, bufs, sizes)
	}
	written := 0
	for i := range bufs {
		size := sizes[i]
		if size == 0 {
			continue
		}
		if err := writeConnFrame(conn, bufs[i][:size]); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
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
		return 0, fmt.Errorf("Talaria server: connection returned invalid read size %d for %d-byte buffer", n, len(frame))
	}
	return n, err
}

func closeOnContext(ctx context.Context, conn net.Conn) func() bool {
	if ctx == nil || conn == nil {
		return func() bool { return true }
	}
	return context.AfterFunc(ctx, func() {
		_ = extension.Do("Talaria server canceled connection close", conn.Close)
	})
}

func isExpectedClose(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if ctx.Err() != nil {
		return true
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func hostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}
