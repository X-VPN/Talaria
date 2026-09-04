// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestPacketSessionExtensionCallbacksMayReenterController(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Server, coretransport.SessionRef, *callbackSessionHandler) SessionWriters
	}{
		{
			name: "attach",
			configure: func(srv *Server, ref coretransport.SessionRef, handler *callbackSessionHandler) SessionWriters {
				handler.onAttach = func() { srv.RevokeSession(ref, "revoked from attach") }
				return SessionWriters{Packet: func(*vpnpacket.VpnPacket) error { return nil }}
			},
		},
		{
			name: "ready write",
			configure: func(srv *Server, ref coretransport.SessionRef, _ *callbackSessionHandler) SessionWriters {
				return SessionWriters{Packet: func(*vpnpacket.VpnPacket) error {
					srv.RevokeSession(ref, "revoked from ready write")
					return nil
				}}
			},
		},
		{
			name: "detach",
			configure: func(srv *Server, ref coretransport.SessionRef, handler *callbackSessionHandler) SessionWriters {
				handler.detach = func() { srv.RevokeSession(ref, "revoked from detach") }
				return SessionWriters{Packet: func(*vpnpacket.VpnPacket) error {
					return errors.New("forced ready failure")
				}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{}
			ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
			binding, err := srv.prepareSession(activeServerSessionConfig{Ref: ref})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.releaseSession(binding)
			handler := &callbackSessionHandler{}
			srv.handler = handler
			gate, handlerWriters := newSessionWriterGate(tt.configure(srv, ref, handler), nil, ref.ClientID)
			done := make(chan struct{})
			go func() {
				ctx := context.Background()
				detach, err := srv.attachPacketSession(ctx, ctx, SessionContext{
					ClientID:   ref.ClientID,
					Generation: ref.Generation,
				}, handlerWriters)
				if err == nil {
					err = srv.commitSession(binding)
				}
				if err == nil {
					err = gate.markReady(ref.ClientID)
				}
				if detach != nil {
					detach()
				}
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("extension callback deadlocked while reentering SessionController")
			}
		})
	}
}

func TestPacketSessionCleansDetachReturnedWithAttachError(t *testing.T) {
	srv := &Server{}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	binding, err := srv.prepareSession(activeServerSessionConfig{Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(binding)
	want := errors.New("synthetic attach failure")
	var detachCalls atomic.Int32
	detachDone := make(chan struct{})
	srv.handler = &callbackSessionHandler{
		attachErr: want,
		detach: func() {
			detachCalls.Add(1)
			close(detachDone)
			panic("synthetic detach failure")
		},
	}
	_, writers := newSessionWriterGate(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			t.Fatal("ready write ran after attach failure")
			return nil
		},
	}, nil, ref.ClientID)
	ctx := context.Background()
	detach, err := srv.attachPacketSession(ctx, ctx, SessionContext{
		ClientID:   ref.ClientID,
		Generation: ref.Generation,
	}, writers)
	if detach != nil || !errors.Is(err, want) {
		t.Fatalf("attach result has detach=%t, error=%v; want false, %v", detach != nil, err, want)
	}
	select {
	case <-detachDone:
	case <-time.After(time.Second):
		t.Fatal("detach callback did not run")
	}
	if got := detachCalls.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
}

func TestStagedTransportPrepareMayReenterController(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{resources: newResourceLimiter(limits)}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	transport := &callbackStagedTransport{}
	transport.onPrepare = func() {
		srv.RevokeClient(ref.ClientID, "revoked from transport prepare")
	}
	sessions := &streamControlSessions{server: srv, transport: transport}
	done := make(chan error, 1)
	go func() {
		_, _, _, activateErr := sessions.ActivateControlSession(
			context.Background(),
			nil,
			SessionContext{ClientID: ref.ClientID, Generation: ref.Generation},
			func(*vpnpacket.VpnPacket) error { return nil },
			nil,
		)
		done <- activateErr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("transport preparation succeeded after its pending session was revoked")
		}
	case <-time.After(time.Second):
		t.Fatal("transport Prepare deadlocked while reentering SessionController")
	}
	if srv.resources.sessions != 0 {
		t.Fatalf("session resources after reentrant revoke = %d, want 0", srv.resources.sessions)
	}
}

func TestControlSessionFinalizesBeforeReady(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	finalizeStarted := make(chan struct{})
	releaseFinalize := make(chan struct{})
	transport := &callbackStagedTransport{onFinalize: func() {
		close(finalizeStarted)
		<-releaseFinalize
	}}
	srv := &Server{
		protocol:  client.ProtocolTalariaTCP,
		codec:     dataplane.WireCodec{},
		auth:      StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 7},
		handler:   EchoPacketHandler{},
		resources: newResourceLimiter(limits),
	}
	serverConn, clientConn := net.Pipe()
	ordered := &readyOrderConn{
		Conn:      serverConn,
		server:    srv,
		transport: transport,
		ready:     make(chan bool, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ServeControlConn(ctx, ordered, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			AuthTimeout: time.Second,
			Sessions:    &streamControlSessions{server: srv, transport: transport},
		})
	}()
	writeTestPacket(t, srv.codec, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	for _, command := range []byte{vpnpacket.CmdAuthSuccess, vpnpacket.CmdSessionGrant} {
		if packet := readTestPacket(t, srv.codec, clientConn); packet.Cmd != command {
			t.Fatalf("session response command = %d, want %d", packet.Cmd, command)
		}
	}
	select {
	case <-finalizeStarted:
	case <-time.After(time.Second):
		t.Fatal("session finalization did not start")
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := readConnFrame(clientConn, make([]byte, 64)); err == nil {
		t.Fatal("SessionReady was written before finalization completed")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before finalization = %v, want timeout", err)
	}
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(releaseFinalize)
	select {
	case ready := <-ordered.ready:
		if !ready {
			t.Fatal("session became current before readiness was written")
		}
	case <-time.After(time.Second):
		t.Fatal("session ready write was not observed")
	}
	type streamResult struct {
		conn net.Conn
		err  error
	}
	streamDone := make(chan streamResult, 1)
	go func() {
		conn, err := srv.openStream(context.Background(), coretransport.StreamRequest{
			Session: coretransport.SessionRef{ClientID: 7, Generation: 1},
		})
		streamDone <- streamResult{conn: conn, err: err}
	}()
	select {
	case result := <-streamDone:
		t.Fatalf("announced stream returned before Ready: %v, %v", result.conn, result.err)
	case <-time.After(20 * time.Millisecond):
	}
	if packet := readTestPacket(t, srv.codec, clientConn); packet.Cmd != vpnpacket.CmdSessionReady {
		t.Fatalf("session response command = %d, want %d", packet.Cmd, vpnpacket.CmdSessionReady)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if ref, ok := srv.CurrentSession(7); ok && ref.Generation == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session did not become current after readiness")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case result := <-streamDone:
		if result.conn != nil || result.err == nil {
			t.Fatalf("stream after Ready = %v, %v; want target validation error", result.conn, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("announced stream remained blocked after Ready")
	}
	cancel()
	_ = clientConn.Close()
	select {
	case <-serveErr:
	case <-time.After(time.Second):
		t.Fatal("control session did not stop")
	}
}

func TestStagedTransportPreparePanicRollsBackResources(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{resources: newResourceLimiter(limits)}
	transport := &callbackStagedTransport{onPrepare: func() { panic("boom") }}
	sessions := &streamControlSessions{server: srv, transport: transport}
	_, _, _, err = sessions.ActivateControlSession(
		context.Background(),
		nil,
		SessionContext{ClientID: 7, Generation: 1},
		func(*vpnpacket.VpnPacket) error { return nil },
		nil,
	)
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("transport Prepare panic error = %v, want extension panic", err)
	}
	if srv.resources.sessions != 0 {
		t.Fatalf("session resources after Prepare panic = %d, want 0", srv.resources.sessions)
	}
	if transport.revokes.Load() != 1 {
		t.Fatalf("transport revokes after Prepare panic = %d, want 1", transport.revokes.Load())
	}
}

func TestStagedGrantWriterPanicRollsBackResourcesAndClearsToken(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{resources: newResourceLimiter(limits)}
	transport := &callbackStagedTransport{}
	sessions := &streamControlSessions{server: srv, transport: transport}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	var token []byte
	err = extension.Run("test staged grant writer", func() {
		_, _, _, _ = sessions.ActivateControlSession(
			context.Background(),
			nil,
			SessionContext{ClientID: ref.ClientID, Generation: ref.Generation},
			func(packet *vpnpacket.VpnPacket) error {
				token = packet.SessionDataToken
				panic("boom")
			},
			nil,
		)
	})
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("grant writer panic error = %v, want extension panic", err)
	}
	if srv.resources.sessions != 0 {
		t.Fatalf("session resources after grant writer panic = %d, want 0", srv.resources.sessions)
	}
	if srv.getActiveSessions().isPending(ref) {
		t.Fatal("grant writer panic retained a pending session")
	}
	deadline := time.Now().Add(time.Second)
	for transport.revokes.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("transport revokes after grant writer panic = %d, want 1", transport.revokes.Load())
		}
		time.Sleep(time.Millisecond)
	}
	for i, value := range token {
		if value != 0 {
			t.Fatalf("session token byte %d was not cleared", i)
		}
	}
}

func TestStagedTransportRevokeContinuesAfterCallbackPanic(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{resources: newResourceLimiter(limits)}
	transport := &callbackStagedTransport{}
	sessions := &streamControlSessions{server: srv, transport: transport}
	_, _, revoke, err := sessions.ActivateControlSession(
		context.Background(),
		nil,
		SessionContext{ClientID: 7, Generation: 1},
		func(*vpnpacket.VpnPacket) error { return nil },
		func() { panic("boom") },
	)
	if err != nil {
		t.Fatal(err)
	}
	revoke()
	deadline := time.Now().Add(time.Second)
	for transport.revokes.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("transport revokes after callback panic = %d, want 1", transport.revokes.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if srv.resources.sessions != 0 {
		t.Fatalf("session resources after callback panic = %d, want 0", srv.resources.sessions)
	}
}

func TestSessionRevokeCallbackMayReenterController(t *testing.T) {
	srv := &Server{}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	reentered := make(chan struct{})
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref: ref,
		RevokeData: func() {
			close(reentered)
			srv.RevokeSession(ref, "reentrant revoke")
		},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		srv.RevokeSession(ref, "outer revoke")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session revoke callback deadlocked while reentering SessionController")
	}
	select {
	case <-reentered:
	case <-time.After(time.Second):
		t.Fatal("session revoke callback did not run")
	}
}

func TestSessionReasonWriteMayReenterController(t *testing.T) {
	srv := &Server{protocol: client.ProtocolTalariaTCP}
	ref := coretransport.SessionRef{ClientID: 8, Generation: 1}
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	conn := &reentrantSessionWriteConn{Conn: serverConn}
	writers := srv.newSessionWriters(context.Background(), conn)
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref:   ref,
		Conn:  conn,
		Write: writers.Packet,
	}); err != nil {
		t.Fatal(err)
	}
	conn.onWrite = func() { srv.RevokeSession(ref, "revoked from connection write") }

	done := make(chan error, 1)
	go func() {
		done <- writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session reason write deadlocked after reentering SessionController")
	}
}

func TestServerCloseExtensionsMayReenterClose(t *testing.T) {
	handler := &reentrantCloseHandler{}
	srv := &Server{handler: handler}
	handler.close = func() { _ = srv.Close() }
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	sessionClosed := make(chan struct{})
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref: ref,
		RevokeData: func() {
			handler.sessionCloseCalls++
			_ = srv.Close()
			close(sessionClosed)
		},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Server.Close deadlocked on a reentrant extension")
	}
	select {
	case <-sessionClosed:
	case <-time.After(time.Second):
		t.Fatal("session close callback did not run")
	}
	if handler.sessionCloseCalls != 1 || handler.closeCalls != 1 {
		t.Fatalf("session/handler close calls = %d/%d, want 1/1", handler.sessionCloseCalls, handler.closeCalls)
	}
}

func TestIdempotentCallbackMayReenterItself(t *testing.T) {
	var calls int
	var callback func()
	callback = onceFunc(func() {
		calls++
		callback()
	})
	done := make(chan struct{})
	go func() {
		callback()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idempotent callback deadlocked on reentry")
	}
	if calls != 1 {
		t.Fatalf("callback calls = %d, want 1", calls)
	}
}

type callbackSessionHandler struct {
	onAttach  func()
	detach    func()
	attachErr error
}

type callbackStagedTransport struct {
	onPrepare  func()
	onFinalize func()
	revokes    atomic.Int32
	committed  bool
	finalized  bool
}

type readyOrderConn struct {
	net.Conn
	server    *Server
	transport *callbackStagedTransport
	ready     chan bool
}

func (c *readyOrderConn) Write(p []byte) (int, error) {
	if len(p) > 8 && p[8] == vpnpacket.CmdSessionReady {
		_, ok := c.server.CurrentSession(7)
		c.ready <- c.transport.committed && c.transport.finalized && !ok
	}
	return c.Conn.Write(p)
}

type reentrantSessionWriteConn struct {
	net.Conn
	once    sync.Once
	onWrite func()
}

func (c *reentrantSessionWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() {
		if c.onWrite != nil {
			c.onWrite()
		}
	})
	return len(p), nil
}

func (*callbackStagedTransport) Serve(context.Context, coretransport.ControlHandler, coretransport.StreamHandler) error {
	return nil
}

func (*callbackStagedTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (t *callbackStagedTransport) Prepare(context.Context, coretransport.SessionGrant) error {
	if t.onPrepare != nil {
		t.onPrepare()
	}
	return nil
}

func (t *callbackStagedTransport) Commit(context.Context, coretransport.SessionRef) error {
	t.committed = true
	return nil
}

func (t *callbackStagedTransport) Finalize(context.Context, coretransport.SessionRef) error {
	if t.onFinalize != nil {
		t.onFinalize()
	}
	t.finalized = true
	return nil
}

func (t *callbackStagedTransport) Revoke(context.Context, coretransport.SessionRef) error {
	t.revokes.Add(1)
	return nil
}

func (*callbackStagedTransport) Addr() net.Addr { return nil }

func (*callbackStagedTransport) Close() error { return nil }

func (*callbackSessionHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (h *callbackSessionHandler) AttachSessionWriters(context.Context, SessionContext, SessionWriters) (func(), error) {
	if h.onAttach != nil {
		h.onAttach()
	}
	return h.detach, h.attachErr
}

type reentrantCloseHandler struct {
	close             func()
	closeCalls        int
	sessionCloseCalls int
}

func (*reentrantCloseHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (h *reentrantCloseHandler) Close() error {
	h.closeCalls++
	if h.close != nil {
		h.close()
	}
	return nil
}
