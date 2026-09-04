// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestControlSessionWithoutActivatorIsRevocable(t *testing.T) {
	codec := dataplane.WireCodec{}
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    codec,
		auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 77,
			Version:          1,
		},
		handler: EchoPacketHandler{},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(ctx, serverConn, ServeOptions{Protocol: client.ProtocolTalariaTCP})
	}()

	authRaw, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "client",
		Sk:      "secret",
		Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(authRaw); err != nil {
		t.Fatal(err)
	}
	for _, want := range []byte{vpnpacket.CmdAuthSuccess, vpnpacket.CmdSessionReady} {
		if response := readTestPacket(t, codec, clientConn); response.Cmd != want {
			t.Fatalf("response command = %d, want %d", response.Cmd, want)
		}
	}

	var ref coretransport.SessionRef
	var ok bool
	deadline := time.Now().Add(time.Second)
	for !ok && time.Now().Before(deadline) {
		ref, ok = srv.CurrentSession(77)
		runtime.Gosched()
	}
	if !ok {
		t.Fatal("attached control session is not registered as an active session")
	}
	if ref.ClientID != 77 || ref.Generation == 0 {
		t.Fatalf("session ref = %+v", ref)
	}

	if !srv.RevokeClient(77, "revoked by test") {
		t.Fatal("RevokeClient did not revoke the attached control session")
	}
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("revoking the control session did not stop it")
	}
	if _, ok := srv.CurrentSession(77); ok {
		t.Fatal("revoked control session is still reported as current")
	}
}

func TestControlSessionReadyFailureLeavesNoCurrentSession(t *testing.T) {
	codec := dataplane.WireCodec{}
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    codec,
		auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 77,
			Version:          1,
		},
		handler: EchoPacketHandler{},
	}
	oldRef := coretransport.SessionRef{ClientID: 77, Generation: 1}
	var oldRevoked atomic.Bool
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref:        oldRef,
		RevokeData: func() { oldRevoked.Store(true) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(old)
	srv.sessionGeneration.Store(oldRef.Generation)

	clientConn, rawServerConn := net.Pipe()
	defer clientConn.Close()
	readyErr := errors.New("forced ready write failure")
	serverConn := &failWriteConn{Conn: rawServerConn, failAt: 2, err: readyErr}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{Protocol: client.ProtocolTalariaTCP})
	}()

	authRaw, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "client",
		Sk:      "secret",
		Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(authRaw); err != nil {
		t.Fatal(err)
	}
	if response := readTestPacket(t, codec, clientConn); response.Cmd != vpnpacket.CmdAuthSuccess {
		t.Fatalf("response command = %d, want %d", response.Cmd, vpnpacket.CmdAuthSuccess)
	}
	if err := <-errCh; !errors.Is(err, readyErr) {
		t.Fatalf("ServeControlConn error = %v, want %v", err, readyErr)
	}
	if current, ok := srv.CurrentSession(oldRef.ClientID); ok {
		t.Fatalf("current session after Ready failure = %+v/true, want none", current)
	}
	deadline := time.Now().Add(time.Second)
	for !oldRevoked.Load() {
		if time.Now().After(deadline) {
			t.Fatal("previous session was not revoked after finalization")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestControlSessionCleanupDoesNotBlockReplacement(t *testing.T) {
	resources := newResourceLimiter(ResourceLimits{MaxSessions: 2})
	srv := &Server{resources: resources}
	staged := &registryStagedTransport{registry: coretransport.NewSessionRegistry()}
	sessions := &streamControlSessions{server: srv, transport: staged}
	now := time.Now()
	oldRef := coretransport.SessionRef{ClientID: 77, Generation: 1}
	oldGrant, err := coretransport.NewSessionGrant(oldRef.ClientID, oldRef.Generation, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	oldLease, err := resources.acquireSession(oldRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref:       oldRef,
		Resources: oldLease,
		Write: func(*vpnpacket.VpnPacket) error {
			closeOnce.Do(func() { close(closeStarted) })
			<-releaseClose
			return nil
		},
		RevokeData: func() { _ = staged.Revoke(context.Background(), oldRef) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(old)
	defer close(releaseClose)

	activate := func(generation uint64) (func(), error) {
		commit, finalize, revoke, err := sessions.ActivateControlSession(
			context.Background(), nil,
			SessionContext{ClientID: oldRef.ClientID, Generation: generation},
			func(*vpnpacket.VpnPacket) error { return nil }, nil,
		)
		if err != nil {
			return nil, err
		}
		if err := commit(); err != nil {
			revoke()
			return nil, err
		}
		if err := finalize(); err != nil {
			revoke()
			return nil, err
		}
		ref := coretransport.SessionRef{ClientID: oldRef.ClientID, Generation: generation}
		if !srv.beginSessionReady(ref) || !srv.markSessionReady(ref) {
			revoke()
			return nil, errors.New("session did not become ready")
		}
		return revoke, nil
	}

	revokeSecond, err := activate(2)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeSecond()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("previous session close did not start")
	}

	revokeThird, err := activate(3)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeThird()
	thirdRef := coretransport.SessionRef{ClientID: oldRef.ClientID, Generation: 3}
	if current, ok := srv.CurrentSession(oldRef.ClientID); !ok || current != thirdRef {
		t.Fatalf("server current session = %+v/%v, want %+v/true", current, ok, thirdRef)
	}
	if current, ok := staged.registry.Current(oldRef.ClientID, time.Now()); !ok || current != thirdRef {
		t.Fatalf("transport current session = %+v/%v, want %+v/true", current, ok, thirdRef)
	}
}

func TestControlSessionFinalizeFailureLeavesRegistriesConsistent(t *testing.T) {
	resources := newResourceLimiter(ResourceLimits{MaxSessions: 2})
	srv := &Server{resources: resources}
	staged := &registryStagedTransport{registry: coretransport.NewSessionRegistry()}
	sessions := &streamControlSessions{server: srv, transport: staged}

	activate := func(generation uint64) (func(), error) {
		commit, finalize, revoke, err := sessions.ActivateControlSession(
			context.Background(), nil,
			SessionContext{ClientID: 77, Generation: generation},
			func(*vpnpacket.VpnPacket) error { return nil }, nil,
		)
		if err != nil {
			return nil, err
		}
		if err := commit(); err != nil {
			revoke()
			return nil, err
		}
		if err := finalize(); err != nil {
			revoke()
			return nil, err
		}
		ref := coretransport.SessionRef{ClientID: 77, Generation: generation}
		if !srv.beginSessionReady(ref) || !srv.markSessionReady(ref) {
			revoke()
			return nil, errors.New("session did not become ready")
		}
		return revoke, nil
	}

	revokeFirst, err := activate(1)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeFirst()
	registry := srv.getActiveSessions()
	registry.mu.Lock()
	registry.cleanupSlots = make(chan struct{}, 1)
	registry.cleanupSlots <- struct{}{}
	registry.mu.Unlock()
	defer func() { <-registry.cleanupSlots }()

	commit, finalize, revokeSecond, err := sessions.ActivateControlSession(
		context.Background(), nil,
		SessionContext{ClientID: 77, Generation: 2},
		func(*vpnpacket.VpnPacket) error { return nil }, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeSecond()
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if err := finalize(); !errors.Is(err, errResourceLimit) {
		t.Fatalf("finalize error = %v, want resource limit", err)
	}
	if current, ok := srv.CurrentSession(77); ok {
		t.Fatalf("server retained session %+v after finalize failure", current)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := staged.registry.Current(77, time.Now()); !ok {
			break
		}
		if time.Now().After(deadline) {
			current, _ := staged.registry.Current(77, time.Now())
			t.Fatalf("transport retained session %+v after finalize failure", current)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestControlSessionRevokeDisablesTransportBeforeCleanup(t *testing.T) {
	resources := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	srv := &Server{resources: resources}
	workersStarted := make(chan struct{}, defaultSessionReclaimWorkers)
	releaseWorkers := make(chan struct{})
	var releaseWorkersOnce sync.Once
	defer func() {
		releaseWorkersOnce.Do(func() { close(releaseWorkers) })
		srv.stopSessionReclaimer()
	}()
	for range defaultSessionReclaimWorkers {
		srv.reclaimSession(func() {
			workersStarted <- struct{}{}
			<-releaseWorkers
		})
	}
	for range defaultSessionReclaimWorkers {
		select {
		case <-workersStarted:
		case <-time.After(time.Second):
			t.Fatal("session cleanup worker did not start")
		}
	}
	staged := &registryStagedTransport{registry: coretransport.NewSessionRegistry()}
	sessions := &streamControlSessions{server: srv, transport: staged}
	cleanupStarted := make(chan struct{})
	cleanupFinished := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var releaseCleanupOnce sync.Once
	defer releaseCleanupOnce.Do(func() { close(releaseCleanup) })
	var token [coretransport.DataTokenSize]byte

	commit, finalize, revoke, err := sessions.ActivateControlSession(
		context.Background(), nil,
		SessionContext{ClientID: 77, Generation: 1},
		func(packet *vpnpacket.VpnPacket) error {
			copy(token[:], packet.SessionDataToken)
			return nil
		},
		func() {
			defer close(cleanupFinished)
			close(cleanupStarted)
			<-releaseCleanup
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if err := finalize(); err != nil {
		t.Fatal(err)
	}
	ref := coretransport.SessionRef{ClientID: 77, Generation: 1}
	if authenticated, ok := staged.registry.Authenticate(ref.ClientID, token, time.Now()); !ok || authenticated != ref {
		t.Fatal("transport token did not authenticate before revocation")
	}

	revoked := make(chan struct{})
	go func() {
		revoke()
		close(revoked)
	}()
	select {
	case <-revoked:
	case <-time.After(time.Second):
		t.Fatal("session revocation waited for physical cleanup workers")
	}
	if authenticated, ok := staged.registry.Authenticate(ref.ClientID, token, time.Now()); ok {
		t.Fatalf("transport token still authenticated as %+v while cleanup workers are blocked", authenticated)
	}
	if revokes := staged.revokes.Load(); revokes != 1 {
		t.Fatalf("transport revoke calls = %d, want 1", revokes)
	}
	select {
	case <-cleanupStarted:
		t.Fatal("physical session cleanup bypassed occupied workers")
	default:
	}
	releaseWorkersOnce.Do(func() { close(releaseWorkers) })
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("session cleanup did not start after workers were released")
	}
	releaseCleanupOnce.Do(func() { close(releaseCleanup) })
	select {
	case <-cleanupFinished:
	case <-time.After(time.Second):
		t.Fatal("session cleanup did not finish")
	}
}

type registryStagedTransport struct {
	registry *coretransport.SessionRegistry
	revokes  atomic.Int32
}

func (*registryStagedTransport) Serve(context.Context, coretransport.ControlHandler, coretransport.StreamHandler) error {
	return nil
}

func (t *registryStagedTransport) Activate(_ context.Context, grant coretransport.SessionGrant) error {
	return t.registry.Activate(grant, time.Now())
}

func (t *registryStagedTransport) Prepare(_ context.Context, grant coretransport.SessionGrant) error {
	return t.registry.Prepare(grant, time.Now())
}

func (t *registryStagedTransport) Commit(_ context.Context, ref coretransport.SessionRef) error {
	_, _, _, err := t.registry.Commit(ref, time.Now())
	return err
}

func (t *registryStagedTransport) Finalize(_ context.Context, ref coretransport.SessionRef) error {
	_, _, err := t.registry.Finalize(ref)
	return err
}

func (t *registryStagedTransport) Revoke(_ context.Context, ref coretransport.SessionRef) error {
	t.revokes.Add(1)
	t.registry.Revoke(ref)
	return nil
}

func (*registryStagedTransport) Addr() net.Addr { return nil }
func (*registryStagedTransport) Close() error   { return nil }

type failWriteConn struct {
	net.Conn
	failAt int
	writes int
	err    error
}

func (c *failWriteConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes == c.failAt {
		return 0, c.err
	}
	return c.Conn.Write(p)
}
