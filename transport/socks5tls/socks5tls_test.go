// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestNormalizeTLSConfigUsesFullSizedRecords(t *testing.T) {
	clientInput := &tls.Config{ServerName: "example.com"}
	clientConfig, err := normalizeClientTLSConfig(clientInput)
	if err != nil {
		t.Fatal(err)
	}
	if !clientConfig.DynamicRecordSizingDisabled {
		t.Fatal("client TLS dynamic record sizing is enabled")
	}
	if clientInput.DynamicRecordSizingDisabled {
		t.Fatal("client TLS input config was mutated")
	}

	serverInput, _ := testTLSConfigs(t)
	serverConfig, err := normalizeServerTLSConfig(serverInput)
	if err != nil {
		t.Fatal(err)
	}
	if !serverConfig.DynamicRecordSizingDisabled {
		t.Fatal("server TLS dynamic record sizing is enabled")
	}
	if serverInput.DynamicRecordSizingDisabled {
		t.Fatal("server TLS input config was mutated")
	}
}

func TestServerTLSConfigDisablesAES128GCM(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  listener,
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	hello := &tls.ClientHelloInfo{CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
	}}
	if _, err := server.tlsConfig.GetConfigForClient(hello); err != nil {
		t.Fatal(err)
	}
	if hello.CipherSuites[0] == tls.TLS_AES_128_GCM_SHA256 || hello.CipherSuites[1] != tls.TLS_AES_256_GCM_SHA384 {
		t.Fatalf("server TLS cipher suites = %x", hello.CipherSuites)
	}
	if err := validateNegotiatedCipherSuite(tls.TLS_AES_128_GCM_SHA256); err == nil {
		t.Fatal("negotiated TLS AES-128-GCM was accepted")
	}
	if err := validateNegotiatedCipherSuite(tls.TLS_AES_256_GCM_SHA384); err != nil {
		t.Fatalf("negotiated TLS AES-256-GCM was rejected: %v", err)
	}
}

func TestClientServerControlAndStreamLifecycle(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	var negotiatedCipherSuite uint16
	clientTLS.VerifyConnection = func(state tls.ConnectionState) error {
		negotiatedCipherSuite = state.CipherSuite
		return nil
	}
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  listener,
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(ctx,
			coretransport.ControlHandlerFunc(echoControl),
			coretransport.StreamHandlerFunc(openEchoStream),
		)
	}()

	client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Address:   listener.Addr().String(),
		TLSConfig: clientTLS,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	control, err := client.DialControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if negotiatedCipherSuite == tls.TLS_AES_128_GCM_SHA256 {
		t.Fatal("control connection negotiated TLS AES-128-GCM")
	}
	if _, err := control.Write([]byte("auth")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := control.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "auth" {
		t.Fatalf("control response = %q", buf[:n])
	}
	_ = control.Close()

	now := time.Now()
	grant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(ctx, grant); err != nil {
		t.Fatal(err)
	}
	stream := dialAndCheckEcho(t, ctx, client, "first")

	if err := server.Revoke(ctx, grant.SessionRef); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(buf); err == nil {
		t.Fatal("revocation did not close the active stream")
	}
	if _, err := client.DialStream(ctx, testDestination()); err == nil {
		t.Fatal("revoked session opened a new stream")
	}

	replacement, err := coretransport.NewSessionGrant(1001, 2, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacementStream := dialAndCheckEcho(t, ctx, client, "replacement")
	_ = replacementStream.Close()

	cancel()
	_ = server.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerClockMayReenterSessionMethods(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	var callback func()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
		now: func() time.Time {
			if callback != nil {
				callback()
			}
			return time.Now()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	callback = func() {
		once.Do(func() { _ = server.Revoke(context.Background(), grant.SessionRef) })
	}
	done := make(chan error, 1)
	go func() { done <- server.Prepare(context.Background(), grant) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("clock callback reentry deadlocked session preparation")
	}
}

func TestServerContainsClockPanic(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
		now:       func() time.Time { panic("clock panic") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Prepare(context.Background(), grant); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Prepare() error = %v, want extension panic", err)
	}
}

func TestServerActivateRollsBackFailedCommit(t *testing.T) {
	now := time.Now()
	clockCalls := 0
	panicOnSecondCall := true
	server := &Server{
		registry: coretransport.NewSessionRegistry(),
		now: func() time.Time {
			clockCalls++
			if panicOnSecondCall && clockCalls == 2 {
				panic("clock panic")
			}
			return now
		},
	}
	grant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grant); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Activate() error = %v, want extension panic", err)
	}
	panicOnSecondCall = false
	if err := server.Prepare(context.Background(), grant); err != nil {
		t.Fatalf("Prepare() after failed activation = %v", err)
	}
}

func TestBufferedConnForwardsCloseWrite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	underlying := &recordingCloseWriter{Conn: left}
	conn := &bufferedConn{Conn: underlying, reader: left}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !underlying.called {
		t.Fatal("CloseWrite was not forwarded to the TLS stream")
	}
}

func TestSessionExpiryClosesActiveStream(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	grant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer peer.Close()
	flow := &streamFlow{client: client}
	server.trackFlow(grant.SessionRef, flow, true)
	defer server.trackFlow(grant.SessionRef, flow, false)

	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("session expiry did not close the active stream")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("timed out waiting for session expiry")
	}
}

func TestServeWaitsForSessionExpiryClose(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx,
			coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error { return nil }),
			coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				return nil, net.ErrClosed
			}),
		)
	}()

	grant, err := coretransport.NewSessionGrant(1002, 1, time.Now(), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer peer.Close()
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseClose) })
	server.trackFlow(grant.SessionRef, &streamFlow{client: &blockingCloseConn{
		Conn:    client,
		started: closeStarted,
		release: releaseClose,
	}}, true)

	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("session expiry cleanup did not start")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		t.Fatalf("Serve returned before blocked expiry close finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseClose) })
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after expiry close finished")
	}
}

func TestRevocationClosesOnlyTheExactSessionFlows(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	grantA, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grantB, err := coretransport.NewSessionGrant(2002, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grantA); err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), grantB); err != nil {
		t.Fatal(err)
	}
	clientA, peerA := net.Pipe()
	clientB, peerB := net.Pipe()
	defer peerA.Close()
	defer peerB.Close()
	flowA := &streamFlow{client: clientA}
	flowB := &streamFlow{client: clientB}
	server.trackFlow(grantA.SessionRef, flowA, true)
	server.trackFlow(grantB.SessionRef, flowB, true)
	defer server.trackFlow(grantA.SessionRef, flowA, false)
	defer server.trackFlow(grantB.SessionRef, flowB, false)
	if err := peerA.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peerB.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if err := server.Revoke(context.Background(), grantA.SessionRef); err != nil {
		t.Fatal(err)
	}
	if _, err := peerA.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked client A flow remained open")
	}
	if _, ok := server.registry.Authenticate(grantA.ClientID, grantA.DataToken, time.Now()); ok {
		t.Fatal("revoked client A token remained valid")
	}
	if ref, ok := server.registry.Authenticate(grantB.ClientID, grantB.DataToken, time.Now()); !ok || ref != grantB.SessionRef {
		t.Fatalf("client B token was affected: ref=%+v ok=%v", ref, ok)
	}
	if _, err := peerB.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data on client B flow")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("client B flow was closed by client A revoke: %v", err)
	}
}

func TestSessionReplacementClosesOldTCPFlows(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Listener:  newPipeListener(),
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	if err := oldPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	oldFlow := &streamFlow{client: oldConn}
	server.trackFlow(oldGrant.SessionRef, oldFlow, true)
	defer server.trackFlow(oldGrant.SessionRef, oldFlow, false)

	if err := server.Activate(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if _, err := oldPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("replaced session's TCP flow remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("timed out waiting for replaced TCP flow to close")
	}
	if _, ok := server.registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, time.Now()); ok {
		t.Fatal("old session token remained valid after replacement")
	}
	if ref, ok := server.registry.Authenticate(newGrant.ClientID, newGrant.DataToken, time.Now()); !ok || ref != newGrant.SessionRef {
		t.Fatalf("replacement token is not current: ref=%+v ok=%v", ref, ok)
	}
}

func TestFlowRegistrationCannotRecreateReplacedGeneration(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	oldFlow := &streamFlow{}
	if server.trackCurrentFlow(oldGrant.SessionRef, oldFlow, now) {
		t.Fatal("replaced generation accepted a late flow")
	}
	server.connMu.Lock()
	_, retainedOld := server.flows[oldGrant.SessionRef]
	server.connMu.Unlock()
	if retainedOld {
		t.Fatal("late flow recreated the replaced generation")
	}
	newFlow := &streamFlow{}
	if !server.trackCurrentFlow(newGrant.SessionRef, newFlow, now) {
		t.Fatal("current generation rejected a flow")
	}
	server.trackFlow(newGrant.SessionRef, newFlow, false)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if server.trackCurrentFlow(newGrant.SessionRef, &streamFlow{}, now) {
		t.Fatal("closed server accepted a late flow")
	}
}

func TestPreparedSessionDoesNotAuthenticateOrCloseCurrentFlow(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	flow := &streamFlow{client: oldConn}
	server.trackFlow(oldGrant.SessionRef, flow, true)
	defer server.trackFlow(oldGrant.SessionRef, flow, false)
	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.registry.Authenticate(newGrant.ClientID, newGrant.DataToken, time.Now()); ok {
		t.Fatal("prepared SOCKS token authenticated before commit")
	}
	if ref, ok := server.registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, time.Now()); !ok || ref != oldGrant.SessionRef {
		t.Fatal("preparing SOCKS token revoked current token")
	}
	if err := oldPeer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := oldPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("current flow closed while replacement was only prepared")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("current flow read after prepare = %v", err)
	}
}

func TestSessionReplacementClosesFlowsOutsideSessionLock(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer peer.Close()
	reentrant := &reentrantCloseConn{Conn: client}
	reentrant.onClose = func() { _ = server.Revoke(context.Background(), oldGrant.SessionRef) }
	flow := &streamFlow{client: reentrant}
	server.trackFlow(oldGrant.SessionRef, flow, true)
	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
			done <- err
			return
		}
		done <- server.Finalize(context.Background(), newGrant.SessionRef)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session replacement deadlocked while closing an old flow")
	}
}

func TestSessionFinalizeDoesNotWaitForOldFlowClose(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer peer.Close()
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	releaseOldFlow := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	defer releaseOldFlow()
	flow := &streamFlow{client: &blockingCloseConn{
		Conn:    client,
		started: closeStarted,
		release: releaseClose,
	}}
	server.trackFlow(oldGrant.SessionRef, flow, true)
	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	finalized := make(chan error, 1)
	go func() { finalized <- server.Finalize(context.Background(), newGrant.SessionRef) }()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old flow close did not start")
	}
	select {
	case err := <-finalized:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("session finalization waited for the old flow to close")
	}
	if ref, ok := server.registry.Authenticate(newGrant.ClientID, newGrant.DataToken, time.Now()); !ok || ref != newGrant.SessionRef {
		t.Fatal("new session was not current while the old flow was closing")
	}
	server.cleanupMu.Lock()
	cleanups := len(server.cleanupByClient)
	cleanupWorkers := len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanups != 0 || cleanupWorkers != 0 {
		t.Fatalf("session cleanup ownership = %d clients, %d workers", cleanups, cleanupWorkers)
	}
	thirdGrant, err := coretransport.NewSessionGrant(1001, 3, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Prepare(context.Background(), thirdGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Commit(context.Background(), thirdGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if err := server.Finalize(context.Background(), thirdGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if ref, ok := server.registry.Authenticate(thirdGrant.ClientID, thirdGrant.DataToken, time.Now()); !ok || ref != thirdGrant.SessionRef {
		t.Fatal("later replacement did not become current")
	}
	releaseOldFlow()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("old flow remained open")
		}
	} else if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	server.cleanupMu.Lock()
	cleanups = len(server.cleanupByClient)
	cleanupWorkers = len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanups != 0 || cleanupWorkers != 0 {
		t.Fatalf("session cleanup ownership = %d clients, %d workers", cleanups, cleanupWorkers)
	}
}

func TestBlockedFlowReclaimsDoNotExhaustSessionCleanup(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	server.cleanupSlots = make(chan struct{}, 2)
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	now := time.Now()
	peers := make([]net.Conn, 0, 2)
	for i := range 2 {
		clientID := uint64(1001 + i)
		oldGrant, err := coretransport.NewSessionGrant(clientID, 1, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		newGrant, err := coretransport.NewSessionGrant(clientID, 2, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Activate(context.Background(), oldGrant); err != nil {
			t.Fatal(err)
		}
		target, peer := net.Pipe()
		peers = append(peers, peer)
		closeStarted := make(chan struct{})
		flowCtx, cancelFlow := context.WithCancel(context.Background())
		server.trackFlow(oldGrant.SessionRef, &streamFlow{
			cancel: cancelFlow,
			target: &blockingCloseConn{
				Conn:    target,
				started: closeStarted,
				release: releaseClose,
			},
		}, true)
		if err := server.Prepare(context.Background(), newGrant); err != nil {
			t.Fatal(err)
		}
		if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
			t.Fatal(err)
		}
		if err := server.Finalize(context.Background(), newGrant.SessionRef); err != nil {
			t.Fatal(err)
		}
		select {
		case <-flowCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("old flow was not canceled")
		}
		select {
		case <-closeStarted:
		case <-time.After(time.Second):
			t.Fatal("old flow close did not start")
		}
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	server.cleanupMu.Lock()
	cleanups := len(server.cleanupByClient)
	cleanupWorkers := len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanups != 0 || cleanupWorkers != 0 {
		t.Fatalf("blocked cleanup ownership = %d clients, %d workers", cleanups, cleanupWorkers)
	}
	healthy, err := coretransport.NewSessionGrant(9001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), healthy); err != nil {
		t.Fatal(err)
	}
	if ref, ok := server.registry.Authenticate(healthy.ClientID, healthy.DataToken, time.Now()); !ok || ref != healthy.SessionRef {
		t.Fatal("healthy session did not become current")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited for blocked flow reclamation")
	}
	release()
}

func TestSessionReplacementCancelsAllOldFlowsBeforeCloseReturns(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	blockedTarget, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	indexedAtCancel := make(chan bool, 2)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	firstCancel := func() {
		_, indexed := server.flows[oldGrant.SessionRef]
		indexedAtCancel <- indexed
		cancelFirst()
	}
	secondCancel := func() {
		_, indexed := server.flows[oldGrant.SessionRef]
		indexedAtCancel <- indexed
		cancelSecond()
	}
	firstFlow := &streamFlow{
		cancel: firstCancel,
		target: &blockingCloseConn{
			Conn:    blockedTarget,
			started: closeStarted,
			release: releaseClose,
		},
	}
	secondFlow := &streamFlow{cancel: secondCancel}
	server.trackFlow(oldGrant.SessionRef, firstFlow, true)
	server.trackFlow(oldGrant.SessionRef, secondFlow, true)

	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if err := server.Finalize(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old flow close did not start")
	}
	for range 2 {
		if !<-indexedAtCancel {
			t.Fatal("old generation was removed before every flow was canceled")
		}
	}
	for name, flowCtx := range map[string]context.Context{"first": firstCtx, "second": secondCtx} {
		select {
		case <-flowCtx.Done():
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("%s old flow was not canceled before a sibling Close blocked", name)
		}
	}
	if ref, ok := server.registry.Authenticate(newGrant.ClientID, newGrant.DataToken, time.Now()); !ok || ref != newGrant.SessionRef {
		t.Fatalf("replacement token is not current: ref=%+v ok=%v", ref, ok)
	}
	if _, ok := server.registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, time.Now()); ok {
		t.Fatal("old token authenticated while cleanup was blocked")
	}
	server.cleanupMu.Lock()
	_, cleanupOwned := server.cleanupByClient[oldGrant.ClientID]
	cleanupWorkers := len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanupOwned || cleanupWorkers != 0 {
		t.Fatalf("blocked cleanup ownership = %v, workers = %d", cleanupOwned, cleanupWorkers)
	}
	if err := server.Revoke(context.Background(), oldGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if err := server.Revoke(context.Background(), oldGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if err := server.Finalize(context.Background(), newGrant.SessionRef); err == nil || !strings.Contains(err.Error(), "not being committed") {
		t.Fatalf("repeated Finalize error = %v", err)
	}

	lateTarget, latePeer := net.Pipe()
	defer latePeer.Close()
	late := &notifyingCloseConn{Conn: lateTarget, closed: make(chan struct{})}
	if secondFlow.setTarget(late) {
		t.Fatal("canceled flow accepted a late target")
	}
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("late target was not closed")
	}

	release()
	server.wg.Wait()
	server.cleanupMu.Lock()
	cleanups := len(server.cleanupByClient)
	cleanupWorkers = len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanups != 0 || cleanupWorkers != 0 {
		t.Fatalf("completed cleanup ownership = %d clients, %d workers", cleanups, cleanupWorkers)
	}
	server.connMu.Lock()
	remainingOldFlows := len(server.flows[oldGrant.SessionRef])
	server.connMu.Unlock()
	if remainingOldFlows != 0 {
		t.Fatalf("old generation retained %d flows", remainingOldFlows)
	}
	if err := server.Finalize(context.Background(), newGrant.SessionRef); err == nil || !strings.Contains(err.Error(), "not being committed") {
		t.Fatalf("late repeated Finalize error = %v", err)
	}
}

func TestLateFlowTargetAfterCloseUsesReclaimer(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	server.serveMu.Lock()
	server.serving = true
	server.serveMu.Unlock()
	if !server.startWorker() {
		t.Fatal("failed to start test worker")
	}
	flow := &streamFlow{reclaim: server.reclaimConn}
	flow.cancelFlow()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	target, peer := net.Pipe()
	defer peer.Close()
	late := &notifyingCloseConn{Conn: target, closed: make(chan struct{})}
	if flow.setTarget(late) {
		t.Fatal("canceled flow accepted a late target")
	}
	select {
	case <-late.closed:
	case <-time.After(time.Second):
		t.Fatal("late target was not reclaimed after close")
	}
	server.wg.Done()
	server.waitWorkers()
	server.reclaimMu.Lock()
	stopped := server.reclaimStopped
	server.reclaimMu.Unlock()
	if !stopped {
		t.Fatal("flow reclaimer remained active after worker drain")
	}
}

func TestSessionCleanupDoesNotWaitForCloseAlreadyInProgress(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	blockedTarget, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	flow := &streamFlow{target: &blockingCloseConn{
		Conn:    blockedTarget,
		started: closeStarted,
		release: releaseClose,
	}}
	server.trackFlow(oldGrant.SessionRef, flow, true)
	flowCloseDone := make(chan struct{})
	go func() {
		flow.close()
		close(flowCloseDone)
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old flow did not enter Close")
	}

	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if err := server.Finalize(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	cleanupDone := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("session cleanup waited for a Close already in progress")
	}
	server.cleanupMu.Lock()
	_, cleanupOwned := server.cleanupByClient[oldGrant.ClientID]
	cleanupWorkers := len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanupOwned || cleanupWorkers != 0 {
		t.Fatalf("in-progress cleanup ownership = %v, workers = %d", cleanupOwned, cleanupWorkers)
	}

	release()
	select {
	case <-flowCloseDone:
	case <-time.After(time.Second):
		t.Fatal("old flow Close did not finish")
	}
	server.cleanupMu.Lock()
	cleanups := len(server.cleanupByClient)
	cleanupWorkers = len(server.cleanupSlots)
	server.cleanupMu.Unlock()
	if cleanups != 0 || cleanupWorkers != 0 {
		t.Fatalf("completed cleanup ownership = %d clients, %d workers", cleanups, cleanupWorkers)
	}
}

func TestFlowReclaimerBoundsPhysicalCloseConcurrency(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(func() {
		release()
		_ = server.Close()
	})

	started := make([]chan struct{}, defaultFlowReclaimWorkers+1)
	peers := make([]net.Conn, 0, len(started))
	for i := range started {
		target, peer := net.Pipe()
		peers = append(peers, peer)
		started[i] = make(chan struct{})
		server.reclaimFlow(&streamFlow{target: &blockingCloseConn{
			Conn:    target,
			started: started[i],
			release: releaseClose,
		}})
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	for i := range defaultFlowReclaimWorkers {
		select {
		case <-started[i]:
		case <-time.After(time.Second):
			t.Fatalf("flow close %d did not start", i)
		}
	}
	select {
	case <-started[defaultFlowReclaimWorkers]:
		t.Fatal("flow reclaimer exceeded its worker bound")
	case <-time.After(20 * time.Millisecond):
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited for the reclaim workers")
	}
	workersDone := make(chan struct{})
	go func() {
		server.waitWorkers()
		close(workersDone)
	}()
	select {
	case <-workersDone:
		t.Fatal("worker completion ignored active flow cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-started[defaultFlowReclaimWorkers]:
	case <-time.After(time.Second):
		t.Fatal("queued flow close did not drain")
	}
	select {
	case <-workersDone:
	case <-time.After(time.Second):
		t.Fatal("worker completion did not follow drained flow cleanup")
	}
}

func TestFlowReclaimerOwnsEveryAcceptedCleanup(t *testing.T) {
	capacity := defaultFlowReclaimWorkers + 2
	server := &Server{
		reclaimQueue: make(chan flowReclaimTask, capacity),
		reclaimSlots: make(chan struct{}, capacity),
		reclaimStop:  make(chan struct{}),
	}
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(func() {
		release()
		server.stopFlowReclaimer()
	})

	flows := make([]*streamFlow, capacity)
	started := make([]chan struct{}, capacity)
	peers := make([]net.Conn, 0, capacity)
	for i := range flows {
		reclaimDone, ok := server.acquireFlowReclaim()
		if !ok {
			t.Fatalf("cleanup reservation %d was rejected", i)
		}
		target, peer := net.Pipe()
		peers = append(peers, peer)
		started[i] = make(chan struct{})
		flows[i] = &streamFlow{
			client: &blockingCloseConn{
				Conn:    target,
				started: started[i],
				release: releaseClose,
			},
			reclaimDone: reclaimDone,
		}
		server.reclaimFlow(flows[i])
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	for i := range defaultFlowReclaimWorkers {
		select {
		case <-started[i]:
		case <-time.After(time.Second):
			t.Fatalf("flow close %d did not start", i)
		}
	}
	if reclaimDone, ok := server.acquireFlowReclaim(); ok {
		reclaimDone()
		t.Fatal("cleanup capacity accepted an unowned overflow task")
	}
	for _, flow := range flows {
		server.reclaimFlow(flow)
	}
	release()
	for i, flow := range flows {
		select {
		case <-flow.closeSignal():
		case <-time.After(time.Second):
			t.Fatalf("flow close %d was lost", i)
		}
	}
	if got := len(server.reclaimSlots); got != 0 {
		t.Fatalf("cleanup reservations = %d, want 0", got)
	}
}

func TestSessionFinalizeDoesNotJoinServeWorkers(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now()
	oldGrant, err := coretransport.NewSessionGrant(1001, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := coretransport.NewSessionGrant(1001, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Activate(context.Background(), oldGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Prepare(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	if err := server.Commit(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if !server.startWorker() {
		t.Fatal("failed to start test worker")
	}
	waitDone := make(chan struct{})
	go func() {
		server.waitWorkers()
		close(waitDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		server.workerMu.Lock()
		waiting := server.workersDone
		server.workerMu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker wait did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := server.Finalize(context.Background(), newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if current, ok := server.registry.Current(newGrant.ClientID, time.Now()); !ok || current != newGrant.SessionRef {
		t.Fatalf("current session = %+v/%v, want %+v/true", current, ok, newGrant.SessionRef)
	}
	server.wg.Done()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("worker wait did not finish")
	}
}

func TestServerCloseListenerMayReenterClose(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	listener := &reentrantCloseListener{Listener: newPipeListener()}
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	listener.onClose = func() { _ = server.Close() }
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close deadlocked on a reentrant listener")
	}
}

func TestServerCloseCancelsAllFlowsBeforeCloseReturns(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: newPipeListener(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	t.Cleanup(release)

	blockedTarget, blockedPeer := net.Pipe()
	defer blockedPeer.Close()
	firstCtx, firstCancel := context.WithCancel(context.Background())
	secondCtx, secondCancel := context.WithCancel(context.Background())
	server.trackFlow(coretransport.SessionRef{ClientID: 1001, Generation: 1}, &streamFlow{
		cancel: firstCancel,
		target: &blockingCloseConn{
			Conn:    blockedTarget,
			started: closeStarted,
			release: releaseClose,
		},
	}, true)
	server.trackFlow(coretransport.SessionRef{ClientID: 2002, Generation: 1}, &streamFlow{cancel: secondCancel}, true)
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()

	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("global flow close did not start")
	}
	for name, flowCtx := range map[string]context.Context{"first": firstCtx, "second": secondCtx} {
		select {
		case <-flowCtx.Done():
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("%s flow was not canceled before global Close blocked", name)
		}
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited for a blocking flow")
	}
	release()
	server.connMu.Lock()
	remainingFlows := len(server.flows)
	server.connMu.Unlock()
	if remainingFlows != 0 {
		t.Fatalf("Server.Close retained %d flow generations", remainingFlows)
	}
}

func TestStreamFlowCloseMayReenterItself(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	reentrant := &reentrantCloseConn{Conn: client}
	flow := &streamFlow{client: reentrant}
	reentrant.onClose = flow.close
	done := make(chan struct{})
	go func() {
		flow.close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream flow Close deadlocked on reentry")
	}
}

func TestClientRejectsStaleAndCrossClientGrantActivation(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
		Address:   "127.0.0.1:443",
		TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := time.Now()
	newGrant, err := coretransport.NewSessionGrant(100, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(context.Background(), newGrant); err != nil {
		t.Fatal(err)
	}
	staleGrant, err := coretransport.NewSessionGrant(100, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(context.Background(), staleGrant); err == nil {
		t.Fatal("client accepted a stale session generation")
	}
	otherClient, err := coretransport.NewSessionGrant(200, 3, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Activate(context.Background(), otherClient); err == nil {
		t.Fatal("client transport changed ownership to another client ID")
	}
	if client.grant != newGrant {
		t.Fatalf("active grant changed after rejected activation: %+v", client.grant.SessionRef)
	}
}

func TestClientRejectsUnsafeTLSConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *tls.Config
	}{
		{name: "disabled verification", cfg: &tls.Config{InsecureSkipVerify: true}},
		{name: "Rand", cfg: &tls.Config{Rand: rand.Reader}},
		{name: "Time", cfg: &tls.Config{Time: time.Now}},
		{name: "KeyLogWriter", cfg: &tls.Config{KeyLogWriter: io.Discard}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ServerName = "vpn.test"
			client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
				Address:   "127.0.0.1:443",
				TLSConfig: tt.cfg,
			})
			if client != nil {
				defer client.Close()
			}
			if err == nil {
				t.Fatal("client accepted unsafe TLS config")
			}
		})
	}
}

func dialAndCheckEcho(t *testing.T, ctx context.Context, client *Client, payload string) net.Conn {
	t.Helper()
	stream, err := client.DialStream(ctx, testDestination())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte(payload)); err != nil {
		_ = stream.Close()
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, buf); err != nil {
		_ = stream.Close()
		t.Fatal(err)
	}
	if string(buf) != payload {
		_ = stream.Close()
		t.Fatalf("stream response = %q want %q", buf, payload)
	}
	return stream
}

func testDestination() coretransport.Destination {
	return coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    "echo.test",
		Port:    443,
	}
}

func echoControl(_ context.Context, conn net.Conn) error {
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	return err
}

func openEchoStream(_ context.Context, req coretransport.StreamRequest) (net.Conn, error) {
	if req.Target != testDestination() {
		return nil, errors.New("unexpected target")
	}
	left, right := net.Pipe()
	go func() {
		defer right.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := right.Read(buf)
			if n > 0 {
				if _, writeErr := right.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return left, nil
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	return testTLSConfigsWithServerValidity(t, now.Add(-time.Minute), now.Add(time.Hour))
}

func testTLSConfigsWithServerValidity(t *testing.T, serverNotBefore, serverNotAfter time.Time) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Talaria test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vpn.test"},
		DNSNames:     []string{"vpn.test"},
		NotBefore:    serverNotBefore,
		NotAfter:     serverNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate := tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverKey,
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{Certificates: []tls.Certificate{serverCertificate}}, &tls.Config{
		ServerName: "vpn.test",
		RootCAs:    roots,
	}
}

type pipeListener struct {
	accept chan net.Conn
	done   chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		accept: make(chan net.Conn),
		done:   make(chan struct{}),
		addr:   testAddr("pipe:443"),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

func (l *pipeListener) DialContext(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.accept <- server:
		return client, nil
	case <-l.done:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
}

type testAddr string

func (a testAddr) Network() string { return "pipe" }
func (a testAddr) String() string  { return string(a) }

type recordingCloseWriter struct {
	net.Conn
	called bool
}

type reentrantCloseListener struct {
	net.Listener
	onClose func()
}

func (l *reentrantCloseListener) Close() error {
	if l.onClose != nil {
		l.onClose()
	}
	return l.Listener.Close()
}

type reentrantCloseConn struct {
	net.Conn
	onClose func()
}

func (c *reentrantCloseConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() {
		close(c.started)
		<-c.release
	})
	return c.Conn.Close()
}

type notifyingCloseConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *notifyingCloseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *recordingCloseWriter) CloseWrite() error {
	c.called = true
	return nil
}
