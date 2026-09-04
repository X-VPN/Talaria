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
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestActiveSessionReplacementAndRevocationAreGenerationSafe(t *testing.T) {
	srv := &Server{}
	serverConn1, clientConn1 := net.Pipe()
	defer clientConn1.Close()
	serverConn2, clientConn2 := net.Pipe()
	defer clientConn2.Close()
	var revoked1 atomic.Int32
	var revoked2 atomic.Int32
	ref1 := coretransport.SessionRef{ClientID: 7, Generation: 1}
	ref2 := coretransport.SessionRef{ClientID: 7, Generation: 2}

	srv.activateSession(activeServerSessionConfig{
		Ref:        ref1,
		Conn:       serverConn1,
		RevokeData: func() { revoked1.Add(1) },
	})
	srv.activateSession(activeServerSessionConfig{
		Ref:        ref2,
		Conn:       serverConn2,
		RevokeData: func() { revoked2.Add(1) },
	})
	if current, ok := srv.CurrentSession(7); !ok || current != ref2 {
		t.Fatalf("current session = %+v ok=%v", current, ok)
	}
	deadline := time.Now().Add(time.Second)
	for revoked1.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("old generation revoke count = %d want 1", revoked1.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if srv.RevokeSession(ref1, "stale quota response") {
		t.Fatal("stale generation revoked the replacement session")
	}
	if !srv.RevokeSession(ref2, "subscription expired") {
		t.Fatal("current generation was not revoked")
	}
	deadline = time.Now().Add(time.Second)
	for revoked2.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("current generation revoke count = %d want 1", revoked2.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := srv.CurrentSession(7); ok {
		t.Fatal("revoked session remains current")
	}
	if _, err := clientConn1.Read(make([]byte, 1)); err == nil {
		t.Fatal("replaced control connection remains open")
	}
	if _, err := clientConn2.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked control connection remains open")
	}
}

func TestPreparedSessionDoesNotReplaceCurrentBeforeCommit(t *testing.T) {
	srv := &Server{}
	oldRef := coretransport.SessionRef{ClientID: 7, Generation: 1}
	newRef := coretransport.SessionRef{ClientID: 7, Generation: 2}
	old, err := srv.activateSession(activeServerSessionConfig{Ref: oldRef})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(old)
	pending, err := srv.prepareSession(activeServerSessionConfig{Ref: newRef})
	if err != nil {
		t.Fatal(err)
	}
	if current, ok := srv.CurrentSession(7); !ok || current != oldRef {
		t.Fatalf("current while replacement pending = %+v, %v", current, ok)
	}
	srv.releaseSession(pending)
	if current, ok := srv.CurrentSession(7); !ok || current != oldRef {
		t.Fatalf("current after pending rollback = %+v, %v", current, ok)
	}
}

func TestPacketSessionAttachTimeoutReleasesPendingGeneration(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallback()
	var detachCalls atomic.Int32
	srv := &Server{
		resources: newResourceLimiter(limits),
		authSlots: make(chan struct{}, 2),
		handler: &callbackSessionHandler{
			onAttach: func() {
				started <- struct{}{}
				<-release
			},
			detach: func() { detachCalls.Add(1) },
		},
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	firstRef := coretransport.SessionRef{ClientID: 7, Generation: 1}
	firstLease, err := srv.resources.acquireSession(firstRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       firstRef,
		Conn:      serverConn,
		Resources: firstLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, writers := newSessionWriterGate(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
	}, nil, firstRef.ClientID)
	attachDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, attachErr := srv.attachPacketSession(ctx, ctx, SessionContext{
			ClientID:   firstRef.ClientID,
			Generation: firstRef.Generation,
		}, writers)
		srv.releaseSession(first)
		attachDone <- attachErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("packet session attach did not start")
	}
	select {
	case err := <-attachDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attach error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocking packet session attach retained its worker")
	}
	if srv.getActiveSessions().isPending(firstRef) {
		t.Fatal("timed-out packet session remained pending")
	}
	srv.resources.mu.Lock()
	sessions := srv.resources.sessions
	srv.resources.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("session leases after attach timeout = %d, want 0", sessions)
	}
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("timed-out packet session connection remained open")
	}

	secondRef := coretransport.SessionRef{ClientID: firstRef.ClientID, Generation: 2}
	second, err := srv.prepareSession(activeServerSessionConfig{Ref: secondRef})
	if err != nil {
		t.Fatalf("replacement session prepare failed: %v", err)
	}
	defer srv.releaseSession(second)
	releaseCallback()
	deadline := time.Now().Add(time.Second)
	for detachCalls.Load() != 1 || len(srv.authSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("late attach cleanup = %d detaches, %d workers", detachCalls.Load(), len(srv.authSlots))
		}
		time.Sleep(time.Millisecond)
	}
	if !srv.getActiveSessions().isPending(secondRef) {
		t.Fatal("late first-generation cleanup removed the replacement")
	}
}

func TestPacketSessionAttachWorkerSourceLimitSurvivesTimeout(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{MaxPendingAuth: 4, MaxPendingAuthPerSource: 2})
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	started := make(chan struct{}, 3)
	srv := &Server{
		resources: newResourceLimiter(limits),
		authSlots: make(chan struct{}, limits.MaxPendingAuth),
		handler: &callbackSessionHandler{onAttach: func() {
			started <- struct{}{}
			<-release
		}},
	}
	writers := SessionWriters{Packet: func(*vpnpacket.VpnPacket) error { return nil }}
	callBlocked := func(source string, clientID uint64) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		_, _, callErr := srv.callPacketSessionAttach(ctx, ctx, SessionContext{
			ClientID: clientID, RemoteIP: source,
		}, writers)
		if !errors.Is(callErr, context.DeadlineExceeded) {
			t.Fatalf("blocking attach error = %v, want deadline exceeded", callErr)
		}
		select {
		case <-started:
		default:
			t.Fatal("packet session attach callback did not start")
		}
	}
	callBlocked("192.0.2.1", 1)
	callBlocked("192.0.2.1", 2)
	if _, _, err := srv.callPacketSessionAttach(context.Background(), context.Background(), SessionContext{
		ClientID: 3, RemoteIP: "192.0.2.1",
	}, writers); !errors.Is(err, errResourceLimit) {
		t.Fatalf("source worker overflow error = %v, want resource limit", err)
	}
	callBlocked("192.0.2.2", 4)
	if got := len(srv.authSlots); got != 3 {
		t.Fatalf("attach workers = %d, want 3", got)
	}

	releaseAll()
	deadline := time.Now().Add(time.Second)
	for {
		srv.resources.mu.Lock()
		owners := len(srv.resources.authWorkersBySource)
		srv.resources.mu.Unlock()
		if len(srv.authSlots) == 0 && owners == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("attach worker ownership was not released: slots=%d sources=%d", len(srv.authSlots), owners)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPacketSessionAttachReleasesWorkerBeforeExpiredDetach(t *testing.T) {
	limits, err := normalizeResourceLimits(ResourceLimits{MaxPendingAuth: 2, MaxPendingAuthPerSource: 1})
	if err != nil {
		t.Fatal(err)
	}
	detachStarted := make(chan struct{})
	releaseDetach := make(chan struct{})
	var detachOnce sync.Once
	srv := &Server{
		resources: newResourceLimiter(limits),
		authSlots: make(chan struct{}, limits.MaxPendingAuth),
		handler: &callbackSessionHandler{detach: func() {
			detachOnce.Do(func() { close(detachStarted) })
			<-releaseDetach
		}},
	}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	binding, err := srv.prepareSession(activeServerSessionConfig{Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelOnSecondErrContext{Context: context.Background()}
	done := make(chan error, 1)
	go func() {
		_, attachErr := srv.attachPacketSession(ctx, ctx, SessionContext{
			ClientID: ref.ClientID, Generation: ref.Generation, RemoteIP: "192.0.2.1",
		}, SessionWriters{Packet: func(*vpnpacket.VpnPacket) error { return nil }})
		done <- attachErr
	}()
	select {
	case <-detachStarted:
	case <-time.After(time.Second):
		close(releaseDetach)
		t.Fatal("expired attach detach did not start")
	}
	defer func() {
		close(releaseDetach)
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("expired attach error = %v, want context canceled", err)
		}
		srv.releaseSession(binding)
		srv.stopSessionReclaimer()
	}()

	detach, releaseWorker, err := srv.callPacketSessionAttach(context.Background(), context.Background(), SessionContext{
		ClientID: 8, RemoteIP: "192.0.2.1",
	}, SessionWriters{Packet: func(*vpnpacket.VpnPacket) error { return nil }})
	if err != nil {
		t.Fatalf("same-source attach during blocked detach = %v", err)
	}
	releaseWorker()
	srv.reclaimSession(func() { srv.runPacketSessionDetach("test packet handler detach", detach) })
	if len(srv.authSlots) != 0 {
		t.Fatalf("auth workers during blocked detach = %d, want 0", len(srv.authSlots))
	}
}

func TestPreparedSessionRollbackRestoresCurrentResourceLease(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	oldLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 1},
		Resources: oldLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(old)
	pendingLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 2},
		Resources: pendingLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.releaseSession(pending)
	limiter.mu.Lock()
	owner := limiter.sessionOwners[7]
	sessions := limiter.sessions
	limiter.mu.Unlock()
	if owner != oldLease.token || sessions != 1 {
		t.Fatalf("resource owner/session count after rollback = %d/%d, want %d/1", owner, sessions, oldLease.token)
	}
}

func TestPromotedSessionRollbackRestoresCurrentResourceLease(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	oldRef := coretransport.SessionRef{ClientID: 7, Generation: 1}
	oldLease, err := limiter.acquireSession(oldRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	old, err := srv.activateSession(activeServerSessionConfig{Ref: oldRef, Resources: oldLease})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(old)
	newRef := coretransport.SessionRef{ClientID: oldRef.ClientID, Generation: 2}
	newLease, err := limiter.acquireSession(newRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := srv.prepareSession(activeServerSessionConfig{Ref: newRef, Resources: newLease})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.commitSession(pending); err != nil {
		t.Fatal(err)
	}
	if current, ok := srv.CurrentSession(oldRef.ClientID); !ok || current != oldRef {
		t.Fatalf("current during promotion = %+v/%v, want %+v/true", current, ok, oldRef)
	}
	srv.releaseSession(pending)
	if current, ok := srv.CurrentSession(oldRef.ClientID); !ok || current != oldRef {
		t.Fatalf("current after promotion rollback = %+v/%v, want %+v/true", current, ok, oldRef)
	}
	limiter.mu.Lock()
	owner := limiter.sessionOwners[oldRef.ClientID]
	sessions := limiter.sessions
	limiter.mu.Unlock()
	if owner != oldLease.token || sessions != 1 {
		t.Fatalf("resource owner/session count after promotion rollback = %d/%d, want %d/1", owner, sessions, oldLease.token)
	}
}

func TestExpiredCommittedSessionFinalizesBeforeRevocation(t *testing.T) {
	srv := &Server{}
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 7, Generation: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 2},
		ExpiresAt: time.Now().Add(20 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.commitSession(candidate); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if err := srv.finalizeSession(candidate); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !old.closed.Load() || !candidate.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("finalized expiry left sessions open: old=%t candidate=%t", old.closed.Load(), candidate.closed.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFinalizeSessionDoesNotWaitForPreviousClose(t *testing.T) {
	srv := &Server{}
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	oldLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	closeFinished := make(chan struct{})
	releaseClose := make(chan struct{})
	var closeOnce sync.Once
	var releaseOnce sync.Once
	releasePrevious := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	defer releasePrevious()
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 1},
		Resources: oldLease,
		RevokeData: func() {
			defer close(closeFinished)
			closeOnce.Do(func() { close(closeStarted) })
			<-releaseClose
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidateLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 2},
		Resources: candidateLease,
		RevokeData: func() {
			<-releaseClose
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.commitSession(candidate); err != nil {
		t.Fatal(err)
	}
	finalized := make(chan error, 1)
	go func() { finalized <- srv.finalizeSession(candidate) }()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("previous session close did not start")
	}
	select {
	case err := <-finalized:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("session finalization waited for the previous session to close")
	}
	if !srv.markSessionReady(candidate.Ref) {
		t.Fatal("finalized session could not become ready")
	}
	if current, ok := srv.CurrentSession(7); !ok || current != candidate.Ref {
		t.Fatalf("current session = %+v/%v, want %+v/true", current, ok, candidate.Ref)
	}
	cleanupDone := make(chan struct{})
	go func() {
		srv.runWG.Wait()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("server worker accounting retained physical session cleanup")
	}
	limiter.mu.Lock()
	tokens := len(limiter.sessionTokens)
	limiter.mu.Unlock()
	if tokens != 1 {
		t.Fatalf("session resource tokens while old close is blocked = %d, want 1", tokens)
	}
	thirdLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	third, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 3},
		Resources: thirdLease,
	})
	if err != nil {
		thirdLease.rollback()
		t.Fatal(err)
	}
	if err := srv.commitSession(third); err != nil {
		t.Fatal(err)
	}
	if err := srv.finalizeSession(third); err != nil {
		t.Fatal(err)
	}
	if !srv.markSessionReady(third.Ref) {
		t.Fatal("third session could not become ready")
	}
	if current, ok := srv.CurrentSession(7); !ok || current != third.Ref {
		t.Fatalf("current session during blocked cleanup = %+v/%v, want %+v/true", current, ok, third.Ref)
	}
	releasePrevious()
	select {
	case <-closeFinished:
	case <-time.After(time.Second):
		t.Fatal("previous session did not finish closing")
	}
	if !old.closed.Load() {
		t.Fatal("previous session remained open")
	}
	registry := srv.getActiveSessions()
	registry.mu.RLock()
	cleanups := len(registry.cleanup)
	registry.mu.RUnlock()
	if cleanups != 0 || len(registry.cleanupSlots) != 0 {
		t.Fatalf("session cleanup ownership = %d clients, %d workers", cleanups, len(registry.cleanupSlots))
	}
	limiter.mu.Lock()
	tokens = len(limiter.sessionTokens)
	limiter.mu.Unlock()
	if tokens != 1 {
		t.Fatalf("session resource tokens after old cleanup = %d, want 1", tokens)
	}
	srv.releaseSession(third)
}

func TestBlockedSessionReclaimsDoNotExhaustLogicalCapacity(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: defaultSessionReclaimWorkers + 2})
	srv := &Server{resources: limiter}
	registry := srv.getActiveSessions()
	registry.cleanupSlots = make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseAll()
		_ = srv.Close()
	})

	blocked := defaultSessionReclaimWorkers + 1
	started := make([]chan struct{}, blocked)
	finished := make([]chan struct{}, blocked)
	for i := range blocked {
		clientID := uint64(1001 + i)
		oldLease, err := limiter.acquireSession(clientID)
		if err != nil {
			t.Fatal(err)
		}
		canceled := make(chan struct{})
		started[i] = make(chan struct{})
		finished[i] = make(chan struct{})
		if _, err := srv.activateSession(activeServerSessionConfig{
			Ref:        coretransport.SessionRef{ClientID: clientID, Generation: 1},
			Resources:  oldLease,
			CancelData: func() { close(canceled) },
			RevokeData: func() {
				close(started[i])
				<-release
				close(finished[i])
			},
		}); err != nil {
			t.Fatal(err)
		}
		replacementLease, err := limiter.acquireSession(clientID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.activateSession(activeServerSessionConfig{
			Ref:       coretransport.SessionRef{ClientID: clientID, Generation: 2},
			Resources: replacementLease,
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("old session was not canceled during replacement")
		}
	}
	for i := range defaultSessionReclaimWorkers {
		select {
		case <-started[i]:
		case <-time.After(time.Second):
			t.Fatalf("session reclaim %d did not start", i)
		}
	}
	select {
	case <-started[defaultSessionReclaimWorkers]:
		t.Fatal("session reclaimer exceeded its worker bound")
	case <-time.After(20 * time.Millisecond):
	}
	registry.mu.RLock()
	cleanups := len(registry.cleanup)
	registry.mu.RUnlock()
	if cleanups != 0 || len(registry.cleanupSlots) != 0 {
		t.Fatalf("logical cleanup ownership = %d clients, %d slots", cleanups, len(registry.cleanupSlots))
	}

	healthyID := uint64(9001)
	healthyLease, err := limiter.acquireSession(healthyID)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := srv.activateSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: healthyID, Generation: 1},
		Resources: healthyLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	if current, ok := srv.CurrentSession(healthyID); !ok || current != healthy.Ref {
		t.Fatal("healthy session did not become current")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	limiter.mu.Lock()
	sessions := limiter.sessions
	tokens := len(limiter.sessionTokens)
	limiter.mu.Unlock()
	if sessions != 0 || tokens != 0 {
		t.Fatalf("session accounting after close = %d sessions, %d tokens", sessions, tokens)
	}
	releaseAll()
	for i := range blocked {
		select {
		case <-finished[i]:
		case <-time.After(time.Second):
			t.Fatalf("session reclaim %d did not finish", i)
		}
	}
}

func TestSessionReclaimerOwnsEveryAcceptedCleanup(t *testing.T) {
	capacity := defaultSessionReclaimWorkers + 2
	srv := &Server{
		sessionReclaimQueue: make(chan sessionReclaimTask, capacity),
		sessionReclaimSlots: make(chan struct{}, capacity),
		sessionReclaimStop:  make(chan struct{}),
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseAll()
		srv.stopSessionReclaimer()
	})

	started := make(chan struct{}, capacity)
	var finished atomic.Int32
	for i := 0; i < capacity; i++ {
		reclaimDone, ok := srv.acquireSessionReclaim()
		if !ok {
			t.Fatalf("session cleanup reservation %d was rejected", i)
		}
		srv.reclaimOwnedSession(func() {
			started <- struct{}{}
			<-release
			finished.Add(1)
		}, reclaimDone)
	}
	for range defaultSessionReclaimWorkers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("session cleanup worker did not start")
		}
	}
	if _, err := srv.prepareSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 7001, Generation: 1},
	}); !errors.Is(err, errResourceLimit) {
		t.Fatalf("session admission at cleanup capacity = %v, want resource limit", err)
	}
	releaseAll()
	deadline := time.Now().Add(time.Second)
	for finished.Load() != int32(capacity) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := finished.Load(); got != int32(capacity) {
		t.Fatalf("completed session cleanups = %d, want %d", got, capacity)
	}
	if got := len(srv.sessionReclaimSlots); got != 0 {
		t.Fatalf("session cleanup reservations = %d, want 0", got)
	}
}

func TestBlockingSessionCleanupReleasesResourceOwnership(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	srv := &Server{resources: limiter}
	lease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStarted := make(chan struct{})
	cleanupFinished := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var startedOnce sync.Once
	binding, err := srv.activateSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 1},
		Resources: lease,
		RevokeData: func() {
			defer close(cleanupFinished)
			startedOnce.Do(func() { close(cleanupStarted) })
			<-releaseCleanup
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		srv.releaseSession(binding)
		close(released)
	}()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		close(releaseCleanup)
		t.Fatal("session cleanup did not start")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("session release waited for physical cleanup")
	}
	defer func() {
		select {
		case <-releaseCleanup:
		default:
			close(releaseCleanup)
		}
		<-cleanupFinished
		srv.stopSessionReclaimer()
	}()

	limiter.mu.Lock()
	sessions := limiter.sessions
	limiter.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("session resources during blocked cleanup = %d, want 0", sessions)
	}

	replacementLease, err := limiter.acquireSession(7)
	if err != nil {
		t.Fatal(err)
	}
	replacement, prepareErr := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 7, Generation: 2},
		Resources: replacementLease,
	})
	if prepareErr != nil {
		replacementLease.rollback()
		t.Fatal(prepareErr)
	}
	srv.releaseSession(replacement)
}

func TestAnnouncedSessionWaitsForReadiness(t *testing.T) {
	srv := &Server{}
	ref := coretransport.SessionRef{ClientID: 7, Generation: 1}
	binding, err := srv.prepareSession(activeServerSessionConfig{Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.releaseSession(binding)
	if err := srv.commitSession(binding); err != nil {
		t.Fatal(err)
	}
	if err := srv.finalizeSession(binding); err != nil {
		t.Fatal(err)
	}
	if srv.getActiveSessions().awaitCurrent(context.Background(), ref) {
		t.Fatal("session became current before readiness was announced")
	}
	if !srv.beginSessionReady(ref) {
		t.Fatal("failed to announce session readiness")
	}
	result := make(chan bool, 1)
	go func() {
		result <- srv.getActiveSessions().awaitCurrent(context.Background(), ref)
	}()
	select {
	case <-result:
		t.Fatal("announced session did not wait for the Ready write")
	case <-time.After(20 * time.Millisecond):
	}
	if !srv.markSessionReady(ref) {
		t.Fatal("failed to mark announced session ready")
	}
	select {
	case current := <-result:
		if !current {
			t.Fatal("ready session was not current")
		}
	case <-time.After(time.Second):
		t.Fatal("ready session did not release its waiter")
	}
}

func TestBlockedCloseWriterDoesNotRetainCleanupOwnership(t *testing.T) {
	srv := &Server{}
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var startOnce sync.Once
	old, err := srv.activateSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 7, Generation: 1},
		Write: func(*vpnpacket.VpnPacket) error {
			startOnce.Do(func() { close(writeStarted) })
			<-releaseWrite
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := srv.prepareSession(activeServerSessionConfig{
		Ref:   coretransport.SessionRef{ClientID: 7, Generation: 2},
		Write: func(*vpnpacket.VpnPacket) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.commitSession(candidate); err != nil {
		t.Fatal(err)
	}
	if err := srv.finalizeSession(candidate); err != nil {
		t.Fatal(err)
	}
	if !srv.markSessionReady(candidate.Ref) {
		t.Fatal("finalized session could not become ready")
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("previous session close writer did not start")
	}
	time.Sleep(sessionCloseWriteTimeout + 20*time.Millisecond)
	third, err := srv.prepareSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 7, Generation: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.releaseSession(third)
	close(releaseWrite)
	deadline := time.Now().Add(time.Second)
	for {
		registry := srv.getActiveSessions()
		registry.mu.RLock()
		cleanups := len(registry.cleanup)
		registry.mu.RUnlock()
		if cleanups == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked close writer did not release cleanup ownership")
		}
		time.Sleep(time.Millisecond)
	}
	if !old.closed.Load() {
		t.Fatal("previous session remained open")
	}
	srv.releaseSession(candidate)
}

func TestPreparedSessionRollbackDoesNotRestoreReleasedResourceLease(t *testing.T) {
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	oldRef := coretransport.SessionRef{ClientID: 7, Generation: 1}
	oldLease, err := limiter.acquireSession(oldRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	if _, err := srv.activateSession(activeServerSessionConfig{Ref: oldRef, Resources: oldLease}); err != nil {
		t.Fatal(err)
	}
	pendingLease, err := limiter.acquireSession(oldRef.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := srv.prepareSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: oldRef.ClientID, Generation: 2},
		Resources: pendingLease,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.RevokeSession(oldRef, "old session ended while replacement was pending") {
		t.Fatal("current session was not revoked")
	}
	srv.releaseSession(pending)

	limiter.mu.Lock()
	_, hasOwner := limiter.sessionOwners[oldRef.ClientID]
	sessions := limiter.sessions
	limiter.mu.Unlock()
	if hasOwner || sessions != 0 {
		t.Fatalf("resource owner/session count after both sessions ended = %v/%d, want false/0", hasOwner, sessions)
	}
}

func TestRevokeClientSendsReasonBeforeClosing(t *testing.T) {
	srv := &Server{codec: dataplane.WireCodec{}}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	ref := coretransport.SessionRef{ClientID: 9, Generation: 1}
	srv.activateSession(activeServerSessionConfig{
		Ref:  ref,
		Conn: serverConn,
		Write: func(packet *vpnpacket.VpnPacket) error {
			return writePacket(srv.codec, serverConn, packet)
		},
	})

	packetCh := make(chan *vpnpacket.VpnPacket, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := clientConn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		packet, _, err := srv.codec.Decode(buf[:n])
		if err != nil {
			errCh <- err
			return
		}
		packetCh <- packet
	}()
	if !srv.RevokeClient(9, "traffic quota exhausted") {
		t.Fatal("current client was not revoked")
	}
	select {
	case err := <-errCh:
		t.Fatal(err)
	case packet := <-packetCh:
		if packet.Cmd != vpnpacket.CmdErr || packet.ErrorMessage != "traffic quota exhausted" {
			t.Fatalf("revoke packet = %+v", packet)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for revoke reason")
	}
}

func TestActiveSessionCloseInterruptsBlockedReasonWrite(t *testing.T) {
	srv := &Server{
		protocol:     client.ProtocolTalariaTCP,
		codec:        dataplane.WireCodec{},
		writeTimeout: 3 * time.Second,
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	writers := srv.newSessionWriters(context.Background(), serverConn)
	var revoked atomic.Int32
	binding := &activeServerSession{activeServerSessionConfig: activeServerSessionConfig{
		Ref:        coretransport.SessionRef{ClientID: 10, Generation: 1},
		Conn:       serverConn,
		Write:      writers.Packet,
		RevokeData: func() { revoked.Add(1) },
	}}

	done := make(chan struct{})
	go func() {
		binding.close("session replaced")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("session close remained blocked by the normal write deadline")
	}
	if revoked.Load() != 1 {
		t.Fatalf("revoke callback count = %d, want 1", revoked.Load())
	}
}

func TestActiveSessionRevokesDataBeforeWritingReason(t *testing.T) {
	revoked := false
	wroteAfterRevoke := false
	binding := &activeServerSession{activeServerSessionConfig: activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 11, Generation: 1},
		Write: func(*vpnpacket.VpnPacket) error {
			wroteAfterRevoke = revoked
			return nil
		},
		RevokeData: func() { revoked = true },
	}}

	binding.close("session revoked")
	if !wroteAfterRevoke {
		t.Fatal("session wrote the revoke reason before revoking the data plane")
	}
}

func TestActiveSessionOptionalMaximumAgeClosesControl(t *testing.T) {
	srv := &Server{}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	ref := coretransport.SessionRef{ClientID: 12, Generation: 1}
	srv.activateSession(activeServerSessionConfig{
		Ref:       ref,
		Conn:      serverConn,
		ExpiresAt: time.Now().Add(50 * time.Millisecond),
	})
	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("maximum session age did not close control connection")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("timed out waiting for maximum session age")
	}
	if _, ok := srv.CurrentSession(12); ok {
		t.Fatal("expired session remains active")
	}
}

func TestServerDoneWaitsForSessionExpiryCallback(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		cancel:    cancel,
		closeDone: make(chan struct{}),
		done:      make(chan struct{}),
	}
	srv.runWG.Add(1)
	go func() {
		defer srv.runWG.Done()
		<-runCtx.Done()
		_ = srv.Close()
		<-srv.closeDone
	}()
	go func() {
		srv.runWG.Wait()
		srv.waitSessionReclaimer()
		srv.waitErrorLogger()
		close(srv.done)
	}()

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() {
		releaseOnce.Do(func() { close(release) })
		srv.stopSessionReclaimer()
	}()
	_, err := srv.activateSession(activeServerSessionConfig{
		Ref:       coretransport.SessionRef{ClientID: 14, Generation: 1},
		ExpiresAt: time.Now().Add(20 * time.Millisecond),
		RevokeData: func() {
			close(started)
			<-release
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("session expiry callback did not start")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed before the expiry cleanup callback finished")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-srv.Done():
	case <-time.After(time.Second):
		t.Fatal("server Done did not close after the expiry cleanup callback finished")
	}
}

func TestServerDoneWaitsForForcedSessionClose(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		cancel:    cancel,
		closeDone: make(chan struct{}),
		done:      make(chan struct{}),
	}
	srv.runWG.Add(1)
	go func() {
		defer srv.runWG.Done()
		<-runCtx.Done()
		_ = srv.Close()
		<-srv.closeDone
	}()
	go func() {
		srv.runWG.Wait()
		srv.waitSessionReclaimer()
		srv.waitErrorLogger()
		close(srv.done)
	}()

	firstClose := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondClose := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(func() {
		release()
		_ = srv.Close()
	})
	conn := &forcedSessionCloseConn{
		firstClose:   firstClose,
		releaseFirst: releaseFirst,
		secondClose:  secondClose,
	}
	ref := coretransport.SessionRef{ClientID: 15, Generation: 1}
	_, err := srv.activateSession(activeServerSessionConfig{
		Ref:  ref,
		Conn: conn,
		Write: func(*vpnpacket.VpnPacket) error {
			<-firstClose
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.RevokeSession(ref, "session revoked") {
		t.Fatal("session was not revoked")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondClose:
	case <-time.After(time.Second):
		t.Fatal("session connection close did not follow the forced close")
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed while the forced connection close was still running")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	ctx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if err := srv.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

type forcedSessionCloseConn struct {
	net.Conn
	closeCalls   atomic.Int32
	firstClose   chan struct{}
	releaseFirst chan struct{}
	secondClose  chan struct{}
}

func (c *forcedSessionCloseConn) Close() error {
	switch c.closeCalls.Add(1) {
	case 1:
		close(c.firstClose)
		<-c.releaseFirst
	case 2:
		close(c.secondClose)
	}
	return nil
}

func (*forcedSessionCloseConn) SetWriteDeadline(time.Time) error { return nil }

func TestExpiredActiveSessionIsNotCurrentBeforeRevocation(t *testing.T) {
	ref := coretransport.SessionRef{ClientID: 13, Generation: 1}
	registry := newActiveSessionRegistry()
	registry.byClient[ref.ClientID] = &activeServerSession{activeServerSessionConfig: activeServerSessionConfig{
		Ref:       ref,
		ExpiresAt: time.Now().Add(-time.Second),
	}}
	if _, ok := registry.current(ref.ClientID); ok {
		t.Fatal("expired session was reported as current")
	}
	if registry.isCurrent(ref) {
		t.Fatal("expired session passed the current-generation check")
	}
}

func TestRapidReplacementIgnoresOneThousandStaleReleaseAndRevokeActions(t *testing.T) {
	srv := &Server{}
	const clientID = 77
	var wg sync.WaitGroup
	var previous *activeServerSession
	for generation := uint64(1); generation <= 1000; generation++ {
		current, err := srv.activateSession(activeServerSessionConfig{
			Ref: coretransport.SessionRef{ClientID: clientID, Generation: generation},
		})
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil {
			stale := previous
			wg.Add(2)
			go func() {
				defer wg.Done()
				srv.releaseSession(stale)
			}()
			go func() {
				defer wg.Done()
				_ = srv.RevokeSession(stale.Ref, "stale asynchronous response")
			}()
		}
		previous = current
	}
	wg.Wait()
	want := coretransport.SessionRef{ClientID: clientID, Generation: 1000}
	if got, ok := srv.CurrentSession(clientID); !ok || got != want {
		t.Fatalf("current session = %+v ok=%v, want %+v/true", got, ok, want)
	}
	if !srv.RevokeSession(want, "test complete") {
		t.Fatal("final session was not revocable")
	}
}
