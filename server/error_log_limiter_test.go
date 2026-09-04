// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestErrorLogLimiterSuppressesBurstAndReportsNextWindow(t *testing.T) {
	limiter := newErrorLogLimiter(2, time.Second)
	now := time.Unix(100, 0)
	if suppressed, allowed := limiter.admit("auth", now); suppressed != 0 || !allowed {
		t.Fatalf("first event = (%d, %v), want (0, true)", suppressed, allowed)
	}
	if suppressed, allowed := limiter.admit("auth", now); suppressed != 0 || !allowed {
		t.Fatalf("second event = (%d, %v), want (0, true)", suppressed, allowed)
	}
	if suppressed, allowed := limiter.admit("auth", now); suppressed != 0 || allowed {
		t.Fatalf("third event = (%d, %v), want (0, false)", suppressed, allowed)
	}
	if suppressed, allowed := limiter.admit("auth", now.Add(time.Second)); suppressed != 1 || !allowed {
		t.Fatalf("next-window event = (%d, %v), want (1, true)", suppressed, allowed)
	}
}

func TestBlockingErrorLogDoesNotRetainProtocolWork(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	started := make(chan struct{})
	var startedOnce sync.Once
	var calls atomic.Int32
	limiter := newResourceLimiter(ResourceLimits{MaxSessions: 1})
	lease, err := limiter.acquireSession(1)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		cancel: cancel,
		logErr: func(string, error) {
			calls.Add(1)
			startedOnce.Do(func() { close(started) })
			<-release
		},
		errorLogs:     newErrorLogLimiter(1, time.Millisecond),
		closeDone:     make(chan struct{}),
		done:          make(chan struct{}),
		errorLogQueue: make(chan serverErrorLog, 2),
		errorLogStop:  make(chan struct{}),
	}
	srv.runWG.Add(1)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer srv.runWG.Done()
		defer lease.release()
		srv.logError("auth", errors.New("first"))
		<-started
		for range 4 {
			time.Sleep(2 * time.Millisecond)
			srv.logError("auth", errors.New("repeated"))
		}
	}()
	go func() {
		srv.runWG.Wait()
		srv.waitSessionReclaimer()
		srv.waitErrorLogger()
		close(srv.done)
	}()
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("protocol work waited for the error logger")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("active error log callbacks = %d, want 1", got)
	}
	if got := len(srv.errorLogQueue); got != cap(srv.errorLogQueue) {
		t.Fatalf("queued error logs = %d, want bounded capacity %d", got, cap(srv.errorLogQueue))
	}
	limiter.mu.Lock()
	sessions := limiter.sessions
	limiter.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("session resources after logging = %d, want 0", sessions)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed before the error logger finished")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-srv.Done():
	case <-time.After(time.Second):
		t.Fatal("server Done did not close after the error logger finished")
	}
}

func TestErrorLoggerContinuesAfterPanic(t *testing.T) {
	logged := make(chan struct{})
	var calls atomic.Int32
	srv := &Server{
		logErr: func(string, error) {
			if calls.Add(1) == 1 {
				panic("synthetic logger panic")
			}
			close(logged)
		},
		errorLogs:     newErrorLogLimiter(2, time.Second),
		errorLogQueue: make(chan serverErrorLog, 2),
		errorLogStop:  make(chan struct{}),
	}
	srv.logError("test", errors.New("first"))
	srv.logError("test", errors.New("second"))
	select {
	case <-logged:
	case <-time.After(time.Second):
		t.Fatal("error logger stopped after callback panic")
	}
	srv.stopErrorLogger()
}
