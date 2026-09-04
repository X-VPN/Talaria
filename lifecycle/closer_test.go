// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package lifecycle

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupUnregisterRemovesCloseCallback(t *testing.T) {
	group := NewCloser()
	var calls atomic.Int32
	unregister := group.AddOnClose(func() { calls.Add(1) })
	if len(group.callbacks) != 1 {
		t.Fatalf("registered callbacks = %d want 1", len(group.callbacks))
	}
	unregister()
	unregister()
	if len(group.callbacks) != 0 {
		t.Fatalf("callbacks after unregister = %d want 0", len(group.callbacks))
	}
	group.Close()
	if got := calls.Load(); got != 0 {
		t.Fatalf("unregistered callback calls = %d want 0", got)
	}
}

func TestGroupRunsRegisteredCallback(t *testing.T) {
	group := NewCloser()
	var calls atomic.Int32
	group.AddOnClose(func() { calls.Add(1) })
	group.Close()
	if got := calls.Load(); got != 1 {
		t.Fatalf("registered callback calls = %d want 1", got)
	}
}

func TestGroupRejectsRegistrationAfterClose(t *testing.T) {
	group := NewCloser()
	group.Close()
	var calls atomic.Int32
	if unregister := group.AddOnClose(func() { calls.Add(1) }); unregister != nil {
		t.Fatal("closed group returned an unregister handle")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("rejected callback ran synchronously %d times", got)
	}
}

func TestGroupCloseCallbackMayReenterClose(t *testing.T) {
	group := NewCloser()
	var calls atomic.Int32
	group.AddOnClose(func() {
		calls.Add(1)
		group.Close()
	})
	done := make(chan struct{})
	go func() {
		group.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reentrant Close deadlocked")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls = %d, want 1", got)
	}
}

func TestGroupCloseContinuesAfterCallbackPanic(t *testing.T) {
	group := NewCloser()
	group.AddOnClose(func() { panic("boom") })
	var calls atomic.Int32
	group.AddOnClose(func() { calls.Add(1) })
	group.Close()
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls after panic = %d, want 1", got)
	}
}
