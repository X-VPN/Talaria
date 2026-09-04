// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package lifecycle provides a shared close signal for objects whose lifetime is
// tied to something larger, such as every connection belonging to one session.
//
// A Group is closed once; callbacks still registered at that point run. A
// resource that closes independently should invoke the unregister function
// returned by AddOnClose so the Group does not retain it.
package lifecycle

import (
	"sync"

	"github.com/X-VPN/Talaria/internal/extension"
)

type Closer interface {
	IsClose() bool
	GetCloseChan() <-chan struct{}
	AddOnClose(func()) func()
}

type Group struct {
	mu             sync.Mutex
	done           chan struct{}
	closed         bool
	nextCallbackID uint64
	callbacks      map[uint64]func()
}

func NewCloser() *Group {
	return &Group{}
}

func (g *Group) IsClose() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	return closed
}

func (g *Group) GetCloseChan() <-chan struct{} {
	if g == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	g.mu.Lock()
	if g.done == nil {
		g.done = make(chan struct{})
		if g.closed {
			close(g.done)
		}
	}
	done := g.done
	g.mu.Unlock()
	return done
}

// AddOnClose registers fn and returns an idempotent unregister function. It
// returns nil without running fn when the Group is already closed.
func (g *Group) AddOnClose(fn func()) func() {
	if g == nil || fn == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	if g.callbacks == nil {
		g.callbacks = make(map[uint64]func())
	}
	g.nextCallbackID++
	id := g.nextCallbackID
	g.callbacks[id] = fn
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.callbacks, id)
			g.mu.Unlock()
		})
	}
}

func (g *Group) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	if g.done != nil {
		close(g.done)
	}
	callbacks := g.callbacks
	g.callbacks = nil
	g.mu.Unlock()
	for _, callback := range callbacks {
		_ = extension.Run("lifecycle close callback", callback)
	}
}
