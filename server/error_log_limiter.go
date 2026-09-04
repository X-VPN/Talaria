// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
)

const (
	defaultErrorLogBurst  = 10
	defaultErrorLogWindow = time.Second
	defaultErrorLogQueue  = 64
)

type serverErrorLog struct {
	scope string
	err   error
}

type errorLogWindow struct {
	started    time.Time
	emitted    int
	suppressed uint64
}

type errorLogLimiter struct {
	mu      sync.Mutex
	burst   int
	window  time.Duration
	byScope map[string]errorLogWindow
}

func newErrorLogLimiter(burst int, window time.Duration) *errorLogLimiter {
	if burst <= 0 {
		burst = defaultErrorLogBurst
	}
	if window <= 0 {
		window = defaultErrorLogWindow
	}
	return &errorLogLimiter{
		burst:   burst,
		window:  window,
		byScope: make(map[string]errorLogWindow),
	}
}

func (l *errorLogLimiter) admit(scope string, now time.Time) (uint64, bool) {
	if l == nil {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.byScope[scope]
	if state.started.IsZero() || now.Before(state.started) || now.Sub(state.started) >= l.window {
		suppressed := state.suppressed
		l.byScope[scope] = errorLogWindow{started: now, emitted: 1}
		return suppressed, true
	}
	if state.emitted < l.burst {
		state.emitted++
		l.byScope[scope] = state
		return 0, true
	}
	state.suppressed++
	l.byScope[scope] = state
	return 0, false
}

func (s *Server) enqueueErrorLog(scope string, err error) {
	if s == nil || s.logErr == nil || err == nil {
		return
	}
	s.errorLogMu.Lock()
	if s.errorLogStopped {
		s.errorLogMu.Unlock()
		return
	}
	if s.errorLogQueue == nil {
		s.errorLogQueue = make(chan serverErrorLog, defaultErrorLogQueue)
	}
	if s.errorLogStop == nil {
		s.errorLogStop = make(chan struct{})
	}
	s.errorLogStart.Do(func() {
		s.errorLogWG.Add(1)
		go func() {
			defer s.errorLogWG.Done()
			s.runErrorLogger()
		}()
	})
	select {
	case s.errorLogQueue <- serverErrorLog{scope: scope, err: err}:
	default:
	}
	s.errorLogMu.Unlock()
}

func (s *Server) runErrorLogger() {
	for {
		select {
		case entry := <-s.errorLogQueue:
			s.emitErrorLog(entry)
		case <-s.errorLogStop:
			for {
				select {
				case entry := <-s.errorLogQueue:
					s.emitErrorLog(entry)
				default:
					return
				}
			}
		}
	}
}

func (s *Server) emitErrorLog(entry serverErrorLog) {
	_ = extension.Run("server error log", func() { s.logErr(entry.scope, entry.err) })
}

func (s *Server) stopErrorLogger() {
	if s == nil {
		return
	}
	s.errorLogMu.Lock()
	if !s.errorLogStopped {
		s.errorLogStopped = true
		if s.errorLogStop != nil {
			close(s.errorLogStop)
		}
	}
	s.errorLogMu.Unlock()
}

func (s *Server) waitErrorLogger() {
	if s == nil {
		return
	}
	s.stopErrorLogger()
	s.errorLogWG.Wait()
}
