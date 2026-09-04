// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

const sessionCloseWriteTimeout = 250 * time.Millisecond
const defaultSessionCleanupWorkers = 256
const defaultSessionReclaimWorkers = 8
const defaultSessionReclaimQueue = defaultMaxSessions

type activeServerSessionConfig struct {
	Ref         coretransport.SessionRef
	Context     SessionContext
	Conn        net.Conn
	Write       PacketWriter
	CancelData  func()
	RevokeData  func()
	Resources   *sessionResourceLease
	ExpiresAt   time.Time
	reclaimDone func()
}

type activeServerSession struct {
	activeServerSessionConfig
	owner            *Server
	closed           atomic.Bool
	cleanupScheduled atomic.Bool
	committed        atomic.Bool
	announced        atomic.Bool
	ready            atomic.Bool
	readyDone        chan struct{}
	readyOnce        sync.Once
	expiry           *time.Timer
	expiryDone       func()
}

type activeSessionRegistry struct {
	mu           sync.RWMutex
	byClient     map[uint64]*activeServerSession
	pending      map[uint64]*activeServerSession
	promotions   map[uint64]activeSessionPromotion
	cleanup      map[uint64]int
	cleanupSlots chan struct{}
}

type activeSessionPromotion struct {
	current  *activeServerSession
	previous *activeServerSession
}

type clientSessionLock struct {
	mu   sync.Mutex
	refs int
}

type clientSessionLocks struct {
	mu       sync.Mutex
	byClient map[uint64]*clientSessionLock
}

func (l *clientSessionLocks) lock(clientID uint64) func() {
	l.mu.Lock()
	if l.byClient == nil {
		l.byClient = make(map[uint64]*clientSessionLock)
	}
	entry := l.byClient[clientID]
	if entry == nil {
		entry = new(clientSessionLock)
		l.byClient[clientID] = entry
	}
	entry.refs++
	l.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		l.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(l.byClient, clientID)
		}
		l.mu.Unlock()
	}
}

func newActiveSessionRegistry() *activeSessionRegistry {
	return &activeSessionRegistry{
		byClient:     make(map[uint64]*activeServerSession),
		pending:      make(map[uint64]*activeServerSession),
		promotions:   make(map[uint64]activeSessionPromotion),
		cleanup:      make(map[uint64]int),
		cleanupSlots: make(chan struct{}, defaultSessionCleanupWorkers),
	}
}

func (s *Server) getActiveSessions() *activeSessionRegistry {
	s.activeSessionsOnce.Do(func() {
		s.activeSessions = newActiveSessionRegistry()
	})
	return s.activeSessions
}

func (s *Server) prepareSession(cfg activeServerSessionConfig) (*activeServerSession, error) {
	if s == nil || s.closeState.Load() != 0 {
		return nil, net.ErrClosed
	}
	reclaimDone, ok := s.acquireSessionReclaim()
	if !ok {
		return nil, errResourceLimit
	}
	cfg.reclaimDone = reclaimDone
	binding := &activeServerSession{
		activeServerSessionConfig: cfg,
		owner:                     s,
		readyDone:                 make(chan struct{}),
	}
	registry := s.getActiveSessions()
	s.packetAttachMu.Lock()
	if s.closeState.Load() != 0 {
		s.packetAttachMu.Unlock()
		reclaimDone()
		return nil, net.ErrClosed
	}
	registry.mu.Lock()
	latest := registry.byClient[cfg.Ref.ClientID]
	if registry.cleanup[cfg.Ref.ClientID] != 0 {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		reclaimDone()
		return nil, errors.New("Talaria server: session cleanup is still in progress")
	}
	if pending := registry.pending[cfg.Ref.ClientID]; pending != nil {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		reclaimDone()
		return nil, errors.New("Talaria server: session setup is already pending")
	}
	if _, promoting := registry.promotions[cfg.Ref.ClientID]; promoting {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		reclaimDone()
		return nil, errors.New("Talaria server: session commit is still in progress")
	}
	if latest != nil && cfg.Ref.Generation <= latest.Ref.Generation {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		reclaimDone()
		return nil, fmt.Errorf(
			"Talaria server: session generation %d is not newer than %d",
			cfg.Ref.Generation,
			latest.Ref.Generation,
		)
	}
	registry.pending[cfg.Ref.ClientID] = binding
	registry.mu.Unlock()
	s.packetAttachMu.Unlock()
	return binding, nil
}

func (s *Server) activateSession(cfg activeServerSessionConfig) (*activeServerSession, error) {
	binding, err := s.prepareSession(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.commitSession(binding); err != nil {
		s.releaseSession(binding)
		return nil, err
	}
	if err := s.finalizeSession(binding); err != nil {
		s.releaseSession(binding)
		return nil, err
	}
	binding.completeReadiness(true)
	return binding, nil
}

func (s *Server) commitSession(binding *activeServerSession) error {
	if s == nil || binding == nil {
		return net.ErrClosed
	}
	registry := s.getActiveSessions()
	s.packetAttachMu.Lock()
	registry.mu.Lock()
	if registry.pending[binding.Ref.ClientID] != binding {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		return errors.New("Talaria server: session is not pending")
	}
	if !binding.ExpiresAt.IsZero() && !time.Now().Before(binding.ExpiresAt) {
		delete(registry.pending, binding.Ref.ClientID)
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		return errors.New("Talaria server: pending session expired before readiness")
	}
	old := registry.byClient[binding.Ref.ClientID]
	registry.byClient[binding.Ref.ClientID] = binding
	delete(registry.pending, binding.Ref.ClientID)
	registry.promotions[binding.Ref.ClientID] = activeSessionPromotion{current: binding, previous: old}
	registry.mu.Unlock()
	s.packetAttachMu.Unlock()
	return nil
}

func (s *Server) finalizeSession(binding *activeServerSession) error {
	if s == nil || binding == nil {
		return net.ErrClosed
	}
	registry := s.getActiveSessions()
	s.packetAttachMu.Lock()
	registry.mu.Lock()
	promotion, ok := registry.promotions[binding.Ref.ClientID]
	if !ok || promotion.current != binding || registry.byClient[binding.Ref.ClientID] != binding {
		registry.mu.Unlock()
		s.packetAttachMu.Unlock()
		return errors.New("Talaria server: session promotion is no longer current")
	}
	var releaseCleanup func()
	previous := promotion.previous
	if previous != nil && previous != binding && !previous.closed.Load() && previous.requiresAsyncClose() {
		var acquired bool
		releaseCleanup, acquired = registry.acquireCleanupLocked(binding.Ref.ClientID)
		if !acquired {
			registry.mu.Unlock()
			s.packetAttachMu.Unlock()
			return errResourceLimit
		}
	}
	delete(registry.promotions, binding.Ref.ClientID)
	binding.committed.Store(true)
	if releaseCleanup != nil {
		previous.cleanupScheduled.Store(true)
	}
	if !binding.ExpiresAt.IsZero() {
		var expiryOnce sync.Once
		s.runWG.Add(1)
		binding.expiryDone = func() {
			expiryOnce.Do(s.runWG.Done)
		}
		expiryDone := binding.expiryDone
		binding.expiry = time.AfterFunc(time.Until(binding.ExpiresAt), func() {
			defer expiryDone()
			s.RevokeSession(binding.Ref, "maximum session age reached")
		})
	}
	registry.mu.Unlock()
	s.packetAttachMu.Unlock()
	if previous == nil || previous == binding {
		return nil
	}
	if releaseCleanup != nil {
		previous.close("session replaced by a newer connection")
		releaseCleanup()
	} else {
		previous.close("session replaced by a newer connection")
	}
	return nil
}

func (r *activeSessionRegistry) acquireCleanupLocked(clientID uint64) (func(), bool) {
	if r.cleanup[clientID] != 0 {
		return nil, false
	}
	select {
	case r.cleanupSlots <- struct{}{}:
		r.cleanup[clientID] = 1
	default:
		return nil, false
	}
	return r.cleanupRelease(clientID, true), true
}

func (r *activeSessionRegistry) retainCleanupLocked(clientID uint64) func() {
	r.cleanup[clientID]++
	return r.cleanupRelease(clientID, false)
}

func (r *activeSessionRegistry) cleanupRelease(clientID uint64, releaseSlot bool) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			if count := r.cleanup[clientID]; count <= 1 {
				delete(r.cleanup, clientID)
			} else {
				r.cleanup[clientID] = count - 1
			}
			if releaseSlot {
				<-r.cleanupSlots
			}
			r.mu.Unlock()
		})
	}
}

func (s *Server) releaseSession(binding *activeServerSession) {
	if s == nil || binding == nil {
		return
	}
	unlock := s.sessionLocks.lock(binding.Ref.ClientID)
	registry := s.getActiveSessions()
	s.packetAttachMu.Lock()
	registry.mu.Lock()
	var releaseCleanup func()
	if promotion, ok := registry.promotions[binding.Ref.ClientID]; ok && promotion.current == binding {
		if promotion.previous != nil && !promotion.previous.closed.Load() {
			registry.byClient[binding.Ref.ClientID] = promotion.previous
		} else {
			delete(registry.byClient, binding.Ref.ClientID)
		}
		delete(registry.promotions, binding.Ref.ClientID)
	} else if registry.byClient[binding.Ref.ClientID] == binding {
		delete(registry.byClient, binding.Ref.ClientID)
	}
	if registry.pending[binding.Ref.ClientID] == binding {
		delete(registry.pending, binding.Ref.ClientID)
	}
	scheduled := binding.cleanupScheduled.Load()
	if !scheduled && !binding.closed.Load() && binding.requiresAsyncClose() {
		releaseCleanup = registry.retainCleanupLocked(binding.Ref.ClientID)
	}
	registry.mu.Unlock()
	s.packetAttachMu.Unlock()
	unlock()
	if !scheduled {
		binding.close("")
	}
	if releaseCleanup != nil {
		releaseCleanup()
	}
}

// CurrentSession returns the currently active generation for clientID.
func (s *Server) CurrentSession(clientID uint64) (coretransport.SessionRef, bool) {
	if s == nil || clientID == 0 {
		return coretransport.SessionRef{}, false
	}
	return s.getActiveSessions().current(clientID)
}

// RevokeClient revokes the current and any not-yet-ready generation for clientID.
// It is appropriate for an administrator's explicit "disconnect now" action.
func (s *Server) RevokeClient(clientID uint64, reason string) bool {
	if s == nil || clientID == 0 {
		return false
	}
	unlock := s.sessionLocks.lock(clientID)
	s.packetAttachMu.Lock()
	bindings, releaseCleanup := s.getActiveSessions().takeClient(clientID)
	s.packetAttachMu.Unlock()
	unlock()
	if len(bindings) == 0 {
		return false
	}
	for _, binding := range bindings {
		if !binding.cleanupScheduled.Load() {
			binding.close(normalizeSessionCloseReason(reason))
		}
	}
	if releaseCleanup != nil {
		releaseCleanup()
	}
	return true
}

// RevokeSession revokes only the exact generation. Use it for asynchronous
// quota or subscription responses so a stale response cannot close a reconnect.
func (s *Server) RevokeSession(ref coretransport.SessionRef, reason string) bool {
	if s == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	unlock := s.sessionLocks.lock(ref.ClientID)
	s.packetAttachMu.Lock()
	binding, releaseCleanup := s.getActiveSessions().take(ref)
	s.packetAttachMu.Unlock()
	unlock()
	if binding == nil {
		return false
	}
	if !binding.cleanupScheduled.Load() {
		binding.close(normalizeSessionCloseReason(reason))
	}
	if releaseCleanup != nil {
		releaseCleanup()
	}
	return true
}

func (r *activeSessionRegistry) current(clientID uint64) (coretransport.SessionRef, bool) {
	r.mu.RLock()
	binding := r.visibleCurrent(clientID)
	r.mu.RUnlock()
	if binding == nil {
		return coretransport.SessionRef{}, false
	}
	return binding.Ref, true
}

func (r *activeSessionRegistry) isCurrent(ref coretransport.SessionRef) bool {
	if r == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	r.mu.RLock()
	binding := r.visibleCurrent(ref.ClientID)
	r.mu.RUnlock()
	return binding != nil && binding.Ref == ref
}

func (r *activeSessionRegistry) awaitCurrent(ctx context.Context, ref coretransport.SessionRef) bool {
	if r == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	if r.isCurrent(ref) {
		return true
	}
	r.mu.RLock()
	binding := r.byClient[ref.ClientID]
	_, promoting := r.promotions[ref.ClientID]
	if binding == nil || binding.Ref != ref || promoting || binding.closed.Load() || !binding.announced.Load() || binding.readyDone == nil {
		r.mu.RUnlock()
		return false
	}
	readyDone := binding.readyDone
	r.mu.RUnlock()
	select {
	case <-ctx.Done():
		return false
	case <-readyDone:
		return r.isCurrent(ref)
	}
}

func (s *Server) beginSessionReady(ref coretransport.SessionRef) bool {
	if s == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	registry := s.getActiveSessions()
	registry.mu.RLock()
	binding := registry.byClient[ref.ClientID]
	_, promoting := registry.promotions[ref.ClientID]
	if binding == nil || binding.Ref != ref || promoting || binding.closed.Load() {
		registry.mu.RUnlock()
		return false
	}
	binding.announced.Store(true)
	registry.mu.RUnlock()
	return true
}

func (s *Server) markSessionReady(ref coretransport.SessionRef) bool {
	if s == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	registry := s.getActiveSessions()
	registry.mu.RLock()
	binding := registry.byClient[ref.ClientID]
	_, promoting := registry.promotions[ref.ClientID]
	if binding == nil || binding.Ref != ref || promoting || binding.closed.Load() {
		registry.mu.RUnlock()
		return false
	}
	binding.completeReadiness(true)
	registry.mu.RUnlock()
	return true
}

func (s *activeServerSession) completeReadiness(ready bool) {
	if s == nil {
		return
	}
	if ready {
		s.ready.Store(true)
	}
	if s.readyDone != nil {
		s.readyOnce.Do(func() { close(s.readyDone) })
	}
}

func (r *activeSessionRegistry) visibleCurrent(clientID uint64) *activeServerSession {
	binding := r.byClient[clientID]
	if promotion, ok := r.promotions[clientID]; ok && promotion.current == binding {
		binding = promotion.previous
	}
	if binding != nil && (binding.closed.Load() || (!binding.ExpiresAt.IsZero() && !time.Now().Before(binding.ExpiresAt))) {
		return nil
	}
	if binding != nil && !binding.ready.Load() {
		return nil
	}
	return binding
}

func (r *activeSessionRegistry) isPending(ref coretransport.SessionRef) bool {
	if r == nil || ref.ClientID == 0 || ref.Generation == 0 {
		return false
	}
	r.mu.RLock()
	binding := r.pending[ref.ClientID]
	r.mu.RUnlock()
	return binding != nil && binding.Ref == ref
}

func (r *activeSessionRegistry) takeClient(clientID uint64) ([]*activeServerSession, func()) {
	r.mu.Lock()
	bindings := make([]*activeServerSession, 0, 3)
	if binding := r.byClient[clientID]; binding != nil {
		bindings = append(bindings, binding)
	}
	if binding := r.pending[clientID]; binding != nil {
		bindings = append(bindings, binding)
	}
	if promotion, ok := r.promotions[clientID]; ok && promotion.previous != nil {
		bindings = append(bindings, promotion.previous)
	}
	delete(r.byClient, clientID)
	delete(r.pending, clientID)
	delete(r.promotions, clientID)
	var releaseCleanup func()
	for _, binding := range bindings {
		if binding != nil && !binding.cleanupScheduled.Load() && !binding.closed.Load() && binding.requiresAsyncClose() {
			releaseCleanup = r.retainCleanupLocked(clientID)
			break
		}
	}
	r.mu.Unlock()
	return bindings, releaseCleanup
}

func (r *activeSessionRegistry) take(ref coretransport.SessionRef) (*activeServerSession, func()) {
	r.mu.Lock()
	finish := func(binding *activeServerSession) (*activeServerSession, func()) {
		var releaseCleanup func()
		if binding != nil && !binding.cleanupScheduled.Load() && !binding.closed.Load() && binding.requiresAsyncClose() {
			releaseCleanup = r.retainCleanupLocked(ref.ClientID)
		}
		r.mu.Unlock()
		return binding, releaseCleanup
	}
	if binding := r.pending[ref.ClientID]; binding != nil && binding.Ref == ref {
		delete(r.pending, ref.ClientID)
		return finish(binding)
	}
	if promotion, ok := r.promotions[ref.ClientID]; ok {
		if promotion.current != nil && promotion.current.Ref == ref {
			delete(r.promotions, ref.ClientID)
			if promotion.previous != nil && !promotion.previous.closed.Load() {
				r.byClient[ref.ClientID] = promotion.previous
			} else {
				delete(r.byClient, ref.ClientID)
			}
			return finish(promotion.current)
		}
		if promotion.previous != nil && promotion.previous.Ref == ref {
			previous := promotion.previous
			promotion.previous = nil
			r.promotions[ref.ClientID] = promotion
			return finish(previous)
		}
	}
	binding := r.byClient[ref.ClientID]
	if binding != nil && binding.Ref == ref {
		delete(r.byClient, ref.ClientID)
	} else {
		binding = nil
	}
	return finish(binding)
}

func (r *activeSessionRegistry) takeAll() []*activeServerSession {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	bindings := make([]*activeServerSession, 0, len(r.byClient)+len(r.pending)+len(r.promotions))
	for _, binding := range r.byClient {
		bindings = append(bindings, binding)
	}
	for _, binding := range r.pending {
		bindings = append(bindings, binding)
	}
	for _, promotion := range r.promotions {
		if promotion.previous != nil {
			bindings = append(bindings, promotion.previous)
		}
	}
	clear(r.byClient)
	clear(r.pending)
	clear(r.promotions)
	r.mu.Unlock()
	return bindings
}

func (s *Server) closeAllSessions(reason string) {
	if s == nil {
		return
	}
	s.packetAttachMu.Lock()
	bindings := s.getActiveSessions().takeAll()
	s.packetAttachMu.Unlock()
	pending := make([]*activeServerSession, 0, len(bindings))
	for _, binding := range bindings {
		if binding == nil || binding.cleanupScheduled.Load() || binding.closed.Load() {
			continue
		}
		if !binding.requiresAsyncClose() {
			binding.close(reason)
			continue
		}
		if binding.cleanupScheduled.CompareAndSwap(false, true) {
			pending = append(pending, binding)
		}
	}
	for _, binding := range pending {
		binding.close(reason)
	}
}

type sessionReclaimTask struct {
	reclaim     func()
	reclaimDone func()
}

func (s *Server) acquireSessionReclaim() (func(), bool) {
	if s == nil {
		return nil, false
	}
	s.sessionReclaimMu.Lock()
	defer s.sessionReclaimMu.Unlock()
	if s.sessionReclaimStopped {
		return nil, false
	}
	if s.sessionReclaimQueue == nil {
		s.sessionReclaimQueue = make(chan sessionReclaimTask, defaultSessionReclaimQueue)
	}
	if s.sessionReclaimSlots == nil {
		s.sessionReclaimSlots = make(chan struct{}, cap(s.sessionReclaimQueue))
	}
	select {
	case s.sessionReclaimSlots <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() { <-s.sessionReclaimSlots })
	}, true
}

func (s *Server) reclaimSession(reclaim func()) {
	if s == nil || reclaim == nil {
		return
	}
	reclaimDone, ok := s.acquireSessionReclaim()
	if !ok {
		s.runSessionReclaim(sessionReclaimTask{reclaim: reclaim})
		return
	}
	s.reclaimOwnedSession(reclaim, reclaimDone)
}

func (s *Server) reclaimOwnedSession(reclaim, reclaimDone func()) {
	if reclaimDone == nil {
		s.reclaimSession(reclaim)
		return
	}
	if reclaim == nil {
		reclaimDone()
		return
	}
	task := sessionReclaimTask{reclaim: reclaim, reclaimDone: reclaimDone}
	s.sessionReclaimMu.Lock()
	if s.sessionReclaimStopped {
		s.sessionReclaimMu.Unlock()
		s.runSessionReclaim(task)
		return
	}
	if s.sessionReclaimQueue == nil {
		s.sessionReclaimQueue = make(chan sessionReclaimTask, defaultSessionReclaimQueue)
	}
	if s.sessionReclaimStop == nil {
		s.sessionReclaimStop = make(chan struct{})
	}
	s.sessionReclaimStart.Do(func() {
		for range defaultSessionReclaimWorkers {
			s.sessionReclaimWG.Add(1)
			go func() {
				defer s.sessionReclaimWG.Done()
				s.runSessionReclaimer()
			}()
		}
	})
	s.sessionReclaimQueue <- task
	s.sessionReclaimMu.Unlock()
}

func (s *Server) runSessionReclaimer() {
	for {
		select {
		case task := <-s.sessionReclaimQueue:
			s.runSessionReclaim(task)
		case <-s.sessionReclaimStop:
			for {
				select {
				case task := <-s.sessionReclaimQueue:
					s.runSessionReclaim(task)
				default:
					return
				}
			}
		}
	}
}

func (s *Server) runSessionReclaim(task sessionReclaimTask) {
	if task.reclaimDone != nil {
		defer task.reclaimDone()
	}
	if task.reclaim == nil {
		return
	}
	if err := extension.Run("session physical cleanup", task.reclaim); err != nil {
		s.logError("session physical cleanup", err)
	}
}

func (s *Server) stopSessionReclaimer() {
	if s == nil {
		return
	}
	s.sessionReclaimMu.Lock()
	if !s.sessionReclaimStopped {
		s.sessionReclaimStopped = true
		if s.sessionReclaimStop != nil {
			close(s.sessionReclaimStop)
		}
	}
	s.sessionReclaimMu.Unlock()
}

func (s *Server) waitSessionReclaimer() {
	if s == nil {
		return
	}
	s.stopSessionReclaimer()
	s.sessionReclaimWG.Wait()
}

func (s *activeServerSession) close(reason string) {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.completeReadiness(false)
	if s.expiry != nil && s.expiry.Stop() && s.expiryDone != nil {
		s.expiryDone()
	}
	if s.CancelData != nil {
		if err := extension.Run("session cancel callback", s.CancelData); err != nil {
			s.logError("session cancel callback", err)
		}
	}
	if s.Resources != nil {
		if s.committed.Load() {
			s.Resources.release()
		} else {
			s.Resources.rollback()
		}
	}
	if !s.requiresAsyncClose() {
		if s.reclaimDone != nil {
			s.reclaimDone()
		}
		return
	}
	finish := func() { s.finishClose(reason) }
	if s.owner != nil {
		s.owner.reclaimOwnedSession(finish, s.reclaimDone)
	} else {
		if s.reclaimDone != nil {
			defer s.reclaimDone()
		}
		finish()
	}
}

func (s *activeServerSession) finishClose(reason string) {
	if s.RevokeData != nil {
		if err := extension.Run("session revoke callback", s.RevokeData); err != nil {
			s.logError("session revoke callback", err)
		}
	}
	if reason != "" && s.Write != nil {
		if s.Conn != nil {
			_ = extension.Do("session close write deadline", func() error {
				return s.Conn.SetWriteDeadline(time.Now().Add(sessionCloseWriteTimeout))
			})
		}
		var closeTimer *time.Timer
		var forcedCloseDone chan struct{}
		if s.Conn != nil {
			forcedCloseDone = make(chan struct{})
			closeTimer = time.AfterFunc(sessionCloseWriteTimeout, func() {
				defer close(forcedCloseDone)
				_ = extension.Do("session forced connection close", s.Conn.Close)
			})
		}
		err := extension.Do("session close writer", func() error {
			return s.Write(&vpnpacket.VpnPacket{
				Cmd:          vpnpacket.CmdErr,
				ClientId:     s.Ref.ClientID,
				ErrorMessage: reason,
			})
		})
		closeTimerStopped := closeTimer == nil || closeTimer.Stop()
		if err != nil {
			s.logError("session close writer", err)
		}
		if s.Conn != nil {
			_ = extension.Do("session connection close", s.Conn.Close)
		}
		if !closeTimerStopped {
			<-forcedCloseDone
		}
		return
	}
	if s.Conn != nil {
		_ = extension.Do("session connection close", s.Conn.Close)
	}
}

func (s *activeServerSession) requiresAsyncClose() bool {
	return s != nil && (s.RevokeData != nil || s.Write != nil || s.Conn != nil)
}

func (s *activeServerSession) logError(scope string, err error) {
	if s != nil && s.owner != nil {
		s.owner.logError(scope, err)
	}
}

func normalizeSessionCloseReason(reason string) string {
	if reason == "" {
		return "session revoked"
	}
	if len(reason) <= 255 && utf8.ValidString(reason) {
		return reason
	}
	runes := []rune(reason)
	for len(runes) > 0 && len(string(runes)) > 255 {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 {
		return "session revoked"
	}
	return string(runes)
}

var _ SessionController = (*Server)(nil)
