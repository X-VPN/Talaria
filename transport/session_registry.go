// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

type sessionRecord struct {
	ref       SessionRef
	tokenHash [sha256.Size]byte
	expiresAt time.Time
}

type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[uint64]sessionRecord
	pending  map[uint64]sessionRecord
	commits  map[uint64]sessionCommit
}

type sessionCommit struct {
	current     sessionRecord
	previous    sessionRecord
	hadPrevious bool
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions: make(map[uint64]sessionRecord),
		pending:  make(map[uint64]sessionRecord),
		commits:  make(map[uint64]sessionCommit),
	}
}

func (r *SessionRegistry) Activate(grant SessionGrant, now time.Time) error {
	defer clear(grant.DataToken[:])
	if err := r.Prepare(grant, now); err != nil {
		return err
	}
	if _, _, _, err := r.Commit(grant.SessionRef, now); err != nil {
		return err
	}
	if _, _, err := r.Finalize(grant.SessionRef); err != nil {
		r.Revoke(grant.SessionRef)
		return err
	}
	return nil
}

func (r *SessionRegistry) Prepare(grant SessionGrant, now time.Time) error {
	defer clear(grant.DataToken[:])
	if err := grant.Validate(now); err != nil {
		return err
	}
	record := sessionRecord{
		ref:       grant.SessionRef,
		tokenHash: sha256.Sum256(grant.DataToken[:]),
		expiresAt: grant.ExpiresAt,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, committing := r.commits[grant.ClientID]; committing {
		return errors.New("session commit is still in progress")
	}
	latest := r.sessions[grant.ClientID]
	if pending, ok := r.pending[grant.ClientID]; ok {
		if !sessionExpired(pending.expiresAt, now) {
			return errors.New("session setup is already pending")
		}
		delete(r.pending, grant.ClientID)
	}
	if latest.ref.Generation != 0 && grant.Generation <= latest.ref.Generation {
		return fmt.Errorf("session generation %d is not newer than %d", grant.Generation, latest.ref.Generation)
	}
	r.pending[grant.ClientID] = record
	return nil
}

func (r *SessionRegistry) Commit(ref SessionRef, now time.Time) (SessionRef, bool, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pending, ok := r.pending[ref.ClientID]
	if !ok || pending.ref != ref {
		return SessionRef{}, false, time.Time{}, fmt.Errorf("session %+v is not pending", ref)
	}
	if sessionExpired(pending.expiresAt, now) {
		delete(r.pending, ref.ClientID)
		return SessionRef{}, false, time.Time{}, errors.New("pending session grant is expired")
	}
	old, hadOld := r.sessions[ref.ClientID]
	r.sessions[ref.ClientID] = pending
	delete(r.pending, ref.ClientID)
	r.commits[ref.ClientID] = sessionCommit{current: pending, previous: old, hadPrevious: hadOld}
	return old.ref, hadOld, pending.expiresAt, nil
}

func (r *SessionRegistry) Finalize(ref SessionRef) (SessionRef, bool, error) {
	if r == nil {
		return SessionRef{}, false, errors.New("session registry is closed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	commit, ok := r.commits[ref.ClientID]
	if !ok || commit.current.ref != ref {
		return SessionRef{}, false, fmt.Errorf("session %+v is not being committed", ref)
	}
	current, ok := r.sessions[ref.ClientID]
	if !ok || current.ref != ref {
		return SessionRef{}, false, fmt.Errorf("session %+v is no longer current", ref)
	}
	delete(r.commits, ref.ClientID)
	return commit.previous.ref, commit.hadPrevious, nil
}

func (r *SessionRegistry) Revoke(session SessionRef) bool {
	if r == nil || session.ClientID == 0 || session.Generation == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if record, ok := r.pending[session.ClientID]; ok && record.ref == session {
		delete(r.pending, session.ClientID)
		return true
	}
	if record, ok := r.sessions[session.ClientID]; ok && record.ref == session {
		if commit, committing := r.commits[session.ClientID]; committing && commit.current.ref == session {
			delete(r.commits, session.ClientID)
			if commit.hadPrevious {
				r.sessions[session.ClientID] = commit.previous
			} else {
				delete(r.sessions, session.ClientID)
			}
		} else {
			delete(r.sessions, session.ClientID)
		}
		return true
	}
	if commit, committing := r.commits[session.ClientID]; committing && commit.hadPrevious && commit.previous.ref == session {
		commit.hadPrevious = false
		commit.previous = sessionRecord{}
		r.commits[session.ClientID] = commit
		return true
	}
	return false
}

func (r *SessionRegistry) Current(clientID uint64, now time.Time) (SessionRef, bool) {
	if r == nil || clientID == 0 {
		return SessionRef{}, false
	}
	r.mu.RLock()
	record, ok := r.currentRecord(clientID)
	r.mu.RUnlock()
	if !ok || sessionExpired(record.expiresAt, now) {
		return SessionRef{}, false
	}
	return record.ref, true
}

func (r *SessionRegistry) Authenticate(clientID uint64, token [DataTokenSize]byte, now time.Time) (SessionRef, bool) {
	defer clear(token[:])
	return r.AuthenticateBytes(clientID, token[:], now)
}

func (r *SessionRegistry) AuthenticateBytes(clientID uint64, token []byte, now time.Time) (SessionRef, bool) {
	if r == nil || clientID == 0 || len(token) != DataTokenSize {
		return SessionRef{}, false
	}
	tokenHash := sha256.Sum256(token)
	r.mu.RLock()
	record, ok := r.currentRecord(clientID)
	r.mu.RUnlock()
	valid := ok && !sessionExpired(record.expiresAt, now)
	expectedHash := [sha256.Size]byte{}
	if valid {
		expectedHash = record.tokenHash
	}
	matched := subtle.ConstantTimeCompare(expectedHash[:], tokenHash[:])
	clear(expectedHash[:])
	clear(tokenHash[:])
	if !valid || matched != 1 {
		return SessionRef{}, false
	}
	return record.ref, true
}

func (r *SessionRegistry) currentRecord(clientID uint64) (sessionRecord, bool) {
	record, ok := r.sessions[clientID]
	if commit, committing := r.commits[clientID]; committing && commit.current.ref == record.ref {
		return commit.previous, commit.hadPrevious
	}
	return record, ok
}

func sessionExpired(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !now.Before(expiresAt)
}

func (r *SessionRegistry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	clear(r.sessions)
	clear(r.pending)
	clear(r.commits)
	r.mu.Unlock()
}
