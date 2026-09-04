// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"testing"
	"time"
)

func TestSessionRegistryRejectsStaleRevocation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	oldGrant, err := NewSessionGrant(42, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := NewSessionGrant(42, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(oldGrant, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(newGrant, now); err != nil {
		t.Fatal(err)
	}
	if registry.Revoke(oldGrant.SessionRef) {
		t.Fatal("stale session revoked the current generation")
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); !ok {
		t.Fatal("current session was not accepted")
	}
	if !registry.Revoke(newGrant.SessionRef) {
		t.Fatal("current session was not revoked")
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); ok {
		t.Fatal("revoked session was accepted")
	}
}

func TestSessionRegistryKeepsPreparedGrantInactiveUntilFinalize(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	oldGrant, err := NewSessionGrant(42, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := NewSessionGrant(42, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(oldGrant, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Prepare(newGrant, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); ok {
		t.Fatal("prepared token authenticated before commit")
	}
	if ref, ok := registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, now); !ok || ref != oldGrant.SessionRef {
		t.Fatal("preparing replacement revoked the current token")
	}
	if _, _, _, err := registry.Commit(newGrant.SessionRef, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); ok {
		t.Fatal("committing token authenticated before finalize")
	}
	if ref, ok := registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, now); !ok || ref != oldGrant.SessionRef {
		t.Fatal("committing replacement revoked the current token")
	}
	if _, _, err := registry.Finalize(newGrant.SessionRef); err != nil {
		t.Fatal(err)
	}
	if ref, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); !ok || ref != newGrant.SessionRef {
		t.Fatal("committed token was not activated")
	}
}

func TestSessionRegistryReplacesExpiredPendingGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	expired, err := NewSessionGrant(42, 1, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := NewSessionGrant(42, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Prepare(expired, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Prepare(replacement, now.Add(time.Second)); err != nil {
		t.Fatalf("Prepare() after pending expiry: %v", err)
	}
	if _, _, _, err := registry.Commit(replacement.SessionRef, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Finalize(replacement.SessionRef); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(replacement.ClientID, replacement.DataToken, now.Add(time.Second)); !ok {
		t.Fatal("replacement grant did not authenticate")
	}
}

func TestSessionRegistryRestoresCurrentWhenCommitIsRevoked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	oldGrant, err := NewSessionGrant(42, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newGrant, err := NewSessionGrant(42, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(oldGrant, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Prepare(newGrant, now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := registry.Commit(newGrant.SessionRef, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); ok {
		t.Fatal("committing token authenticated before finalize")
	}
	if !registry.Revoke(newGrant.SessionRef) {
		t.Fatal("committing session was not revoked")
	}
	if ref, ok := registry.Authenticate(oldGrant.ClientID, oldGrant.DataToken, now); !ok || ref != oldGrant.SessionRef {
		t.Fatal("revoking the committing session did not restore the current token")
	}
}

func TestSessionRegistryRejectsExpiredAndWrongTokens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	grant, err := NewSessionGrant(7, 1, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	wrong := grant.DataToken
	wrong[0] ^= 0xff
	if _, ok := registry.Authenticate(grant.ClientID, wrong, now); ok {
		t.Fatal("wrong token was accepted")
	}
	if _, ok := registry.Authenticate(grant.ClientID, grant.DataToken, now.Add(time.Second)); ok {
		t.Fatal("expired token was accepted")
	}
}

func TestSessionRegistryRejectsValidShapeFailureStates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	grant, err := NewSessionGrant(7, 1, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	wrong := grant.DataToken
	wrong[0] ^= 0xff
	tests := []struct {
		name     string
		clientID uint64
		token    [DataTokenSize]byte
		at       time.Time
	}{
		{name: "unknown", clientID: grant.ClientID + 1, token: wrong, at: now},
		{name: "expired", clientID: grant.ClientID, token: grant.DataToken, at: now.Add(time.Second)},
		{name: "wrong token", clientID: grant.ClientID, token: wrong, at: now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := registry.AuthenticateBytes(tt.clientID, tt.token[:], tt.at); ok {
				t.Fatal("invalid credentials were accepted")
			}
		})
	}
	if ref, ok := registry.AuthenticateBytes(grant.ClientID, grant.DataToken[:], now); !ok || ref != grant.SessionRef {
		t.Fatal("valid credentials were rejected")
	}
}

func TestSessionRegistryRejectsStaleActivation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	newGrant, err := NewSessionGrant(42, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	staleGrant, err := NewSessionGrant(42, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(newGrant, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(staleGrant, now); err == nil {
		t.Fatal("stale generation replaced the current session")
	}
	if _, ok := registry.Authenticate(newGrant.ClientID, newGrant.DataToken, now); !ok {
		t.Fatal("current session was lost after stale activation")
	}
}

func TestSessionGrantWithoutTTLRemainsValidUntilRevoked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	grant, err := NewSessionGrant(88, 1, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !grant.ExpiresAt.IsZero() {
		t.Fatalf("expires at = %v want zero", grant.ExpiresAt)
	}
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(grant.ClientID, grant.DataToken, now.Add(10*365*24*time.Hour)); !ok {
		t.Fatal("session without a TTL expired")
	}
	if !registry.Revoke(grant.SessionRef) {
		t.Fatal("session was not revoked")
	}
	if _, ok := registry.Authenticate(grant.ClientID, grant.DataToken, now); ok {
		t.Fatal("revoked session was accepted")
	}
}

func TestSessionGrantRejectsNegativeTTL(t *testing.T) {
	if _, err := NewSessionGrant(88, 1, time.Now(), -time.Second); err == nil {
		t.Fatal("negative session TTL was accepted")
	}
}

func TestSessionRegistryBindsTokensToClientAndLatestGeneration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewSessionRegistry()
	clientA1, err := NewSessionGrant(100, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clientB1, err := NewSessionGrant(200, 1, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(clientA1, now); err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(clientB1, now); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		clientID uint64
		token    [DataTokenSize]byte
		want     bool
	}{
		{name: "A with A token", clientID: clientA1.ClientID, token: clientA1.DataToken, want: true},
		{name: "A with B token", clientID: clientA1.ClientID, token: clientB1.DataToken},
		{name: "B with A token", clientID: clientB1.ClientID, token: clientA1.DataToken},
		{name: "B with B token", clientID: clientB1.ClientID, token: clientB1.DataToken, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := registry.Authenticate(tt.clientID, tt.token, now)
			if ok != tt.want {
				t.Fatalf("authentication = %v, want %v", ok, tt.want)
			}
		})
	}

	clientA2, err := NewSessionGrant(clientA1.ClientID, 2, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Activate(clientA2, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Authenticate(clientA1.ClientID, clientA1.DataToken, now); ok {
		t.Fatal("old token remained valid after reconnect")
	}
	if ref, ok := registry.Authenticate(clientA2.ClientID, clientA2.DataToken, now); !ok || ref != clientA2.SessionRef {
		t.Fatalf("replacement grant = ref=%+v ok=%v", ref, ok)
	}
}
