// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package transport defines the protocol-neutral contracts between the Talaria
// server and whatever carries its traffic, so a transport can be replaced
// without touching session or policy logic.
//
// A SessionGrant binds a client ID, a monotonic generation and a random 256-bit
// data token. The registry stores only the token's SHA-256 hash and compares in
// constant time, so a numeric client ID alone never authorizes a data stream,
// and a token authorizes only its own generation.
package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const DataTokenSize = 32

type Network string

const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
	NetworkIP  Network = "ip"
)

type Destination struct {
	Network Network
	Host    string
	Port    uint16
}

func (d Destination) Validate() error {
	if d.Network != NetworkTCP {
		return fmt.Errorf("unsupported destination network %q", d.Network)
	}
	if strings.TrimSpace(d.Host) == "" {
		return errors.New("destination host is required")
	}
	if d.Port == 0 {
		return errors.New("destination port is required")
	}
	return nil
}

func (d Destination) Address() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

type SessionRef struct {
	ClientID   uint64
	Generation uint64
}

type SessionGrant struct {
	SessionRef
	DataToken [DataTokenSize]byte
	ExpiresAt time.Time
}

func NewSessionGrant(clientID, generation uint64, now time.Time, ttl time.Duration) (SessionGrant, error) {
	if clientID == 0 {
		return SessionGrant{}, errors.New("client id is required")
	}
	if generation == 0 {
		return SessionGrant{}, errors.New("session generation is required")
	}
	if ttl < 0 {
		return SessionGrant{}, errors.New("session ttl cannot be negative")
	}
	grant := SessionGrant{
		SessionRef: SessionRef{
			ClientID:   clientID,
			Generation: generation,
		},
	}
	if ttl > 0 {
		grant.ExpiresAt = now.Add(ttl)
	}
	if _, err := rand.Read(grant.DataToken[:]); err != nil {
		return SessionGrant{}, fmt.Errorf("generate session token: %w", err)
	}
	return grant, nil
}

func (g *SessionGrant) Validate(now time.Time) error {
	if g == nil {
		return errors.New("session grant is required")
	}
	if g.ClientID == 0 {
		return errors.New("client id is required")
	}
	if g.Generation == 0 {
		return errors.New("session generation is required")
	}
	if !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt) {
		return errors.New("session grant is expired")
	}
	var zero [DataTokenSize]byte
	if g.DataToken == zero {
		return errors.New("session data token is required")
	}
	return nil
}

type Client interface {
	DialControl(ctx context.Context) (net.Conn, error)
	Activate(ctx context.Context, grant SessionGrant) error
	DialStream(ctx context.Context, target Destination) (net.Conn, error)
	Close() error
}

type ControlHandler interface {
	HandleControl(ctx context.Context, conn net.Conn) error
}

type ControlHandlerFunc func(ctx context.Context, conn net.Conn) error

func (fn ControlHandlerFunc) HandleControl(ctx context.Context, conn net.Conn) error {
	return fn(ctx, conn)
}

type StreamRequest struct {
	Session SessionRef
	Target  Destination
	Source  net.Addr
	Local   net.Addr
}

type StreamHandler interface {
	OpenStream(ctx context.Context, req StreamRequest) (net.Conn, error)
}

type StreamHandlerFunc func(ctx context.Context, req StreamRequest) (net.Conn, error)

func (fn StreamHandlerFunc) OpenStream(ctx context.Context, req StreamRequest) (net.Conn, error) {
	return fn(ctx, req)
}

type Server interface {
	Serve(ctx context.Context, control ControlHandler, streams StreamHandler) error
	Activate(ctx context.Context, grant SessionGrant) error
	Revoke(ctx context.Context, session SessionRef) error
	Addr() net.Addr
	Close() error
}

// StagedServer keeps a new data credential pending while the control session
// attaches its resources. Commit records rollback state without accepting the
// credential; Finalize makes it current before SessionReady is written.
type StagedServer interface {
	Server
	Prepare(ctx context.Context, grant SessionGrant) error
	Commit(ctx context.Context, session SessionRef) error
	Finalize(ctx context.Context, session SessionRef) error
}
