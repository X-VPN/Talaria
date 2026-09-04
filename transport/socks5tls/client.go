// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/X-VPN/Talaria/internal/controlframe"
	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
	"golang.org/x/net/proxy"
)

type Client struct {
	address        string
	tlsConfig      *tls.Config
	dialContext    DialContextFunc
	dialSlots      chan struct{}
	timeout        time.Duration
	wireKey        *wireKey
	lifetimeCtx    context.Context
	lifetimeCancel context.CancelFunc

	mu         sync.RWMutex
	grant      coretransport.SessionGrant
	generation uint64
	closed     bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("SOCKS5 TLS server address is required")
	}
	if cfg.EstablishmentTimeout < 0 || cfg.EstablishmentTimeout > maxClientEstablishmentTimeout {
		return nil, errors.New("SOCKS5 TLS establishment timeout is out of range")
	}
	if cfg.EstablishmentTimeout == 0 {
		cfg.EstablishmentTimeout = defaultClientEstablishmentTimeout
	}
	tlsConfig, err := normalizeClientTLSConfig(cfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	wireKey, err := newWireKey(cfg.WireSecret, cfg.WireIdentity)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = nil
	dialContext := cfg.DialContext
	if dialContext == nil {
		dialer := &net.Dialer{}
		dialContext = dialer.DialContext
	}
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	return &Client{
		address:        cfg.Address,
		tlsConfig:      tlsConfig,
		dialContext:    dialContext,
		dialSlots:      make(chan struct{}, maxConcurrentClientDials),
		timeout:        cfg.EstablishmentTimeout,
		wireKey:        wireKey,
		lifetimeCtx:    lifetimeCtx,
		lifetimeCancel: cancel,
		generation:     1,
	}, nil
}

func (c *Client) DialControl(ctx context.Context) (net.Conn, error) {
	generation, err := c.beginDial()
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.establishmentContext(ctx)
	defer cancel()
	conn, err := c.dialTLS(ctx, connectionRoleControl)
	if err != nil {
		return nil, err
	}
	if err := c.commitDial(generation, conn); err != nil {
		return nil, err
	}
	return controlframe.New(conn), nil
}

func (c *Client) Activate(_ context.Context, grant coretransport.SessionGrant) error {
	defer clear(grant.DataToken[:])
	if err := grant.Validate(time.Now()); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.grant.ClientID != 0 {
		if grant.ClientID != c.grant.ClientID {
			return errors.New("SOCKS5 TLS session client ID cannot change")
		}
		if grant.Generation <= c.grant.Generation {
			return errors.New("SOCKS5 TLS session generation is not newer")
		}
	}
	clear(c.grant.DataToken[:])
	c.grant = grant
	return nil
}

func (c *Client) DialStream(ctx context.Context, target coretransport.Destination) (net.Conn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	generation, err := c.beginDial()
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	grant := c.grant
	c.mu.RUnlock()
	defer clear(grant.DataToken[:])
	if err := grant.Validate(time.Now()); err != nil {
		return nil, fmt.Errorf("SOCKS5 TLS session is not active: %w", err)
	}
	ctx, cancel := c.establishmentContext(ctx)
	defer cancel()

	auth := &proxy.Auth{
		User:     strconv.FormatUint(grant.ClientID, 10),
		Password: base64.RawURLEncoding.EncodeToString(grant.DataToken[:]),
	}
	defer func() {
		auth.User = ""
		auth.Password = ""
	}()
	proxyTransport := &streamDialer{client: c}
	dialer, err := proxy.SOCKS5("tcp", c.address, auth, proxyTransport)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	var conn net.Conn
	err = extension.Do("SOCKS5 TLS stream negotiation", func() error {
		var dialErr error
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			conn, dialErr = contextDialer.DialContext(ctx, string(target.Network), target.Address())
		} else {
			conn, dialErr = dialer.Dial(string(target.Network), target.Address())
		}
		return dialErr
	})
	if err != nil {
		failedConn := conn
		if extension.IsNil(failedConn) {
			failedConn = proxyTransport.conn
		}
		if !extension.IsNil(failedConn) {
			_ = extension.Do("SOCKS5 TLS failed stream negotiation close", failedConn.Close)
		}
		return nil, c.normalizeDialError(err)
	}
	if extension.IsNil(conn) {
		if !extension.IsNil(proxyTransport.conn) {
			_ = extension.Do("SOCKS5 TLS invalid stream negotiation close", proxyTransport.conn.Close)
		}
		return nil, errors.New("SOCKS5 TLS stream dialer returned a nil connection")
	}
	if err := c.commitDial(generation, conn); err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	shouldCancel := false
	if !c.closed {
		c.closed = true
		c.generation++
		shouldCancel = true
	}
	clear(c.grant.DataToken[:])
	c.grant = coretransport.SessionGrant{}
	if c.wireKey != nil {
		clear(c.wireKey[:])
		c.wireKey = nil
	}
	c.mu.Unlock()
	if shouldCancel {
		c.lifetimeCancel()
	}
	return nil
}

func (c *Client) dialTLS(ctx context.Context, role connectionRole) (result net.Conn, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var raw net.Conn
	defer func() {
		if recovered := recover(); recovered != nil {
			err = extension.PanicError("SOCKS5 TLS client handshake extension", recovered)
			result = nil
			if !extension.IsNil(raw) {
				_ = extension.Do("SOCKS5 TLS panicked handshake connection close", raw.Close)
			}
		}
	}()
	raw, err = c.dialRaw(ctx)
	if err != nil {
		return nil, c.normalizeDialError(err)
	}
	if extension.IsNil(raw) {
		return nil, errors.New("SOCKS5 TLS dialer returned a nil connection")
	}
	c.mu.RLock()
	wireConn := wrapClientWire(raw, c.wireKey)
	c.mu.RUnlock()
	conn := tls.Client(wireConn, c.tlsConfig.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = extension.Do("SOCKS5 TLS raw connection close", raw.Close)
		return nil, c.normalizeDialError(fmt.Errorf("TLS handshake: %w", err))
	}
	state := conn.ConnectionState()
	if err := validateNegotiatedCipherSuite(state.CipherSuite); err != nil {
		_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
		return nil, err
	}
	if err := validateNegotiatedProtocol(state.NegotiatedProtocol); err != nil {
		_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
		return nil, err
	}
	writeDeadlineSet := false
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
			return nil, c.normalizeDialError(fmt.Errorf("set TLS role write deadline: %w", err))
		}
		writeDeadlineSet = true
	}
	if err := writeConnectionRole(conn, role); err != nil {
		_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
		return nil, c.normalizeDialError(fmt.Errorf("write TLS connection role: %w", err))
	}
	if writeDeadlineSet {
		if err := conn.SetWriteDeadline(time.Time{}); err != nil {
			_ = extension.Do("SOCKS5 TLS connection close", conn.Close)
			return nil, c.normalizeDialError(fmt.Errorf("clear TLS role write deadline: %w", err))
		}
	}
	return conn, nil
}

func (c *Client) establishmentContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	establishmentCtx, cancel := context.WithTimeout(ctx, c.timeout)
	stopLifetimeCancel := context.AfterFunc(c.lifetimeCtx, cancel)
	return establishmentCtx, func() {
		stopLifetimeCancel()
		cancel()
	}
}

func (c *Client) beginDial() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.generation, nil
}

func (c *Client) commitDial(generation uint64, conn net.Conn) error {
	c.mu.RLock()
	valid := !c.closed && c.generation == generation
	c.mu.RUnlock()
	if valid {
		return nil
	}
	if conn != nil {
		_ = extension.Do("SOCKS5 TLS stale connection close", conn.Close)
	}
	return net.ErrClosed
}

func (c *Client) normalizeDialError(err error) error {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return net.ErrClosed
	}
	return err
}

func (c *Client) dialRaw(ctx context.Context) (net.Conn, error) {
	select {
	case c.dialSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, errors.New("SOCKS5 TLS has too many concurrent connection attempts")
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult)
	abandoned := make(chan struct{})
	go func() {
		defer func() { <-c.dialSlots }()
		var conn net.Conn
		err := extension.Do("SOCKS5 TLS client dialer", func() error {
			var dialErr error
			conn, dialErr = c.dialContext(ctx, "tcp", c.address)
			return dialErr
		})
		select {
		case resultCh <- dialResult{conn: conn, err: err}:
		case <-abandoned:
			if conn != nil {
				_ = extension.Do("SOCKS5 TLS abandoned connection close", conn.Close)
			}
		}
	}()
	defer close(abandoned)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil && result.conn != nil {
			_ = extension.Do("SOCKS5 TLS failed connection close", result.conn.Close)
		}
		return result.conn, result.err
	}
}

type streamDialer struct {
	client *Client
	conn   net.Conn
}

func (d *streamDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *streamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.client == nil {
		return nil, net.ErrClosed
	}
	if network != "tcp" || address != d.client.address {
		return nil, fmt.Errorf("unexpected SOCKS5 proxy destination %s %s", network, address)
	}
	conn, err := d.client.dialTLS(ctx, connectionRoleStream)
	d.conn = conn
	return conn, err
}

var _ coretransport.Client = (*Client)(nil)
