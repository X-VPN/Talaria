// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/X-VPN/Talaria/internal/sourceip"
)

const (
	defaultMaxConnections            = 4096
	defaultMaxConnectionsPerSourceIP = 1024
	defaultMaxPendingHandshakes      = 512
	defaultMaxPendingPerSourceIP     = 64
	maxAdmissionLimit                = 1 << 20
)

type sourceAdmissionUsage struct {
	connections int
	pending     int
}

type admissionLimiter struct {
	mu          sync.Mutex
	limits      AdmissionLimits
	connections int
	pending     int
	bySource    map[string]sourceAdmissionUsage
}

type admissionLease struct {
	limiter        *admissionLimiter
	source         string
	pendingOnce    sync.Once
	connectionOnce sync.Once
}

func normalizeAdmissionLimits(limits AdmissionLimits) (AdmissionLimits, error) {
	values := []*int{
		&limits.MaxConnections,
		&limits.MaxConnectionsPerSourceIP,
		&limits.MaxPendingHandshakes,
		&limits.MaxPendingPerSourceIP,
	}
	for _, value := range values {
		if *value < 0 {
			return AdmissionLimits{}, errors.New("SOCKS5 TLS admission limits cannot be negative")
		}
		if *value > maxAdmissionLimit {
			return AdmissionLimits{}, errors.New("SOCKS5 TLS admission limit is too large")
		}
	}
	if limits.MaxConnections == 0 {
		limits.MaxConnections = defaultMaxConnections
	}
	if limits.MaxConnectionsPerSourceIP == 0 {
		limits.MaxConnectionsPerSourceIP = min(defaultMaxConnectionsPerSourceIP, limits.MaxConnections/2)
	}
	if limits.MaxConnectionsPerSourceIP == 0 || limits.MaxConnectionsPerSourceIP >= limits.MaxConnections {
		return AdmissionLimits{}, errors.New("SOCKS5 TLS source connection limit must be less than global limit")
	}
	if limits.MaxPendingHandshakes == 0 {
		limits.MaxPendingHandshakes = defaultMaxPendingHandshakes
	}
	if limits.MaxPendingPerSourceIP == 0 {
		limits.MaxPendingPerSourceIP = min(defaultMaxPendingPerSourceIP, limits.MaxPendingHandshakes/2)
	}
	if limits.MaxPendingPerSourceIP == 0 || limits.MaxPendingPerSourceIP >= limits.MaxPendingHandshakes {
		return AdmissionLimits{}, errors.New("SOCKS5 TLS source pending handshake limit must be less than global limit")
	}
	var err error
	limits.IPv6SourcePrefixBits, err = sourceip.NormalizePrefixBits(limits.IPv6SourcePrefixBits)
	if err != nil {
		return AdmissionLimits{}, err
	}
	return limits, nil
}

func newAdmissionLimiter(limits AdmissionLimits) *admissionLimiter {
	return &admissionLimiter{
		limits:   limits,
		bySource: make(map[string]sourceAdmissionUsage),
	}
}

func (l *admissionLimiter) acquire(addr net.Addr) (*admissionLease, bool) {
	if l == nil {
		return nil, false
	}
	source := admissionSourceKey(addr, l.limits.IPv6SourcePrefixBits)
	l.mu.Lock()
	defer l.mu.Unlock()
	usage := l.bySource[source]
	if l.connections >= l.limits.MaxConnections ||
		usage.connections >= l.limits.MaxConnectionsPerSourceIP ||
		l.pending >= l.limits.MaxPendingHandshakes ||
		usage.pending >= l.limits.MaxPendingPerSourceIP {
		return nil, false
	}
	l.connections++
	l.pending++
	usage.connections++
	usage.pending++
	l.bySource[source] = usage
	return &admissionLease{limiter: l, source: source}, true
}

func (l *admissionLease) releasePending() {
	if l == nil || l.limiter == nil {
		return
	}
	l.pendingOnce.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		usage := limiter.bySource[l.source]
		if limiter.pending > 0 {
			limiter.pending--
		}
		if usage.pending > 0 {
			usage.pending--
		}
		limiter.storeSourceUsageLocked(l.source, usage)
		limiter.mu.Unlock()
	})
}

func (l *admissionLease) release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.releasePending()
	l.connectionOnce.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		usage := limiter.bySource[l.source]
		if limiter.connections > 0 {
			limiter.connections--
		}
		if usage.connections > 0 {
			usage.connections--
		}
		limiter.storeSourceUsageLocked(l.source, usage)
		limiter.mu.Unlock()
	})
}

func (l *admissionLimiter) storeSourceUsageLocked(source string, usage sourceAdmissionUsage) {
	if usage.connections == 0 && usage.pending == 0 {
		delete(l.bySource, source)
		return
	}
	l.bySource[source] = usage
}

func admissionSourceKey(addr net.Addr, ipv6PrefixBits int) string {
	if addr == nil {
		return "unknown"
	}
	raw := strings.TrimSpace(addr.String())
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return raw
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if ip := net.ParseIP(host); ip != nil {
		return sourceip.Key(ip.String(), ipv6PrefixBits)
	}
	return strings.ToLower(host)
}

type admittedConn struct {
	net.Conn
	lease *admissionLease
}

func (c *admittedConn) finishAdmission() {
	if c != nil && c.lease != nil {
		c.lease.releasePending()
	}
}

func (c *admittedConn) CloseWrite() error {
	closeWrite, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	return closeWrite.CloseWrite()
}
