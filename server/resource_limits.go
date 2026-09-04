// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/sourceip"
)

const (
	defaultMaxSessions                       = 4096
	defaultMaxStreams                        = 4096
	defaultMaxStreamsPerClient               = 256
	defaultMaxPendingDials                   = 512
	defaultMaxPendingDialsPerClient          = 32
	defaultOutboundDialTimeout               = 10 * time.Second
	defaultMaxPendingAuth                    = 256
	defaultMaxPendingAuthPerSource           = 32
	defaultMaxAuthAttemptsPerWindow          = 4096
	defaultMaxAuthAttemptsPerSourcePerWindow = 512
	defaultAuthAttemptWindow                 = time.Second
	maxConfiguredResourceLimit               = 1 << 20
)

var errResourceLimit = errors.New("Talaria server: resource limit reached")

type clientResourceUsage struct {
	streams     int
	pendingDial int
}

type sessionTokenLinks struct {
	previous uint64
	next     uint64
}

type resourceLimiter struct {
	mu                  sync.Mutex
	limits              ResourceLimits
	sessions            int
	nextSessionToken    uint64
	sessionOwners       map[uint64]uint64
	sessionTokens       map[uint64]sessionTokenLinks
	streams             int
	pending             int
	byClient            map[uint64]clientResourceUsage
	outboundWorkers     map[uint64]int
	pendingAuth         int
	pendingAuthBySource map[string]int
	authWorkersBySource map[string]int
	authWindowStarted   time.Time
	authAttempts        int
	authBySource        map[string]int
}

type sessionResourceLease struct {
	limiter  *resourceLimiter
	clientID uint64
	token    uint64
	once     sync.Once
}

type streamResourceLease struct {
	limiter     *resourceLimiter
	clientID    uint64
	pendingOnce sync.Once
	streamOnce  sync.Once
}

type pendingAuthResourceLease struct {
	limiter *resourceLimiter
	source  string
	once    sync.Once
}

func normalizeResourceLimits(limits ResourceLimits) (ResourceLimits, error) {
	values := []*int{
		&limits.MaxSessions,
		&limits.MaxStreams,
		&limits.MaxStreamsPerClient,
		&limits.MaxPendingDials,
		&limits.MaxPendingDialsPerClient,
		&limits.MaxPendingAuth,
		&limits.MaxPendingAuthPerSource,
		&limits.MaxAuthAttemptsPerWindow,
		&limits.MaxAuthAttemptsPerSourcePerWindow,
	}
	for _, value := range values {
		if *value < 0 {
			return ResourceLimits{}, errors.New("Talaria server: resource limits cannot be negative")
		}
		if *value > maxConfiguredResourceLimit {
			return ResourceLimits{}, errors.New("Talaria server: resource limit is too large")
		}
	}
	if limits.DialTimeout < 0 {
		return ResourceLimits{}, errors.New("Talaria server: dial timeout cannot be negative")
	}
	if limits.AuthAttemptWindow < 0 {
		return ResourceLimits{}, errors.New("Talaria server: auth attempt window cannot be negative")
	}
	var err error
	limits.IPv6SourcePrefixBits, err = sourceip.NormalizePrefixBits(limits.IPv6SourcePrefixBits)
	if err != nil {
		return ResourceLimits{}, fmt.Errorf("Talaria server: %w", err)
	}
	if limits.MaxSessions == 0 {
		limits.MaxSessions = defaultMaxSessions
	}
	if limits.MaxStreams == 0 {
		limits.MaxStreams = defaultMaxStreams
	}
	if limits.MaxStreamsPerClient == 0 {
		limits.MaxStreamsPerClient = min(defaultMaxStreamsPerClient, limits.MaxStreams/2)
	}
	if limits.MaxStreamsPerClient == 0 || limits.MaxStreamsPerClient >= limits.MaxStreams {
		return ResourceLimits{}, errors.New("Talaria server: client stream limit must be less than global limit")
	}
	if limits.MaxPendingDials == 0 {
		limits.MaxPendingDials = defaultMaxPendingDials
	}
	if limits.MaxPendingDialsPerClient == 0 {
		limits.MaxPendingDialsPerClient = min(defaultMaxPendingDialsPerClient, limits.MaxPendingDials/2)
	}
	if limits.MaxPendingDialsPerClient == 0 || limits.MaxPendingDialsPerClient >= limits.MaxPendingDials {
		return ResourceLimits{}, errors.New("Talaria server: client pending dial limit must be less than global limit")
	}
	if limits.DialTimeout == 0 {
		limits.DialTimeout = defaultOutboundDialTimeout
	}
	if limits.MaxPendingAuth == 0 {
		limits.MaxPendingAuth = defaultMaxPendingAuth
	}
	if limits.MaxPendingAuthPerSource == 0 {
		limits.MaxPendingAuthPerSource = min(defaultMaxPendingAuthPerSource, limits.MaxPendingAuth/2)
	}
	if limits.MaxPendingAuthPerSource == 0 || limits.MaxPendingAuthPerSource >= limits.MaxPendingAuth {
		return ResourceLimits{}, errors.New("Talaria server: source pending authentication limit must be less than global limit")
	}
	if limits.MaxAuthAttemptsPerWindow == 0 {
		limits.MaxAuthAttemptsPerWindow = defaultMaxAuthAttemptsPerWindow
	}
	if limits.MaxAuthAttemptsPerSourcePerWindow == 0 {
		limits.MaxAuthAttemptsPerSourcePerWindow = min(
			defaultMaxAuthAttemptsPerSourcePerWindow,
			limits.MaxAuthAttemptsPerWindow/2,
		)
	}
	if limits.MaxAuthAttemptsPerSourcePerWindow == 0 ||
		limits.MaxAuthAttemptsPerSourcePerWindow >= limits.MaxAuthAttemptsPerWindow {
		return ResourceLimits{}, errors.New("Talaria server: source authentication attempt limit must be less than global limit")
	}
	if limits.AuthAttemptWindow == 0 {
		limits.AuthAttemptWindow = defaultAuthAttemptWindow
	}
	return limits, nil
}

func newResourceLimiter(limits ResourceLimits) *resourceLimiter {
	return &resourceLimiter{
		limits:              limits,
		sessionOwners:       make(map[uint64]uint64),
		sessionTokens:       make(map[uint64]sessionTokenLinks),
		byClient:            make(map[uint64]clientResourceUsage),
		outboundWorkers:     make(map[uint64]int),
		pendingAuthBySource: make(map[string]int),
		authWorkersBySource: make(map[string]int),
		authBySource:        make(map[string]int),
	}
}

func (l *resourceLimiter) acquireOutboundWorker(clientID uint64, slots chan struct{}) (func(), bool) {
	if l == nil || clientID == 0 || slots == nil {
		return nil, false
	}
	l.mu.Lock()
	if l.limits.MaxPendingDialsPerClient > 0 &&
		l.outboundWorkers[clientID] >= l.limits.MaxPendingDialsPerClient {
		l.mu.Unlock()
		return nil, false
	}
	select {
	case slots <- struct{}{}:
		l.outboundWorkers[clientID]++
		l.mu.Unlock()
	default:
		l.mu.Unlock()
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			<-slots
			if count := l.outboundWorkers[clientID]; count <= 1 {
				delete(l.outboundWorkers, clientID)
			} else {
				l.outboundWorkers[clientID] = count - 1
			}
			l.mu.Unlock()
		})
	}, true
}

func (l *resourceLimiter) acquireAuthWorker(source string, slots chan struct{}) (func(), bool) {
	if l == nil || slots == nil {
		return nil, false
	}
	if source == "" {
		source = "unknown"
	}
	source = sourceip.Key(source, l.limits.IPv6SourcePrefixBits)
	l.mu.Lock()
	if l.limits.MaxPendingAuthPerSource > 0 &&
		l.authWorkersBySource[source] >= l.limits.MaxPendingAuthPerSource {
		l.mu.Unlock()
		return nil, false
	}
	select {
	case slots <- struct{}{}:
		l.authWorkersBySource[source]++
		l.mu.Unlock()
	default:
		l.mu.Unlock()
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			<-slots
			if count := l.authWorkersBySource[source]; count <= 1 {
				delete(l.authWorkersBySource, source)
			} else {
				l.authWorkersBySource[source] = count - 1
			}
			l.mu.Unlock()
		})
	}, true
}

func (l *resourceLimiter) acquirePendingAuth(source string) (*pendingAuthResourceLease, error) {
	if l == nil {
		return nil, nil
	}
	if source == "" {
		source = "unknown"
	}
	source = sourceip.Key(source, l.limits.IPv6SourcePrefixBits)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pendingAuth >= l.limits.MaxPendingAuth ||
		l.pendingAuthBySource[source] >= l.limits.MaxPendingAuthPerSource {
		return nil, errResourceLimit
	}
	l.pendingAuth++
	l.pendingAuthBySource[source]++
	return &pendingAuthResourceLease{limiter: l, source: source}, nil
}

func (l *pendingAuthResourceLease) release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		defer limiter.mu.Unlock()
		if limiter.pendingAuth > 0 {
			limiter.pendingAuth--
		}
		if limiter.pendingAuthBySource[l.source] > 1 {
			limiter.pendingAuthBySource[l.source]--
		} else {
			delete(limiter.pendingAuthBySource, l.source)
		}
	})
}

// allowAuthAttempt consumes one global and per-source authentication attempt.
func (l *resourceLimiter) allowAuthAttempt(source string, now time.Time) bool {
	if l == nil {
		return true
	}
	if source == "" {
		source = "unknown"
	}
	source = sourceip.Key(source, l.limits.IPv6SourcePrefixBits)
	l.mu.Lock()
	defer l.mu.Unlock()
	// A backward wall-clock jump must not reopen the current rate-limit window.
	if l.authWindowStarted.IsZero() || now.Sub(l.authWindowStarted) >= l.limits.AuthAttemptWindow {
		l.authWindowStarted = now
		l.authAttempts = 0
		clear(l.authBySource)
	}
	if l.authAttempts >= l.limits.MaxAuthAttemptsPerWindow ||
		l.authBySource[source] >= l.limits.MaxAuthAttemptsPerSourcePerWindow {
		return false
	}
	l.authAttempts++
	l.authBySource[source]++
	return true
}

func (l *resourceLimiter) acquireSession(clientID uint64) (*sessionResourceLease, error) {
	if l == nil || clientID == 0 {
		return nil, errResourceLimit
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	previousToken, hadPrevious := l.sessionOwners[clientID]
	if !hadPrevious && l.sessions >= l.limits.MaxSessions {
		return nil, errResourceLimit
	}
	l.nextSessionToken++
	if l.nextSessionToken == 0 {
		l.nextSessionToken++
	}
	token := l.nextSessionToken
	if !hadPrevious {
		l.sessions++
	} else {
		links := l.sessionTokens[previousToken]
		links.next = token
		l.sessionTokens[previousToken] = links
	}
	l.sessionTokens[token] = sessionTokenLinks{previous: previousToken}
	l.sessionOwners[clientID] = token
	return &sessionResourceLease{
		limiter:  l,
		clientID: clientID,
		token:    token,
	}, nil
}

func (l *resourceLimiter) removeSessionTokenLocked(token uint64) uint64 {
	links, ok := l.sessionTokens[token]
	if !ok {
		return 0
	}
	if links.previous != 0 {
		previous := l.sessionTokens[links.previous]
		previous.next = links.next
		l.sessionTokens[links.previous] = previous
	}
	if links.next != 0 {
		next := l.sessionTokens[links.next]
		next.previous = links.previous
		l.sessionTokens[links.next] = next
	}
	delete(l.sessionTokens, token)
	return links.previous
}

func (l *resourceLimiter) clearSessionTokensLocked(token uint64) {
	for token != 0 {
		links := l.sessionTokens[token]
		delete(l.sessionTokens, token)
		token = links.previous
	}
}

func (l *sessionResourceLease) rollback() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		defer limiter.mu.Unlock()
		if limiter.sessionOwners[l.clientID] != l.token {
			limiter.removeSessionTokenLocked(l.token)
			return
		}
		if previous := limiter.removeSessionTokenLocked(l.token); previous != 0 {
			limiter.sessionOwners[l.clientID] = previous
			return
		}
		delete(limiter.sessionOwners, l.clientID)
		if limiter.sessions > 0 {
			limiter.sessions--
		}
	})
}

func (l *sessionResourceLease) release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		defer limiter.mu.Unlock()
		if limiter.sessionOwners[l.clientID] != l.token {
			limiter.removeSessionTokenLocked(l.token)
			return
		}
		delete(limiter.sessionOwners, l.clientID)
		limiter.clearSessionTokensLocked(l.token)
		if limiter.sessions > 0 {
			limiter.sessions--
		}
	})
}

func (l *resourceLimiter) acquireStream(clientID uint64) (*streamResourceLease, error) {
	if l == nil || clientID == 0 {
		return nil, errResourceLimit
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	usage := l.byClient[clientID]
	if l.streams >= l.limits.MaxStreams ||
		usage.streams >= l.limits.MaxStreamsPerClient ||
		l.pending >= l.limits.MaxPendingDials ||
		usage.pendingDial >= l.limits.MaxPendingDialsPerClient {
		return nil, errResourceLimit
	}
	l.streams++
	l.pending++
	usage.streams++
	usage.pendingDial++
	l.byClient[clientID] = usage
	return &streamResourceLease{limiter: l, clientID: clientID}, nil
}

func (l *streamResourceLease) dialDone() {
	if l == nil || l.limiter == nil {
		return
	}
	l.pendingOnce.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		usage := limiter.byClient[l.clientID]
		if limiter.pending > 0 {
			limiter.pending--
		}
		if usage.pendingDial > 0 {
			usage.pendingDial--
		}
		limiter.storeClientUsageLocked(l.clientID, usage)
		limiter.mu.Unlock()
	})
}

func (l *streamResourceLease) release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.dialDone()
	l.streamOnce.Do(func() {
		limiter := l.limiter
		limiter.mu.Lock()
		usage := limiter.byClient[l.clientID]
		if limiter.streams > 0 {
			limiter.streams--
		}
		if usage.streams > 0 {
			usage.streams--
		}
		limiter.storeClientUsageLocked(l.clientID, usage)
		limiter.mu.Unlock()
	})
}

func (l *resourceLimiter) storeClientUsageLocked(clientID uint64, usage clientResourceUsage) {
	if usage.streams == 0 && usage.pendingDial == 0 {
		delete(l.byClient, clientID)
		return
	}
	l.byClient[clientID] = usage
}

func (l *resourceLimiter) dialTimeout() time.Duration {
	if l == nil {
		return defaultOutboundDialTimeout
	}
	return l.limits.DialTimeout
}

type resourceLimitedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *resourceLimitedConn) Close() error {
	if c == nil {
		return nil
	}
	defer c.releaseOnce.Do(c.release)
	if extension.IsNil(c.Conn) {
		return net.ErrClosed
	}
	return extension.Do("Talaria resource-limited connection close", c.Conn.Close)
}

func (c *resourceLimitedConn) CloseWrite() error {
	if c == nil || extension.IsNil(c.Conn) {
		return net.ErrClosed
	}
	closeWrite, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	return extension.Do("Talaria resource-limited connection close write", closeWrite.CloseWrite)
}
