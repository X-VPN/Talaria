// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	minimumWireSecretSize      = 32
	wirePreambleTimeSize       = 8
	wirePreambleRandomSize     = 16
	wirePreambleNonceSize      = wirePreambleTimeSize + wirePreambleRandomSize
	wirePreambleTagSize        = 16
	wirePreambleSize           = wirePreambleNonceSize + wirePreambleTagSize
	wirePreambleValidity       = time.Minute
	defaultWireReplayCacheSize = 1 << 16
	defaultWireReplayPerSource = 1 << 12
	obfuscationWriteChunkSize  = 32 * 1024
	// These domain-separation labels define the single supported wire profile.
	// Keep them stable after release; changing one requires a coordinated rollout.
	wireKeyDomain            = "talaria-tcp-wire"
	wirePreambleDomain       = "talaria-tcp-preamble"
	wireTimeDomain           = "talaria-tcp-time"
	wireClientToServerDomain = "talaria-tcp-c2s"
	wireServerToClientDomain = "talaria-tcp-s2c"
)

var errInvalidWirePreamble = errors.New("TalariaTCP wire preamble authentication failed")

type wireRole uint8

const (
	wireRoleClient wireRole = iota
	wireRoleServer
)

type wireKey [sha256.Size]byte

func newWireKey(secret []byte, identity string) (*wireKey, error) {
	if len(secret) < minimumWireSecretSize {
		return nil, errors.New("TalariaTCP wire secret must contain at least 32 bytes")
	}
	identity = normalizeWireIdentity(identity)
	if identity == "" {
		return nil, errors.New("TalariaTCP wire identity is required")
	}
	input := make([]byte, 0, len(wireKeyDomain)+len(identity)+len(secret)+2)
	input = append(input, wireKeyDomain...)
	input = append(input, 0)
	input = append(input, identity...)
	input = append(input, 0)
	input = append(input, secret...)
	key := wireKey(sha256.Sum256(input))
	clear(input)
	return &key, nil
}

func normalizeWireIdentity(identity string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(identity), "."))
}

func wrapClientWire(conn net.Conn, key *wireKey) *obfuscatedConn {
	return wrapWire(conn, wireRoleClient, key)
}

func wrapServerWire(conn net.Conn, key *wireKey, replay *wireReplayCache, source string, now func() time.Time) *obfuscatedConn {
	wrapped := wrapWire(conn, wireRoleServer, key)
	if wrapped == nil {
		return nil
	}
	wrapped.replay = replay
	wrapped.source = source
	wrapped.now = now
	return wrapped
}

func wrapWire(conn net.Conn, role wireRole, key *wireKey) *obfuscatedConn {
	if conn == nil {
		return nil
	}
	return &obfuscatedConn{
		Conn:  conn,
		role:  role,
		key:   cloneWireKey(key),
		ready: make(chan struct{}),
	}
}

func cloneWireKey(key *wireKey) *wireKey {
	if key == nil {
		return nil
	}
	cloned := *key
	return &cloned
}

type obfuscatedConn struct {
	net.Conn
	role   wireRole
	key    *wireKey
	keyMu  sync.Mutex
	replay *wireReplayCache
	source string
	now    func() time.Time

	readMu  sync.Mutex
	writeMu sync.Mutex
	initMu  sync.Mutex
	started bool
	ready   chan struct{}
	initErr error

	readStream  cipher.Stream
	writeStream cipher.Stream
	writeBuf    []byte
}

func (c *obfuscatedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.ensureReadReady(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n < 0 || n > len(p) {
		return 0, fmt.Errorf("TalariaTCP connection returned invalid read size %d for %d-byte buffer", n, len(p))
	}
	if n > 0 {
		c.readStream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (c *obfuscatedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ensureWriteReady(); err != nil {
		return 0, err
	}
	total := 0
	for len(p) > 0 {
		chunkSize := min(len(p), obfuscationWriteChunkSize)
		if cap(c.writeBuf) < chunkSize {
			c.writeBuf = make([]byte, chunkSize)
		}
		buf := c.writeBuf[:chunkSize]
		c.writeStream.XORKeyStream(buf, p[:chunkSize])
		written, err := writeAllCount(c.Conn, buf)
		total += written
		if err != nil {
			return total, err
		}
		p = p[chunkSize:]
	}
	return total, nil
}

func (c *obfuscatedConn) Close() (err error) {
	defer c.clearKey()
	return c.Conn.Close()
}

func (c *obfuscatedConn) takeKey() *wireKey {
	c.keyMu.Lock()
	key := c.key
	c.key = nil
	c.keyMu.Unlock()
	return key
}

func (c *obfuscatedConn) clearKey() {
	c.keyMu.Lock()
	if c.key != nil {
		clear(c.key[:])
		c.key = nil
	}
	c.keyMu.Unlock()
}

func (c *obfuscatedConn) ensureReadReady() error {
	if c.role == wireRoleServer {
		return c.initializeServer()
	}
	<-c.ready
	return c.initErr
}

func (c *obfuscatedConn) ensureWriteReady() error {
	if c.role == wireRoleClient {
		return c.initializeClient()
	}
	<-c.ready
	return c.initErr
}

func (c *obfuscatedConn) initializeClient() error {
	c.initMu.Lock()
	if c.started {
		c.initMu.Unlock()
		<-c.ready
		return c.initErr
	}
	c.started = true
	key := c.takeKey()
	defer func() {
		if key != nil {
			clear(key[:])
		}
		close(c.ready)
		c.initMu.Unlock()
	}()
	if key == nil {
		c.initErr = errInvalidWirePreamble
		return c.initErr
	}
	preamble := make([]byte, wirePreambleSize)
	if _, err := io.ReadFull(rand.Reader, preamble[:wirePreambleRandomSize]); err != nil {
		c.initErr = err
		return err
	}
	encodeWirePreambleTime(key, preamble[:wirePreambleNonceSize], time.Now())
	c.writeStream, c.readStream = wireStreams(key, preamble[:wirePreambleNonceSize], wireRoleClient)
	copy(preamble[wirePreambleNonceSize:], wirePreambleTag(key, preamble[:wirePreambleNonceSize]))
	if _, err := writeAllCount(c.Conn, preamble); err != nil {
		c.initErr = err
		return err
	}
	return nil
}

func (c *obfuscatedConn) initializeServer() error {
	c.initMu.Lock()
	if c.started {
		c.initMu.Unlock()
		<-c.ready
		return c.initErr
	}
	c.started = true
	key := c.takeKey()
	defer func() {
		if key != nil {
			clear(key[:])
		}
		close(c.ready)
		c.initMu.Unlock()
	}()
	preamble := make([]byte, wirePreambleSize)
	if _, err := io.ReadFull(validatingWireReader{c.Conn}, preamble); err != nil {
		c.initErr = err
		return err
	}
	nonce := preamble[:wirePreambleNonceSize]
	if key == nil || !hmac.Equal(preamble[wirePreambleNonceSize:], wirePreambleTag(key, nonce)) {
		c.initErr = errInvalidWirePreamble
		return c.initErr
	}
	if c.replay == nil || c.now == nil || !c.replay.accept(nonce, decodeWirePreambleTime(key, nonce), c.now(), c.source) {
		c.initErr = errInvalidWirePreamble
		return c.initErr
	}
	c.writeStream, c.readStream = wireStreams(key, nonce, wireRoleServer)
	return nil
}

func wirePreambleTag(key *wireKey, nonce []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(wirePreambleDomain))
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)[:wirePreambleTagSize]
}

func encodeWirePreambleTime(key *wireKey, nonce []byte, now time.Time) {
	encoded := uint64(now.Unix()) ^ wirePreambleTimeMask(key, nonce[:wirePreambleRandomSize])
	binary.BigEndian.PutUint64(nonce[wirePreambleRandomSize:], encoded)
}

func decodeWirePreambleTime(key *wireKey, nonce []byte) time.Time {
	encoded := binary.BigEndian.Uint64(nonce[wirePreambleRandomSize:])
	seconds := encoded ^ wirePreambleTimeMask(key, nonce[:wirePreambleRandomSize])
	return time.Unix(int64(seconds), 0)
}

func wirePreambleTimeMask(key *wireKey, random []byte) uint64 {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(wireTimeDomain))
	_, _ = mac.Write(random)
	return binary.BigEndian.Uint64(mac.Sum(nil))
}

func wireStreams(key *wireKey, nonce []byte, role wireRole) (write, read cipher.Stream) {
	clientToServer := wireStream(key, nonce, wireClientToServerDomain)
	serverToClient := wireStream(key, nonce, wireServerToClientDomain)
	if role == wireRoleServer {
		return serverToClient, clientToServer
	}
	return clientToServer, serverToClient
}

type wireReplayCache struct {
	mu          sync.Mutex
	limit       int
	sourceLimit int
	entries     map[[wirePreambleNonceSize]byte]int
	bySource    map[string]wireReplaySource
	slots       []wireReplayEntry
	free        []int
	head        int
	tail        int
	lastNow     time.Time
	clockSet    bool
	closed      bool
}

type wireReplayEntry struct {
	key        [wirePreambleNonceSize]byte
	expiresAt  time.Time
	source     string
	globalPrev int
	globalNext int
	sourcePrev int
	sourceNext int
	used       bool
}

type wireReplaySource struct {
	head  int
	tail  int
	count int
}

func newWireReplayCache(limit, sourceLimit int) *wireReplayCache {
	return &wireReplayCache{
		limit:       limit,
		sourceLimit: sourceLimit,
		entries:     make(map[[wirePreambleNonceSize]byte]int),
		bySource:    make(map[string]wireReplaySource),
		head:        -1,
		tail:        -1,
	}
}

func (c *wireReplayCache) accept(nonce []byte, sentAt, now time.Time, source string) bool {
	if c == nil || c.limit <= 0 || c.sourceLimit <= 0 || len(nonce) != wirePreambleNonceSize {
		return false
	}
	now = time.Unix(now.Unix(), 0)
	if source == "" {
		source = "unknown"
	}
	var key [wirePreambleNonceSize]byte
	copy(key[:], nonce)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if !c.clockSet || now.After(c.lastNow) {
		c.lastNow = now
		c.clockSet = true
	} else {
		now = c.lastNow
	}
	if sentAt.Before(now.Add(-wirePreambleValidity)) || sentAt.After(now.Add(wirePreambleValidity)) {
		return false
	}
	c.purgeExpiredLocked(now)
	if _, exists := c.entries[key]; exists {
		return false
	}
	if state := c.bySource[source]; state.count >= c.sourceLimit {
		c.removeLocked(state.head)
	}
	if len(c.entries) >= c.limit {
		c.removeLocked(c.head)
	}
	c.insertLocked(key, source, now.Add(2*wirePreambleValidity))
	return true
}

func (c *wireReplayCache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	clear(c.entries)
	clear(c.bySource)
	clear(c.slots)
	c.slots = nil
	c.free = nil
	c.head = -1
	c.tail = -1
	c.lastNow = time.Time{}
	c.clockSet = false
	c.mu.Unlock()
}

func (c *wireReplayCache) purgeExpiredLocked(now time.Time) {
	for c.head >= 0 && c.slots[c.head].expiresAt.Before(now) {
		c.removeLocked(c.head)
	}
}

func (c *wireReplayCache) insertLocked(key [wirePreambleNonceSize]byte, source string, expiresAt time.Time) {
	index := -1
	if last := len(c.free) - 1; last >= 0 {
		index = c.free[last]
		c.free = c.free[:last]
	} else {
		index = len(c.slots)
		c.slots = append(c.slots, wireReplayEntry{})
	}
	entry := wireReplayEntry{
		key:        key,
		expiresAt:  expiresAt,
		source:     source,
		globalPrev: c.tail,
		globalNext: -1,
		sourcePrev: -1,
		sourceNext: -1,
		used:       true,
	}
	if c.tail >= 0 {
		c.slots[c.tail].globalNext = index
	} else {
		c.head = index
	}
	c.tail = index
	state, exists := c.bySource[source]
	if exists {
		entry.sourcePrev = state.tail
		c.slots[state.tail].sourceNext = index
		state.tail = index
		state.count++
	} else {
		state = wireReplaySource{head: index, tail: index, count: 1}
	}
	c.slots[index] = entry
	c.entries[key] = index
	c.bySource[source] = state
}

func (c *wireReplayCache) removeLocked(index int) {
	if index < 0 || index >= len(c.slots) || !c.slots[index].used {
		return
	}
	entry := c.slots[index]
	delete(c.entries, entry.key)
	if entry.globalPrev >= 0 {
		c.slots[entry.globalPrev].globalNext = entry.globalNext
	} else {
		c.head = entry.globalNext
	}
	if entry.globalNext >= 0 {
		c.slots[entry.globalNext].globalPrev = entry.globalPrev
	} else {
		c.tail = entry.globalPrev
	}
	state := c.bySource[entry.source]
	if entry.sourcePrev >= 0 {
		c.slots[entry.sourcePrev].sourceNext = entry.sourceNext
	} else {
		state.head = entry.sourceNext
	}
	if entry.sourceNext >= 0 {
		c.slots[entry.sourceNext].sourcePrev = entry.sourcePrev
	} else {
		state.tail = entry.sourcePrev
	}
	state.count--
	if state.count == 0 {
		delete(c.bySource, entry.source)
	} else {
		c.bySource[entry.source] = state
	}
	c.slots[index] = wireReplayEntry{}
	c.free = append(c.free, index)
}

func wireStream(key *wireKey, nonce []byte, label string) cipher.Stream {
	mac := hmac.New(sha512.New, key[:])
	_, _ = io.WriteString(mac, label)
	_, _ = mac.Write(nonce)
	material := mac.Sum(nil)
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, material[32:48])
	clear(material)
	return stream
}

func writeAllCount(conn io.Writer, payload []byte) (int, error) {
	total := 0
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if n < 0 || n > len(payload) {
			return total, io.ErrShortWrite
		}
		if n > 0 {
			total += n
			payload = payload[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

type validatingWireReader struct {
	io.Reader
}

func (r validatingWireReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n < 0 || n > len(p) {
		return 0, fmt.Errorf("TalariaTCP connection returned invalid read size %d for %d-byte buffer", n, len(p))
	}
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
