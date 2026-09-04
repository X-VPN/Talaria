// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type WireProfile uint8

const (
	WireProfileSecure WireProfile = 0
	// Value 1 was accepted by an older configuration surface. Keep it reserved
	// permanently so persisted configurations can never acquire new semantics.
	wireProfileReserved1 WireProfile = 1

	minimumWireSecretSize        = 32
	wireMaskNonceSize            = 12
	wireSenderIDSize             = 16
	wireRecordSize               = 8
	wireSenderIDOffset           = wireMaskNonceSize
	wireRecordOffset             = wireSenderIDOffset + wireSenderIDSize
	wireNonceSize                = 12
	wireTagSize                  = 16
	wireHeaderSize               = wireMaskNonceSize + wireSenderIDSize + wireRecordSize
	wireEnvelopeOverhead         = wireHeaderSize + wireTagSize
	wireEpochDuration            = 10 * time.Minute
	wireRecordsPerKey            = uint32(1 << 22)
	wireAttemptsPerKey           = uint64(1 << 52)
	wireReceiveStateLimit        = 4096
	wireReceiveSourceLimit       = wireReceiveStateLimit / 2
	wireReceiveOwnerHistoryLimit = 128
	wireAttemptBuckets           = wireReceiveStateLimit

	wireDirectionClient = byte(1)
	wireDirectionServer = byte(2)

	wireRootDomain       = "talaria-udp-wire"
	wireKeyDomain        = "talaria-udp-wire-key"
	wireSenderMaskDomain = "talaria-udp-wire-sender"
	wireRecordMaskDomain = "talaria-udp-wire-record"
)

type wireCodec struct {
	root                   [sha256.Size]byte
	random                 io.Reader
	now                    func() time.Time
	mu                     sync.Mutex
	senders                map[byte]*wireSendState
	receivers              map[wireReceiveKey]*wireReceiveState
	receiverCounts         map[wireReceiveEpochKey]int
	receiverQueues         map[wireReceiveEpochKey]*wireReceiveQueue
	receiverAttempts       map[wireReceiveAttemptKey]uint64
	receiverSourceCounts   map[wireReceiveSourceEpochKey]int
	receiverOwners         map[*wireReceiveOwner]struct{}
	receiverIPv6PrefixBits int
	receiverSourceLimited  bool
	receiverStateLimit     int
	receiverSourceLimit    int
	receiverEpoch          uint32
	receiverEpochSet       bool
	closed                 bool
}

type wireSendState struct {
	epoch    uint32
	senderID [wireSenderIDSize]byte
	sequence uint32
	aead     cipher.AEAD
}

type wireReceiveKey struct {
	direction byte
	epoch     uint32
	senderID  [wireSenderIDSize]byte
	scope     wireReceiveScope
}

type wireReceiveScope struct {
	source   handshakeSourceKey
	endpoint wireEndpointKey
}

type wireEndpointKey struct {
	raw   string
	zone  string
	port  int
	ip    [16]byte
	ipLen uint8
}

type wireReceiveEpochKey struct {
	direction byte
	epoch     uint32
}

type wireReceiveAttemptKey struct {
	direction byte
	epoch     uint32
	bucket    uint16
}

type wireReceiveSourceEpochKey struct {
	direction byte
	epoch     uint32
	source    handshakeSourceKey
}

type wireReceiveState struct {
	key       wireReceiveKey
	aead      cipher.AEAD
	replay    udptlsReplayWindow
	attempts  uint64
	owners    int
	ownerRefs map[*wireReceiveOwner]struct{}
	previous  *wireReceiveState
	next      *wireReceiveState
}

type wireReceiveOwner struct {
	scope   wireReceiveScope
	state   *wireReceiveState
	retired map[wireReceiveKey]struct{}
	active  bool
}

type wireReceiveQueue struct {
	head *wireReceiveState
	tail *wireReceiveState
}

func wireReceiveScopeFromAddr(addr net.Addr, ipv6PrefixBits int) wireReceiveScope {
	return wireReceiveScope{
		source:   handshakeSourceKeyFromAddr(addr, ipv6PrefixBits),
		endpoint: wireEndpointKeyFromAddr(addr),
	}
}

func wireEndpointKeyFromAddr(addr net.Addr) wireEndpointKey {
	var key wireEndpointKey
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		if addr != nil {
			key.raw = addr.Network() + "\x00" + addr.String()
		}
		return key
	}
	key.zone = udpAddr.Zone
	key.port = udpAddr.Port
	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		copy(key.ip[:4], ip4)
		key.ipLen = 4
		return key
	}
	if ip16 := udpAddr.IP.To16(); ip16 != nil {
		copy(key.ip[:], ip16)
		key.ipLen = 16
		return key
	}
	key.raw = udpAddr.IP.String()
	return key
}

func newWireCodec(profile WireProfile, secret []byte, identity string, random io.Reader) (*wireCodec, error) {
	switch profile {
	case WireProfileSecure:
	default:
		return nil, errors.New("TalariaUDP wire profile is invalid")
	}
	if len(secret) < minimumWireSecretSize {
		return nil, fmt.Errorf("TalariaUDP wire secret must contain at least %d bytes", minimumWireSecretSize)
	}
	identity = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(identity), "."))
	if identity == "" {
		return nil, errors.New("TalariaUDP wire identity is required")
	}
	if random == nil {
		random = rand.Reader
	}
	keyInput := make([]byte, 0, len(wireRootDomain)+8+len(identity)+len(secret))
	keyInput = append(keyInput, wireRootDomain...)
	var identitySize [8]byte
	binary.BigEndian.PutUint64(identitySize[:], uint64(len(identity)))
	keyInput = append(keyInput, identitySize[:]...)
	keyInput = append(keyInput, identity...)
	keyInput = append(keyInput, secret...)
	root := sha256.Sum256(keyInput)
	clear(keyInput)
	return &wireCodec{
		root:                 root,
		random:               random,
		now:                  time.Now,
		senders:              make(map[byte]*wireSendState),
		receivers:            make(map[wireReceiveKey]*wireReceiveState),
		receiverCounts:       make(map[wireReceiveEpochKey]int),
		receiverQueues:       make(map[wireReceiveEpochKey]*wireReceiveQueue),
		receiverAttempts:     make(map[wireReceiveAttemptKey]uint64),
		receiverSourceCounts: make(map[wireReceiveSourceEpochKey]int),
		receiverOwners:       make(map[*wireReceiveOwner]struct{}),
		receiverStateLimit:   wireReceiveStateLimit,
		receiverSourceLimit:  wireReceiveSourceLimit,
	}, nil
}

func (c *wireCodec) seal(packet []byte, direction byte) ([]byte, bool) {
	if c == nil {
		return append([]byte(nil), packet...), true
	}
	if c.now == nil {
		return nil, false
	}
	epoch, ok := wireEpochAt(c.now())
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false
	}
	state, ok := c.sendStateLocked(direction, epoch)
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	var maskNonce [wireMaskNonceSize]byte
	if _, err := io.ReadFull(c.random, maskNonce[:]); err != nil {
		c.mu.Unlock()
		return nil, false
	}
	state.sequence++
	senderID := state.senderID
	sequence := state.sequence
	aead := state.aead
	root := c.root
	c.mu.Unlock()
	defer clear(root[:])
	sealed := make([]byte, wireHeaderSize, wireHeaderSize+len(packet)+wireTagSize)
	copy(sealed[:wireMaskNonceSize], maskNonce[:])
	encodeWireSenderID(root[:], sealed[:wireHeaderSize], senderID)
	encodeWireRecord(root[:], sealed[:wireHeaderSize], epoch, sequence)
	aad := wireAAD(direction, sealed[:wireHeaderSize])
	nonce := wireRecordNonce(epoch, sequence)
	sealed = aead.Seal(sealed, nonce[:], packet, aad[:])
	return sealed, true
}

func (c *wireCodec) open(packet []byte, direction byte) ([]byte, bool) {
	plain, state, sequence, ok := c.openAuthenticated(packet, direction)
	if !ok {
		return nil, false
	}
	if c != nil && !c.acceptRecord(state, sequence) {
		clear(plain)
		return nil, false
	}
	return plain, true
}

func (c *wireCodec) openAuthenticated(packet []byte, direction byte) ([]byte, *wireReceiveState, uint32, bool) {
	return c.openAuthenticatedFrom(packet, direction, wireReceiveScope{})
}

func (c *wireCodec) openAuthenticatedFrom(packet []byte, direction byte, scope wireReceiveScope) ([]byte, *wireReceiveState, uint32, bool) {
	if c == nil {
		return packet, nil, 0, true
	}
	state, epoch, sequence, ok := c.openState(packet, direction, scope)
	if !ok {
		return nil, nil, 0, false
	}
	aad := wireAAD(direction, packet[:wireHeaderSize])
	nonce := wireRecordNonce(epoch, sequence)
	plain, err := state.aead.Open(nil, nonce[:], packet[wireHeaderSize:], aad[:])
	if err != nil {
		clear(plain)
		return nil, nil, 0, false
	}
	return plain, state, sequence, true
}

func (c *wireCodec) openInPlace(packet []byte, direction byte) ([]byte, bool) {
	return c.openInPlaceFrom(packet, direction, wireReceiveScope{})
}

func (c *wireCodec) openInPlaceFrom(packet []byte, direction byte, scope wireReceiveScope) ([]byte, bool) {
	return c.openInPlaceFromOwner(packet, direction, scope, nil)
}

func (c *wireCodec) openInPlaceFromOwner(packet []byte, direction byte, scope wireReceiveScope, owner *wireReceiveOwner) ([]byte, bool) {
	if c == nil {
		return packet, true
	}
	state, epoch, sequence, ok := c.openState(packet, direction, scope)
	if !ok {
		return nil, false
	}
	ciphertext := packet[wireHeaderSize:]
	aad := wireAAD(direction, packet[:wireHeaderSize])
	nonce := wireRecordNonce(epoch, sequence)
	plain, err := state.aead.Open(ciphertext[:0], nonce[:], ciphertext, aad[:])
	if err != nil {
		clear(plain)
		return nil, false
	}
	if !c.acceptRecordForOwner(state, sequence, owner) {
		clear(plain)
		return nil, false
	}
	return plain, true
}

func (c *wireCodec) openState(packet []byte, direction byte, scope wireReceiveScope) (*wireReceiveState, uint32, uint32, bool) {
	if len(packet) < wireEnvelopeOverhead || c.now == nil {
		return nil, 0, 0, false
	}
	current, ok := wireEpochAt(c.now())
	if !ok {
		return nil, 0, 0, false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, 0, 0, false
	}
	current = c.monotonicReceiverEpochLocked(current)
	senderID := decodeWireSenderID(c.root[:], packet[:wireHeaderSize])
	epoch, sequence := decodeWireRecord(c.root[:], packet[:wireHeaderSize])
	if !wireEpochAccepted(epoch, current) || sequence == 0 || sequence > wireRecordsPerKey {
		c.mu.Unlock()
		return nil, 0, 0, false
	}
	c.rotateReceiverEpochLocked(current)
	key := wireReceiveKey{direction: direction, epoch: epoch, senderID: senderID, scope: scope}
	state := c.receivers[key]
	newState := state == nil
	attemptKey := wireReceiveAttemptKey{
		direction: direction,
		epoch:     epoch,
		bucket:    wireAttemptBucket(senderID),
	}
	if (newState && c.receiverAttempts[attemptKey] >= wireAttemptsPerKey) ||
		(!newState && state.attempts >= wireAttemptsPerKey) {
		c.mu.Unlock()
		return nil, 0, 0, false
	}
	if newState {
		aead, derived := deriveWireAEAD(c.root[:], direction, epoch, senderID)
		if !derived {
			c.mu.Unlock()
			return nil, 0, 0, false
		}
		state = &wireReceiveState{key: key, aead: aead}
	}
	if newState {
		c.receiverAttempts[attemptKey]++
	}
	state.attempts++
	c.mu.Unlock()
	return state, epoch, sequence, true
}

func (c *wireCodec) acceptRecord(state *wireReceiveState, sequence uint32) bool {
	return c.acceptRecordForOwner(state, sequence, nil)
}

func (c *wireCodec) acceptRecordForOwner(state *wireReceiveState, sequence uint32, owner *wireReceiveOwner) bool {
	if state == nil || c.now == nil {
		return false
	}
	current, ok := wireEpochAt(c.now())
	if !ok {
		return false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	if owner != nil {
		if !owner.active {
			c.mu.Unlock()
			return false
		}
		if _, exists := c.receiverOwners[owner]; !exists {
			c.mu.Unlock()
			return false
		}
		if state.key.scope != owner.scope {
			c.mu.Unlock()
			return false
		}
	}
	current = c.monotonicReceiverEpochLocked(current)
	if !wireEpochAccepted(state.key.epoch, current) {
		c.mu.Unlock()
		return false
	}
	c.rotateReceiverEpochLocked(current)
	var previousKey wireReceiveKey
	transition := false
	if owner != nil {
		if owner.hasRetired(state.key) {
			c.mu.Unlock()
			return false
		}
		if owner.state != nil && owner.state.key != state.key {
			if len(owner.retired) >= wireReceiveOwnerHistoryLimit {
				c.mu.Unlock()
				return false
			}
			previousKey = owner.state.key
			transition = true
		}
	}
	if owner == nil {
		state, ok = c.registerReceiveStateLocked(state)
	} else {
		state, ok = c.registerReceiveStateForOwnerLocked(state, owner)
	}
	if ok {
		ok = state.replay.CanAccept(uint64(sequence))
	}
	if ok && owner != nil {
		ok = c.addReceiveStateOwnerRefLocked(state, owner)
	}
	if ok && transition {
		if owner.retired == nil {
			owner.retired = make(map[wireReceiveKey]struct{})
		}
		owner.retired[previousKey] = struct{}{}
	}
	if ok {
		ok = state.replay.Accept(uint64(sequence))
	}
	c.mu.Unlock()
	return ok
}

func (c *wireCodec) registerReceiveStateForOwnerLocked(state *wireReceiveState, owner *wireReceiveOwner) (*wireReceiveState, bool) {
	registered, ok := c.registerReceiveStateLocked(state)
	if ok || state == nil || owner == nil || c.receivers[state.key] != nil {
		return registered, ok
	}
	previous := owner.state
	if previous == nil || previous == state || c.receivers[previous.key] != previous ||
		previous.key.direction != state.key.direction || previous.key.epoch != state.key.epoch ||
		previous.key.scope != state.key.scope || state.key.scope != owner.scope ||
		previous.owners != 1 || len(previous.ownerRefs) != 1 {
		return nil, false
	}
	if _, exists := previous.ownerRefs[owner]; !exists {
		return nil, false
	}
	c.removeReceiveStateLocked(previous)
	return c.registerReceiveStateLocked(state)
}

func (c *wireCodec) canAcceptRecord(state *wireReceiveState, sequence uint32) bool {
	if state == nil || c.now == nil {
		return false
	}
	current, ok := wireEpochAt(c.now())
	if !ok {
		return false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	current = c.monotonicReceiverEpochLocked(current)
	if !wireEpochAccepted(state.key.epoch, current) {
		c.mu.Unlock()
		return false
	}
	c.rotateReceiverEpochLocked(current)
	if registered := c.receivers[state.key]; registered != nil {
		state = registered
	}
	ok = state.replay.CanAccept(uint64(sequence))
	c.mu.Unlock()
	return ok
}

func (c *wireCodec) commitReceiveState(state *wireReceiveState, sequence uint32, scope wireReceiveScope, owner *wireReceiveOwner) (func(), bool) {
	if state == nil || state.key.scope != scope || owner == nil || c.now == nil {
		return nil, false
	}
	current, ok := wireEpochAt(c.now())
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false
	}
	if owner.active {
		c.mu.Unlock()
		return nil, false
	}
	if _, exists := c.receiverOwners[owner]; exists {
		c.mu.Unlock()
		return nil, false
	}
	current = c.monotonicReceiverEpochLocked(current)
	if !wireEpochAccepted(state.key.epoch, current) {
		c.mu.Unlock()
		return nil, false
	}
	c.rotateReceiverEpochLocked(current)
	target := state
	if registered := c.receivers[state.key]; registered != nil {
		target = registered
	}
	if !target.replay.CanAccept(uint64(sequence)) {
		c.mu.Unlock()
		return nil, false
	}
	target, ok = c.registerReceiveStateLocked(state)
	if ok {
		owner.scope = scope
		owner.active = true
		c.receiverOwners[owner] = struct{}{}
		if !c.addReceiveStateOwnerRefLocked(target, owner) {
			delete(c.receiverOwners, owner)
			owner.active = false
			ok = false
		}
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.releaseReceiveOwnerLocked(owner)
			c.mu.Unlock()
		})
	}, true
}

func (c *wireCodec) addReceiveStateOwnerRefLocked(state *wireReceiveState, owner *wireReceiveOwner) bool {
	if state == nil || owner == nil || !owner.active || state.key.scope != owner.scope {
		return false
	}
	if _, ok := c.receiverOwners[owner]; !ok {
		return false
	}
	if owner.state == state {
		return true
	}
	if !c.addReceiveStateOwnerLocked(state, owner.scope) {
		return false
	}
	if state.ownerRefs == nil {
		state.ownerRefs = make(map[*wireReceiveOwner]struct{})
	}
	state.ownerRefs[owner] = struct{}{}
	previous := owner.state
	owner.state = state
	if previous != nil {
		delete(previous.ownerRefs, owner)
		if c.receivers[previous.key] == previous {
			c.releaseReceiveStateOwnerLocked(previous, owner.scope)
		}
	}
	return true
}

func (c *wireCodec) releaseReceiveOwnerLocked(owner *wireReceiveOwner) {
	if owner == nil || !owner.active {
		return
	}
	delete(c.receiverOwners, owner)
	owner.active = false
	state := owner.state
	owner.state = nil
	clear(owner.retired)
	owner.retired = nil
	if state != nil {
		delete(state.ownerRefs, owner)
		if c.receivers[state.key] == state {
			c.releaseReceiveStateOwnerLocked(state, owner.scope)
		}
	}
}

func (c *wireCodec) addReceiveStateOwnerLocked(state *wireReceiveState, scope wireReceiveScope) bool {
	if state == nil || state.key.scope != scope {
		return false
	}
	state.owners++
	return true
}

func (c *wireCodec) releaseReceiveStateOwnerLocked(state *wireReceiveState, scope wireReceiveScope) {
	if state == nil || state.key.scope != scope || state.owners == 0 {
		return
	}
	state.owners--
}

func (c *wireCodec) rotateReceiverEpochLocked(current uint32) {
	if c.receiverEpochSet && c.receiverEpoch == current {
		return
	}
	for candidate, state := range c.receivers {
		if !wireEpochAccepted(candidate.epoch, current) {
			c.removeReceiveStateLocked(state)
		}
	}
	for candidate := range c.receiverAttempts {
		if !wireEpochAccepted(candidate.epoch, current) {
			delete(c.receiverAttempts, candidate)
		}
	}
	for owner := range c.receiverOwners {
		owner.pruneRetired(current)
	}
	c.receiverEpoch = current
	c.receiverEpochSet = true
}

func (c *wireCodec) monotonicReceiverEpochLocked(current uint32) uint32 {
	if c.receiverEpochSet && current < c.receiverEpoch {
		return c.receiverEpoch
	}
	return current
}

func (c *wireCodec) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		clear(c.root[:])
		clear(c.senders)
		clear(c.receivers)
		clear(c.receiverCounts)
		clear(c.receiverQueues)
		clear(c.receiverAttempts)
		clear(c.receiverSourceCounts)
		for owner := range c.receiverOwners {
			owner.active = false
			owner.state = nil
			clear(owner.retired)
			owner.retired = nil
		}
		clear(c.receiverOwners)
	}
	c.mu.Unlock()
}

func (o *wireReceiveOwner) hasRetired(key wireReceiveKey) bool {
	_, retired := o.retired[key]
	return retired
}

func (o *wireReceiveOwner) pruneRetired(current uint32) {
	for retired := range o.retired {
		if !wireEpochAccepted(retired.epoch, current) {
			delete(o.retired, retired)
		}
	}
	if len(o.retired) == 0 {
		o.retired = nil
	}
}

func (c *wireCodec) sendStateLocked(direction byte, epoch uint32) (*wireSendState, bool) {
	if direction != wireDirectionClient && direction != wireDirectionServer {
		return nil, false
	}
	if state := c.senders[direction]; state != nil && state.epoch == epoch && state.sequence < wireRecordsPerKey {
		return state, true
	}
	var senderID [wireSenderIDSize]byte
	if _, err := io.ReadFull(c.random, senderID[:]); err != nil {
		return nil, false
	}
	aead, ok := deriveWireAEAD(c.root[:], direction, epoch, senderID)
	if !ok {
		return nil, false
	}
	state := &wireSendState{epoch: epoch, senderID: senderID, aead: aead}
	c.senders[direction] = state
	return state, true
}

func (c *wireCodec) receiveStateLocked(direction byte, epoch uint32, senderID [wireSenderIDSize]byte) (*wireReceiveState, bool) {
	if direction != wireDirectionClient && direction != wireDirectionServer {
		return nil, false
	}
	key := wireReceiveKey{direction: direction, epoch: epoch, senderID: senderID}
	if state := c.receivers[key]; state != nil {
		return state, true
	}
	aead, ok := deriveWireAEAD(c.root[:], direction, epoch, senderID)
	if !ok {
		return nil, false
	}
	return c.registerReceiveStateLocked(&wireReceiveState{key: key, aead: aead})
}

func (c *wireCodec) registerReceiveStateLocked(state *wireReceiveState) (*wireReceiveState, bool) {
	if c.closed || state == nil {
		return nil, false
	}
	if registered := c.receivers[state.key]; registered != nil {
		if registered != state {
			if registered.attempts > wireAttemptsPerKey-state.attempts {
				return nil, false
			}
			registered.attempts += state.attempts
		}
		return registered, true
	}
	countKey := wireReceiveEpochKey{direction: state.key.direction, epoch: state.key.epoch}
	sourceKey := wireReceiveSourceEpochKey{direction: state.key.direction, epoch: state.key.epoch, source: state.key.scope.source}
	var victim *wireReceiveState
	if c.receiverSourceLimited && c.receiverSourceCounts[sourceKey] >= c.receiverSourceLimit {
		victim = c.findReceiveSourceStateLocked(sourceKey)
		if victim == nil || c.receiverSourceCounts[sourceKey]-1 >= c.receiverSourceLimit {
			return nil, false
		}
	}
	projectedCount := c.receiverCounts[countKey]
	if victim != nil {
		projectedCount--
	}
	if projectedCount >= c.receiverStateLimit {
		if victim != nil {
			return nil, false
		}
		victim = c.findReceiveStateLocked(countKey)
		if victim == nil || projectedCount-1 >= c.receiverStateLimit {
			return nil, false
		}
	}
	if victim != nil {
		c.removeReceiveStateLocked(victim)
	}
	c.receivers[state.key] = state
	c.receiverCounts[countKey]++
	queue := c.receiverQueues[countKey]
	if queue == nil {
		queue = &wireReceiveQueue{}
		c.receiverQueues[countKey] = queue
	}
	state.previous = queue.tail
	state.next = nil
	if queue.tail == nil {
		queue.head = state
	} else {
		queue.tail.next = state
	}
	queue.tail = state
	if c.receiverSourceLimited {
		c.receiverSourceCounts[sourceKey]++
	}
	return state, true
}

func (c *wireCodec) findReceiveStateLocked(key wireReceiveEpochKey) *wireReceiveState {
	queue := c.receiverQueues[key]
	if queue == nil {
		return nil
	}
	for state := queue.head; state != nil; state = state.next {
		if state.owners == 0 {
			return state
		}
	}
	return nil
}

func (c *wireCodec) findReceiveSourceStateLocked(key wireReceiveSourceEpochKey) *wireReceiveState {
	queue := c.receiverQueues[wireReceiveEpochKey{direction: key.direction, epoch: key.epoch}]
	if queue == nil {
		return nil
	}
	for state := queue.head; state != nil; state = state.next {
		if state.key.scope.source == key.source && state.owners == 0 {
			return state
		}
	}
	return nil
}

func (c *wireCodec) removeReceiveStateLocked(state *wireReceiveState) {
	if state == nil || c.receivers[state.key] != state {
		return
	}
	delete(c.receivers, state.key)
	countKey := wireReceiveEpochKey{direction: state.key.direction, epoch: state.key.epoch}
	queue := c.receiverQueues[countKey]
	if queue != nil {
		if state.previous == nil {
			queue.head = state.next
		} else {
			state.previous.next = state.next
		}
		if state.next == nil {
			queue.tail = state.previous
		} else {
			state.next.previous = state.previous
		}
		state.previous = nil
		state.next = nil
	}
	c.receiverCounts[countKey]--
	if c.receiverCounts[countKey] == 0 {
		delete(c.receiverCounts, countKey)
		delete(c.receiverQueues, countKey)
	}
	c.decrementReceiverSourceKeyLocked(state.key)
	for owner := range state.ownerRefs {
		if owner.state == state {
			owner.state = nil
		}
	}
	clear(state.ownerRefs)
	state.ownerRefs = nil
}

func (c *wireCodec) decrementReceiverSourceKeyLocked(stateKey wireReceiveKey) {
	if !c.receiverSourceLimited {
		return
	}
	key := wireReceiveSourceEpochKey{direction: stateKey.direction, epoch: stateKey.epoch, source: stateKey.scope.source}
	if c.receiverSourceCounts[key] <= 1 {
		delete(c.receiverSourceCounts, key)
	} else {
		c.receiverSourceCounts[key]--
	}
}

func (c *wireCodec) limitReceiverStatesBySource(ipv6PrefixBits int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.receiverSourceLimited {
		c.receiverSourceLimited = true
		c.receiverIPv6PrefixBits = ipv6PrefixBits
		for _, state := range c.receivers {
			key := wireReceiveSourceEpochKey{direction: state.key.direction, epoch: state.key.epoch, source: state.key.scope.source}
			c.receiverSourceCounts[key]++
		}
	}
	c.mu.Unlock()
}

func deriveWireAEAD(root []byte, direction byte, epoch uint32, senderID [wireSenderIDSize]byte) (cipher.AEAD, bool) {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write([]byte(wireKeyDomain))
	var context [5]byte
	context[0] = direction
	binary.BigEndian.PutUint32(context[1:], epoch)
	_, _ = mac.Write(context[:])
	_, _ = mac.Write(senderID[:])
	keyMaterial := mac.Sum(nil)
	block, err := aes.NewCipher(keyMaterial)
	clear(keyMaterial)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	return aead, true
}

func wireEpochAt(now time.Time) (uint32, bool) {
	seconds := now.Unix()
	if seconds < 0 {
		return 0, false
	}
	epoch := uint64(seconds) / uint64(wireEpochDuration/time.Second)
	if epoch > uint64(^uint32(0)) {
		return 0, false
	}
	return uint32(epoch), true
}

func wireEpochAccepted(epoch, current uint32) bool {
	if epoch > current {
		return epoch-current <= 1
	}
	return current-epoch <= 1
}

func wireAAD(direction byte, header []byte) [wireHeaderSize + 1]byte {
	var aad [wireHeaderSize + 1]byte
	aad[0] = direction
	copy(aad[1:], header)
	return aad
}

func encodeWireSenderID(root, header []byte, senderID [wireSenderIDSize]byte) {
	mask := wireMask(root, wireSenderMaskDomain, header[:wireMaskNonceSize])
	for i := range senderID {
		header[wireSenderIDOffset+i] = senderID[i] ^ mask[i]
	}
}

func decodeWireSenderID(root, header []byte) [wireSenderIDSize]byte {
	mask := wireMask(root, wireSenderMaskDomain, header[:wireMaskNonceSize])
	var senderID [wireSenderIDSize]byte
	for i := range senderID {
		senderID[i] = header[wireSenderIDOffset+i] ^ mask[i]
	}
	return senderID
}

func encodeWireRecord(root, header []byte, epoch, sequence uint32) {
	record := uint64(epoch)<<32 | uint64(sequence)
	binary.BigEndian.PutUint64(header[wireRecordOffset:wireHeaderSize], record^wireRecordMask(root, header[:wireRecordOffset]))
}

func decodeWireRecord(root, header []byte) (uint32, uint32) {
	encoded := binary.BigEndian.Uint64(header[wireRecordOffset:wireHeaderSize])
	record := encoded ^ wireRecordMask(root, header[:wireRecordOffset])
	return uint32(record >> 32), uint32(record)
}

func wireRecordMask(root, senderID []byte) uint64 {
	mask := wireMask(root, wireRecordMaskDomain, senderID)
	return binary.BigEndian.Uint64(mask[:])
}

func wireMask(root []byte, label string, input []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write([]byte(label))
	_, _ = mac.Write(input)
	var mask [sha256.Size]byte
	copy(mask[:], mac.Sum(nil))
	return mask
}

func wireRecordNonce(epoch, sequence uint32) [wireNonceSize]byte {
	var nonce [wireNonceSize]byte
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:], uint64(sequence))
	return nonce
}

func wireAttemptBucket(senderID [wireSenderIDSize]byte) uint16 {
	return binary.BigEndian.Uint16(senderID[wireSenderIDSize-2:]) & (wireAttemptBuckets - 1)
}

func (c *wireCodec) packetSize(inner int) int {
	if c == nil {
		return inner
	}
	return inner + wireEnvelopeOverhead
}

type wireBatchConn struct {
	inner          batchConn
	codec          *wireCodec
	readDirection  byte
	writeDirection byte
	readScope      wireReceiveScope
	receiveOwner   *wireReceiveOwner
}

func newWireBatchConn(inner batchConn, codec *wireCodec, mode udptlsMode) batchConn {
	if codec == nil {
		return inner
	}
	conn := &wireBatchConn{inner: inner, codec: codec}
	if mode == udptlsModeServer {
		conn.readDirection = wireDirectionClient
		conn.writeDirection = wireDirectionServer
		conn.readScope = wireReceiveScopeFromAddr(inner.RemoteAddr(), codec.receiverIPv6PrefixBits)
		if state, ok := inner.(interface{ NewSessionState() any }); ok {
			conn.receiveOwner, _ = state.NewSessionState().(*wireReceiveOwner)
		}
	} else {
		conn.readDirection = wireDirectionServer
		conn.writeDirection = wireDirectionClient
	}
	return conn
}

func (c *wireBatchConn) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := c.ReadBatch(context.Background(), [][]byte{p}, sizes)
	if n == 0 {
		return 0, err
	}
	return sizes[0], err
}

func (c *wireBatchConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func (c *wireBatchConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	limit := min(len(bufs), len(sizes))
	if limit == 0 {
		return 0, nil
	}
	scratchBytes, ok := wireScratchBytes(bufs[:limit], nil)
	if !ok || !c.ReserveQueuedBytes(scratchBytes) {
		return 0, errTalariaUDPQueueMemoryLimit
	}
	defer c.ReleaseQueuedBytes(scratchBytes)
	scratch := make([][]byte, limit)
	scratchSizes := make([]int, limit)
	for i := range scratch {
		scratch[i] = make([]byte, len(bufs[i])+wireEnvelopeOverhead)
	}
	for {
		n, err := c.inner.ReadBatch(ctx, scratch, scratchSizes)
		if validateErr := validateReadBatch(n, scratch, scratchSizes); validateErr != nil {
			return 0, validateErr
		}
		visible := 0
		for i := 0; i < n; i++ {
			size := scratchSizes[i]
			if size < 0 || size > len(scratch[i]) {
				return visible, io.ErrUnexpectedEOF
			}
			plain, ok := c.codec.openInPlaceFromOwner(scratch[i][:size], c.readDirection, c.readScope, c.receiveOwner)
			if !ok || len(plain) > len(bufs[visible]) {
				continue
			}
			copy(bufs[visible], plain)
			sizes[visible] = len(plain)
			visible++
		}
		if visible > 0 {
			return visible, nil
		}
		if err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
}

func (c *wireBatchConn) ReadBatchRetained(ctx context.Context, bufs [][]byte, sizes []int) (int, int64, error) {
	retained, ok := c.inner.(retainedBatchConn)
	if !ok {
		n, err := c.ReadBatch(ctx, bufs, sizes)
		return n, 0, err
	}
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, 0, nil
	}
	scratchBytes, ok := wireScratchBytes(bufs[:1], nil)
	if !ok || !c.ReserveQueuedBytes(scratchBytes) {
		return 0, 0, errTalariaUDPQueueMemoryLimit
	}
	defer c.ReleaseQueuedBytes(scratchBytes)
	scratch := [][]byte{make([]byte, len(bufs[0])+wireEnvelopeOverhead)}
	scratchSizes := []int{0}
	for {
		n, retainedBytes, err := retained.ReadBatchRetained(ctx, scratch, scratchSizes)
		if validateErr := validateReadBatch(n, scratch, scratchSizes); validateErr != nil {
			if retainedBytes > 0 {
				retained.ReleaseQueuedBytes(retainedBytes)
			}
			return 0, 0, validateErr
		}
		if n == 0 {
			if retainedBytes > 0 {
				retained.ReleaseQueuedBytes(retainedBytes)
			}
			return 0, 0, err
		}
		size := scratchSizes[0]
		if size < 0 || size > len(scratch[0]) {
			retained.ReleaseQueuedBytes(retainedBytes)
			return 0, 0, io.ErrUnexpectedEOF
		}
		plain, valid := c.codec.openInPlaceFromOwner(scratch[0][:size], c.readDirection, c.readScope, c.receiveOwner)
		if !valid || len(plain) > len(bufs[0]) {
			retained.ReleaseQueuedBytes(retainedBytes)
			if err != nil {
				return 0, 0, err
			}
			continue
		}
		copy(bufs[0], plain)
		sizes[0] = len(plain)
		return 1, retainedBytes, nil
	}
}

func (c *wireBatchConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if len(sizes) < len(bufs) {
		return 0, errors.New("TalariaUDP wire write sizes too small")
	}
	for i := range bufs {
		if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
			return 0, errors.New("TalariaUDP wire write size is invalid")
		}
	}
	scratchBytes, ok := wireScratchBytes(bufs, sizes)
	if !ok || !c.ReserveQueuedBytes(scratchBytes) {
		return 0, errTalariaUDPQueueMemoryLimit
	}
	defer c.ReleaseQueuedBytes(scratchBytes)
	packets := make([][]byte, len(bufs))
	packetSizes := make([]int, len(bufs))
	for i := range bufs {
		sealed, ok := c.codec.seal(bufs[i][:sizes[i]], c.writeDirection)
		if !ok {
			return 0, errors.New("TalariaUDP wire nonce generation failed")
		}
		packets[i] = sealed
		packetSizes[i] = len(sealed)
	}
	return writeBatchValidated(ctx, c.inner, packets, packetSizes)
}

func wireScratchBytes(bufs [][]byte, sizes []int) (int64, bool) {
	var total int64
	for i := range bufs {
		payload := len(bufs[i])
		if sizes != nil {
			payload = sizes[i]
		}
		if payload > int(^uint(0)>>1)-wireEnvelopeOverhead {
			return 0, false
		}
		allocation := int64(payload + wireEnvelopeOverhead)
		if allocation > int64(^uint64(0)>>1)-total {
			return 0, false
		}
		total += allocation
	}
	return total, true
}

func (c *wireBatchConn) ReserveQueuedBytes(n int64) bool {
	if budget, ok := c.inner.(queuedByteBudget); ok {
		return budget.ReserveQueuedBytes(n)
	}
	return true
}

func (c *wireBatchConn) ReleaseQueuedBytes(n int64) {
	if budget, ok := c.inner.(queuedByteBudget); ok {
		budget.ReleaseQueuedBytes(n)
	}
}

func (c *wireBatchConn) Close() error                       { return c.inner.Close() }
func (c *wireBatchConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wireBatchConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *wireBatchConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wireBatchConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wireBatchConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *wireBatchConn) BatchSize() int                     { return c.inner.BatchSize() }
