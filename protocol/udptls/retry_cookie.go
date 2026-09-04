// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/X-VPN/Talaria/internal/udpsession"
)

const (
	retryCookieKeySize     = 32
	retryCookieTagSize     = 16
	retryPacketBindingSize = sha256.Size

	retryFrameVersion       = 2
	retryFrameTypeChallenge = 1
	retryFrameTypeResponse  = 2

	retryFrameIssuedOffset  = 6
	retryFrameBindingOffset = retryFrameIssuedOffset + 8
	retryFrameTagOffset     = retryFrameBindingOffset + retryPacketBindingSize
	retryChallengeSize      = retryFrameTagOffset + retryCookieTagSize
	minimumRetryMaxPacket   = retryChallengeSize * 2

	defaultRetryCookieTTL        = 30 * time.Second
	defaultRetryCookieFutureSkew = 5 * time.Second
)

var (
	retryFrameMagic  = [4]byte{'E', 'V', 'R', 'C'}
	retryCookieLabel = []byte("talaria-udp-retry-cookie")
)

type retryCookieGate struct {
	mu        sync.RWMutex
	key       [retryCookieKeySize]byte
	now       func() time.Time
	maxPacket int
	wire      *wireCodec
	closed    bool
}

func newRetryCookieGate(maxPacket int, random io.Reader, now func() time.Time) (*retryCookieGate, error) {
	return newRetryCookieGateWithWire(maxPacket, random, now, nil)
}

func newRetryCookieGateWithWire(maxPacket int, random io.Reader, now func() time.Time, wire *wireCodec) (*retryCookieGate, error) {
	if random == nil {
		return nil, io.ErrUnexpectedEOF
	}
	if now == nil {
		now = time.Now
	}
	wire.limitReceiverStatesBySource(0)
	gate := &retryCookieGate{
		now:       now,
		maxPacket: wire.packetSize(maxPacket),
		wire:      wire,
	}
	if _, err := io.ReadFull(random, gate.key[:]); err != nil {
		clear(gate.key[:])
		return nil, err
	}
	return gate, nil
}

func (g *retryCookieGate) EvaluateNewSession(packet []byte, remote net.Addr) udpsession.NewSessionDecision {
	if g == nil || len(packet) == 0 || len(packet) > g.maxPacket {
		return udpsession.NewSessionDecision{}
	}
	var scope wireReceiveScope
	if g.wire != nil {
		scope = wireReceiveScopeFromAddr(remote, g.wire.receiverIPv6PrefixBits)
	}
	innerPacket, receiveState, sequence, ok := g.wire.openAuthenticatedFrom(packet, wireDirectionClient, scope)
	if !ok {
		return udpsession.NewSessionDecision{}
	}
	if validHandshakeStartPacket(innerPacket) {
		if len(innerPacket) < retryChallengeSize {
			return udpsession.NewSessionDecision{}
		}
		challenge, ok := g.issue(innerPacket, remote)
		if !ok {
			return udpsession.NewSessionDecision{}
		}
		challenge, ok = g.wire.seal(challenge, wireDirectionServer)
		if !ok {
			return udpsession.NewSessionDecision{}
		}
		return udpsession.NewSessionDecision{Reply: challenge}
	}

	issued, binding, tag, inner, ok := parseRetryResponse(innerPacket)
	if !ok || !validHandshakeStartPacket(inner) {
		return udpsession.NewSessionDecision{}
	}
	if !g.verify(issued, binding, tag, inner, remote) {
		return udpsession.NewSessionDecision{}
	}
	if g.wire != nil && !g.wire.canAcceptRecord(receiveState, sequence) {
		return udpsession.NewSessionDecision{}
	}
	// Keep the verified response intact so the per-session server wrapper can
	// establish the same temporary authentication context without generic
	// udpsession metadata.
	decision := udpsession.NewSessionDecision{Admit: true, Payload: packet}
	if g.wire != nil {
		owner := new(wireReceiveOwner)
		decision.State = owner
		decision.Commit = func() (func(), bool) {
			return g.wire.commitReceiveState(receiveState, sequence, scope, owner)
		}
	}
	return decision
}

func (g *retryCookieGate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	clear(g.key[:])
	g.closed = true
	g.mu.Unlock()
	g.wire.Close()
}

func (g *retryCookieGate) issue(packet []byte, remote net.Addr) ([]byte, bool) {
	issued := g.now().Unix()
	if issued < 0 {
		return nil, false
	}
	binding := sha256.Sum256(packet)
	tag, ok := g.computeTag(uint64(issued), binding[:], packet, remote)
	if !ok {
		return nil, false
	}
	challenge := make([]byte, retryChallengeSize)
	copy(challenge[:4], retryFrameMagic[:])
	challenge[4] = retryFrameVersion
	challenge[5] = retryFrameTypeChallenge
	binary.BigEndian.PutUint64(challenge[retryFrameIssuedOffset:retryFrameBindingOffset], uint64(issued))
	copy(challenge[retryFrameBindingOffset:retryFrameTagOffset], binding[:])
	copy(challenge[retryFrameTagOffset:retryChallengeSize], tag[:])
	return challenge, true
}

// verify accepts a Retry response only when its public binding and private cookie cover the same initial packet.
func (g *retryCookieGate) verify(issued uint64, binding, tag, packet []byte, remote net.Addr) bool {
	if len(binding) != retryPacketBindingSize {
		return false
	}
	expectedBinding := sha256.Sum256(packet)
	if !hmac.Equal(binding, expectedBinding[:]) {
		return false
	}
	if issued > uint64(^uint64(0)>>1) {
		return false
	}
	now := g.now()
	issuedAt := time.Unix(int64(issued), 0)
	if issuedAt.After(now.Add(defaultRetryCookieFutureSkew)) || now.Sub(issuedAt) > defaultRetryCookieTTL {
		return false
	}
	expected, ok := g.computeTag(issued, binding, packet, remote)
	return ok && hmac.Equal(tag, expected[:])
}

// computeTag binds a Retry cookie to its public packet digest, exact packet, source, and issue time.
func (g *retryCookieGate) computeTag(issued uint64, binding, packet []byte, remote net.Addr) ([retryCookieTagSize]byte, bool) {
	var tag [retryCookieTagSize]byte
	if len(binding) != retryPacketBindingSize {
		return tag, false
	}
	addr, ok := remote.(*net.UDPAddr)
	if !ok || addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return tag, false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return tag, false
	}
	mac := hmac.New(sha256.New, g.key[:])
	_, _ = mac.Write(retryCookieLabel)
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], issued)
	_, _ = mac.Write(value[:])
	if !writeRetryCookieAddress(mac, addr) {
		return tag, false
	}
	_, _ = mac.Write(binding)
	_, _ = mac.Write(packet)
	copy(tag[:], mac.Sum(nil)[:retryCookieTagSize])
	return tag, true
}

func writeRetryCookieAddress(w io.Writer, addr *net.UDPAddr) bool {
	ip := addr.IP
	if ip4 := ip.To4(); ip4 != nil {
		_, _ = w.Write([]byte{4})
		_, _ = w.Write(ip4)
	} else {
		ip16 := ip.To16()
		if ip16 == nil {
			return false
		}
		_, _ = w.Write([]byte{6})
		_, _ = w.Write(ip16)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(addr.Port))
	_, _ = w.Write(port[:])
	if len(addr.Zone) > 65535 {
		return false
	}
	var zoneLen [2]byte
	binary.BigEndian.PutUint16(zoneLen[:], uint16(len(addr.Zone)))
	_, _ = w.Write(zoneLen[:])
	_, _ = io.WriteString(w, addr.Zone)
	return true
}

func validHandshakeStartPacket(packet []byte) bool {
	if !isHandshakeStartPacket(packet) || len(packet) <= handshakeDataHeaderSize {
		return false
	}
	payloadLen := binary.LittleEndian.Uint32(packet[18:22])
	return uint64(payloadLen) == uint64(len(packet)-handshakeDataHeaderSize)
}

// parseRetryResponse splits an untrusted response without validating its binding or cookie.
func parseRetryResponse(packet []byte) (uint64, []byte, []byte, []byte, bool) {
	if len(packet) <= retryChallengeSize || !isRetryFrame(packet, retryFrameTypeResponse) {
		return 0, nil, nil, nil, false
	}
	issued := binary.BigEndian.Uint64(packet[retryFrameIssuedOffset:retryFrameBindingOffset])
	binding := packet[retryFrameBindingOffset:retryFrameTagOffset]
	tag := packet[retryFrameTagOffset:retryChallengeSize]
	return issued, binding, tag, packet[retryChallengeSize:], true
}

// buildRetryResponse echoes a challenge only when it names the client's exact initial packet.
func buildRetryResponse(challenge, firstPacket []byte) ([]byte, bool) {
	if len(challenge) != retryChallengeSize || !isRetryFrame(challenge, retryFrameTypeChallenge) || !validHandshakeStartPacket(firstPacket) {
		return nil, false
	}
	binding := sha256.Sum256(firstPacket)
	if !hmac.Equal(challenge[retryFrameBindingOffset:retryFrameTagOffset], binding[:]) {
		return nil, false
	}
	response := make([]byte, retryChallengeSize+len(firstPacket))
	copy(response, challenge)
	response[5] = retryFrameTypeResponse
	copy(response[retryChallengeSize:], firstPacket)
	return response, true
}

func isRetryFrame(packet []byte, frameType byte) bool {
	return len(packet) >= retryChallengeSize &&
		packet[0] == retryFrameMagic[0] &&
		packet[1] == retryFrameMagic[1] &&
		packet[2] == retryFrameMagic[2] &&
		packet[3] == retryFrameMagic[3] &&
		packet[4] == retryFrameVersion &&
		packet[5] == frameType
}
