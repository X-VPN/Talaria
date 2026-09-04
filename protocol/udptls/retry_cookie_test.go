// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/udpsession"
)

const testWireIdentity = "vpn.test"

func TestRetryCookieBindsAddressPacketAndLifetime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x5a}, retryCookieKeySize)), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	challenge := gate.EvaluateNewSession(firstPacket, addr)
	if challenge.Admit {
		t.Fatal("bare handshake start was admitted")
	}
	if len(challenge.Reply) != retryChallengeSize {
		t.Fatalf("challenge size = %d, want %d", len(challenge.Reply), retryChallengeSize)
	}
	if len(challenge.Reply) > len(firstPacket) {
		t.Fatalf("challenge amplified request: challenge=%d request=%d", len(challenge.Reply), len(firstPacket))
	}

	response, ok := buildRetryResponse(challenge.Reply, firstPacket)
	if !ok {
		t.Fatal("failed to build retry response")
	}
	decision := gate.EvaluateNewSession(response, addr)
	if !decision.Admit {
		t.Fatal("valid retry response was rejected")
	}
	_, _, _, admittedPacket, ok := parseRetryResponse(decision.Payload)
	if !ok || !bytes.Equal(admittedPacket, firstPacket) {
		t.Fatal("admitted response does not contain the original handshake packet")
	}

	tampered := append([]byte(nil), response...)
	tampered[len(tampered)-1] ^= 0x01
	if gate.EvaluateNewSession(tampered, addr).Admit {
		t.Fatal("tampered handshake packet was admitted")
	}
	tampered = append([]byte(nil), response...)
	tampered[retryFrameBindingOffset] ^= 0x01
	if gate.EvaluateNewSession(tampered, addr).Admit {
		t.Fatal("tampered packet binding was admitted")
	}

	otherAddr := &net.UDPAddr{IP: addr.IP, Port: addr.Port + 1}
	if gate.EvaluateNewSession(response, otherAddr).Admit {
		t.Fatal("cookie was accepted from a different source port")
	}

	now = now.Add(defaultRetryCookieTTL + time.Second)
	if gate.EvaluateNewSession(response, addr).Admit {
		t.Fatal("expired cookie was admitted")
	}
}

func TestRetryCookieSilentlyDropsNonHandshakeInput(t *testing.T) {
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x11}, retryCookieKeySize)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	decision := gate.EvaluateNewSession([]byte("not a handshake"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 20002})
	if decision.Admit || len(decision.Reply) != 0 {
		t.Fatalf("non-handshake decision = %+v, want silent rejection", decision)
	}
}

func TestSecureWireGateRequiresSecretAndHidesProtocolFrames(t *testing.T) {
	secret := bytes.Repeat([]byte{0x7a}, minimumWireSecretSize)
	serverWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x42}, retryCookieKeySize)), time.Now, serverWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 20005}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))

	if decision := gate.EvaluateNewSession(firstPacket, addr); decision.Admit || len(decision.Reply) != 0 {
		t.Fatal("public handshake shape received a secure-profile response")
	}
	sealedFirst, ok := clientWire.seal(firstPacket, wireDirectionClient)
	if !ok {
		t.Fatal("failed to seal first packet")
	}
	decision := gate.EvaluateNewSession(sealedFirst, addr)
	if decision.Admit || len(decision.Reply) == 0 {
		t.Fatal("secret-authenticated first packet did not receive Retry")
	}
	for _, marker := range [][]byte{retryFrameMagic[:], handshakeAuthMagic[:], []byte(TunnelTLSALPN)} {
		if bytes.Contains(decision.Reply, marker) {
			t.Fatalf("secure Retry exposed protocol marker %q", marker)
		}
	}
	challenge, ok := clientWire.open(decision.Reply, wireDirectionServer)
	if !ok {
		t.Fatal("failed to open secure Retry")
	}
	response, ok := buildRetryResponse(challenge, firstPacket)
	if !ok {
		t.Fatal("failed to build secure Retry response")
	}
	sealedResponse, ok := clientWire.seal(response, wireDirectionClient)
	if !ok || !gate.EvaluateNewSession(sealedResponse, addr).Admit {
		t.Fatal("secure Retry response was not admitted")
	}

	second, ok := clientWire.seal(firstPacket, wireDirectionClient)
	if !ok || bytes.Equal(second[:wireMaskNonceSize], sealedFirst[:wireMaskNonceSize]) {
		t.Fatal("secure wire reused a packet prefix")
	}
	wrongWire, err := newWireCodec(WireProfileSecure, bytes.Repeat([]byte{0x6b}, minimumWireSecretSize), testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong, ok := wrongWire.seal(firstPacket, wireDirectionClient)
	if !ok {
		t.Fatal("failed to seal wrong-secret probe")
	}
	if rejected := gate.EvaluateNewSession(wrong, addr); rejected.Admit || len(rejected.Reply) != 0 {
		t.Fatal("wrong-secret probe received a response")
	}
}

func TestSecureWireSeparatesSendersAndRotatesRecordKeys(t *testing.T) {
	secret := bytes.Repeat([]byte{0x28}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newCodec := func(seed byte) *wireCodec {
		random := make([]byte, 256)
		for i := range random {
			random[i] = seed + byte(i)
		}
		codec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(random))
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return now }
		return codec
	}
	server := newCodec(0x10)
	secondServer := newCodec(0x20)
	firstClient := newCodec(0x30)
	secondClient := newCodec(0x40)

	first, ok := firstClient.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("first client failed to seal")
	}
	if _, ok := server.open(first, wireDirectionClient); !ok {
		t.Fatal("server rejected first client record")
	}
	if _, ok := server.open(first, wireDirectionServer); ok {
		t.Fatal("client record authenticated with the server direction key")
	}
	if _, ok := secondServer.open(first, wireDirectionClient); !ok {
		t.Fatal("second server instance rejected the record")
	}
	second, ok := secondClient.seal([]byte("second"), wireDirectionClient)
	if !ok {
		t.Fatal("second client failed to seal")
	}
	if _, ok := server.open(second, wireDirectionClient); !ok {
		t.Fatal("server rejected second client record")
	}
	firstSender := decodeWireSenderID(firstClient.root[:], first[:wireHeaderSize])
	secondSender := decodeWireSenderID(secondClient.root[:], second[:wireHeaderSize])
	if firstSender == secondSender {
		t.Fatal("independent clients reused a sender identity")
	}
	epoch, sequence := decodeWireRecord(firstClient.root[:], first[:wireHeaderSize])
	if sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", sequence)
	}

	restarted := newCodec(0x50)
	restartedPacket, ok := restarted.seal([]byte("restarted"), wireDirectionClient)
	if !ok {
		t.Fatal("restarted client failed to seal")
	}
	if restartedSender := decodeWireSenderID(restarted.root[:], restartedPacket[:wireHeaderSize]); restartedSender == firstSender {
		t.Fatal("restarted client reused the previous sender identity")
	}
	if plain, ok := server.open(restartedPacket, wireDirectionClient); !ok || string(plain) != "restarted" {
		t.Fatalf("server failed to open restarted client record: %q, %v", plain, ok)
	}

	firstClient.mu.Lock()
	firstClient.senders[wireDirectionClient].sequence = wireRecordsPerKey
	firstClient.mu.Unlock()
	rotated, ok := firstClient.seal([]byte("rotated sender"), wireDirectionClient)
	if !ok {
		t.Fatal("client did not rotate after the key limit")
	}
	rotatedSender := decodeWireSenderID(firstClient.root[:], rotated[:wireHeaderSize])
	rotatedEpoch, rotatedSequence := decodeWireRecord(firstClient.root[:], rotated[:wireHeaderSize])
	if rotatedEpoch != epoch {
		t.Fatal("sender rotation changed the wire epoch")
	}
	if rotatedSender == firstSender {
		t.Fatal("sender identity did not rotate at the key limit")
	}
	if rotatedSequence != 1 {
		t.Fatalf("rotated sender sequence = %d, want 1", rotatedSequence)
	}
	if plain, ok := server.open(rotated, wireDirectionClient); !ok || string(plain) != "rotated sender" {
		t.Fatalf("server failed to open rotated sender record: %q, %v", plain, ok)
	}
	now = now.Add(wireEpochDuration)
	rotated, ok = firstClient.seal([]byte("rotated epoch"), wireDirectionClient)
	if !ok {
		t.Fatal("client did not rotate to the next epoch")
	}
	rotatedSender = decodeWireSenderID(firstClient.root[:], rotated[:wireHeaderSize])
	rotatedEpoch, rotatedSequence = decodeWireRecord(firstClient.root[:], rotated[:wireHeaderSize])
	if rotatedEpoch == epoch {
		t.Fatal("wire epoch did not advance")
	}
	if rotatedSender == firstSender {
		t.Fatal("wire sender identity did not rotate with the epoch")
	}
	if rotatedSequence != 1 {
		t.Fatalf("rotated sequence = %d, want 1", rotatedSequence)
	}
	if plain, ok := server.open(rotated, wireDirectionClient); !ok || string(plain) != "rotated epoch" {
		t.Fatalf("server failed to open rotated record: %q, %v", plain, ok)
	}

	now = now.Add(2 * wireEpochDuration)
	if _, ok := server.open(first, wireDirectionClient); ok {
		t.Fatal("server accepted a record outside the epoch window")
	}
}

func TestSecureWireRejectsInvalidTagsHeadersAndSequences(t *testing.T) {
	secret := bytes.Repeat([]byte{0x29}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newCodec := func() *wireCodec {
		codec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return now }
		return codec
	}
	client := newCodec()
	server := newCodec()
	packet, ok := client.seal([]byte("invalid tag"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	packet[len(packet)-1] ^= 1
	if _, ok := server.open(packet, wireDirectionClient); ok {
		t.Fatal("server accepted a packet with an invalid tag")
	}

	packet, ok = client.seal([]byte("invalid header"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	tamperedHeader := append([]byte(nil), packet...)
	tamperedHeader[0] ^= 1
	if _, ok := server.open(tamperedHeader, wireDirectionClient); ok {
		t.Fatal("server accepted a packet with a modified header")
	}

	epoch, _ := decodeWireRecord(client.root[:], packet[:wireHeaderSize])
	overLimit := append([]byte(nil), packet...)
	encodeWireRecord(client.root[:], overLimit[:wireHeaderSize], epoch, wireRecordsPerKey+1)
	if _, ok := server.open(overLimit, wireDirectionClient); ok {
		t.Fatal("server accepted a sequence above the sender limit")
	}
}

func TestSecureWireRejectsReplayedRecordsAfterAuthentication(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2b}, minimumWireSecretSize)
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	packet, ok := client.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	if _, ok := server.open(tampered, wireDirectionClient); ok {
		t.Fatal("server accepted a packet with an invalid tag")
	}
	if _, ok := server.open(packet, wireDirectionClient); !ok {
		t.Fatal("failed authentication consumed a valid sequence")
	}
	if _, ok := server.open(packet, wireDirectionClient); ok {
		t.Fatal("server accepted a replayed record")
	}
}

func TestSecureWireGateRepeatsRetryForReplayedInitialPacket(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2c}, minimumWireSecretSize)
	serverWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x42}, retryCookieKeySize)), time.Now, serverWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	packet := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	sealed, ok := clientWire.seal(packet, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 20005}
	if decision := gate.EvaluateNewSession(sealed, addr); decision.Admit || len(decision.Reply) == 0 {
		t.Fatal("authenticated initial packet did not receive Retry")
	}
	if decision := gate.EvaluateNewSession(sealed, addr); decision.Admit || len(decision.Reply) == 0 || len(decision.Reply) > len(sealed) {
		t.Fatal("replayed initial packet did not receive a non-amplifying Retry")
	}
}

func TestSecureWireRetryBindsEndpointIdentity(t *testing.T) {
	secret := bytes.Repeat([]byte{0x3c}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newCodec := func(identity string, wireSecret []byte, seed byte, codecNow time.Time) *wireCodec {
		codec, err := newWireCodec(
			WireProfileSecure,
			wireSecret,
			identity,
			bytes.NewReader(bytes.Repeat([]byte{seed}, 64)),
		)
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return codecNow }
		t.Cleanup(codec.Close)
		return codec
	}
	newGate := func(wire *wireCodec, seed byte) *retryCookieGate {
		gate, err := newRetryCookieGateWithWire(
			1500,
			bytes.NewReader(bytes.Repeat([]byte{seed}, retryCookieKeySize)),
			func() time.Time { return now },
			wire,
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)
		return gate
	}
	clientA := newCodec(" ENDPOINT-A.EXAMPLE. ", secret, 0x10, now)
	clientB := newCodec("endpoint-b.example", secret, 0x20, now)
	wrongSecret := newCodec("endpoint-a.example", bytes.Repeat([]byte{0x4d}, minimumWireSecretSize), 0x30, now)
	expired := newCodec("endpoint-a.example", secret, 0x40, now.Add(-2*wireEpochDuration))
	gateA := newGate(newCodec("endpoint-a.example", secret, 0x50, now), 0x60)
	gateB := newGate(newCodec("endpoint-b.example", secret, 0x70, now), 0x80)
	sourceA := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 50), Port: 20500}
	sourceB := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 50), Port: 30500}
	handshake := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	firstA, ok := clientA.seal(handshake, wireDirectionClient)
	if !ok {
		t.Fatal("endpoint A client failed to seal initial packet")
	}
	firstRetry := gateA.EvaluateNewSession(firstA, sourceA)
	secondRetry := gateA.EvaluateNewSession(firstA, sourceA)
	for _, decision := range []udpsession.NewSessionDecision{firstRetry, secondRetry} {
		if decision.Admit || len(decision.Reply) == 0 || len(decision.Reply) > len(firstA) {
			t.Fatal("same-endpoint initial retry was not repeatable and non-amplifying")
		}
	}
	challenge, ok := clientA.open(firstRetry.Reply, wireDirectionServer)
	if !ok {
		t.Fatal("endpoint A client failed to open Retry")
	}
	response, ok := buildRetryResponse(challenge, handshake)
	if !ok {
		t.Fatal("endpoint A client failed to build Retry response")
	}
	sealedResponse, ok := clientA.seal(response, wireDirectionClient)
	if !ok {
		t.Fatal("endpoint A client failed to seal Retry response")
	}
	if moved := gateA.EvaluateNewSession(sealedResponse, sourceB); moved.Admit || len(moved.Reply) != 0 {
		t.Fatal("Retry response moved to another source received a response")
	}
	if valid := gateA.EvaluateNewSession(sealedResponse, sourceA); !valid.Admit || len(valid.Reply) != 0 {
		t.Fatal("same-source Retry response was not admitted")
	}
	for _, source := range []net.Addr{sourceA, sourceB} {
		for range 2 {
			if decision := gateB.EvaluateNewSession(firstA, source); decision.Admit || len(decision.Reply) != 0 {
				t.Fatal("cross-endpoint replay received a response")
			}
		}
	}
	firstB, ok := clientB.seal(handshake, wireDirectionClient)
	if !ok || len(gateB.EvaluateNewSession(firstB, sourceA).Reply) == 0 {
		t.Fatal("endpoint B rejected its own authenticated initial packet")
	}
	if decision := gateA.EvaluateNewSession(firstB, sourceA); decision.Admit || len(decision.Reply) != 0 {
		t.Fatal("endpoint A responded to endpoint B packet")
	}
	wrong, ok := wrongSecret.seal(handshake, wireDirectionClient)
	if !ok {
		t.Fatal("wrong-secret client failed to seal initial packet")
	}
	if decision := gateA.EvaluateNewSession(wrong, sourceA); decision.Admit || len(decision.Reply) != 0 {
		t.Fatal("wrong-secret initial packet received a response")
	}
	old, ok := expired.seal(handshake, wireDirectionClient)
	if !ok {
		t.Fatal("expired client failed to seal initial packet")
	}
	if decision := gateA.EvaluateNewSession(old, sourceA); decision.Admit || len(decision.Reply) != 0 {
		t.Fatal("expired initial packet received a response")
	}
}

func TestSecureWireGateDoesNotRetainUnverifiedSourceState(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2e}, minimumWireSecretSize)
	serverWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x45}, retryCookieKeySize)), time.Now, serverWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	packet := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	sealed, ok := clientWire.seal(packet, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	decision := gate.EvaluateNewSession(sealed, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 28), Port: 20008})
	if decision.Admit || len(decision.Reply) == 0 {
		t.Fatal("authenticated initial packet did not receive Retry")
	}
	serverWire.mu.Lock()
	states := len(serverWire.receivers)
	serverWire.mu.Unlock()
	if states != 0 {
		t.Fatalf("unverified source retained %d receiver states", states)
	}
}

func TestSecureWireAdmittedRetryResponseTransfersReplayOwnership(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2d}, minimumWireSecretSize)
	serverWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientWire, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x43}, retryCookieKeySize)), time.Now, serverWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 26), Port: 20006}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	sealedFirst, ok := clientWire.seal(firstPacket, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal initial packet")
	}
	challengeWire := gate.EvaluateNewSession(sealedFirst, addr).Reply
	challenge, ok := clientWire.open(challengeWire, wireDirectionServer)
	if !ok {
		t.Fatal("client failed to open Retry")
	}
	response, ok := buildRetryResponse(challenge, firstPacket)
	if !ok {
		t.Fatal("client failed to build Retry response")
	}
	sealedResponse, ok := clientWire.seal(response, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal Retry response")
	}
	decision := gate.EvaluateNewSession(sealedResponse, addr)
	if !decision.Admit || decision.Commit == nil {
		t.Fatal("valid Retry response was not admitted")
	}
	release, committed := decision.Commit()
	if !committed {
		t.Fatal("valid Retry response receiver state was not committed")
	}
	defer release()
	owner, ok := decision.State.(*wireReceiveOwner)
	if !ok {
		t.Fatal("valid Retry response state had no receiver owner")
	}
	scope := wireReceiveScopeFromAddr(addr, serverWire.receiverIPv6PrefixBits)
	if _, ok := serverWire.openInPlaceFromOwner(append([]byte(nil), decision.Payload...), wireDirectionClient, scope, owner); !ok {
		t.Fatal("admitted Retry response was consumed before session handoff")
	}
	if _, ok := serverWire.openInPlaceFromOwner(append([]byte(nil), decision.Payload...), wireDirectionClient, scope, owner); ok {
		t.Fatal("session accepted the admitted Retry response twice")
	}
	if replay := gate.EvaluateNewSession(sealedResponse, addr); replay.Admit || len(replay.Reply) != 0 {
		t.Fatal("consumed Retry response was admitted again")
	}
}

func TestSecureWireRetryHandoffCountsNewSenderAuthentication(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2d}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newCodec := func(fill byte) *wireCodec {
		codec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return now }
		return codec
	}
	serverWire := newCodec(0x41)
	initialWire := newCodec(0x42)
	responseWire := newCodec(0x43)
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x44}, retryCookieKeySize)), func() time.Time { return now }, serverWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 27), Port: 20007}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	sealedFirst, ok := initialWire.seal(firstPacket, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal initial packet")
	}
	challengeWire := gate.EvaluateNewSession(sealedFirst, addr).Reply
	challenge, ok := initialWire.open(challengeWire, wireDirectionServer)
	if !ok {
		t.Fatal("client failed to open Retry")
	}
	response, ok := buildRetryResponse(challenge, firstPacket)
	if !ok {
		t.Fatal("client failed to build Retry response")
	}
	sealedResponse, ok := responseWire.seal(response, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal Retry response")
	}
	decision := gate.EvaluateNewSession(sealedResponse, addr)
	if !decision.Admit {
		t.Fatal("valid Retry response was not admitted")
	}
	if decision.Commit == nil {
		t.Fatal("valid Retry response state had no commit")
	}
	release, committed := decision.Commit()
	if !committed {
		t.Fatal("valid Retry response state was not committed")
	}
	senderID := decodeWireSenderID(serverWire.root[:], sealedResponse[:wireHeaderSize])
	epoch, _ := decodeWireRecord(serverWire.root[:], sealedResponse[:wireHeaderSize])
	scope := wireReceiveScopeFromAddr(addr, serverWire.receiverIPv6PrefixBits)
	key := wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: senderID, scope: scope}
	serverWire.mu.Lock()
	state := serverWire.receivers[key]
	attempts := uint64(0)
	if state != nil {
		attempts = state.attempts
	}
	serverWire.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("Retry handoff authentication attempts = %d, want 1", attempts)
	}
	owner, ok := decision.State.(*wireReceiveOwner)
	if !ok {
		t.Fatal("valid Retry response state had no receiver owner")
	}
	if _, ok := serverWire.openInPlaceFromOwner(append([]byte(nil), decision.Payload...), wireDirectionClient, scope, owner); !ok {
		t.Fatal("session failed to consume admitted Retry response")
	}
	serverWire.mu.Lock()
	attempts = serverWire.receivers[key].attempts
	serverWire.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("session handoff authentication attempts = %d, want 2", attempts)
	}
	release()
}

func TestSecureWireCountsFailedAuthenticationAttempts(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newCodec := func() *wireCodec {
		codec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return now }
		return codec
	}
	client := newCodec()
	server := newCodec()
	packet, ok := client.seal([]byte("last attempt"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	senderID := decodeWireSenderID(server.root[:], packet[:wireHeaderSize])
	epoch, _ := decodeWireRecord(server.root[:], packet[:wireHeaderSize])
	server.mu.Lock()
	state, ok := server.receiveStateLocked(wireDirectionClient, epoch, senderID)
	if ok {
		state.attempts = wireAttemptsPerKey - 1
	}
	server.mu.Unlock()
	if !ok {
		t.Fatal("server failed to create receiver state")
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	if _, ok := server.open(tampered, wireDirectionClient); ok {
		t.Fatal("server accepted a packet with an invalid tag")
	}
	if _, ok := server.open(packet, wireDirectionClient); ok {
		t.Fatal("server accepted a record after failed attempts exhausted the key")
	}
}

func TestSecureWireCountsFailedAttemptsBeforeStateAdmission(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	server.now = func() time.Time { return now }
	packet, ok := client.seal([]byte("last attempt"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	if _, ok := server.open(tampered, wireDirectionClient); ok {
		t.Fatal("server accepted a packet with an invalid tag")
	}
	senderID := decodeWireSenderID(server.root[:], packet[:wireHeaderSize])
	epoch, _ := decodeWireRecord(server.root[:], packet[:wireHeaderSize])
	attemptKey := wireReceiveAttemptKey{
		direction: wireDirectionClient,
		epoch:     epoch,
		bucket:    wireAttemptBucket(senderID),
	}
	server.mu.Lock()
	if len(server.receivers) != 0 {
		server.mu.Unlock()
		t.Fatal("failed authentication admitted a receiver state")
	}
	server.receiverAttempts[attemptKey] = wireAttemptsPerKey - 1
	server.mu.Unlock()
	if _, ok := server.open(tampered, wireDirectionClient); ok {
		t.Fatal("server accepted the final failed attempt")
	}
	if _, ok := server.open(packet, wireDirectionClient); ok {
		t.Fatal("server accepted a record after pre-admission failures exhausted the key")
	}
}

func TestSecureWirePreAdmissionLimitDoesNotBlockKnownSender(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	server.now = func() time.Time { return now }
	first, ok := client.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal first record")
	}
	if _, ok := server.open(first, wireDirectionClient); !ok {
		t.Fatal("server rejected first record")
	}
	senderID := decodeWireSenderID(server.root[:], first[:wireHeaderSize])
	epoch, _ := decodeWireRecord(server.root[:], first[:wireHeaderSize])
	attemptKey := wireReceiveAttemptKey{
		direction: wireDirectionClient,
		epoch:     epoch,
		bucket:    wireAttemptBucket(senderID),
	}
	server.mu.Lock()
	server.receiverAttempts[attemptKey] = wireAttemptsPerKey
	server.mu.Unlock()
	second, ok := client.seal([]byte("second"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal second record")
	}
	if plain, ok := server.open(second, wireDirectionClient); !ok || string(plain) != "second" {
		t.Fatalf("pre-admission limit blocked known sender: %q, %v", plain, ok)
	}
}

func TestSecureWireInvalidPacketsDoNotConsumeReceiverStates(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	epoch, ok := wireEpochAt(now)
	if !ok {
		t.Fatal("failed to determine wire epoch")
	}
	for i := 0; i < wireReceiveStateLimit; i++ {
		packet := make([]byte, wireEnvelopeOverhead)
		var senderID [wireSenderIDSize]byte
		binary.BigEndian.PutUint32(senderID[:], uint32(i+1))
		encodeWireSenderID(server.root[:], packet[:wireHeaderSize], senderID)
		encodeWireRecord(server.root[:], packet[:wireHeaderSize], epoch, 1)
		if _, accepted := server.open(packet, wireDirectionClient); accepted {
			t.Fatal("server accepted an invalid wire packet")
		}
	}
	server.mu.Lock()
	states := len(server.receivers)
	server.mu.Unlock()
	if states != 0 {
		t.Fatalf("invalid wire packets retained %d receiver states", states)
	}
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	packet, ok := client.seal([]byte("valid"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}
	plain, ok := server.open(packet, wireDirectionClient)
	if !ok || string(plain) != "valid" {
		t.Fatal("invalid packets blocked a valid sender")
	}
}

func TestSecureWireReceiverStatesRotatePerSource(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x42}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	handshake := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	retryResponse := func(id uint64, source *net.UDPAddr) []byte {
		random := make([]byte, wireSenderIDSize+2*wireMaskNonceSize)
		binary.BigEndian.PutUint64(random[wireSenderIDSize-8:wireSenderIDSize], id)
		client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(random))
		if err != nil {
			t.Fatal(err)
		}
		client.now = func() time.Time { return now }
		first, ok := client.seal(handshake, wireDirectionClient)
		if !ok {
			t.Fatal("client failed to seal initial packet")
		}
		challenge, ok := client.open(gate.EvaluateNewSession(first, source).Reply, wireDirectionServer)
		if !ok {
			t.Fatal("client failed to open Retry")
		}
		response, ok := buildRetryResponse(challenge, handshake)
		if !ok {
			t.Fatal("client failed to build Retry response")
		}
		packet, ok := client.seal(response, wireDirectionClient)
		client.Close()
		if !ok {
			t.Fatal("client failed to seal Retry response")
		}
		return packet
	}

	sourceA := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 20001}
	responses := make([][]byte, server.receiverStateLimit)
	for i := range responses {
		responses[i] = retryResponse(uint64(i+1), sourceA)
	}
	sourceB := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 20002}
	responseB := retryResponse(uint64(server.receiverStateLimit+1), sourceB)

	admitted := 0
	releases := make([]func(), 0, server.receiverSourceLimit+1)
	for _, response := range responses {
		decision := gate.EvaluateNewSession(response, sourceA)
		if decision.Admit && decision.Commit != nil {
			if release, committed := decision.Commit(); committed {
				admitted++
				releases = append(releases, release)
			}
		}
	}
	server.mu.Lock()
	retained := make(map[wireReceiveKey]*wireReceiveState, len(server.receivers))
	for key, state := range server.receivers {
		retained[key] = state
	}
	server.mu.Unlock()
	invalid := retryResponse(99, sourceA)
	invalid[len(invalid)-1] ^= 1
	if decision := gate.EvaluateNewSession(invalid, sourceA); decision.Admit || decision.Commit != nil {
		t.Fatal("invalid tag reached same-source rotation")
	}
	server.mu.Lock()
	for key, state := range retained {
		if server.receivers[key] != state {
			server.mu.Unlock()
			t.Fatal("invalid tag evicted a receiver state")
		}
	}
	server.mu.Unlock()
	decision := gate.EvaluateNewSession(responseB, sourceB)
	if !decision.Admit || decision.Commit == nil {
		t.Fatal("one source exhausted receiver states for another source")
	}
	releaseB, committed := decision.Commit()
	if !committed {
		t.Fatal("one source exhausted receiver states for another source")
	}
	releases = append(releases, releaseB)
	server.mu.Lock()
	sourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{
		direction: wireDirectionClient,
		epoch:     server.receiverEpoch,
		source:    handshakeSourceKeyFromAddr(sourceA, server.receiverIPv6PrefixBits),
	}]
	states := len(server.receivers)
	server.mu.Unlock()
	if admitted != server.receiverSourceLimit || sourceCount != server.receiverSourceLimit || states != server.receiverSourceLimit+1 {
		t.Fatalf("receiver states admitted=%d source=%d states=%d", admitted, sourceCount, states)
	}
	for _, release := range releases {
		release()
		release()
	}
	server.mu.Lock()
	states = len(server.receivers)
	owners := 0
	for _, state := range server.receivers {
		owners += state.owners
	}
	server.mu.Unlock()
	if states != server.receiverSourceLimit+1 || owners != 0 {
		t.Fatalf("released receiver accounting states=%d owners=%d", states, owners)
	}
}

func TestSecureWireFutureEpochStateCommitsAfterSessionAdmission(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5c}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x6c}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := udpsession.NewListener(udpsession.NewListenerReq{
		PacketConn:             &udptlsResultPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            2,
		SessionQueue:           2,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
		ReadBufferSize:         gate.maxPacket,
		MaxPacket:              gate.maxPacket,
	})
	if err != nil {
		gate.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		gate.Close()
	})

	accept := func() *udpsession.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	seedSources := []*net.UDPAddr{
		{IP: net.IPv4(192, 0, 2, 1), Port: 20001},
		{IP: net.IPv4(192, 0, 2, 2), Port: 20002},
	}
	seedSessions := make([]*udpsession.Conn, 0, len(seedSources))
	for i, source := range seedSources {
		response := secureRetryResponseAt(t, secret, gate, now, source, byte(0x10+i))
		if err := listener.ReceivePacket(response, source); err != nil {
			t.Fatal(err)
		}
		seedSessions = append(seedSessions, accept())
	}

	futureEpoch, ok := wireEpochAt(now.Add(wireEpochDuration))
	if !ok {
		t.Fatal("failed to determine future epoch")
	}
	attackSources := []*net.UDPAddr{
		{IP: net.IPv4(192, 0, 2, 10), Port: 21001},
		{IP: net.IPv4(192, 0, 2, 11), Port: 22001},
	}
	seed := byte(0x20)
	for _, source := range attackSources {
		for i := 0; i < server.receiverSourceLimit; i++ {
			remote := &net.UDPAddr{IP: source.IP, Port: source.Port + i}
			response := secureRetryResponseAt(t, secret, gate, now.Add(wireEpochDuration), remote, seed)
			seed++
			if err := listener.ReceivePacket(response, remote); !errors.Is(err, udpsession.ErrSessionLimit) {
				t.Fatalf("future-epoch admission error = %v, want %v", err, udpsession.ErrSessionLimit)
			}
		}
	}
	server.mu.Lock()
	futureCount := server.receiverCounts[wireReceiveEpochKey{direction: wireDirectionClient, epoch: futureEpoch}]
	futureSources := 0
	for key, count := range server.receiverSourceCounts {
		if key.direction == wireDirectionClient && key.epoch == futureEpoch {
			futureSources += count
		}
	}
	server.mu.Unlock()
	if futureCount != 0 || futureSources != 0 {
		t.Fatalf("rejected future epoch retained states=%d sources=%d", futureCount, futureSources)
	}

	for _, conn := range seedSessions {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(wireEpochDuration)
	normalSource := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 30), Port: 23001}
	normalResponse := secureRetryResponseAt(t, secret, gate, now, normalSource, 0x70)
	if err := listener.ReceivePacket(normalResponse, normalSource); err != nil {
		t.Fatal(err)
	}
	normalSession := accept()
	server.mu.Lock()
	currentCount := server.receiverCounts[wireReceiveEpochKey{direction: wireDirectionClient, epoch: futureEpoch}]
	currentSourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{
		direction: wireDirectionClient,
		epoch:     futureEpoch,
		source:    handshakeSourceKeyFromAddr(normalSource, server.receiverIPv6PrefixBits),
	}]
	server.mu.Unlock()
	if currentCount != 1 || currentSourceCount != 1 {
		t.Fatalf("current epoch accounting states=%d source=%d, want 1 and 1", currentCount, currentSourceCount)
	}
	_ = normalSession.Close()
	server.mu.Lock()
	releasedOwners := 0
	for _, state := range server.receivers {
		releasedOwners += state.owners
	}
	server.mu.Unlock()
	if releasedOwners != 0 {
		t.Fatalf("session close retained %d receiver owners", releasedOwners)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	gate.Close()
	server.mu.Lock()
	closed := server.closed
	states := len(server.receivers)
	counts := len(server.receiverCounts)
	queues := len(server.receiverQueues)
	sources := len(server.receiverSourceCounts)
	attempts := len(server.receiverAttempts)
	server.mu.Unlock()
	if !closed || states != 0 || counts != 0 || queues != 0 || sources != 0 || attempts != 0 {
		t.Fatalf("closed accounting closed=%v states=%d counts=%d queues=%d sources=%d attempts=%d", closed, states, counts, queues, sources, attempts)
	}
}

func TestSecureWireFutureEpochSameSourceReleasesAfterSessionClose(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5e}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x6e}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := udpsession.NewListener(udpsession.NewListenerReq{
		PacketConn:             &udptlsResultPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            1,
		SessionQueue:           1,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
		ReadBufferSize:         gate.maxPacket,
		MaxPacket:              gate.maxPacket,
	})
	if err != nil {
		gate.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		gate.Close()
	})
	accept := func() *udpsession.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	future := now.Add(wireEpochDuration)
	futureEpoch, ok := wireEpochAt(future)
	if !ok {
		t.Fatal("failed to determine future epoch")
	}
	sourceIP := net.IPv4(192, 0, 2, 50)
	for i := 0; i < server.receiverSourceLimit+2; i++ {
		source := &net.UDPAddr{IP: sourceIP, Port: 25000 + i}
		response := secureRetryResponseAt(t, secret, gate, future, source, byte(0x80+i))
		if err := listener.ReceivePacket(response, source); err != nil {
			t.Fatal(err)
		}
		if err := accept().Close(); err != nil {
			t.Fatal(err)
		}
	}

	now = future
	normalSource := &net.UDPAddr{IP: sourceIP, Port: 26000}
	normalResponse := secureRetryResponseAt(t, secret, gate, now, normalSource, 0x90)
	if err := listener.ReceivePacket(normalResponse, normalSource); err != nil {
		t.Fatal(err)
	}
	if err := accept().Close(); err != nil {
		t.Fatal(err)
	}

	server.mu.Lock()
	count := server.receiverCounts[wireReceiveEpochKey{direction: wireDirectionClient, epoch: futureEpoch}]
	sourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{
		direction: wireDirectionClient,
		epoch:     futureEpoch,
		source:    handshakeSourceKeyFromAddr(normalSource, server.receiverIPv6PrefixBits),
	}]
	states := len(server.receivers)
	owners := 0
	for _, state := range server.receivers {
		owners += state.owners
	}
	server.mu.Unlock()
	if count != server.receiverSourceLimit || sourceCount != server.receiverSourceLimit || states != server.receiverSourceLimit || owners != 0 {
		t.Fatalf("released future epoch accounting states=%d count=%d source=%d owners=%d", states, count, sourceCount, owners)
	}
}

func TestSecureWireActiveReceiverStateSurvivesSameSourceTurnover(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5f}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x6f}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	sourceIP := net.IPv4(192, 0, 2, 60)
	activeSource := &net.UDPAddr{IP: sourceIP, Port: 26001}
	activePacket := secureRetryResponseAt(t, secret, gate, now, activeSource, 0xa0)
	activeDecision := gate.EvaluateNewSession(activePacket, activeSource)
	if !activeDecision.Admit || activeDecision.Commit == nil {
		t.Fatal("active sender did not reach admission")
	}
	releaseActive, committed := activeDecision.Commit()
	if !committed {
		t.Fatal("active sender state was not committed")
	}
	activeOwner, ok := activeDecision.State.(*wireReceiveOwner)
	if !ok {
		t.Fatal("active sender did not retain a receiver owner")
	}
	activeScope := wireReceiveScopeFromAddr(activeSource, server.receiverIPv6PrefixBits)
	if _, ok := server.openInPlaceFromOwner(append([]byte(nil), activeDecision.Payload...), wireDirectionClient, activeScope, activeOwner); !ok {
		t.Fatal("active sender first record was not consumed")
	}

	for i := 0; i < server.receiverSourceLimit+2; i++ {
		source := &net.UDPAddr{IP: sourceIP, Port: 26100 + i}
		packet := secureRetryResponseAt(t, secret, gate, now, source, byte(0xb0+i))
		decision := gate.EvaluateNewSession(packet, source)
		if !decision.Admit || decision.Commit == nil {
			t.Fatal("same-source sender did not reach admission")
		}
		release, committed := decision.Commit()
		if !committed {
			t.Fatal("inactive same-source state blocked admission")
		}
		release()
	}

	if decision := gate.EvaluateNewSession(activePacket, activeSource); decision.Admit || decision.Commit != nil {
		t.Fatal("same-source turnover reset the active sender replay window")
	}
	server.mu.Lock()
	activeStates := len(server.receivers)
	activeOwners := 0
	for _, state := range server.receivers {
		activeOwners += state.owners
	}
	server.mu.Unlock()
	if activeStates != server.receiverSourceLimit || activeOwners != 1 {
		t.Fatalf("active accounting states=%d owners=%d, want %d and 1", activeStates, activeOwners, server.receiverSourceLimit)
	}
	releaseActive()
	releaseActive()
	server.mu.Lock()
	owners := 0
	for _, state := range server.receivers {
		owners += state.owners
	}
	server.mu.Unlock()
	if owners != 0 {
		t.Fatalf("active release retained %d receiver owners", owners)
	}
}

func TestSecureWireSessionOwnsRotatedReceiverStates(t *testing.T) {
	secret := bytes.Repeat([]byte{0x61}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x71}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := udpsession.NewListener(udpsession.NewListenerReq{
		PacketConn:             &udptlsResultPacketConn{},
		ManualReceive:          true,
		NewSessionGate:         gate,
		AcceptQueue:            1,
		SessionQueue:           2,
		MaxSessions:            2,
		MaxSessionsPerSourceIP: 1,
		ReadBufferSize:         gate.maxPacket,
		MaxPacket:              gate.maxPacket,
	})
	if err != nil {
		gate.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		gate.Close()
	})

	clientRandom := make([]byte, 256)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(clientRandom))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	t.Cleanup(client.Close)
	source := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 80), Port: 28001}
	handshake := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	first, ok := client.seal(handshake, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal initial packet")
	}
	challenge, ok := client.open(gate.EvaluateNewSession(first, source).Reply, wireDirectionServer)
	if !ok {
		t.Fatal("client failed to open Retry")
	}
	response, ok := buildRetryResponse(challenge, handshake)
	if !ok {
		t.Fatal("client failed to build Retry response")
	}
	responsePacket, ok := client.seal(response, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal Retry response")
	}
	if err := listener.ReceivePacket(responsePacket, source); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	baseConn, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn := newWireBatchConn(baseConn, server, udptlsModeServer)
	read := func(want []byte) {
		buf := make([]byte, gate.maxPacket)
		sizes := []int{0}
		n, err := conn.ReadBatch(ctx, [][]byte{buf}, sizes)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 || !bytes.Equal(buf[:sizes[0]], want) {
			t.Fatalf("wire read n=%d payload=%q, want %q", n, buf[:sizes[0]], want)
		}
	}
	read(response)

	client.mu.Lock()
	client.senders[wireDirectionClient].sequence = wireRecordsPerKey
	client.mu.Unlock()
	rotatedPayload := []byte("rotated sender payload")
	rotated, ok := client.seal(rotatedPayload, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to rotate sender")
	}
	if err := listener.ReceivePacket(rotated, source); err != nil {
		t.Fatal(err)
	}
	read(rotatedPayload)

	owner, ok := baseConn.NewSessionState().(*wireReceiveOwner)
	if !ok {
		t.Fatal("session did not retain receiver owner")
	}
	epoch, _ := decodeWireRecord(server.root[:], rotated[:wireHeaderSize])
	senderID := decodeWireSenderID(server.root[:], rotated[:wireHeaderSize])
	scope := wireReceiveScopeFromAddr(source, server.receiverIPv6PrefixBits)
	rotatedKey := wireReceiveKey{
		direction: wireDirectionClient,
		epoch:     epoch,
		senderID:  senderID,
		scope:     scope,
	}
	server.mu.Lock()
	rotatedState := server.receivers[rotatedKey]
	ownerState := owner.state
	activeOwners := len(server.receiverOwners)
	rotatedOwners := 0
	hasOwnerRef := false
	if rotatedState != nil {
		rotatedOwners = rotatedState.owners
		_, hasOwnerRef = rotatedState.ownerRefs[owner]
	}
	server.mu.Unlock()
	if rotatedState == nil || ownerState != rotatedState || activeOwners != 1 || rotatedOwners != 1 || !hasOwnerRef {
		t.Fatalf("rotated ownership state=%v current=%v active=%d owners=%d ref=%v", rotatedState != nil, ownerState == rotatedState, activeOwners, rotatedOwners, hasOwnerRef)
	}

	churn, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{0x82}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	churn.now = func() time.Time { return now }
	t.Cleanup(churn.Close)
	churnPacket, ok := churn.seal([]byte("churn"), wireDirectionClient)
	if !ok {
		t.Fatal("churn client failed to seal")
	}
	if _, ok := server.openInPlaceFrom(append([]byte(nil), churnPacket...), wireDirectionClient, scope); !ok {
		t.Fatal("active receiver state blocked fair same-source turnover")
	}
	if _, ok := server.openInPlaceFromOwner(append([]byte(nil), rotated...), wireDirectionClient, scope, owner); ok {
		t.Fatal("sender turnover reset the rotated replay window")
	}

	if err := baseConn.Close(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	activeOwners = len(server.receiverOwners)
	ownerState = owner.state
	ownerActive := owner.active
	remainingOwners := 0
	remainingRefs := 0
	for _, state := range server.receivers {
		remainingOwners += state.owners
		remainingRefs += len(state.ownerRefs)
	}
	server.mu.Unlock()
	if activeOwners != 0 || ownerState != nil || ownerActive || remainingOwners != 0 || remainingRefs != 0 {
		t.Fatalf("released ownership active=%d state=%v ownerActive=%v owners=%d refs=%d", activeOwners, ownerState != nil, ownerActive, remainingOwners, remainingRefs)
	}
	afterClose, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{0x83}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	afterClose.now = func() time.Time { return now }
	t.Cleanup(afterClose.Close)
	afterClosePacket, ok := afterClose.seal([]byte("after close"), wireDirectionClient)
	if !ok {
		t.Fatal("post-close client failed to seal")
	}
	if _, ok := server.openInPlaceFrom(append([]byte(nil), afterClosePacket...), wireDirectionClient, scope); !ok {
		t.Fatal("released receiver ownership did not restore source progress")
	}
}

func TestSecureWireOwnerRotationAtReceiverCapacity(t *testing.T) {
	secret := bytes.Repeat([]byte{0x62}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 1
	server.receiverSourceLimit = 1
	server.limitReceiverStatesBySource(0)
	clientRandom := make([]byte, 64)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(clientRandom))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	t.Cleanup(client.Close)
	scope := wireReceiveScopeFromAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 81), Port: 28101}, 0)
	source := scope.source
	first, ok := client.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal first packet")
	}
	_, firstState, firstSequence, ok := server.openAuthenticatedFrom(first, wireDirectionClient, scope)
	if !ok {
		t.Fatal("server failed to authenticate first packet")
	}
	owner := new(wireReceiveOwner)
	release, committed := server.commitReceiveState(firstState, firstSequence, scope, owner)
	if !committed {
		t.Fatal("server failed to commit first receiver state")
	}
	if plain, ok := server.openInPlaceFromOwner(append([]byte(nil), first...), wireDirectionClient, scope, owner); !ok || !bytes.Equal(plain, []byte("first")) {
		t.Fatal("server failed to consume first packet")
	}

	client.mu.Lock()
	client.senders[wireDirectionClient].sequence = wireRecordsPerKey
	client.mu.Unlock()
	rotated, ok := client.seal([]byte("rotated"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to rotate sender")
	}
	if plain, ok := server.openInPlaceFromOwner(append([]byte(nil), rotated...), wireDirectionClient, scope, owner); !ok || !bytes.Equal(plain, []byte("rotated")) {
		t.Fatal("receiver capacity blocked owner rotation")
	}
	if _, ok := server.openInPlaceFromOwner(append([]byte(nil), rotated...), wireDirectionClient, scope, owner); ok {
		t.Fatal("owner rotation reset the current replay window")
	}
	if _, ok := server.openInPlaceFromOwner(append([]byte(nil), first...), wireDirectionClient, scope, owner); ok {
		t.Fatal("owner rotation reopened a retired sender replay window")
	}

	epoch, _ := decodeWireRecord(server.root[:], rotated[:wireHeaderSize])
	senderID := decodeWireSenderID(server.root[:], rotated[:wireHeaderSize])
	rotatedKey := wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: senderID, scope: scope}
	server.mu.Lock()
	rotatedState := server.receivers[rotatedKey]
	stateCount := server.receiverCounts[wireReceiveEpochKey{direction: wireDirectionClient, epoch: epoch}]
	sourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{direction: wireDirectionClient, epoch: epoch, source: source}]
	activeOwners := len(server.receiverOwners)
	ownerState := owner.state
	retired := len(owner.retired)
	server.mu.Unlock()
	if rotatedState == nil || ownerState != rotatedState || stateCount != 1 || sourceCount != 1 || activeOwners != 1 || retired != 1 {
		t.Fatalf("rotated capacity state=%v owner=%v states=%d source=%d active=%d retired=%d", rotatedState != nil, ownerState == rotatedState, stateCount, sourceCount, activeOwners, retired)
	}

	release()
	release()
	server.mu.Lock()
	releasedOwners := len(server.receiverOwners)
	remainingOwners := rotatedState.owners
	remainingRefs := len(rotatedState.ownerRefs)
	ownerActive := owner.active
	ownerState = owner.state
	retired = len(owner.retired)
	server.mu.Unlock()
	if releasedOwners != 0 || remainingOwners != 0 || remainingRefs != 0 || ownerActive || ownerState != nil || retired != 0 {
		t.Fatalf("released owner active=%d owners=%d refs=%d ownerActive=%v state=%v retired=%d", releasedOwners, remainingOwners, remainingRefs, ownerActive, ownerState != nil, retired)
	}
	server.Close()
	server.mu.Lock()
	states := len(server.receivers)
	counts := len(server.receiverCounts)
	sources := len(server.receiverSourceCounts)
	attempts := len(server.receiverAttempts)
	server.mu.Unlock()
	if states != 0 || counts != 0 || sources != 0 || attempts != 0 {
		t.Fatalf("closed accounting states=%d counts=%d sources=%d attempts=%d", states, counts, sources, attempts)
	}
}

func TestSecureWireOwnerRetiredHistoryIsBoundedAndExpires(t *testing.T) {
	secret := bytes.Repeat([]byte{0x64}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 1
	t.Cleanup(server.Close)
	epoch, ok := wireEpochAt(now)
	if !ok {
		t.Fatal("failed to derive wire epoch")
	}
	scope := wireReceiveScopeFromAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 82), Port: 28102}, 0)
	stateFor := func(epoch uint32, id uint64) *wireReceiveState {
		var senderID [wireSenderIDSize]byte
		binary.BigEndian.PutUint64(senderID[wireSenderIDSize-8:], id)
		return &wireReceiveState{
			key: wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: senderID, scope: scope},
		}
	}
	first := stateFor(epoch, 1)
	owner := new(wireReceiveOwner)
	release, committed := server.commitReceiveState(first, 1, scope, owner)
	if !committed || !server.acceptRecordForOwner(first, 1, owner) {
		t.Fatal("failed to activate initial receiver state")
	}
	var current *wireReceiveState
	for id := uint64(2); id <= wireReceiveOwnerHistoryLimit+1; id++ {
		current = stateFor(epoch, id)
		if !server.acceptRecordForOwner(current, 1, owner) {
			t.Fatalf("receiver history blocked transition %d", id)
		}
	}
	blocked := stateFor(epoch, wireReceiveOwnerHistoryLimit+2)
	if server.acceptRecordForOwner(blocked, 1, owner) {
		t.Fatal("receiver history exceeded its bound")
	}
	server.mu.Lock()
	historyCount := len(owner.retired)
	stateCount := len(server.receivers)
	ownerState := owner.state
	server.mu.Unlock()
	if historyCount != wireReceiveOwnerHistoryLimit || stateCount != 1 || ownerState != current {
		t.Fatalf("bounded history entries=%d states=%d owner=%v", historyCount, stateCount, ownerState == current)
	}

	now = now.Add(2 * wireEpochDuration)
	newEpoch, ok := wireEpochAt(now)
	if !ok {
		t.Fatal("failed to advance wire epoch")
	}
	fresh := stateFor(newEpoch, wireReceiveOwnerHistoryLimit+3)
	if !server.acceptRecordForOwner(fresh, 1, owner) {
		t.Fatal("expired receiver history blocked progress")
	}
	server.mu.Lock()
	historyCount = len(owner.retired)
	stateCount = len(server.receivers)
	ownerState = owner.state
	server.mu.Unlock()
	if historyCount != 0 || stateCount != 1 || ownerState != fresh {
		t.Fatalf("expired history entries=%d states=%d owner=%v", historyCount, stateCount, ownerState == fresh)
	}
	server.receiverStateLimit = 2
	now = now.Add(-2 * wireEpochDuration)
	reopened := stateFor(epoch, 1)
	if server.acceptRecordForOwner(reopened, 1, owner) {
		t.Fatal("clock rollback reopened expired receiver history")
	}
	server.mu.Lock()
	historyCount = len(owner.retired)
	stateCount = len(server.receivers)
	ownerState = owner.state
	receiverEpoch := server.receiverEpoch
	server.mu.Unlock()
	if historyCount != 0 || stateCount != 1 || ownerState != fresh || receiverEpoch != newEpoch {
		t.Fatalf("rollback history entries=%d states=%d owner=%v epoch=%d", historyCount, stateCount, ownerState == fresh, receiverEpoch)
	}
	release()
}

func TestSecureWireReceiverReplayIsIsolatedByAdmittedEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		sourceA *net.UDPAddr
		sourceB *net.UDPAddr
	}{
		{
			name:    "same IPv4 different ports",
			sourceA: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 70), Port: 27001},
			sourceB: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 70), Port: 27101},
		},
		{
			name:    "same IPv6 prefix different addresses",
			sourceA: &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 27001},
			sourceB: &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2::2"), Port: 27001},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSecureWireReceiverReplayIsolation(t, tt.sourceA, tt.sourceB)
		})
	}
}

func testSecureWireReceiverReplayIsolation(t *testing.T, sourceA, sourceB *net.UDPAddr) {
	secret := bytes.Repeat([]byte{0x60}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 8
	server.receiverSourceLimit = 2
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x70}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	handshake := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	newClient := func(seed byte) *wireCodec {
		client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{seed}, 256)))
		if err != nil {
			t.Fatal(err)
		}
		client.now = func() time.Time { return now }
		t.Cleanup(client.Close)
		return client
	}
	retryResponse := func(client *wireCodec, source *net.UDPAddr, high bool) []byte {
		first, ok := client.seal(handshake, wireDirectionClient)
		if !ok {
			t.Fatal("client failed to seal initial packet")
		}
		challengeDecision := gate.EvaluateNewSession(first, source)
		challenge, ok := client.open(challengeDecision.Reply, wireDirectionServer)
		if !ok {
			t.Fatal("client failed to open Retry")
		}
		response, ok := buildRetryResponse(challenge, handshake)
		if !ok {
			t.Fatal("client failed to build Retry response")
		}
		if high {
			client.mu.Lock()
			client.senders[wireDirectionClient].sequence = wireRecordsPerKey - 1
			client.mu.Unlock()
		}
		packet, ok := client.seal(response, wireDirectionClient)
		if !ok {
			t.Fatal("client failed to seal Retry response")
		}
		return packet
	}
	commit := func(client *wireCodec, source *net.UDPAddr, high bool) ([]byte, *wireReceiveOwner, func()) {
		packet := retryResponse(client, source, high)
		decision := gate.EvaluateNewSession(packet, source)
		if !decision.Admit || decision.Commit == nil {
			t.Fatal("Retry response did not reach admission")
		}
		release, ok := decision.Commit()
		if !ok {
			t.Fatal("Retry response receiver state was not committed")
		}
		owner, ok := decision.State.(*wireReceiveOwner)
		if !ok {
			t.Fatal("Retry response did not retain a receiver owner")
		}
		scope := wireReceiveScopeFromAddr(source, server.receiverIPv6PrefixBits)
		if _, ok := server.openInPlaceFromOwner(append([]byte(nil), decision.Payload...), wireDirectionClient, scope, owner); !ok {
			t.Fatal("committed Retry response was not consumed")
		}
		return packet, owner, release
	}

	victim := newClient(0x80)
	otherSource := newClient(0x80)
	victimResponse, victimOwner, releaseVictim := commit(victim, sourceA, false)
	otherResponse, otherOwner, releaseOther := commit(otherSource, sourceB, true)

	victimSender := decodeWireSenderID(server.root[:], victimResponse[:wireHeaderSize])
	otherSender := decodeWireSenderID(server.root[:], otherResponse[:wireHeaderSize])
	if victimSender != otherSender {
		t.Fatal("test clients did not use the same sender identity")
	}
	victimNext, ok := victim.seal([]byte("victim progress"), wireDirectionClient)
	if !ok {
		t.Fatal("victim failed to seal its next record")
	}
	victimReplay := append([]byte(nil), victimNext...)
	scopeA := wireReceiveScopeFromAddr(sourceA, server.receiverIPv6PrefixBits)
	scopeB := wireReceiveScopeFromAddr(sourceB, server.receiverIPv6PrefixBits)
	if scopeA.source != scopeB.source || scopeA.endpoint == scopeB.endpoint {
		t.Fatal("test endpoints did not share one source bucket with distinct endpoints")
	}
	if plain, ok := server.openInPlaceFromOwner(victimNext, wireDirectionClient, scopeA, victimOwner); !ok || !bytes.Equal(plain, []byte("victim progress")) {
		t.Fatal("other endpoint advanced the victim replay window")
	}
	if _, ok := server.openInPlaceFromOwner(victimReplay, wireDirectionClient, scopeA, victimOwner); ok {
		t.Fatal("victim endpoint accepted the same record twice")
	}
	if _, ok := server.openInPlaceFromOwner(append([]byte(nil), otherResponse...), wireDirectionClient, scopeB, otherOwner); ok {
		t.Fatal("other endpoint accepted the same high record twice")
	}

	epoch, ok := wireEpochAt(now)
	if !ok {
		t.Fatal("failed to determine wire epoch")
	}
	victimKey := wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: victimSender, scope: scopeA}
	otherKey := wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: otherSender, scope: scopeB}
	server.mu.Lock()
	victimState := server.receivers[victimKey]
	otherState := server.receivers[otherKey]
	sourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{direction: wireDirectionClient, epoch: epoch, source: scopeA.source}]
	owners := 0
	for _, state := range server.receivers {
		owners += state.owners
	}
	states := len(server.receivers)
	victimHighest := uint64(0)
	otherHighest := uint64(0)
	if victimState != nil {
		victimHighest = victimState.replay.highest
	}
	if otherState != nil {
		otherHighest = otherState.replay.highest
	}
	server.mu.Unlock()
	if victimState == nil || otherState == nil || victimState == otherState || sourceCount != 2 || states != 2 || owners != 2 || victimHighest != 3 || otherHighest != uint64(wireRecordsPerKey) {
		t.Fatalf("isolated receiver accounting source=%d states=%d owners=%d victim=%d other=%d", sourceCount, states, owners, victimHighest, otherHighest)
	}

	releaseVictim()
	releaseVictim()
	releaseOther()
	server.mu.Lock()
	owners = 0
	for _, state := range server.receivers {
		owners += state.owners
	}
	activeOwners := len(server.receiverOwners)
	server.mu.Unlock()
	if owners != 0 || activeOwners != 0 {
		t.Fatalf("receiver releases retained owners=%d active=%d", owners, activeOwners)
	}
	gate.Close()
	server.mu.Lock()
	states = len(server.receivers)
	owners = len(server.receiverOwners)
	sourceCounts := len(server.receiverSourceCounts)
	server.mu.Unlock()
	if states != 0 || owners != 0 || sourceCounts != 0 {
		t.Fatalf("closed receiver accounting states=%d owners=%d sources=%d", states, owners, sourceCounts)
	}
}

func TestSecureWireAdmissionCommitRejectsInvalidTagAndExpiredEpoch(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5d}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0).Truncate(wireEpochDuration).Add(time.Minute)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	gate, err := newRetryCookieGateWithWire(
		1500,
		bytes.NewReader(bytes.Repeat([]byte{0x6d}, retryCookieKeySize)),
		func() time.Time { return now },
		server,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	source := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 40), Port: 24001}
	response := secureRetryResponseAt(t, secret, gate, now, source, 0x7d)
	tampered := append([]byte(nil), response...)
	tampered[len(tampered)-1] ^= 1
	if decision := gate.EvaluateNewSession(tampered, source); decision.Admit || decision.Commit != nil {
		t.Fatal("invalid tag reached receiver-state commit")
	}
	decision := gate.EvaluateNewSession(response, source)
	if !decision.Admit || decision.Commit == nil {
		t.Fatal("valid Retry response did not reach admission")
	}
	server.mu.Lock()
	statesBefore := len(server.receivers)
	server.mu.Unlock()
	if statesBefore != 0 {
		t.Fatalf("pre-admission receiver states = %d, want 0", statesBefore)
	}
	now = now.Add(2 * wireEpochDuration)
	if release, committed := decision.Commit(); committed {
		if release != nil {
			release()
		}
		t.Fatal("expired epoch receiver state was committed")
	}
	server.mu.Lock()
	statesAfter := len(server.receivers)
	countsAfter := len(server.receiverCounts)
	sourcesAfter := len(server.receiverSourceCounts)
	server.mu.Unlock()
	if statesAfter != 0 || countsAfter != 0 || sourcesAfter != 0 {
		t.Fatalf("expired commit retained states=%d counts=%d sources=%d", statesAfter, countsAfter, sourcesAfter)
	}
}

func TestSecureWireConcurrentFirstRecordIsAcceptedOnce(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	server.now = func() time.Time { return now }
	packet, ok := client.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal")
	}

	const readers = 32
	start := make(chan struct{})
	results := make(chan bool, readers)
	for range readers {
		go func() {
			<-start
			_, accepted := server.open(packet, wireDirectionClient)
			results <- accepted
		}()
	}
	close(start)
	accepted := 0
	for range readers {
		if <-results {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent first record accepted %d times, want 1", accepted)
	}
	server.mu.Lock()
	states := len(server.receivers)
	server.mu.Unlock()
	if states != 1 {
		t.Fatalf("concurrent first record retained %d receiver states, want 1", states)
	}
}

func TestSecureWireAuthenticationAttemptLimitIsPerSender(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	newClient := func(fill byte) *wireCodec {
		codec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
		if err != nil {
			t.Fatal(err)
		}
		codec.now = func() time.Time { return now }
		return codec
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	firstPacket, ok := newClient(0x31).seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("first client failed to seal")
	}
	secondPacket, ok := newClient(0x32).seal([]byte("second"), wireDirectionClient)
	if !ok {
		t.Fatal("second client failed to seal")
	}

	firstSender := decodeWireSenderID(server.root[:], firstPacket[:wireHeaderSize])
	epoch, _ := decodeWireRecord(server.root[:], firstPacket[:wireHeaderSize])
	server.mu.Lock()
	state, ok := server.receiveStateLocked(wireDirectionClient, epoch, firstSender)
	if ok {
		state.attempts = wireAttemptsPerKey
	}
	server.mu.Unlock()
	if !ok {
		t.Fatal("server failed to create first receiver state")
	}
	if _, ok := server.open(firstPacket, wireDirectionClient); ok {
		t.Fatal("server accepted a record after its sender exhausted the limit")
	}
	if plain, ok := server.open(secondPacket, wireDirectionClient); !ok || string(plain) != "second" {
		t.Fatal("one sender's attempt limit blocked another sender")
	}
}

func TestSecureWireRotatesReceiverStateCacheAtCapacity(t *testing.T) {
	codec, err := newWireCodec(WireProfileSecure, bytes.Repeat([]byte{0x2a}, minimumWireSecretSize), testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	epoch, ok := wireEpochAt(codec.now())
	if !ok {
		t.Fatal("failed to determine wire epoch")
	}
	codec.mu.Lock()
	for i := 0; i < wireReceiveStateLimit; i++ {
		var senderID [wireSenderIDSize]byte
		binary.BigEndian.PutUint32(senderID[:], uint32(i+1))
		if _, ok := codec.receiveStateLocked(wireDirectionClient, epoch, senderID); !ok {
			codec.mu.Unlock()
			t.Fatal("failed to create receiver state")
		}
	}
	states := len(codec.receivers)
	var extra [wireSenderIDSize]byte
	binary.BigEndian.PutUint32(extra[:], wireReceiveStateLimit+1)
	extraState, accepted := codec.receiveStateLocked(wireDirectionClient, epoch, extra)
	var first [wireSenderIDSize]byte
	binary.BigEndian.PutUint32(first[:], 1)
	_, retainedFirst := codec.receivers[wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: first}]
	retainedExtra := codec.receivers[wireReceiveKey{direction: wireDirectionClient, epoch: epoch, senderID: extra}] == extraState
	statesAfter := len(codec.receivers)
	codec.mu.Unlock()
	if states != wireReceiveStateLimit {
		t.Fatalf("receiver states = %d, want %d", states, wireReceiveStateLimit)
	}
	if !accepted || retainedFirst || !retainedExtra || statesAfter != wireReceiveStateLimit {
		t.Fatal("receiver state cache did not rotate exactly at capacity")
	}
}

func TestSecureWireReceiverCapacityPreservesNewSourceProgress(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	server.receiverStateLimit = 4
	server.receiverSourceLimit = 2
	server.limitReceiverStatesBySource(0)

	packet := func(fill byte) []byte {
		client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{fill}, 64)))
		if err != nil {
			t.Fatal(err)
		}
		client.now = func() time.Time { return now }
		sealed, ok := client.seal([]byte{fill}, wireDirectionClient)
		if !ok {
			t.Fatal("client failed to seal")
		}
		return sealed
	}
	sourceA := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, 0)
	sourceB := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2)}, 0)
	sourceC := handshakeSourceKeyFromAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 3)}, 0)
	for i, source := range []handshakeSourceKey{sourceA, sourceA, sourceB, sourceB} {
		sealed := packet(byte(i + 1))
		if _, ok := server.openInPlaceFrom(sealed, wireDirectionClient, wireReceiveScope{source: source}); !ok {
			t.Fatal("server failed to fill receiver capacity")
		}
	}
	invalid := packet(5)
	invalid[len(invalid)-1] ^= 1
	if _, ok := server.openInPlaceFrom(invalid, wireDirectionClient, wireReceiveScope{source: sourceC}); ok {
		t.Fatal("server accepted an invalid tag at receiver capacity")
	}
	server.mu.Lock()
	invalidStates := len(server.receivers)
	server.mu.Unlock()
	if invalidStates != 4 {
		t.Fatal("invalid tag changed receiver capacity")
	}
	sealed := packet(6)
	if plain, ok := server.openInPlaceFrom(sealed, wireDirectionClient, wireReceiveScope{source: sourceC}); !ok || !bytes.Equal(plain, []byte{6}) {
		t.Fatal("full receiver capacity blocked a new source")
	}
	server.mu.Lock()
	epoch, _ := wireEpochAt(now)
	count := server.receiverCounts[wireReceiveEpochKey{direction: wireDirectionClient, epoch: epoch}]
	sourceCount := server.receiverSourceCounts[wireReceiveSourceEpochKey{
		direction: wireDirectionClient,
		epoch:     epoch,
		source:    sourceC,
	}]
	states := len(server.receivers)
	server.mu.Unlock()
	if count != 4 || sourceCount != 1 || states != 4 {
		t.Fatalf("rotated accounting states=%d count=%d source=%d", states, count, sourceCount)
	}
}

func TestSecureWireReceiverStateLimitIsPerEpoch(t *testing.T) {
	codec, err := newWireCodec(WireProfileSecure, bytes.Repeat([]byte{0x2a}, minimumWireSecretSize), testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	epoch, ok := wireEpochAt(codec.now())
	if !ok || epoch == 0 {
		t.Fatal("failed to determine wire epoch")
	}

	codec.mu.Lock()
	defer codec.mu.Unlock()
	for i := 0; i < wireReceiveStateLimit; i++ {
		var senderID [wireSenderIDSize]byte
		binary.BigEndian.PutUint32(senderID[:], uint32(i+1))
		if _, ok := codec.receiveStateLocked(wireDirectionClient, epoch-1, senderID); !ok {
			t.Fatal("failed to fill previous epoch receiver states")
		}
	}
	var senderID [wireSenderIDSize]byte
	binary.BigEndian.PutUint32(senderID[:], wireReceiveStateLimit+1)
	if _, ok := codec.receiveStateLocked(wireDirectionClient, epoch, senderID); !ok {
		t.Fatal("previous epoch receiver states blocked the current epoch")
	}
}

func TestSecureWirePurgesReceiverStateAfterEpochChange(t *testing.T) {
	secret := bytes.Repeat([]byte{0x2a}, minimumWireSecretSize)
	now := time.Unix(1_800_000_000, 0)
	initialNow := now
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.limitReceiverStatesBySource(0)
	client.now = func() time.Time { return now }
	server.now = func() time.Time { return now }
	first, ok := client.seal([]byte("first"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal first record")
	}
	if _, ok := server.open(first, wireDirectionClient); !ok {
		t.Fatal("server failed to open first record")
	}
	firstSender := decodeWireSenderID(server.root[:], first[:wireHeaderSize])
	firstEpoch, _ := decodeWireRecord(server.root[:], first[:wireHeaderSize])
	firstKey := wireReceiveKey{direction: wireDirectionClient, epoch: firstEpoch, senderID: firstSender}
	firstSourceKey := wireReceiveSourceEpochKey{direction: wireDirectionClient, epoch: firstEpoch}

	now = now.Add(2 * wireEpochDuration)
	second, ok := client.seal([]byte("second"), wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal second record")
	}
	if _, ok := server.open(second, wireDirectionClient); !ok {
		t.Fatal("server failed to open second record")
	}
	server.mu.Lock()
	_, retained := server.receivers[firstKey]
	_, retainedSource := server.receiverSourceCounts[firstSourceKey]
	server.mu.Unlock()
	if retained {
		t.Fatal("server retained receiver state outside the epoch window")
	}
	if retainedSource {
		t.Fatal("server retained receiver source count outside the epoch window")
	}
	secondSender := decodeWireSenderID(server.root[:], second[:wireHeaderSize])
	secondEpoch, _ := decodeWireRecord(server.root[:], second[:wireHeaderSize])
	secondKey := wireReceiveKey{direction: wireDirectionClient, epoch: secondEpoch, senderID: secondSender}
	now = initialNow
	if _, ok := server.open(append([]byte(nil), first...), wireDirectionClient); ok {
		t.Fatal("clock rollback reopened an expired replay window")
	}
	var staleSender [wireSenderIDSize]byte
	binary.BigEndian.PutUint64(staleSender[wireSenderIDSize-8:], 1)
	stale := &wireReceiveState{key: wireReceiveKey{direction: wireDirectionClient, epoch: firstEpoch, senderID: staleSender}}
	if server.canAcceptRecord(stale, 1) {
		t.Fatal("clock rollback made stale provisional state acceptable")
	}
	if _, committed := server.commitReceiveState(stale, 1, wireReceiveScope{}, new(wireReceiveOwner)); committed {
		t.Fatal("clock rollback committed stale receiver state")
	}
	server.mu.Lock()
	_, retainedSecond := server.receivers[secondKey]
	states := len(server.receivers)
	counts := len(server.receiverCounts)
	queues := len(server.receiverQueues)
	attempts := len(server.receiverAttempts)
	sources := len(server.receiverSourceCounts)
	owners := len(server.receiverOwners)
	receiverEpoch := server.receiverEpoch
	server.mu.Unlock()
	if !retainedSecond || states != 1 || counts != 1 || queues != 1 || attempts != 1 || sources != 1 || owners != 0 || receiverEpoch != secondEpoch {
		t.Fatalf("rollback accounting retained=%v states=%d counts=%d queues=%d attempts=%d sources=%d owners=%d epoch=%d", retainedSecond, states, counts, queues, attempts, sources, owners, receiverEpoch)
	}
}

func TestSecureWireBatchConnRoundTripsWithoutPlaintextMarkers(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, minimumWireSecretSize)
	clientCodec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverCodec, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	inner := testHandshakeStartPacket(append([]byte(TunnelTLSALPN), handshakeAuthMagic[:]...))
	sender := &scriptedBatchConn{}
	client := newWireBatchConn(sender, clientCodec, udptlsModeClient)
	if n, err := client.WriteBatch(context.Background(), [][]byte{inner}, []int{len(inner)}); err != nil || n != 1 {
		t.Fatalf("secure write = %d, %v", n, err)
	}
	wirePacket := sender.snapshotWrites()[0]
	if len(wirePacket) != len(inner)+wireEnvelopeOverhead {
		t.Fatalf("wire packet size = %d, want %d", len(wirePacket), len(inner)+wireEnvelopeOverhead)
	}
	for _, marker := range [][]byte{handshakeAuthMagic[:], []byte(TunnelTLSALPN)} {
		if bytes.Contains(wirePacket, marker) {
			t.Fatalf("secure packet exposed marker %q", marker)
		}
	}

	receiver := &scriptedBatchConn{reads: [][][]byte{{wirePacket}}}
	server := newWireBatchConn(receiver, serverCodec, udptlsModeServer)
	buf := make([]byte, len(inner))
	sizes := []int{0}
	n, err := server.ReadBatch(context.Background(), [][]byte{buf}, sizes)
	if err != nil || n != 1 || !bytes.Equal(buf[:sizes[0]], inner) {
		t.Fatalf("secure read = %d, %v, %x", n, err, buf[:sizes[0]])
	}
}

func TestRetryCookieKeyIsListenerLocalAndClearedOnClose(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	newGate := func(fill byte) *retryCookieGate {
		gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{fill}, retryCookieKeySize)), func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		return gate
	}
	first := newGate(0x31)
	second := newGate(0x32)
	t.Cleanup(second.Close)

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 21), Port: 20002}
	packet := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	challenge := first.EvaluateNewSession(packet, addr).Reply
	response, ok := buildRetryResponse(challenge, packet)
	if !ok {
		t.Fatal("failed to build retry response")
	}
	if second.EvaluateNewSession(response, addr).Admit {
		t.Fatal("cookie from another listener key was admitted")
	}

	first.Close()
	first.mu.RLock()
	defer first.mu.RUnlock()
	for i, b := range first.key {
		if b != 0 {
			t.Fatalf("closed listener key byte %d = %x, want 0", i, b)
		}
	}
	if !first.closed {
		t.Fatal("cookie gate was not marked closed")
	}
}

func TestRetryGateCloseClearsWireCodec(t *testing.T) {
	wire, err := newWireCodec(WireProfileSecure, bytes.Repeat([]byte{0x33}, minimumWireSecretSize), testWireIdentity, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := newRetryCookieGateWithWire(1500, bytes.NewReader(bytes.Repeat([]byte{0x34}, retryCookieKeySize)), time.Now, wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wire.seal([]byte("record"), wireDirectionServer); !ok {
		t.Fatal("wire codec failed before close")
	}
	gate.Close()
	wire.mu.Lock()
	closed := wire.closed
	root := wire.root
	states := len(wire.senders) + len(wire.receivers)
	wire.mu.Unlock()
	if !closed {
		t.Fatal("wire codec was not closed")
	}
	for i, value := range root {
		if value != 0 {
			t.Fatalf("wire root byte %d = %x, want 0", i, value)
		}
	}
	if states != 0 {
		t.Fatal("wire codec retained derived state")
	}
	if _, ok := wire.seal([]byte("after close"), wireDirectionServer); ok {
		t.Fatal("closed wire codec sealed another record")
	}
}

func TestRetryClientConnAnswersChallengeAfterUntrustedInputAndHidesIt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x22}, retryCookieKeySize)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 30), Port: 20003}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	challenge := gate.EvaluateNewSession(firstPacket, addr).Reply
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	authenticatedAck, ok := sealHandshakeAuthPacket(
		ack,
		challenge[retryFrameBindingOffset:retryFrameTagOffset],
		challenge[retryFrameTagOffset:retryChallengeSize],
		handshakeAuthDirectionServer,
		1500,
	)
	if !ok {
		t.Fatal("failed to authenticate ACK")
	}
	inner := &scriptedBatchConn{reads: [][][]byte{{ack}, {challenge, ack}, {authenticatedAck}}}
	conn := newRetryClientConn(inner, 1500)

	if n, err := conn.WriteBatch(context.Background(), [][]byte{firstPacket}, []int{len(firstPacket)}); err != nil || n != 1 {
		t.Fatalf("write first packet: n=%d err=%v", n, err)
	}
	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	n, err := conn.ReadBatch(context.Background(), bufs, sizes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !bytes.Equal(bufs[0][:sizes[0]], ack) {
		t.Fatalf("visible packets = %d first=%x, want one authenticated ACK", n, bufs[0][:sizes[0]])
	}

	writes := inner.snapshotWrites()
	if len(writes) != 2 {
		t.Fatalf("writes = %d, want initial packet and retry response", len(writes))
	}
	decision := gate.EvaluateNewSession(writes[1], addr)
	if !decision.Admit || !bytes.Equal(decision.Payload, writes[1]) {
		t.Fatal("client retry response was not accepted by the server gate")
	}
}

func TestRetryClientConnWriteStateSurvivesClear(t *testing.T) {
	conn := &retryClientConn{
		firstPacket:   []byte{1, 2},
		retryResponse: []byte{3, 4},
		authReady:     true,
	}
	firstPacket, retryResponse, _, _, authReady := conn.writeState()
	conn.clearRetryState()
	if !authReady || !bytes.Equal(firstPacket, []byte{1, 2}) || !bytes.Equal(retryResponse, []byte{3, 4}) {
		t.Fatalf("write state changed after clear: first=%v retry=%v ready=%v", firstPacket, retryResponse, authReady)
	}
}

func TestRetryClientConnChallengeBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 31), Port: 20004}
	firstPacket := testHandshakeStartPacket([]byte("current client hello fragment with enough bytes to avoid amplification"))
	otherPacket := testHandshakeStartPacket([]byte("another client hello fragment with enough bytes to avoid amplification"))

	tests := []struct {
		name               string
		challenges         func(valid, other []byte) [][]byte
		wantResponses      int
		wantChallengeCount int
		wantResponseCount  int
		wantErr            error
	}{
		{
			name: "unbound challenges do not consume budget",
			challenges: func(valid, other []byte) [][]byte {
				challenges := make([][]byte, 0, maxRetryResponsesPerHandshake+1)
				for range maxRetryResponsesPerHandshake {
					challenges = append(challenges, other)
				}
				return append(challenges, valid)
			},
			wantResponses:      1,
			wantChallengeCount: 1,
			wantResponseCount:  1,
		},
		{
			name: "interleaved duplicates reach total response limit",
			challenges: func(valid, _ []byte) [][]byte {
				second := append([]byte(nil), valid...)
				second[retryFrameTagOffset] ^= 0x01
				challenges := make([][]byte, maxRetryResponsesPerHandshake+2)
				for i := range challenges {
					if i%2 == 0 {
						challenges[i] = valid
					} else {
						challenges[i] = second
					}
				}
				return challenges
			},
			wantResponses:      maxRetryResponsesPerHandshake,
			wantChallengeCount: 2,
			wantResponseCount:  maxRetryResponsesPerHandshake,
			wantErr:            errRetryResponseLimit,
		},
		{
			name: "distinct bound challenges fail at limit",
			challenges: func(valid, _ []byte) [][]byte {
				challenges := make([][]byte, maxRetryChallengesPerHandshake+1)
				for i := range challenges {
					challenges[i] = append([]byte(nil), valid...)
					challenges[i][retryFrameTagOffset] ^= byte(i)
				}
				return challenges
			},
			wantResponses:      maxRetryChallengesPerHandshake,
			wantChallengeCount: maxRetryChallengesPerHandshake,
			wantResponseCount:  maxRetryChallengesPerHandshake,
			wantErr:            errRetryChallengeLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x23}, retryCookieKeySize)), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(gate.Close)
			valid := gate.EvaluateNewSession(firstPacket, addr).Reply
			other := gate.EvaluateNewSession(otherPacket, addr).Reply
			conn := newRetryClientConn(&scriptedBatchConn{}, 1500)
			conn.rememberFirstPacket(firstPacket)

			responses := 0
			var responseErr error
			for _, challenge := range tt.challenges(valid, other) {
				response, err := conn.responseForChallenge(challenge)
				if err != nil {
					responseErr = err
					break
				}
				if len(response) > 0 {
					responses++
				}
			}
			if responses != tt.wantResponses {
				t.Fatalf("responses = %d, want %d", responses, tt.wantResponses)
			}
			if conn.retryChallengeCount != tt.wantChallengeCount {
				t.Fatalf("retry challenges = %d, want %d", conn.retryChallengeCount, tt.wantChallengeCount)
			}
			if conn.retryResponses != tt.wantResponseCount {
				t.Fatalf("retry responses = %d, want %d", conn.retryResponses, tt.wantResponseCount)
			}
			if !errors.Is(responseErr, tt.wantErr) {
				t.Fatalf("limit error = %v, want %v", responseErr, tt.wantErr)
			}
		})
	}
}

func FuzzRetryCookieGate(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x41}, retryCookieKeySize)), func() time.Time { return now })
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(gate.Close)

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 40), Port: 20004}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	challenge := gate.EvaluateNewSession(firstPacket, addr).Reply
	response, ok := buildRetryResponse(challenge, firstPacket)
	if !ok {
		f.Fatal("failed to build retry response seed")
	}
	f.Add([]byte("malformed"), uint16(20004))
	f.Add(firstPacket, uint16(20004))
	f.Add(response, uint16(20004))

	f.Fuzz(func(t *testing.T, packet []byte, port uint16) {
		remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 40), Port: int(port)}
		decision := gate.EvaluateNewSession(packet, remote)
		if len(decision.Reply) > len(packet) {
			t.Fatalf("reply amplified input: reply=%d input=%d", len(decision.Reply), len(packet))
		}
		if decision.Admit {
			_, _, _, inner, ok := parseRetryResponse(decision.Payload)
			if !ok || !validHandshakeStartPacket(inner) {
				t.Fatalf("gate admitted invalid retry response: %x", decision.Payload)
			}
		}
	})
}

func testHandshakeStartPacket(payload []byte) []byte {
	pkt := make([]byte, handshakeDataHeaderSize+len(payload))
	pkt[0] = handshakePacketTypeData
	pkt[1] = handshakePacketVersion
	binary.LittleEndian.PutUint32(pkt[18:22], uint32(len(payload)))
	copy(pkt[handshakeDataHeaderSize:], payload)
	return pkt
}

func secureRetryResponseAt(t *testing.T, secret []byte, gate *retryCookieGate, now time.Time, source *net.UDPAddr, seed byte) []byte {
	t.Helper()
	client, err := newWireCodec(WireProfileSecure, secret, testWireIdentity, bytes.NewReader(bytes.Repeat([]byte{seed}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	handshake := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to avoid amplification"))
	first, ok := client.seal(handshake, wireDirectionClient)
	if !ok {
		t.Fatal("client failed to seal initial packet")
	}
	challenge, ok := client.open(gate.EvaluateNewSession(first, source).Reply, wireDirectionServer)
	if !ok {
		t.Fatal("client failed to open Retry")
	}
	response, ok := buildRetryResponse(challenge, handshake)
	if !ok {
		t.Fatal("client failed to build Retry response")
	}
	packet, ok := client.seal(response, wireDirectionClient)
	client.Close()
	if !ok {
		t.Fatal("client failed to seal Retry response")
	}
	return packet
}

type scriptedBatchConn struct {
	mu              sync.Mutex
	reads           [][][]byte
	writes          [][]byte
	readBatchWidths []int
	closed          bool
	remoteAddr      net.Addr
	activeMarks     int
}

func (c *scriptedBatchConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *scriptedBatchConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil || n == 0 {
		return 0, err
	}
	return len(p), nil
}

func (c *scriptedBatchConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (*scriptedBatchConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *scriptedBatchConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return &net.UDPAddr{}
}
func (*scriptedBatchConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedBatchConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedBatchConn) SetWriteDeadline(time.Time) error { return nil }
func (*scriptedBatchConn) BatchSize() int                   { return 8 }

func (c *scriptedBatchConn) MarkActive() {
	c.mu.Lock()
	c.activeMarks++
	c.mu.Unlock()
}

func (c *scriptedBatchConn) snapshotActiveMarks() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeMarks
}

func (c *scriptedBatchConn) ReadBatch(_ context.Context, bufs [][]byte, sizes []int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readBatchWidths = append(c.readBatchWidths, len(bufs))
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	batch := c.reads[0]
	c.reads = c.reads[1:]
	n := len(batch)
	if n > len(bufs) {
		n = len(bufs)
	}
	if n > len(sizes) {
		n = len(sizes)
	}
	for i := 0; i < n; i++ {
		copy(bufs[i], batch[i])
		sizes[i] = len(batch[i])
	}
	return n, nil
}

func (c *scriptedBatchConn) WriteBatch(_ context.Context, bufs [][]byte, sizes []int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(bufs)
	if n > len(sizes) {
		n = len(sizes)
	}
	for i := 0; i < n; i++ {
		c.writes = append(c.writes, append([]byte(nil), bufs[i][:sizes[i]]...))
	}
	return n, nil
}

func (c *scriptedBatchConn) snapshotWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	writes := make([][]byte, len(c.writes))
	for i := range c.writes {
		writes[i] = append([]byte(nil), c.writes[i]...)
	}
	return writes
}

func (c *scriptedBatchConn) snapshotReadBatchWidths() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.readBatchWidths...)
}
