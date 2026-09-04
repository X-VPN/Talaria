// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestTalariaTCPWireFormatGolden(t *testing.T) {
	key, err := newWireKey(testTalariaTCPWireSecret, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key[:]); got != "09cb33e6980379bae5713b5d101ae4c59040fe4537b4d4c9cd609b276ff72b51" {
		t.Fatalf("wire key = %s", got)
	}

	nonce := make([]byte, wirePreambleNonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	if got := hex.EncodeToString(wirePreambleTag(key, nonce)); got != "1c942983b6e74d3cc8d142d3f2828c2c" {
		t.Fatalf("preamble tag = %s", got)
	}
	if got := fmt.Sprintf("%016x", wirePreambleTimeMask(key, nonce[:wirePreambleRandomSize])); got != "60cbf0e8d7e9a9d1" {
		t.Fatalf("time mask = %s", got)
	}

	clientToServer, serverToClient := wireStreams(key, nonce, wireRoleClient)
	c2s := make([]byte, 32)
	s2c := make([]byte, 32)
	clientToServer.XORKeyStream(c2s, c2s)
	serverToClient.XORKeyStream(s2c, s2c)
	if got := hex.EncodeToString(c2s); got != "2be529aed20d3954734cf45c9b487908358a78620c74ef2f5f1815dfa62edf54" {
		t.Fatalf("client-to-server stream = %s", got)
	}
	if got := hex.EncodeToString(s2c); got != "16ce5240655d9cabd41c33fbb093d2a6ac2cc0ff53b060052682053fd6a87efa" {
		t.Fatalf("server-to-client stream = %s", got)
	}
}

func TestTalariaTCPHidesTLSProtocolSignature(t *testing.T) {
	prefix := captureClientWirePrefix(t)
	if hasTLSRecordHeader(prefix) {
		t.Fatalf("raw TLS record header is visible; prefix=%x", prefix[:5])
	}
}

func TestTalariaTCPWireUsesRandomPreambleAndTransformsEntireStream(t *testing.T) {
	key := testWireKey(t)
	payload := make([]byte, oldObfuscationBoundary+64)
	copy(payload, []byte{0x16, 0x03, 0x03, 0, 42})
	copy(payload[oldObfuscationBoundary:], []byte{0x16, 0x03, 0x03, 0, 42})
	seen := make(map[string]struct{})
	for range 16 {
		raw := newWireWriteCaptureConn()
		wrapped := wrapClientWire(raw, key)
		if n, err := wrapped.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("write = %d, %v", n, err)
		}
		obfuscated := wrapped
		obfuscated.keyMu.Lock()
		retainedKey := obfuscated.key != nil
		obfuscated.keyMu.Unlock()
		if retainedKey {
			t.Fatal("connection retained its wire key after initialization")
		}
		if len(raw.wire) != wirePreambleSize+len(payload) {
			t.Fatalf("captured bytes = %d, want %d", len(raw.wire), wirePreambleSize+len(payload))
		}
		prefix := string(raw.wire[:wirePreambleSize])
		if _, duplicate := seen[prefix]; duplicate {
			t.Fatalf("reused TalariaTCP preamble: %x", raw.wire[:wirePreambleSize])
		}
		seen[prefix] = struct{}{}
		if hasTLSRecordHeader(raw.wire[wirePreambleSize:]) {
			t.Fatal("TLS record header remained visible after TalariaTCP preamble")
		}
		nonce := raw.wire[:wirePreambleNonceSize]
		sentAt := decodeWirePreambleTime(key, nonce)
		if age := time.Since(sentAt); age < 0 || age > 2*time.Second {
			t.Fatalf("decoded preamble time age = %s", age)
		}
		if binary.BigEndian.Uint64(nonce[wirePreambleRandomSize:]) == uint64(sentAt.Unix()) {
			t.Fatal("TalariaTCP preamble exposed its timestamp")
		}
		boundaryWire := raw.wire[wirePreambleSize+oldObfuscationBoundary:]
		if bytes.Equal(boundaryWire[:32], payload[oldObfuscationBoundary:oldObfuscationBoundary+32]) {
			t.Fatal("TalariaTCP stopped transforming at the old 256 KiB boundary")
		}
	}
}

func TestTalariaTCPWireOwnersClearKeysOnClose(t *testing.T) {
	clientKey := testWireKey(t)
	client := &Client{wireKey: clientKey, lifetimeCancel: func() {}}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if client.wireKey != nil {
		t.Fatal("client retained its wire key")
	}
	for i, value := range clientKey {
		if value != 0 {
			t.Fatalf("client wire key byte %d = %x, want 0", i, value)
		}
	}

	serverKey := testWireKey(t)
	replay := newWireReplayCache(2, 1)
	now := time.Now()
	if !replay.accept(make([]byte, wirePreambleNonceSize), now, now, "source-a") {
		t.Fatal("failed to seed server replay cache")
	}
	server := &Server{wireKey: serverKey, wireReplay: replay, closed: make(chan struct{})}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if server.wireKey != nil {
		t.Fatal("server retained its wire key")
	}
	for i, value := range serverKey {
		if value != 0 {
			t.Fatalf("server wire key byte %d = %x, want 0", i, value)
		}
	}
	if len(replay.entries) != 0 || len(replay.bySource) != 0 || len(replay.slots) != 0 || len(replay.free) != 0 || replay.head != -1 || replay.tail != -1 {
		t.Fatal("server retained replay state")
	}
	if replay.accept(make([]byte, wirePreambleNonceSize), now, now, "source-a") {
		t.Fatal("closed server replay cache accepted a preamble")
	}
}

func TestTalariaTCPWireRejectsUnauthenticatedProbeWithoutResponse(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	server := wrapServerWire(serverRaw, testWireKey(t), newWireReplayCache(1, 1), "source-a", time.Now)
	readResult := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		readResult <- err
	}()
	if _, err := clientRaw.Write(make([]byte, wirePreambleSize)); err != nil {
		t.Fatal(err)
	}
	if err := <-readResult; !errors.Is(err, errInvalidWirePreamble) {
		t.Fatalf("server read error = %v, want %v", err, errInvalidWirePreamble)
	}
	if err := clientRaw.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := clientRaw.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("probe response = %d bytes, %v; want no response", n, err)
	}
}

func TestTalariaTCPWireRejectsReplayedPreamble(t *testing.T) {
	key := testWireKey(t)
	payload := []byte("client hello")
	captured := newWireWriteCaptureConn()
	if _, err := wrapClientWire(captured, key).Write(payload); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	replay := newWireReplayCache(8, 4)
	readCaptured := func() ([]byte, error) {
		server := wrapServerWire(newWireReadConn(captured.wire), key, replay, "source-a", func() time.Time { return now })
		plain := make([]byte, len(payload))
		_, err := io.ReadFull(server, plain)
		obfuscated := server
		obfuscated.keyMu.Lock()
		retainedKey := obfuscated.key != nil
		obfuscated.keyMu.Unlock()
		if retainedKey {
			t.Fatal("server connection retained its wire key after initialization")
		}
		return plain, err
	}
	plain, err := readCaptured()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("first payload = %q, want %q", plain, payload)
	}
	if _, err := readCaptured(); !errors.Is(err, errInvalidWirePreamble) {
		t.Fatalf("replayed preamble error = %v, want %v", err, errInvalidWirePreamble)
	}
}

func TestTalariaTCPWireBindsServerIdentity(t *testing.T) {
	clientKey := testWireKey(t)
	otherKey, err := newWireKey(testTalariaTCPWireSecret, "other.test")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("client hello")
	captured := newWireWriteCaptureConn()
	if _, err := wrapClientWire(captured, clientKey).Write(payload); err != nil {
		t.Fatal(err)
	}
	server := wrapServerWire(
		newWireReadConn(captured.wire),
		otherKey,
		newWireReplayCache(8, 4),
		"source-a",
		time.Now,
	)
	if _, err := io.ReadFull(server, make([]byte, len(payload))); !errors.Is(err, errInvalidWirePreamble) {
		t.Fatalf("cross-identity preamble error = %v, want %v", err, errInvalidWirePreamble)
	}
}

func TestWireReplayCacheRotatesAtCapacity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cache := newWireReplayCache(2, 1)
	first := testWireReplayNonce(1)
	if !cache.accept(first, now, now, "source-a") {
		t.Fatal("fresh preamble was rejected")
	}
	if cache.accept(first, now, now, "source-a") {
		t.Fatal("replayed preamble was accepted")
	}
	second := testWireReplayNonce(2)
	if !cache.accept(second, now, now, "source-a") {
		t.Fatal("source replay quota did not rotate")
	}
	third := testWireReplayNonce(3)
	if !cache.accept(third, now, now, "source-b") {
		t.Fatal("one source exhausted another source's replay quota")
	}
	fourth := testWireReplayNonce(4)
	if !cache.accept(fourth, now, now, "source-c") {
		t.Fatal("full replay cache rejected an unrelated source")
	}
	cache.mu.Lock()
	_, hasFirst := cache.entries[wireReplayKey(first)]
	_, hasSecond := cache.entries[wireReplayKey(second)]
	_, hasThird := cache.entries[wireReplayKey(third)]
	_, hasFourth := cache.entries[wireReplayKey(fourth)]
	cache.mu.Unlock()
	if hasFirst || hasSecond || !hasThird || !hasFourth {
		t.Fatalf("rotation retained first=%t second=%t third=%t fourth=%t", hasFirst, hasSecond, hasThird, hasFourth)
	}
	assertWireReplayAccounting(t, cache)
}

func TestTalariaTCPWireReplayRotationPreservesUnrelatedSourceCapacity(t *testing.T) {
	key := testWireKey(t)
	now := time.Unix(1_800_000_000, 0)
	cache := newWireReplayCache(4, 2)
	acceptPreamble := func(source string, marker uint64) []byte {
		preamble := testTalariaTCPPreamble(key, now, marker)
		server := wrapServerWire(
			newWireReadConn(preamble),
			key,
			cache,
			source,
			func() time.Time { return now },
		)
		if err := server.initializeServer(); err != nil {
			t.Fatalf("source %s preamble error = %v", source, err)
		}
		return preamble[:wirePreambleNonceSize]
	}
	marker := uint64(1)
	var healthy []byte
	for round := range 8 {
		for i := range 16 {
			acceptPreamble(fmt.Sprintf("attacker-%d", i), marker)
			marker++
		}
		healthy = acceptPreamble("healthy-principal", marker)
		marker++
		cache.mu.Lock()
		_, retained := cache.entries[wireReplayKey(healthy)]
		cache.mu.Unlock()
		if !retained {
			t.Fatalf("healthy principal lost capacity in round %d", round)
		}
	}
	cache.mu.Lock()
	_, retained := cache.entries[wireReplayKey(healthy)]
	entries := len(cache.entries)
	slots := len(cache.slots)
	cache.mu.Unlock()
	if !retained || entries != 4 || slots > 4 {
		t.Fatalf("healthy retained=%t entries=%d slots=%d, want true, 4, <=4", retained, entries, slots)
	}
	assertWireReplayAccounting(t, cache)
}

func TestWireReplayCacheUsesSymmetricWindowAndMonotonicClock(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := newWireReplayCache(8, 8)
	if !cache.accept(testWireReplayNonce(1), now.Add(-wirePreambleValidity), now, "past-boundary") {
		t.Fatal("past window boundary was rejected")
	}
	future := testWireReplayNonce(2)
	if !cache.accept(future, now.Add(wirePreambleValidity), now, "future-boundary") {
		t.Fatal("future window boundary was rejected")
	}
	if cache.accept(testWireReplayNonce(3), now.Add(-wirePreambleValidity-time.Nanosecond), now, "past-outside") {
		t.Fatal("timestamp before the past window was accepted")
	}
	if cache.accept(testWireReplayNonce(4), now.Add(wirePreambleValidity+time.Nanosecond), now, "future-outside") {
		t.Fatal("timestamp after the future window was accepted")
	}
	cache.mu.Lock()
	futureIndex := cache.entries[wireReplayKey(future)]
	retainedFor := cache.slots[futureIndex].expiresAt.Sub(now)
	cache.mu.Unlock()
	if retainedFor != 2*wirePreambleValidity {
		t.Fatalf("near-future preamble retention = %s, want %s", retainedFor, 2*wirePreambleValidity)
	}
	if cache.accept(testWireReplayNonce(5), now.Add(-10*time.Minute), now.Add(-10*time.Minute), "rollback") {
		t.Fatal("clock rollback reopened the stale window")
	}
	later := now.Add(3 * wirePreambleValidity)
	if !cache.accept(testWireReplayNonce(6), later, later, "after-expiry") {
		t.Fatal("forward clock movement did not reclaim expired entries")
	}
	cache.mu.Lock()
	remaining := len(cache.entries)
	cache.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("entries after expiry = %d, want 1", remaining)
	}
	if cache.accept(testWireReplayNonce(7), now, now, "second-rollback") {
		t.Fatal("second clock rollback reopened an expired timestamp")
	}
	assertWireReplayAccounting(t, cache)
}

func TestWireReplayCacheUsesWireTimestampPrecision(t *testing.T) {
	now := time.Unix(1_800_000_000, 900_000_000)
	encodedNow := time.Unix(now.Unix(), 0)
	cache := newWireReplayCache(8, 8)
	if !cache.accept(testWireReplayNonce(1), encodedNow.Add(-wirePreambleValidity), now, "past-boundary") {
		t.Fatal("encoded past window boundary was rejected")
	}
	if !cache.accept(testWireReplayNonce(2), encodedNow.Add(wirePreambleValidity), now, "future-boundary") {
		t.Fatal("encoded future window boundary was rejected")
	}
	if cache.accept(testWireReplayNonce(3), encodedNow.Add(-wirePreambleValidity-time.Second), now, "past-outside") {
		t.Fatal("encoded timestamp before the past window was accepted")
	}
	if cache.accept(testWireReplayNonce(4), encodedNow.Add(wirePreambleValidity+time.Second), now, "future-outside") {
		t.Fatal("encoded timestamp after the future window was accepted")
	}
	cache.mu.Lock()
	lastNow := cache.lastNow
	cache.mu.Unlock()
	if lastNow.Nanosecond() != 0 || lastNow != lastNow.Round(0) {
		t.Fatalf("replay clock retained subsecond or monotonic state: %v", lastNow)
	}
	assertWireReplayAccounting(t, cache)
}

func TestWireReplayCacheUsesNormalizedIPv6SourceBuckets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	firstSource := admissionSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1000}, 64)
	secondSource := admissionSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::2"), Port: 2000}, 64)
	otherSource := admissionSourceKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 3000}, 64)
	if firstSource != secondSource || firstSource == otherSource {
		t.Fatalf("IPv6 source buckets first=%q second=%q other=%q", firstSource, secondSource, otherSource)
	}
	cache := newWireReplayCache(2, 1)
	if !cache.accept(testWireReplayNonce(1), now, now, firstSource) ||
		!cache.accept(testWireReplayNonce(2), now, now, secondSource) ||
		!cache.accept(testWireReplayNonce(3), now, now, otherSource) {
		t.Fatal("normalized IPv6 source rotation rejected a fresh preamble")
	}
	cache.mu.Lock()
	firstUsage := cache.bySource[firstSource].count
	otherUsage := cache.bySource[otherSource].count
	cache.mu.Unlock()
	if firstUsage != 1 || otherUsage != 1 {
		t.Fatalf("IPv6 source usage first=%d other=%d, want 1 and 1", firstUsage, otherUsage)
	}
	assertWireReplayAccounting(t, cache)
}

func TestWireReplayCacheMemoryBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := newWireReplayCache(8, 2)
	for i := range 1024 {
		if !cache.accept(testWireReplayNonce(uint64(i+1)), now, now, fmt.Sprintf("source-%d", i%16)) {
			t.Fatalf("fresh preamble %d was rejected", i)
		}
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	slots := len(cache.slots)
	sources := len(cache.bySource)
	cache.mu.Unlock()
	if entries != 8 || slots != 8 || sources > 8 {
		t.Fatalf("bounded cache entries=%d slots=%d sources=%d", entries, slots, sources)
	}
	assertWireReplayAccounting(t, cache)
}

func testWireReplayNonce(marker uint64) []byte {
	nonce := make([]byte, wirePreambleNonceSize)
	binary.BigEndian.PutUint64(nonce, marker)
	return nonce
}

func wireReplayKey(nonce []byte) [wirePreambleNonceSize]byte {
	var key [wirePreambleNonceSize]byte
	copy(key[:], nonce)
	return key
}

func testTalariaTCPPreamble(key *wireKey, sentAt time.Time, marker uint64) []byte {
	preamble := make([]byte, wirePreambleSize)
	binary.BigEndian.PutUint64(preamble, marker)
	nonce := preamble[:wirePreambleNonceSize]
	encodeWirePreambleTime(key, nonce, sentAt)
	copy(preamble[wirePreambleNonceSize:], wirePreambleTag(key, nonce))
	return preamble
}

func assertWireReplayAccounting(t *testing.T, cache *wireReplayCache) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) > cache.limit || len(cache.slots) > cache.limit {
		t.Fatalf("cache bounds entries=%d slots=%d limit=%d", len(cache.entries), len(cache.slots), cache.limit)
	}
	used := 0
	for index, entry := range cache.slots {
		if !entry.used {
			continue
		}
		used++
		if mapped, ok := cache.entries[entry.key]; !ok || mapped != index {
			t.Fatalf("slot %d map entry = %d, %t", index, mapped, ok)
		}
	}
	if used != len(cache.entries) || used+len(cache.free) != len(cache.slots) {
		t.Fatalf("slot accounting used=%d free=%d slots=%d entries=%d", used, len(cache.free), len(cache.slots), len(cache.entries))
	}
	free := make(map[int]struct{}, len(cache.free))
	for _, index := range cache.free {
		if index < 0 || index >= len(cache.slots) || cache.slots[index].used {
			t.Fatalf("invalid free slot %d", index)
		}
		if _, duplicate := free[index]; duplicate {
			t.Fatalf("duplicate free slot %d", index)
		}
		free[index] = struct{}{}
	}
	globalCount := 0
	previous := -1
	seen := make(map[int]struct{}, len(cache.entries))
	for index := cache.head; index >= 0; index = cache.slots[index].globalNext {
		if index >= len(cache.slots) || !cache.slots[index].used {
			t.Fatalf("invalid global slot %d", index)
		}
		if _, duplicate := seen[index]; duplicate {
			t.Fatalf("global replay cycle at slot %d", index)
		}
		seen[index] = struct{}{}
		if cache.slots[index].globalPrev != previous {
			t.Fatalf("global slot %d previous=%d want=%d", index, cache.slots[index].globalPrev, previous)
		}
		previous = index
		globalCount++
	}
	if globalCount != len(cache.entries) || previous != cache.tail {
		t.Fatalf("global accounting count=%d entries=%d tail=%d want=%d", globalCount, len(cache.entries), cache.tail, previous)
	}
	sourceTotal := 0
	for source, state := range cache.bySource {
		count := 0
		previous = -1
		for index := state.head; index >= 0; index = cache.slots[index].sourceNext {
			if index >= len(cache.slots) {
				t.Fatalf("invalid source %q slot %d", source, index)
			}
			entry := cache.slots[index]
			if !entry.used || entry.source != source || entry.sourcePrev != previous {
				t.Fatalf("invalid source %q slot %d", source, index)
			}
			previous = index
			count++
			if count > len(cache.entries) {
				t.Fatalf("source %q replay cycle", source)
			}
		}
		if count != state.count || previous != state.tail || count > cache.sourceLimit {
			t.Fatalf("source %q count=%d state=%d tail=%d want=%d limit=%d", source, count, state.count, state.tail, previous, cache.sourceLimit)
		}
		sourceTotal += count
	}
	if sourceTotal != len(cache.entries) {
		t.Fatalf("source accounting total=%d entries=%d", sourceTotal, len(cache.entries))
	}
}

func TestWriteAllCountRejectsInvalidProgress(t *testing.T) {
	for _, n := range []int{-1, 2} {
		written, err := writeAllCount(invalidProgressWriter{n: n}, []byte{1})
		if written != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeAllCount() with progress %d = %d, %v; want 0, %v", n, written, err, io.ErrShortWrite)
		}
	}
}

func TestTalariaTCPWireRejectsInvalidReadProgress(t *testing.T) {
	for _, n := range []int{-1, 2} {
		ready := make(chan struct{})
		close(ready)
		conn := &obfuscatedConn{
			Conn:       &invalidReadProgressConn{n: n},
			role:       wireRoleClient,
			ready:      ready,
			readStream: wireStream(testWireKey(t), make([]byte, wirePreambleNonceSize), "test"),
		}
		if read, err := conn.Read(make([]byte, 1)); read != 0 || err == nil {
			t.Fatalf("Read() with progress %d = %d, %v; want 0, error", n, read, err)
		}
	}
}

func TestTalariaTCPWireRejectsInvalidPreambleReadProgress(t *testing.T) {
	for _, n := range []int{-1, wirePreambleSize + 1} {
		conn := &obfuscatedConn{
			Conn:  &invalidReadProgressConn{n: n},
			role:  wireRoleServer,
			key:   testWireKey(t),
			ready: make(chan struct{}),
		}
		if read, err := conn.Read(make([]byte, 1)); read != 0 || err == nil {
			t.Fatalf("preamble Read() with progress %d = %d, %v; want 0, error", n, read, err)
		}
	}
}

func TestObfuscatedCloseDoesNotWaitForFailedReadClose(t *testing.T) {
	raw := &panicCloseBlockingReadConn{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	wrapped := wrapServerWire(raw, testWireKey(t), newWireReplayCache(1, 1), "source-a", time.Now)
	readDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Read(make([]byte, 1))
		readDone <- err
	}()
	<-raw.entered
	closeResult := make(chan any, 1)
	go func() {
		defer func() { closeResult <- recover() }()
		_ = wrapped.Close()
	}()
	select {
	case recovered := <-closeResult:
		if recovered == nil {
			t.Fatal("panicking connection close did not propagate its panic")
		}
	case <-time.After(100 * time.Millisecond):
		close(raw.release)
		<-readDone
		<-closeResult
		t.Fatal("wire key cleanup waited for blocked initialization")
	}
	close(raw.release)
	<-readDone
}

func TestTalariaTCPWireRequiresDeploymentSecret(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)
	if _, err := NewClient(ClientConfig{
		Address:   "127.0.0.1:443",
		TLSConfig: clientTLS,
	}); err == nil {
		t.Fatal("TalariaTCP client accepted an empty wire secret")
	}
}

func TestTalariaTCPWireRequiresEndpointIdentity(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	if _, err := NewClient(ClientConfig{
		Address:    "127.0.0.1:443",
		TLSConfig:  clientTLS,
		WireSecret: testTalariaTCPWireSecret,
	}); err == nil {
		t.Fatal("TalariaTCP client accepted an empty wire identity")
	}
	if _, err := NewServer(ServerConfig{
		Listener:   newPipeListener(),
		TLSConfig:  serverTLS,
		WireSecret: testTalariaTCPWireSecret,
	}); err == nil {
		t.Fatal("TalariaTCP server accepted an empty wire identity")
	}
}

func TestTalariaTCPUsesExpectedTLSConfiguration(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	client, err := NewClient(ClientConfig{
		Address:      "127.0.0.1:443",
		TLSConfig:    clientTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		Listener:     newPipeListener(),
		TLSConfig:    serverTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if client.tlsConfig.MinVersion != tls.VersionTLS13 || client.tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("client TLS range = %x-%x, want TLS 1.3 only", client.tlsConfig.MinVersion, client.tlsConfig.MaxVersion)
	}
	if server.tlsConfig.MinVersion != tls.VersionTLS13 || server.tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("server TLS range = %x-%x, want TLS 1.3 only", server.tlsConfig.MinVersion, server.tlsConfig.MaxVersion)
	}
	if !client.tlsConfig.DynamicRecordSizingDisabled || !server.tlsConfig.DynamicRecordSizingDisabled {
		t.Fatal("TLS dynamic record sizing must be disabled")
	}
	if !client.tlsConfig.SessionTicketsDisabled {
		t.Fatal("client TLS session tickets must be disabled")
	}
	if len(client.tlsConfig.NextProtos) != 0 || len(server.tlsConfig.NextProtos) != 0 {
		t.Fatalf("unexpected ALPN client=%v server=%v", client.tlsConfig.NextProtos, server.tlsConfig.NextProtos)
	}
}

func captureClientWirePrefix(t *testing.T) []byte {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{
		Listener:     listener,
		TLSConfig:    serverTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = server.Serve(ctx,
			coretransport.ControlHandlerFunc(echoControl),
			coretransport.StreamHandlerFunc(openEchoStream),
		)
	}()

	var recorded *wireRecordingConn
	client, err := NewClient(ClientConfig{
		Address:      listener.Addr().String(),
		TLSConfig:    clientTLS,
		WireIdentity: "vpn.test",
		WireSecret:   testTalariaTCPWireSecret,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, dialErr := listener.DialContext(ctx)
			if dialErr != nil {
				return nil, dialErr
			}
			recorded = &wireRecordingConn{Conn: conn}
			return recorded, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	control, err := client.DialControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = control.Close()
	if recorded == nil {
		t.Fatal("client connection was not recorded")
	}
	prefix := recorded.prefix()
	if len(prefix) < 5 {
		t.Fatalf("wire prefix length = %d", len(prefix))
	}
	return prefix
}

func hasTLSRecordHeader(prefix []byte) bool {
	if len(prefix) < 5 || prefix[0] != 0x16 || prefix[1] != 0x03 {
		return false
	}
	if prefix[2] > 0x04 {
		return false
	}
	return binary.BigEndian.Uint16(prefix[3:5]) > 0
}

const oldObfuscationBoundary = 256 * 1024

var testTalariaTCPWireSecret = []byte("0123456789abcdef0123456789abcdef")

func testWireKey(t *testing.T) *wireKey {
	t.Helper()
	key, err := newWireKey(testTalariaTCPWireSecret, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type wireRecordingConn struct {
	net.Conn
	mu   sync.Mutex
	wire []byte
}

type panicCloseBlockingReadConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *panicCloseBlockingReadConn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, io.EOF
}

func (*panicCloseBlockingReadConn) Close() error {
	panic("close panic")
}

func (c *wireRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.wire) < 64 {
		remaining := 64 - len(c.wire)
		if remaining > len(p) {
			remaining = len(p)
		}
		c.wire = append(c.wire, p[:remaining]...)
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *wireRecordingConn) prefix() []byte {
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		prefix := append([]byte(nil), c.wire...)
		c.mu.Unlock()
		if len(prefix) >= wirePreambleSize || time.Now().After(deadline) {
			return prefix
		}
		time.Sleep(time.Millisecond)
	}
}

type wireWriteCaptureConn struct {
	wire []byte
}

type wireReadConn struct {
	*wireWriteCaptureConn
	reader *bytes.Reader
}

type invalidProgressWriter struct {
	n int
}

func (w invalidProgressWriter) Write([]byte) (int, error) {
	return w.n, nil
}

type invalidReadProgressConn struct {
	wireWriteCaptureConn
	n int
}

func (c *invalidReadProgressConn) Read([]byte) (int, error) {
	return c.n, nil
}

func newWireWriteCaptureConn() *wireWriteCaptureConn {
	return new(wireWriteCaptureConn)
}

func newWireReadConn(payload []byte) *wireReadConn {
	return &wireReadConn{
		wireWriteCaptureConn: newWireWriteCaptureConn(),
		reader:               bytes.NewReader(payload),
	}
}

func (c *wireReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *wireWriteCaptureConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *wireWriteCaptureConn) Write(p []byte) (int, error) {
	c.wire = append(c.wire, p...)
	return len(p), nil
}

func (c *wireWriteCaptureConn) Close() error {
	return nil
}

func (c *wireWriteCaptureConn) LocalAddr() net.Addr {
	return testAddr("local")
}

func (c *wireWriteCaptureConn) RemoteAddr() net.Addr {
	return testAddr("remote")
}

func (c *wireWriteCaptureConn) SetDeadline(time.Time) error {
	return nil
}

func (c *wireWriteCaptureConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *wireWriteCaptureConn) SetWriteDeadline(time.Time) error {
	return nil
}
