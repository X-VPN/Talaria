// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestHandshakeAuthRejectsForgedACKWithoutChangingSendState(t *testing.T) {
	binding := bytes.Repeat([]byte{0x31}, retryPacketBindingSize)
	tag := bytes.Repeat([]byte{0x42}, retryCookieTagSize)
	otherBinding := bytes.Repeat([]byte{0x53}, retryPacketBindingSize)
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	binary.LittleEndian.PutUint64(ack[2:10], 3)
	valid, ok := sealHandshakeAuthPacket(ack, binding, tag, handshakeAuthDirectionServer, 1500)
	if !ok {
		t.Fatal("failed to seal valid ACK")
	}
	tampered := append([]byte(nil), valid...)
	tampered[handshakeAuthPayloadOffset+2] ^= 0x01
	wrongDirection, _ := sealHandshakeAuthPacket(ack, binding, tag, handshakeAuthDirectionClient, 1500)
	wrongConnection, _ := sealHandshakeAuthPacket(ack, otherBinding, tag, handshakeAuthDirectionServer, 1500)

	tests := []struct {
		name       string
		packet     []byte
		wantOpened bool
		wantAck    uint64
		wantQueued int
	}{
		{name: "raw ACK", packet: ack, wantQueued: 1},
		{name: "modified ACK", packet: tampered, wantQueued: 1},
		{name: "wrong direction", packet: wrongDirection, wantQueued: 1},
		{name: "other connection", packet: wrongConnection, wantQueued: 1},
		{name: "valid ACK", packet: valid, wantOpened: true, wantAck: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &handshakeConn{
				unacked: []*handshakeSegment{{
					offset:  0,
					payload: []byte{1, 2, 3},
					sentAt:  time.Now(),
				}},
			}
			inner, opened := openHandshakeAuthPacket(tt.packet, binding, tag, handshakeAuthDirectionServer)
			if opened {
				if err := conn.handleInboundPacket(inner); err != nil {
					t.Fatal(err)
				}
			}
			if opened != tt.wantOpened {
				t.Fatalf("opened = %v, want %v", opened, tt.wantOpened)
			}
			if conn.sendAck != tt.wantAck {
				t.Fatalf("send ACK = %d, want %d", conn.sendAck, tt.wantAck)
			}
			if len(conn.unacked) != tt.wantQueued {
				t.Fatalf("unacked segments = %d, want %d", len(conn.unacked), tt.wantQueued)
			}
		})
	}
}

func TestHandshakeAuthEnforcesPacketLimit(t *testing.T) {
	binding := bytes.Repeat([]byte{0x21}, retryPacketBindingSize)
	tag := bytes.Repeat([]byte{0x32}, retryCookieTagSize)
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	wireSize := handshakeAuthOverhead + len(ack)
	tests := []struct {
		name      string
		maxPacket int
		wantOK    bool
	}{
		{name: "exact limit", maxPacket: wireSize, wantOK: true},
		{name: "one byte short", maxPacket: wireSize - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, ok := sealHandshakeAuthPacket(ack, binding, tag, handshakeAuthDirectionClient, tt.maxPacket)
			if ok != tt.wantOK {
				t.Fatalf("sealed = %v, want %v", ok, tt.wantOK)
			}
			if ok && len(packet) != wireSize {
				t.Fatalf("wire size = %d, want %d", len(packet), wireSize)
			}
		})
	}
}

func TestHandshakeAuthPreservesCumulativeACKSemantics(t *testing.T) {
	binding := bytes.Repeat([]byte{0x43}, retryPacketBindingSize)
	tag := bytes.Repeat([]byte{0x54}, retryCookieTagSize)
	tests := []struct {
		name string
		acks []uint64
	}{
		{name: "lost first ACK", acks: []uint64{6}},
		{name: "duplicate ACK", acks: []uint64{3, 3, 6}},
		{name: "reordered ACK", acks: []uint64{6, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &handshakeConn{
				unacked: []*handshakeSegment{
					{offset: 0, payload: []byte{1, 2, 3}, sentAt: time.Now()},
					{offset: 3, payload: []byte{4, 5, 6}, sentAt: time.Now()},
				},
			}
			for _, ackUpto := range tt.acks {
				ack := make([]byte, handshakeAckHeaderSize)
				ack[0] = handshakePacketTypeAck
				ack[1] = handshakePacketVersion
				binary.LittleEndian.PutUint64(ack[2:10], ackUpto)
				packet, ok := sealHandshakeAuthPacket(ack, binding, tag, handshakeAuthDirectionServer, 1500)
				if !ok {
					t.Fatal("failed to authenticate ACK")
				}
				opened, ok := openHandshakeAuthPacket(packet, binding, tag, handshakeAuthDirectionServer)
				if !ok {
					t.Fatal("failed to verify authenticated ACK")
				}
				if err := conn.handleInboundPacket(opened); err != nil {
					t.Fatal(err)
				}
			}
			if conn.sendAck != 6 || len(conn.unacked) != 0 {
				t.Fatalf("final send state: ack=%d unacked=%d, want 6/0", conn.sendAck, len(conn.unacked))
			}
		})
	}
}

func TestRetryServerConnRequiresRetryAndAuthenticatesHandshakePackets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0x64}, retryCookieKeySize)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 90), Port: 30090}
	firstPacket := testHandshakeStartPacket([]byte("client hello fragment with enough bytes to authenticate"))
	challenge := gate.EvaluateNewSession(firstPacket, addr).Reply
	response, ok := buildRetryResponse(challenge, firstPacket)
	if !ok {
		t.Fatal("failed to build Retry response")
	}
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	authenticatedACK, ok := sealHandshakeAuthPacket(
		ack,
		challenge[retryFrameBindingOffset:retryFrameTagOffset],
		challenge[retryFrameTagOffset:retryChallengeSize],
		handshakeAuthDirectionClient,
		1500,
	)
	if !ok {
		t.Fatal("failed to authenticate client ACK")
	}
	tampered := append([]byte(nil), authenticatedACK...)
	tampered[len(tampered)-1] ^= 0x01
	inner := &scriptedBatchConn{reads: [][][]byte{{ack, tampered}, {response, ack, authenticatedACK}}, remoteAddr: addr}
	conn, err := newRetryServerConn(inner, gate, 1500)
	if err != nil {
		t.Fatal(err)
	}

	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, len(bufs))
	n, err := conn.ReadBatch(context.Background(), bufs, sizes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("visible packets = %d, want 2", n)
	}
	if !bytes.Equal(bufs[0][:sizes[0]], firstPacket) || !bytes.Equal(bufs[1][:sizes[1]], ack) {
		t.Fatal("server exposed unauthenticated input or changed authenticated packets")
	}

	if n, err := conn.WriteBatch(context.Background(), [][]byte{ack}, []int{len(ack)}); err != nil || n != 1 {
		t.Fatalf("write authenticated ACK: n=%d err=%v", n, err)
	}
	writes := inner.snapshotWrites()
	if len(writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(writes))
	}
	opened, ok := openHandshakeAuthPacket(
		writes[0],
		challenge[retryFrameBindingOffset:retryFrameTagOffset],
		challenge[retryFrameTagOffset:retryChallengeSize],
		handshakeAuthDirectionServer,
	)
	if !ok || !bytes.Equal(opened, ack) {
		t.Fatal("server output was not authenticated in the server direction")
	}
}

func TestAuthenticatedHandshakeCompletesAcrossDatagramFaults(t *testing.T) {
	certificate, roots := newHandshakeTestCertificate(t)
	tests := []struct {
		name        string
		clientFault handshakeTestFaultMode
		serverFault handshakeTestFaultMode
	}{
		{name: "lost client frame", clientFault: handshakeTestFaultDrop},
		{name: "reordered server frames", serverFault: handshakeTestFaultReorder},
		{name: "duplicated client frame", clientFault: handshakeTestFaultDuplicate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientRaw, serverRaw := newHandshakeTestConnPair()
			t.Cleanup(func() {
				_ = clientRaw.Close()
				_ = serverRaw.Close()
			})
			clientRaw.fault.mode = tt.clientFault
			serverRaw.fault.mode = tt.serverFault

			binding := bytes.Repeat([]byte{0x91}, retryPacketBindingSize)
			tag := bytes.Repeat([]byte{0xa2}, retryCookieTagSize)
			clientRetry := newRetryClientConn(clientRaw, 512)
			// Retry exchange behavior is tested separately. Prime only its result so
			// this test exercises a real TLS handshake over the protected carrier.
			clientRetry.firstPacket = []byte{0xff}
			copy(clientRetry.authBinding[:], binding)
			copy(clientRetry.authTag[:], tag)
			clientRetry.authReady = true
			serverRetry := &retryServerConn{batchConn: serverRaw, maxPacket: 512, bound: true}
			copy(serverRetry.binding[:], binding)
			copy(serverRetry.tag[:], tag)

			clientHandshake, err := newHandshakeConnWithReservedOverhead(clientRetry, 512, handshakeAuthOverhead, false)
			if err != nil {
				t.Fatal(err)
			}
			serverHandshake, err := newHandshakeConnWithReservedOverhead(serverRetry, 512, handshakeAuthOverhead, false)
			if err != nil {
				_ = clientHandshake.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = clientHandshake.Close()
				_ = serverHandshake.Close()
			})

			clientTLS := tls.Client(clientHandshake, &tls.Config{
				MinVersion:             tls.VersionTLS13,
				MaxVersion:             tls.VersionTLS13,
				ServerName:             "example.com",
				RootCAs:                roots,
				SessionTicketsDisabled: true,
				NextProtos:             []string{TunnelTLSALPN},
			})
			serverTLS := tls.Server(serverHandshake, serverTLSConfigWithCertificate(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return certificate, nil
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			results := make(chan error, 2)
			go func() {
				err := clientTLS.HandshakeContext(ctx)
				if err == nil {
					err = clientHandshake.Drain(ctx)
				}
				results <- err
			}()
			go func() {
				err := serverTLS.HandshakeContext(ctx)
				if err == nil {
					err = serverHandshake.Drain(ctx)
				}
				results <- err
			}()
			for range 2 {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			if !clientTLS.ConnectionState().HandshakeComplete || !serverTLS.ConnectionState().HandshakeComplete {
				t.Fatal("TLS handshake did not complete on both peers")
			}
			if suite := serverTLS.ConnectionState().CipherSuite; suite == tls.TLS_AES_128_GCM_SHA256 {
				t.Fatal("TalariaUDP handshake negotiated TLS AES-128-GCM")
			}
			if tt.clientFault != handshakeTestFaultNone && !clientRaw.fault.applied() {
				t.Fatal("client fault was not applied")
			}
			if tt.serverFault != handshakeTestFaultNone && !serverRaw.fault.applied() {
				t.Fatal("server fault was not applied")
			}
		})
	}
}

func TestRetryContextChangesAcrossReconnects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gate, err := newRetryCookieGate(1500, bytes.NewReader(bytes.Repeat([]byte{0xb3}, retryCookieKeySize)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 91), Port: 30091}
	firstPackets := [][]byte{
		captureHandshakeStartPacket(t),
		captureHandshakeStartPacket(t),
	}
	if bytes.Equal(firstPackets[0], firstPackets[1]) {
		t.Fatal("reconnect TLS ClientHello packets are equal")
	}
	challenges := make([][]byte, len(firstPackets))
	for i, packet := range firstPackets {
		challenges[i] = gate.EvaluateNewSession(packet, addr).Reply
		if len(challenges[i]) != retryChallengeSize {
			t.Fatalf("challenge %d size = %d, want %d", i, len(challenges[i]), retryChallengeSize)
		}
	}
	if bytes.Equal(challenges[0][retryFrameBindingOffset:retryFrameTagOffset], challenges[1][retryFrameBindingOffset:retryFrameTagOffset]) {
		t.Fatal("reconnect packet bindings are equal")
	}
	if bytes.Equal(challenges[0][retryFrameTagOffset:], challenges[1][retryFrameTagOffset:]) {
		t.Fatal("reconnect Retry tags are equal")
	}
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	firstMAC := handshakeAuthTag(
		ack,
		challenges[0][retryFrameBindingOffset:retryFrameTagOffset],
		challenges[0][retryFrameTagOffset:],
		handshakeAuthDirectionClient,
	)
	secondMAC := handshakeAuthTag(
		ack,
		challenges[1][retryFrameBindingOffset:retryFrameTagOffset],
		challenges[1][retryFrameTagOffset:],
		handshakeAuthDirectionClient,
	)
	if bytes.Equal(firstMAC[:], secondMAC[:]) {
		t.Fatal("reconnect temporary handshake MACs are equal")
	}
}

func FuzzHandshakeAuthPacket(f *testing.F) {
	binding := bytes.Repeat([]byte{0x71}, retryPacketBindingSize)
	tag := bytes.Repeat([]byte{0x82}, retryCookieTagSize)
	ack := make([]byte, handshakeAckHeaderSize)
	ack[0] = handshakePacketTypeAck
	ack[1] = handshakePacketVersion
	valid, ok := sealHandshakeAuthPacket(ack, binding, tag, handshakeAuthDirectionClient, 1500)
	if !ok {
		f.Fatal("failed to build authenticated seed")
	}
	f.Add([]byte{})
	f.Add(ack)
	f.Add(valid)
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65535 {
			t.Skip()
		}
		_, _ = openHandshakeAuthPacket(packet, binding, tag, handshakeAuthDirectionClient)
	})
}

type handshakeTestFaultMode uint8

const (
	handshakeTestFaultNone handshakeTestFaultMode = iota
	handshakeTestFaultDrop
	handshakeTestFaultReorder
	handshakeTestFaultDuplicate
)

type handshakeTestFault struct {
	mu   sync.Mutex
	mode handshakeTestFaultMode
	seen bool
	done bool
	hit  bool
	held []byte
}

func (f *handshakeTestFault) apply(packet []byte) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	cloned := append([]byte(nil), packet...)
	if len(packet) < len(handshakeAuthMagic) || !bytes.Equal(packet[:len(handshakeAuthMagic)], handshakeAuthMagic[:]) || f.done {
		return [][]byte{cloned}
	}
	switch f.mode {
	case handshakeTestFaultDrop:
		f.done = true
		f.hit = true
		return nil
	case handshakeTestFaultReorder:
		if !f.seen {
			f.seen = true
			f.held = cloned
			return nil
		}
		f.done = true
		held := f.held
		f.held = nil
		f.hit = !bytes.Equal(cloned, held)
		return [][]byte{cloned, held}
	case handshakeTestFaultDuplicate:
		f.done = true
		f.hit = true
		return [][]byte{cloned, append([]byte(nil), cloned...)}
	default:
		return [][]byte{cloned}
	}
}

func (f *handshakeTestFault) applied() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hit
}

type handshakeTestConn struct {
	local    net.Addr
	remote   net.Addr
	incoming chan []byte
	closed   chan struct{}
	peer     *handshakeTestConn
	fault    handshakeTestFault

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	closeOnce     sync.Once
}

func newHandshakeTestConnPair() (*handshakeTestConn, *handshakeTestConn) {
	client := &handshakeTestConn{
		local:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 101), Port: 30101},
		remote:   &net.UDPAddr{IP: net.IPv4(192, 0, 2, 102), Port: 30102},
		incoming: make(chan []byte, 256),
		closed:   make(chan struct{}),
	}
	server := &handshakeTestConn{
		local:    client.remote,
		remote:   client.local,
		incoming: make(chan []byte, 256),
		closed:   make(chan struct{}),
	}
	client.peer = server
	server.peer = client
	return client, server
}

func (c *handshakeTestConn) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := c.ReadBatch(context.Background(), [][]byte{p}, sizes)
	if n == 0 {
		return 0, err
	}
	return sizes[0], err
}

func (c *handshakeTestConn) Write(p []byte) (int, error) {
	n, err := c.WriteBatch(context.Background(), [][]byte{p}, []int{len(p)})
	if err != nil || n == 0 {
		return 0, err
	}
	return len(p), nil
}

func (c *handshakeTestConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *handshakeTestConn) LocalAddr() net.Addr  { return c.local }
func (c *handshakeTestConn) RemoteAddr() net.Addr { return c.remote }

func (c *handshakeTestConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *handshakeTestConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *handshakeTestConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (*handshakeTestConn) BatchSize() int { return 8 }

func (c *handshakeTestConn) ReadBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, io.ErrShortBuffer
	}
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	var timer *time.Timer
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(wait)
		defer timer.Stop()
	}
	select {
	case packet := <-c.incoming:
		if len(packet) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0], packet)
		sizes[0] = len(packet)
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-c.closed:
		return 0, net.ErrClosed
	case <-timerChan(timer):
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *handshakeTestConn) WriteBatch(ctx context.Context, bufs [][]byte, sizes []int) (int, error) {
	if len(sizes) < len(bufs) {
		return 0, io.ErrShortBuffer
	}
	for i := range bufs {
		if sizes[i] < 0 || sizes[i] > len(bufs[i]) {
			return i, io.ErrShortBuffer
		}
		for _, packet := range c.fault.apply(bufs[i][:sizes[i]]) {
			select {
			case c.peer.incoming <- packet:
			case <-ctx.Done():
				return i, ctx.Err()
			case <-c.closed:
				return i, net.ErrClosed
			case <-c.peer.closed:
				return i, net.ErrClosed
			}
		}
	}
	return len(bufs), nil
}

func newHandshakeTestCertificate(t *testing.T) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return certificate, roots
}

func newHandshakeTestCertificatePEM(t *testing.T) (string, string) {
	t.Helper()
	certificate, _ := newHandshakeTestCertificate(t)
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
}

func captureHandshakeStartPacket(t *testing.T) []byte {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(clientRaw, &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			ServerName: "example.com",
		}).HandshakeContext(ctx)
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(serverRaw, header); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, len(header)+int(binary.BigEndian.Uint16(header[3:5])))
	copy(record, header)
	if _, err := io.ReadFull(serverRaw, record[len(header):]); err != nil {
		t.Fatal(err)
	}
	_ = serverRaw.Close()
	<-done
	if len(record) > defaultHandshakePayloadSize {
		record = record[:defaultHandshakePayloadSize]
	}
	return testHandshakeStartPacket(record)
}
