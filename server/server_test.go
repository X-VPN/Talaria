// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestExpectedCloseIncludesNormalPipeShutdown(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrClosedPipe, net.ErrClosed} {
		if !isExpectedClose(context.Background(), err) {
			t.Fatalf("isExpectedClose(%v) = false, want true", err)
		}
	}
}

func TestStartRejectsUnknownProtocolBeforeDependencies(t *testing.T) {
	tests := []client.Protocol{
		client.Protocol("unsupported"),
		client.Protocol("TalariaTCP "),
		client.Protocol("TalariaTCP\nforged-log"),
	}
	for _, protocol := range tests {
		t.Run(string(protocol), func(t *testing.T) {
			srv, err := Start(context.Background(), Config{Protocol: protocol})
			if srv != nil {
				_ = srv.Close()
			}
			if err == nil || err.Error() != "Talaria server: unsupported Talaria protocol" {
				t.Fatalf("error = %q", err)
			}
		})
	}
}

func TestNormalizeServeOptionsRejectsUnknownProtocol(t *testing.T) {
	tests := []client.Protocol{
		client.Protocol("unsupported"),
		client.Protocol("TalariaTCP "),
		client.Protocol("TalariaTCP\nforged-log"),
	}
	for _, protocol := range tests {
		t.Run(string(protocol), func(t *testing.T) {
			_, err := normalizeServeOptions(ServeOptions{Protocol: protocol}, client.ProtocolTalariaUDP, 2048)
			if err == nil || err.Error() != "Talaria server: unsupported Talaria protocol" {
				t.Fatalf("error = %q", err)
			}
		})
	}
}

func TestSessionWriterGatePreservesInterruptibleClose(t *testing.T) {
	closed := false
	_, writers := newSessionWriterGate(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() { closed = true },
	}, nil, 7)
	if writers.Close == nil {
		t.Fatal("session writer gate removed the interruptible close hook")
	}
	writers.Close()
	if !closed {
		t.Fatal("session writer gate did not forward the close hook")
	}
}

func TestSessionWriterGateDropsOutputOnceSessionIsNotCurrent(t *testing.T) {
	current := true
	var packetWrites, rawWrites, batchWrites int
	gate, writers := newSessionWriterGate(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			packetWrites++
			return nil
		},
		Raw: func([]byte) error {
			rawWrites++
			return nil
		},
		RawBatch: func(bufs [][]byte, _ []int) (int, error) {
			batchWrites++
			return len(bufs), nil
		},
	}, func() bool { return current }, 7)
	if err := gate.markReady(7); err != nil {
		t.Fatal(err)
	}
	current = false
	if err := writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData}); err != nil {
		t.Fatal(err)
	}
	if err := writers.Raw([]byte("stale")); err != nil {
		t.Fatal(err)
	}
	if n, err := writers.RawBatch([][]byte{{1}, {2}}, []int{1, 1}); err != nil || n != 2 {
		t.Fatalf("stale batch result = %d, %v", n, err)
	}
	if packetWrites != 1 || rawWrites != 0 || batchWrites != 0 {
		t.Fatalf("underlying writes after revocation = packet:%d raw:%d batch:%d", packetWrites-1, rawWrites, batchWrites)
	}
}

func TestHandlerResponseIsDroppedWhenSessionIsRevokedDuringHandling(t *testing.T) {
	ref := coretransport.SessionRef{ClientID: 8, Generation: 1}
	writes := 0
	srv := &Server{}
	srv.handler = PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
		if !srv.RevokeSession(ref, "revoked during handling") {
			t.Fatal("current session was not revoked")
		}
		return []*vpnpacket.VpnPacket{{Cmd: vpnpacket.CmdData}}, nil
	})
	if _, err := srv.activateSession(activeServerSessionConfig{Ref: ref}); err != nil {
		t.Fatal(err)
	}
	err := srv.handleAndWriteResponses(context.Background(), func(*vpnpacket.VpnPacket) error {
		writes++
		return nil
	}, SessionContext{ClientID: ref.ClientID, Generation: ref.Generation}, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("handler result = %v, want net.ErrClosed", err)
	}
	if writes != 0 {
		t.Fatalf("stale handler response writes = %d, want 0", writes)
	}
}

func TestServePacketConnUsesInjectedAuthAndPacketHandler(t *testing.T) {
	codec := dataplane.WireCodec{}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	payload := []byte("hello")
	srv := &Server{
		protocol: client.ProtocolTalariaUDP,
		codec:    codec,
		auth: AuthProviderFunc(func(_ context.Context, req AuthRequest) (AuthResult, error) {
			if req.Protocol != client.ProtocolTalariaUDP {
				t.Fatalf("protocol = %s, want %s", req.Protocol, client.ProtocolTalariaUDP)
			}
			if req.ClientID != "id" || req.SecretKey != "sk" {
				t.Fatalf("auth req id/sk = %q/%q", req.ClientID, req.SecretKey)
			}
			return AuthResult{ClientID: 99, Version: 7}, nil
		}),
		handler: PacketHandlerFunc(func(_ context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
			if session.ClientID != 99 {
				t.Fatalf("session client id = %d, want 99", session.ClientID)
			}
			if !bytes.Equal(packet.Data, payload) {
				t.Fatalf("packet payload = %q, want %q", packet.Data, payload)
			}
			return []*vpnpacket.VpnPacket{{
				Cmd:            vpnpacket.CmdData,
				DataSequenceId: packet.DataSequenceId,
				Data:           packet.Data,
			}}, nil
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServePacketConn(ctx, serverConn, ServeOptions{Protocol: client.ProtocolTalariaUDP})
	}()

	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "id",
		Sk:      "sk",
		Version: 5,
	})
	authResp := readTestPacket(t, codec, clientConn)
	if authResp.Cmd != vpnpacket.CmdAuthSuccess || authResp.NewClientId != 99 || authResp.Version != 7 {
		t.Fatalf("auth response = %+v", authResp)
	}
	readyResp := readTestPacket(t, codec, clientConn)
	if readyResp.Cmd != vpnpacket.CmdSessionReady || readyResp.ClientId != 99 {
		t.Fatalf("ready response = %+v", readyResp)
	}

	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd:            vpnpacket.CmdData,
		ClientId:       99,
		DataSequenceId: 3,
		Data:           payload,
	})
	dataResp := readTestPacket(t, codec, clientConn)
	if dataResp.Cmd != vpnpacket.CmdData || dataResp.ClientId != 99 || dataResp.DataSequenceId != 3 || !bytes.Equal(dataResp.Data, payload) {
		t.Fatalf("data response = %+v", dataResp)
	}

	cancel()
	_ = clientConn.Close()
	select {
	case err := <-errCh:
		// cancel() and Close() race: whichever the server notices first decides
		// whether it returns cleanly or reports the closed pipe. Both mean the
		// session shut down, so only an unexpected error should fail the test.
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServeControlConnBindsAuthenticatedClientID(t *testing.T) {
	codec := dataplane.WireCodec{}
	serverPipe, clientConn := net.Pipe()
	defer clientConn.Close()
	controlConn := &fakeControlConn{Conn: serverPipe}

	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    codec,
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{ClientID: 123, Version: 1}, nil
		}),
		handler: EchoPacketHandler{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(ctx, controlConn, ServeOptions{Protocol: client.ProtocolTalariaTCP})
	}()

	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "id",
		Sk:  "sk",
	})
	authResp := readTestPacket(t, codec, clientConn)
	if authResp.Cmd != vpnpacket.CmdAuthSuccess || authResp.NewClientId != 123 {
		t.Fatalf("auth response = %+v", authResp)
	}
	readyResp := readTestPacket(t, codec, clientConn)
	if readyResp.Cmd != vpnpacket.CmdSessionReady || readyResp.ClientId != 123 {
		t.Fatalf("ready response = %+v", readyResp)
	}
	waitForBoundClientID(t, controlConn, 123)

	cancel()
	_ = clientConn.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServeControlConnClosesIdleSession(t *testing.T) {
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    dataplane.WireCodec{},
		auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 10,
			Version:          1,
		},
		handler: EchoPacketHandler{},
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			IdleTimeout: 50 * time.Millisecond,
		})
	}()

	codec := dataplane.WireCodec{}
	authRaw, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "client",
		Sk:      "secret",
		Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(authRaw); err != nil {
		t.Fatal(err)
	}
	for _, want := range []byte{vpnpacket.CmdAuthSuccess, vpnpacket.CmdSessionReady} {
		if response := readTestPacket(t, codec, clientConn); response.Cmd != want {
			t.Fatalf("response command = %d, want %d", response.Cmd, want)
		}
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("idle control session returned no error")
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("idle control error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle control session was not closed")
	}
}

func writeTestPacket(t *testing.T, codec dataplane.Codec, conn net.Conn, packet *vpnpacket.VpnPacket) {
	t.Helper()
	raw, err := codec.Encode(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func readTestPacket(t *testing.T, codec dataplane.Codec, conn net.Conn) *vpnpacket.VpnPacket {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, err := codec.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func waitForBoundClientID(t *testing.T, conn *fakeControlConn, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if clientID, ok := conn.ClientID(); ok && clientID == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	clientID, ok := conn.ClientID()
	t.Fatalf("bound client id = %d/%v, want %d/true", clientID, ok, want)
}

type fakeControlConn struct {
	net.Conn
	mu       sync.RWMutex
	clientID uint64
}

func (c *fakeControlConn) BindClientID(clientID uint64) error {
	c.mu.Lock()
	c.clientID = clientID
	c.mu.Unlock()
	return nil
}

func (c *fakeControlConn) ClientID() (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientID, c.clientID != 0
}
