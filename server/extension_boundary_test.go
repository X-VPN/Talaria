// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestStartRejectsTypedNilRequiredExtensions(t *testing.T) {
	var auth *typedNilAuthProvider
	if _, err := Start(context.Background(), Config{
		Protocol:      client.ProtocolTalariaTCP,
		Auth:          auth,
		PacketHandler: EchoPacketHandler{},
	}); err == nil || !strings.Contains(err.Error(), "missing auth provider") {
		t.Fatalf("typed-nil auth error = %v", err)
	}

	var handler *typedNilPacketHandler
	if _, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "id",
			SecretKey:        "secret",
			AssignedClientID: 1,
		},
		PacketHandler: handler,
	}); err == nil || !strings.Contains(err.Error(), "missing packet handler") {
		t.Fatalf("typed-nil packet handler error = %v", err)
	}
}

func TestServeConnectionsRejectTypedNilConn(t *testing.T) {
	var conn *typedNilServeConn
	srv := &Server{}
	for _, serve := range []struct {
		name string
		fn   func() error
	}{
		{"packet", func() error { return srv.ServePacketConn(context.Background(), conn, ServeOptions{}) }},
		{"control", func() error { return srv.ServeControlConn(context.Background(), conn, ServeOptions{}) }},
	} {
		t.Run(serve.name, func(t *testing.T) {
			if err := serve.fn(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("serve error = %v, want %v", err, net.ErrClosed)
			}
		})
	}
}

func TestServeControlConnConvertsAuthProviderPanicToError(t *testing.T) {
	codec := dataplane.WireCodec{}
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    codec,
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			panic("auth provider panic")
		}),
		handler: EchoPacketHandler{},
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{Protocol: client.ProtocolTalariaTCP})
	}()
	raw, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "id",
		Sk:      "secret",
		Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("ServeControlConn error = %v, want extension panic", err)
	}
}

func TestServeControlConnConvertsPacketHandlerPanicToError(t *testing.T) {
	codec := dataplane.WireCodec{}
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    codec,
		auth: StaticAuthProvider{
			ClientID:         "id",
			SecretKey:        "secret",
			AssignedClientID: 7,
		},
		handler: panicHandlePacketHandler{},
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{Protocol: client.ProtocolTalariaTCP})
	}()
	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      "id",
		Sk:      "secret",
		Version: 1,
	})
	for _, want := range []byte{vpnpacket.CmdAuthSuccess, vpnpacket.CmdSessionReady} {
		if packet := readTestPacket(t, codec, clientConn); packet.Cmd != want {
			t.Fatalf("response command = %d, want %d", packet.Cmd, want)
		}
	}
	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: []byte("payload")})
	if err := <-errCh; !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("ServeControlConn error = %v, want extension panic", err)
	}
}

func TestServerCleanupContinuesAfterExtensionPanics(t *testing.T) {
	listener := &closeRecordingListener{}
	srv := &Server{
		talariaUDPListener: listener,
		handler:            panicClosePacketHandler{},
		logErr: func(string, error) {
			panic("logger panic")
		},
		errorLogs: newErrorLogLimiter(0, 0),
	}
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 1, Generation: 1},
		RevokeData: func() {
			panic("revoke panic")
		},
	}); err != nil {
		t.Fatal(err)
	}
	err := srv.Close()
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Close error = %v, want extension panic", err)
	}
	if !listener.closed {
		t.Fatal("listener cleanup was skipped after session callback panic")
	}
	srv.logError("test", errors.New("diagnostic"))
}

func TestServerCloseDoesNotWaitForSessionCleanup(t *testing.T) {
	listener := &closeRecordingListener{}
	release := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	srv := &Server{talariaUDPListener: listener}
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 1, Generation: 1},
		RevokeData: func() {
			close(started)
			<-release
			close(finished)
		},
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-finished
	}()
	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server.Close waited for session cleanup")
	}
	if !listener.closed {
		t.Fatal("listener close was skipped")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("session cleanup was not started")
	}
}

func TestSessionWritersContainConnectionPanics(t *testing.T) {
	srv := &Server{protocol: client.ProtocolTalariaTCP, codec: dataplane.WireCodec{}, writeTimeout: time.Second}
	writers := srv.newSessionWriters(context.Background(), panicSessionWriterConn{})
	if err := writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData}); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Packet() error = %v, want extension panic", err)
	}
	if err := writers.Raw([]byte{1}); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Raw() error = %v, want extension panic", err)
	}
	if _, err := writers.RawBatch([][]byte{{1}}, []int{1}); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("RawBatch() error = %v, want extension panic", err)
	}
	writers.Close()
}

func TestSessionWritersRejectShortConnectionWrites(t *testing.T) {
	srv := &Server{protocol: client.ProtocolTalariaTCP, codec: dataplane.WireCodec{}, writeTimeout: time.Second}
	writers := srv.newSessionWriters(context.Background(), shortSessionWriterConn{})
	if err := writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Packet() error = %v, want short write", err)
	}
	if err := writers.Raw([]byte{1, 2}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Raw() error = %v, want short write", err)
	}
	if _, err := writers.RawBatch([][]byte{{1, 2}}, []int{2}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("RawBatch() error = %v, want short write", err)
	}
}

func TestReadConnFrameRejectsInvalidProgress(t *testing.T) {
	for _, readErr := range []error{nil, errors.New("synthetic read failure")} {
		for _, n := range []int{-1, 2} {
			read, err := readConnFrame(invalidReadProgressConn{n: n, err: readErr}, make([]byte, 1))
			if read != 0 || err == nil {
				t.Fatalf("readConnFrame() with progress %d and error %v = %d, %v; want 0, error", n, readErr, read, err)
			}
		}
	}
}

func TestSessionWritersContainCodecPanic(t *testing.T) {
	srv := &Server{protocol: client.ProtocolTalariaTCP, codec: panicSessionWriterCodec{}, writeTimeout: time.Second}
	writers := srv.newSessionWriters(context.Background(), panicSessionWriterConn{})
	if err := writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData}); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Packet() error = %v, want extension panic", err)
	}
}

func TestCloseOnContextContainsConnectionPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan struct{})
	stop := closeOnContext(ctx, &panicAsyncCloseConn{closed: closed})
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not close the connection")
	}
	stop()
}

type typedNilAuthProvider struct{}

func (*typedNilAuthProvider) Authenticate(context.Context, AuthRequest) (AuthResult, error) {
	panic("typed nil auth provider called")
}

type typedNilPacketHandler struct{}

func (*typedNilPacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	panic("typed nil packet handler called")
}

type typedNilServeConn struct{ net.Conn }

type panicClosePacketHandler struct{}

func (panicClosePacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (panicClosePacketHandler) Close() error { panic("handler close panic") }

type panicHandlePacketHandler struct{}

func (panicHandlePacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	panic("packet handler panic")
}

type closeRecordingListener struct {
	closed bool
}

type panicSessionWriterConn struct{ net.Conn }

func (panicSessionWriterConn) Write([]byte) (int, error)        { panic("write panic") }
func (panicSessionWriterConn) Close() error                     { panic("close panic") }
func (panicSessionWriterConn) SetWriteDeadline(time.Time) error { return nil }

type shortSessionWriterConn struct{ net.Conn }

func (shortSessionWriterConn) Write(p []byte) (int, error) {
	return max(0, len(p)-1), nil
}

func (shortSessionWriterConn) SetWriteDeadline(time.Time) error { return nil }

type invalidReadProgressConn struct {
	net.Conn
	n   int
	err error
}

func (c invalidReadProgressConn) Read([]byte) (int, error) {
	return c.n, c.err
}

type panicSessionWriterCodec struct{}

func (panicSessionWriterCodec) Encode(*vpnpacket.VpnPacket) ([]byte, error) { panic("encode panic") }
func (panicSessionWriterCodec) Decode([]byte) (*vpnpacket.VpnPacket, int, error) {
	return nil, 0, errors.New("unused")
}

type panicAsyncCloseConn struct {
	net.Conn
	closed chan struct{}
}

func (c *panicAsyncCloseConn) Close() error {
	close(c.closed)
	panic("async close panic")
}

func (*closeRecordingListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *closeRecordingListener) Close() error {
	l.closed = true
	return nil
}
