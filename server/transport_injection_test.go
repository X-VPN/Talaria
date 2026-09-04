// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestStartTalariaTCPUsesInjectedTransportWithoutCertificate(t *testing.T) {
	transport := newInjectedServerTransport()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := Start(ctx, Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("injected transport did not start")
	}
	if srv.Addr() != transport.Addr().String() {
		t.Fatalf("server addr = %q want %q", srv.Addr(), transport.Addr())
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerWaitCompletesAfterClose(t *testing.T) {
	transport := newInjectedServerTransport()
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("injected transport did not start")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Wait(ctx); err != nil {
		t.Fatalf("wait after close: %v", err)
	}
	select {
	case <-srv.Done():
	default:
		t.Fatal("server done channel is still open")
	}
}

func TestServerDoneWaitsForCleanupAddedDuringClose(t *testing.T) {
	transport := newInjectedServerTransport()
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("injected transport did not start")
	}

	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	if _, err := srv.activateSession(activeServerSessionConfig{
		Ref: coretransport.SessionRef{ClientID: 42, Generation: 1},
		RevokeData: func() {
			close(cleanupStarted)
			<-releaseCleanup
		},
	}); err != nil {
		t.Fatal(err)
	}

	srv.packetAttachMu.Lock()
	closeResult := make(chan error, 1)
	go func() { closeResult <- srv.Close() }()
	select {
	case <-transport.stopped:
	case <-time.After(time.Second):
		srv.packetAttachMu.Unlock()
		t.Fatal("transport did not stop after server cancellation")
	}
	select {
	case <-srv.Done():
		srv.packetAttachMu.Unlock()
		t.Fatal("server reported done before close registered cleanup")
	case <-time.After(20 * time.Millisecond):
	}
	srv.packetAttachMu.Unlock()

	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("session cleanup did not start")
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server close waited for session cleanup")
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed before physical session cleanup finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCleanup)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestServerDoneWaitsForBuiltinTunCleanup(t *testing.T) {
	device := newBlockingWriteTunDevice()
	device.holdWrite = make(chan struct{})
	var releaseWriteOnce sync.Once
	releaseWrite := func() { releaseWriteOnce.Do(func() { close(device.holdWrite) }) }
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        device,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
		Cleanup: func() error {
			close(cleanupStarted)
			<-releaseCleanup
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseWrite()
		release()
		_ = handler.Close()
	})
	transport := newInjectedServerTransport()
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: handler,
		Transport:     transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := SessionContext{ClientID: 42, Generation: 1}
	if _, err := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("built-in TUN write did not start")
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed before built-in TUN write finished")
	case <-time.After(20 * time.Millisecond):
	}
	releaseWrite()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("built-in TUN cleanup did not start")
	}
	select {
	case <-srv.Done():
		t.Fatal("server Done closed before built-in TUN cleanup finished")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestServerStopsAfterTalariaTCPTransportServeFailure(t *testing.T) {
	want := errors.New("synthetic TalariaTCP transport serve failure")
	transport := newFailingServerTransport(want)
	logged := make(chan error, 1)
	srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
		ErrorLog: func(scope string, err error) {
			if scope == "TalariaTCP transport serve" {
				logged <- err
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Wait(ctx); err != nil {
		t.Fatalf("wait after transport failure: %v", err)
	}
	select {
	case err := <-logged:
		if !errors.Is(err, want) {
			t.Fatalf("logged error = %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("TalariaTCP transport failure was not logged")
	}
	select {
	case <-transport.closed:
	default:
		t.Fatal("failed TalariaTCP transport was not closed")
	}
}

func TestStartTalariaTCPClosesTransportAfterAddressFailure(t *testing.T) {
	transport := &nilAddrServerTransport{injectedServerTransport: newInjectedServerTransport()}
	if srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	}); err == nil {
		_ = srv.Close()
		t.Fatal("transport with no address was accepted")
	}
	select {
	case <-transport.closed:
	default:
		t.Fatal("transport was not closed after address validation failed")
	}
}

func TestStartTalariaTCPClosesTransportWithoutStagedActivation(t *testing.T) {
	base := newInjectedServerTransport()
	transport := &nonStagedServerTransport{base: base}
	if srv, err := Start(context.Background(), Config{
		Protocol: client.ProtocolTalariaTCP,
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		PacketHandler: EchoPacketHandler{},
		Transport:     transport,
	}); err == nil {
		_ = srv.Close()
		t.Fatal("transport without staged activation was accepted")
	}
	select {
	case <-base.closed:
	default:
		t.Fatal("transport was not closed after staged activation validation failed")
	}
}

func TestStartRejectsUnsafeTimeoutAndBufferConfig(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Config)
	}{
		{name: "negative read buffer", apply: func(cfg *Config) { cfg.ReadBufferSize = -1 }},
		{name: "oversized read buffer", apply: func(cfg *Config) { cfg.ReadBufferSize = maxServeReadBufferSize + 1 }},
		{name: "negative auth timeout", apply: func(cfg *Config) { cfg.AuthTimeout = -time.Second }},
		{name: "oversized auth timeout", apply: func(cfg *Config) { cfg.AuthTimeout = maxServerAuthTimeout + time.Second }},
		{name: "negative idle timeout", apply: func(cfg *Config) { cfg.SessionIdleTimeout = -time.Second }},
		{name: "negative write timeout", apply: func(cfg *Config) { cfg.SessionWriteTimeout = -time.Second }},
		{name: "negative session ttl", apply: func(cfg *Config) { cfg.SessionTTL = -time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Protocol: client.ProtocolTalariaTCP,
				Auth: StaticAuthProvider{
					ClientID:         "client",
					SecretKey:        "secret",
					AssignedClientID: 42,
				},
				PacketHandler: EchoPacketHandler{},
				Transport:     newInjectedServerTransport(),
			}
			tt.apply(&cfg)
			if srv, err := Start(context.Background(), cfg); err == nil {
				_ = srv.Close()
				t.Fatal("unsafe config was accepted")
			}
		})
	}
}

type injectedServerTransport struct {
	started chan struct{}
	stopped chan struct{}
	closed  chan struct{}
	once    sync.Once
}

type failingServerTransport struct {
	*injectedServerTransport
	err error
}

type nilAddrServerTransport struct{ *injectedServerTransport }

func (*nilAddrServerTransport) Addr() net.Addr { return nil }

type nonStagedServerTransport struct {
	base *injectedServerTransport
}

func (t *nonStagedServerTransport) Serve(ctx context.Context, control coretransport.ControlHandler, streams coretransport.StreamHandler) error {
	return t.base.Serve(ctx, control, streams)
}

func (t *nonStagedServerTransport) Activate(ctx context.Context, grant coretransport.SessionGrant) error {
	return t.base.Activate(ctx, grant)
}

func (t *nonStagedServerTransport) Revoke(ctx context.Context, session coretransport.SessionRef) error {
	return t.base.Revoke(ctx, session)
}

func (t *nonStagedServerTransport) Addr() net.Addr { return t.base.Addr() }
func (t *nonStagedServerTransport) Close() error   { return t.base.Close() }

func newFailingServerTransport(err error) *failingServerTransport {
	return &failingServerTransport{injectedServerTransport: newInjectedServerTransport(), err: err}
}

func (t *failingServerTransport) Serve(context.Context, coretransport.ControlHandler, coretransport.StreamHandler) error {
	close(t.started)
	return t.err
}

func newInjectedServerTransport() *injectedServerTransport {
	return &injectedServerTransport{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (t *injectedServerTransport) Serve(ctx context.Context, _ coretransport.ControlHandler, _ coretransport.StreamHandler) error {
	close(t.started)
	defer close(t.stopped)
	select {
	case <-ctx.Done():
	case <-t.closed:
	}
	return nil
}

func (t *injectedServerTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (t *injectedServerTransport) Prepare(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (t *injectedServerTransport) Commit(context.Context, coretransport.SessionRef) error {
	return nil
}

func (t *injectedServerTransport) Finalize(context.Context, coretransport.SessionRef) error {
	return nil
}

func (t *injectedServerTransport) Revoke(context.Context, coretransport.SessionRef) error {
	return nil
}

func (t *injectedServerTransport) Addr() net.Addr { return injectedAddr("127.0.0.1:9443") }

func (t *injectedServerTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type injectedAddr string

func (a injectedAddr) Network() string { return "tcp" }
func (a injectedAddr) String() string  { return string(a) }
