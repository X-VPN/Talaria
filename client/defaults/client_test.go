// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package defaults

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
	talariaTCPDevice "github.com/X-VPN/Talaria/client/flowrelay"
	"github.com/X-VPN/Talaria/internal/controlframe"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestAuthenticateControlRejectsDeadlineFailure(t *testing.T) {
	want := errors.New("synthetic control deadline failure")
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	_, err := authenticateControlConn(context.Background(), &failingDeadlineConn{Conn: conn, err: want}, client.EndpointDialRequest{
		ClientID:  "client",
		SecretKey: "secret",
	})
	if !errors.Is(err, want) {
		t.Fatalf("control authentication error = %v, want %v", err, want)
	}
}

func TestWriteControlFrameRejectsShortWrite(t *testing.T) {
	if err := writeControlFrame(shortWriteControlConn{}, []byte{1, 2}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeControlFrame() error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestReadControlFrameRejectsInvalidProgress(t *testing.T) {
	for _, readErr := range []error{nil, errors.New("synthetic read failure")} {
		for _, n := range []int{-1, 2} {
			read, err := readControlFrame(invalidReadControlConn{n: n, err: readErr}, make([]byte, 1))
			if read != 0 || err == nil {
				t.Fatalf("readControlFrame() with progress %d and error %v = %d, %v; want 0, error", n, readErr, read, err)
			}
		}
	}
}

type shortWriteControlConn struct{ net.Conn }

func (shortWriteControlConn) Write([]byte) (int, error) { return 1, nil }

type invalidReadControlConn struct {
	net.Conn
	n   int
	err error
}

func (c invalidReadControlConn) Read([]byte) (int, error) {
	return c.n, c.err
}

func TestAuthenticateControlClassifiesServerRejection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		if _, err := serverConn.Read(buf); err != nil {
			serverDone <- err
			return
		}
		raw, err := (dataplane.WireCodec{}).Encode(&vpnpacket.VpnPacket{
			Cmd:          vpnpacket.CmdErr,
			ErrorMessage: "credentials rejected",
		})
		if err == nil {
			_, err = serverConn.Write(raw)
		}
		serverDone <- err
	}()
	_, err := authenticateControlConn(context.Background(), clientConn, client.EndpointDialRequest{
		ClientID:  "client",
		SecretKey: "secret",
	})
	if !errors.Is(err, client.ErrAuthRejected) {
		t.Fatalf("authentication error = %v, want ErrAuthRejected", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTalariaTCPEndpointProviderRejectsTypedNilTransport(t *testing.T) {
	var transport *injectedClientTransport
	_, err := (TalariaTCPEndpointProvider{Options: ClientOptions{
		Domain:    "example.com",
		Transport: transport,
	}}).DialEndpoint(context.Background(), client.EndpointDialRequest{
		Protocol:   client.ProtocolTalariaTCP,
		ServerPort: 443,
	})
	if err == nil {
		t.Fatal("typed-nil TalariaTCP transport was accepted")
	}
}

func TestTalariaTCPEndpointProviderClosesControlConnReturnedWithError(t *testing.T) {
	control, peer := net.Pipe()
	defer peer.Close()
	want := errors.New("control dial failed")
	transport := &dialErrorClientTransport{control: control, err: want}
	_, err := (TalariaTCPEndpointProvider{Options: ClientOptions{
		Domain:    "example.com",
		Transport: transport,
	}}).DialEndpoint(context.Background(), client.EndpointDialRequest{
		Protocol:   client.ProtocolTalariaTCP,
		ServerPort: 443,
	})
	if !errors.Is(err, want) {
		t.Fatalf("DialEndpoint() error = %v, want %v", err, want)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := peer.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("control connection returned with an error was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed control connection to close")
	}
}

func TestTalariaTCPEndpointControlLoopRecoversConnectionPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := &talariaTCPEndpoint{ctrlConn: panicReadControlConn{}, cancel: cancel}
	done := make(chan struct{})
	go func() {
		endpoint.runControlLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control loop did not stop after connection panic")
	}
	endpoint.errMu.RLock()
	err := endpoint.controlErr
	endpoint.errMu.RUnlock()
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("control loop panic error = %v, want extension panic", err)
	}
}

func TestTalariaTCPEndpointCloseContinuesAndAllowsReentry(t *testing.T) {
	transport := &callbackClientTransport{}
	endpoint := &talariaTCPEndpoint{ctrlConn: panicCloseControlConn{}, transport: transport}
	transport.onClose = func() { _ = endpoint.Close() }
	done := make(chan error, 1)
	go func() { done <- endpoint.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("endpoint close error = %v, want extension panic", err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint Close deadlocked on transport reentry")
	}
	if !transport.closed {
		t.Fatal("transport was not closed after control connection panic")
	}
}

func TestAuthenticateControlRejectsDeadlineResetFailure(t *testing.T) {
	want := errors.New("synthetic control deadline reset failure")
	clientRaw, serverRaw := net.Pipe()
	clientConn := controlframe.New(clientRaw)
	serverConn := controlframe.New(serverRaw)
	defer clientConn.Close()
	go serveInjectedControl(t, serverConn)

	_, err := authenticateControlConn(context.Background(), &failingDeadlineResetConn{Conn: clientConn, err: want}, client.EndpointDialRequest{
		ClientID:  "client",
		SecretKey: "secret",
	})
	if !errors.Is(err, want) {
		t.Fatalf("control authentication error = %v, want %v", err, want)
	}
}

func TestAuthenticateControlCancellationInterruptsWrite(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	started := make(chan struct{})
	conn := &observedWriteConn{Conn: clientConn, started: started}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := authenticateControlConn(ctx, conn, client.EndpointDialRequest{
			ClientID:    "client",
			SecretKey:   "secret",
			AuthTimeout: time.Minute,
		})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("control authentication did not start its request write")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("control authentication cancel error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control authentication write was not interrupted by cancellation")
	}
}

type failingDeadlineConn struct {
	net.Conn
	err error
}

type observedWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type panicReadControlConn struct{ net.Conn }

func (panicReadControlConn) Read([]byte) (int, error) { panic("boom") }
func (panicReadControlConn) Close() error             { return nil }

type panicCloseControlConn struct{ net.Conn }

func (panicCloseControlConn) Close() error { panic("boom") }

type callbackClientTransport struct {
	onClose func()
	closed  bool
}

type dialErrorClientTransport struct {
	control net.Conn
	err     error
}

func (t *dialErrorClientTransport) DialControl(context.Context) (net.Conn, error) {
	return t.control, t.err
}

func (*dialErrorClientTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (*dialErrorClientTransport) DialStream(context.Context, coretransport.Destination) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*dialErrorClientTransport) Close() error { return nil }

func (*callbackClientTransport) DialControl(context.Context) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (*callbackClientTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (*callbackClientTransport) DialStream(context.Context, coretransport.Destination) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *callbackClientTransport) Close() error {
	t.closed = true
	if t.onClose != nil {
		t.onClose()
	}
	return nil
}

func (c *failingDeadlineConn) SetDeadline(time.Time) error { return c.err }

type failingDeadlineResetConn struct {
	net.Conn
	err error
}

func (c *failingDeadlineResetConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.err
	}
	return c.Conn.SetDeadline(deadline)
}

func TestNewDepsSelectsOnlySupportedProtocols(t *testing.T) {
	tests := []struct {
		name         string
		protocol     client.Protocol
		wantDialer   bool
		wantEndpoint bool
	}{
		{name: "empty defaults to TalariaUDP", wantDialer: true},
		{name: "TalariaUDP", protocol: client.ProtocolTalariaUDP, wantDialer: true},
		{name: "TalariaTCP", protocol: client.ProtocolTalariaTCP, wantEndpoint: true},
		{name: "unknown", protocol: client.Protocol("unsupported")},
		{name: "whitespace", protocol: client.Protocol("TalariaTCP ")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := NewDeps(client.Config{Protocol: tt.protocol}, nil, ClientOptions{})
			if got := deps.Dialer != nil; got != tt.wantDialer {
				t.Fatalf("Dialer selected = %t, want %t", got, tt.wantDialer)
			}
			if got := deps.Endpoint != nil; got != tt.wantEndpoint {
				t.Fatalf("Endpoint selected = %t, want %t", got, tt.wantEndpoint)
			}
		})
	}
}

func TestTransportProvidersRejectUnexpectedProtocolsBeforeDial(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "TalariaUDP provider rejects TalariaTCP",
			run: func() error {
				_, err := (TalariaUDPDialerProvider{}).Dial(context.Background(), client.DialRequest{Protocol: client.ProtocolTalariaTCP})
				return err
			},
		},
		{
			name: "TalariaUDP provider rejects unknown",
			run: func() error {
				_, err := (TalariaUDPDialerProvider{}).Dial(context.Background(), client.DialRequest{Protocol: client.Protocol("unsupported")})
				return err
			},
		},
		{
			name: "TalariaTCP provider rejects unknown",
			run: func() error {
				_, err := (TalariaTCPEndpointProvider{}).DialEndpoint(context.Background(), client.EndpointDialRequest{Protocol: client.Protocol("unsupported")})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil {
				t.Fatal("unexpected protocol was accepted")
			}
		})
	}
}

func TestTalariaTCPEndpointSendsControlKeepAlive(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	clientConn := controlframe.New(clientRaw)
	serverConn := controlframe.New(serverRaw)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer serverConn.Close()

	endpoint := &talariaTCPEndpoint{
		ctrlConn:          clientConn,
		device:            new(talariaTCPDevice.TUN),
		clientID:          42,
		keepAliveInterval: 10 * time.Millisecond,
		keepAliveTimeout:  500 * time.Millisecond,
	}
	initialReceive := time.Now()
	endpoint.markControlReceive(initialReceive)
	go endpoint.runControlLoop(ctx)
	go endpoint.runControlKeepAlive(ctx)

	codec := dataplane.WireCodec{}
	buf := make([]byte, 2048)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, err := codec.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if packet.Cmd != vpnpacket.CmdKeepAlive || !packet.IsPing || packet.ClientId != 42 {
		t.Fatalf("keepalive packet = %+v", packet)
	}
	response, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:         vpnpacket.CmdKeepAlive,
		ClientId:    42,
		KeepAliveId: packet.KeepAliveId,
		SendTime:    packet.SendTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverConn.Write(response); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for endpoint.lastControlRecv.Load() <= initialReceive.UnixNano() {
		if time.Now().After(deadline) {
			t.Fatal("control keepalive response did not refresh liveness")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	_ = clientConn.Close()
}

func TestTalariaTCPEndpointUsesInjectedClientTransport(t *testing.T) {
	transport := newInjectedClientTransport(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint, err := (TalariaTCPEndpointProvider{Options: ClientOptions{Transport: transport}}).DialEndpoint(ctx, client.EndpointDialRequest{
		Protocol:   client.ProtocolTalariaTCP,
		ClientID:   "client",
		SecretKey:  "secret",
		ServerIP:   "127.0.0.1",
		Domain:     "example.com",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if endpoint.ClientID() != 42 {
		t.Fatalf("client id = %d want 42", endpoint.ClientID())
	}
	grant := transport.activatedGrant()
	if grant.ClientID != 42 || grant.Generation != 7 {
		t.Fatalf("activated grant = %+v", grant.SessionRef)
	}
}

func TestAuthenticateControlConnRequiresSessionReady(t *testing.T) {
	tests := []struct {
		name  string
		final *vpnpacket.VpnPacket
	}{
		{
			name:  "server rejects attach",
			final: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdErr, ErrorMessage: "attach failed"},
		},
		{
			name:  "ready identity mismatch",
			final: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdSessionReady, ClientId: 43},
		},
		{
			name:  "unexpected final packet",
			final: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive, ClientId: 42},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			clientConn := controlframe.New(clientRaw)
			serverConn := controlframe.New(serverRaw)
			defer clientConn.Close()
			defer serverConn.Close()
			go func() {
				codec := dataplane.WireCodec{}
				buf := make([]byte, 2048)
				if _, err := serverConn.Read(buf); err != nil {
					return
				}
				writeInjectedPacket(t, codec, serverConn, &vpnpacket.VpnPacket{
					Cmd:         vpnpacket.CmdAuthSuccess,
					NewClientId: 42,
					Version:     1,
				})
				writeInjectedPacket(t, codec, serverConn, &vpnpacket.VpnPacket{
					Cmd:               vpnpacket.CmdSessionGrant,
					ClientId:          42,
					SessionGeneration: 7,
					SessionExpiresAt:  time.Now().Add(time.Minute).Unix(),
					SessionDataToken:  bytes.Repeat([]byte{1}, coretransport.DataTokenSize),
				})
				writeInjectedPacket(t, codec, serverConn, tt.final)
			}()
			if _, err := authenticateControlConn(context.Background(), clientConn, client.EndpointDialRequest{
				ClientID:  "client",
				SecretKey: "secret",
			}); err == nil {
				t.Fatal("control authentication succeeded without a valid session-ready response")
			}
		})
	}
}

type injectedClientTransport struct {
	control net.Conn

	mu        sync.Mutex
	activated coretransport.SessionGrant
}

func newInjectedClientTransport(t *testing.T) *injectedClientTransport {
	clientConn, serverConn := net.Pipe()
	transport := &injectedClientTransport{control: controlframe.New(clientConn)}
	go serveInjectedControl(t, controlframe.New(serverConn))
	return transport
}

func (t *injectedClientTransport) DialControl(context.Context) (net.Conn, error) {
	return t.control, nil
}

func (t *injectedClientTransport) Activate(_ context.Context, grant coretransport.SessionGrant) error {
	t.mu.Lock()
	t.activated = grant
	t.mu.Unlock()
	return nil
}

func (t *injectedClientTransport) DialStream(context.Context, coretransport.Destination) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (t *injectedClientTransport) Close() error { return t.control.Close() }

func (t *injectedClientTransport) activatedGrant() coretransport.SessionGrant {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.activated
}

func serveInjectedControl(t *testing.T, conn net.Conn) {
	defer conn.Close()
	codec := dataplane.WireCodec{}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	packet, _, err := codec.Decode(buf[:n])
	if err != nil || packet.Cmd != vpnpacket.CmdAuthRequest {
		t.Errorf("auth request = %+v err=%v", packet, err)
		return
	}
	writeInjectedPacket(t, codec, conn, &vpnpacket.VpnPacket{
		Cmd:         vpnpacket.CmdAuthSuccess,
		NewClientId: 42,
		Version:     1,
	})
	writeInjectedPacket(t, codec, conn, &vpnpacket.VpnPacket{
		Cmd:               vpnpacket.CmdSessionGrant,
		ClientId:          42,
		SessionGeneration: 7,
		SessionExpiresAt:  time.Now().Add(time.Minute).Unix(),
		SessionDataToken:  bytes.Repeat([]byte{1}, coretransport.DataTokenSize),
	})
	writeInjectedPacket(t, codec, conn, &vpnpacket.VpnPacket{
		Cmd:      vpnpacket.CmdSessionReady,
		ClientId: 42,
	})
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func writeInjectedPacket(t *testing.T, codec dataplane.Codec, conn net.Conn, packet *vpnpacket.VpnPacket) {
	t.Helper()
	raw, err := codec.Encode(packet)
	if err != nil {
		t.Error(err)
		return
	}
	if _, err := conn.Write(raw); err != nil {
		t.Error(err)
	}
}
