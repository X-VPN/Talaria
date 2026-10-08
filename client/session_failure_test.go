// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestSessionFailsWhenAsynchronousTunWriteFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tunErr := errors.New("forced tun write failure")
	tun := &failingWriteTun{testMemoryTun: newTestMemoryTun(4), err: tunErr}
	events := &recordingEvents{errors: make(chan error, 4)}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{
		Dialer: testDialer{Handler: func(ctx context.Context, conn net.Conn) error {
			return servePacketEcho(ctx, conn, packetEchoOptions{
				ClientID:         "test-client",
				SecretKey:        "test-secret",
				AssignedClientID: 7,
				Version:          1,
			})
		}},
		Tun:    staticTunProvider{tun: tun},
		Events: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	if err := tun.Inject(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-ctx.Done():
		t.Fatal("session did not stop after TUN write failure")
	}
	select {
	case got := <-events.errors:
		if !strings.Contains(got.Error(), tunErr.Error()) {
			t.Fatalf("reported error = %v, want %v", got, tunErr)
		}
	default:
		t.Fatal("TUN write failure was not reported")
	}
}

func TestTalariaUDPServerErrorCancelsBlockedTunWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tun := newBlockingContextTun()
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{
		Dialer: testDialer{Handler: func(ctx context.Context, conn net.Conn) error {
			return servePacketEcho(ctx, conn, packetEchoOptions{
				ClientID:         "test-client",
				SecretKey:        "test-secret",
				AssignedClientID: 7,
				Version:          1,
				InitialData:      payload,
				RejectAfterData:  true,
			})
		}},
		Tun: staticTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tun.writeStarted:
	case <-ctx.Done():
		t.Fatal("TalariaUDP TUN write did not start")
	}
	select {
	case <-sess.Done():
	case <-ctx.Done():
		t.Fatal("TalariaUDP session did not stop after server rejection")
	}
	select {
	case <-tun.writeCanceled:
	default:
		t.Fatal("TalariaUDP TUN write did not observe cancellation")
	}
}

func TestTalariaTCPSessionCloseCancelsBlockedTunWrites(t *testing.T) {
	tests := []struct {
		name     string
		protocol client.Protocol
		kind     string
	}{
		{name: "TalariaTCP ordinary", protocol: client.ProtocolTalariaTCP, kind: "ordinary"},
		{name: "TalariaTCP borrowed", protocol: client.ProtocolTalariaTCP, kind: "borrowed"},
		{name: "TalariaTCP buffered", protocol: client.ProtocolTalariaTCP, kind: "buffered"},
	}
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tun := newBlockingContextTun()
			var endpoint client.EndpointConn
			var inject func()
			var released func() bool
			switch tt.kind {
			case "ordinary":
				ordinary := newFakeEndpoint()
				endpoint = ordinary
				inject = func() { ordinary.incoming <- &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: payload} }
			case "borrowed":
				borrowed := newFakeBorrowedEndpoint()
				endpoint = borrowed
				inject = func() { borrowed.borrowedPayloads <- payload }
				released = func() bool { return borrowed.releaseCount.Load() == 1 }
			case "buffered":
				buffered := newFakeBufferedEndpoint()
				endpoint = buffered
				inject = func() { buffered.bufferedPayloads <- payload }
			}
			sess, err := client.NewSession(client.Config{
				Protocol:  tt.protocol,
				ClientID:  "test-client",
				SecretKey: "test-secret",
				MTU:       1500,
			}, client.Deps{
				Endpoint: fakeEndpointProvider{endpoint: endpoint},
				Tun:      staticTunProvider{tun: tun},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			inject()
			select {
			case <-tun.writeStarted:
			case <-time.After(time.Second):
				t.Fatal("TalariaTCP TUN write did not start")
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- sess.Close() }()
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("TalariaTCP session Close blocked on TUN write")
			}
			select {
			case <-sess.Done():
			case <-time.After(time.Second):
				t.Fatal("TalariaTCP session Done blocked on TUN write")
			}
			select {
			case <-tun.writeCanceled:
			default:
				t.Fatal("TalariaTCP TUN write did not observe cancellation")
			}
			if released != nil && !released() {
				t.Fatal("borrowed payload was not released")
			}
		})
	}
}

func TestTalariaTCPTransportFailureCancelsBlockedTunWrites(t *testing.T) {
	tests := []struct {
		name     string
		protocol client.Protocol
		kind     string
	}{
		{name: "TalariaTCP ordinary", protocol: client.ProtocolTalariaTCP, kind: "ordinary"},
		{name: "TalariaTCP borrowed", protocol: client.ProtocolTalariaTCP, kind: "borrowed"},
		{name: "TalariaTCP buffered", protocol: client.ProtocolTalariaTCP, kind: "buffered"},
	}
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tun := newBlockingContextTun()
			var endpoint client.EndpointConn
			var injectData func()
			var injectFailure func()
			var released func() bool
			switch tt.kind {
			case "ordinary":
				ordinary := newFakeEndpoint()
				endpoint = ordinary
				injectData = func() { ordinary.incoming <- &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: payload} }
				injectFailure = func() { ordinary.incoming <- &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdErr, ErrorMessage: "rejected"} }
			case "borrowed":
				borrowed := newFakeBorrowedEndpoint()
				endpoint = borrowed
				injectData = func() { borrowed.borrowedPayloads <- payload }
				injectFailure = func() { _ = borrowed.Close() }
				released = func() bool { return borrowed.releaseCount.Load() == 1 }
			case "buffered":
				buffered := newFakeBufferedEndpoint()
				endpoint = buffered
				injectData = func() { buffered.bufferedPayloads <- payload }
				injectFailure = func() { buffered.incoming <- &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdErr, ErrorMessage: "rejected"} }
			}
			sess, err := client.NewSession(client.Config{
				Protocol:  tt.protocol,
				ClientID:  "test-client",
				SecretKey: "test-secret",
				MTU:       1500,
			}, client.Deps{
				Endpoint: fakeEndpointProvider{endpoint: endpoint},
				Tun:      staticTunProvider{tun: tun},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			if err := sess.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			injectData()
			select {
			case <-tun.writeStarted:
			case <-time.After(time.Second):
				t.Fatal("TalariaTCP TUN write did not start")
			}
			injectFailure()
			select {
			case <-sess.Done():
			case <-time.After(time.Second):
				t.Fatal("TalariaTCP transport failure did not stop blocked TUN write")
			}
			select {
			case <-tun.writeCanceled:
			default:
				t.Fatal("TalariaTCP TUN write did not observe transport failure cancellation")
			}
			if released != nil && !released() {
				t.Fatal("borrowed payload was not released exactly once")
			}
		})
	}
}

func TestSessionFailsWhenAsynchronousConnWriteFails(t *testing.T) {
	writeErr := errors.New("forced connection write failure")
	tun := newTestMemoryTun(4)
	events := &recordingEvents{errors: make(chan error, 4)}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{
		Dialer: failingDataWriteDialer{
			err: writeErr,
			handler: func(ctx context.Context, conn net.Conn) error {
				return servePacketEcho(ctx, conn, packetEchoOptions{
					ClientID:         "test-client",
					SecretKey:        "test-secret",
					AssignedClientID: 7,
					Version:          1,
				})
			},
		},
		Tun:    staticTunProvider{tun: tun},
		Events: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	if err := tun.Inject(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not stop after asynchronous connection write failure")
	}
	if got := sess.Err(); got == nil || !strings.Contains(got.Error(), writeErr.Error()) {
		t.Fatalf("session error = %v, want %v", got, writeErr)
	}
	select {
	case got := <-events.errors:
		if !strings.Contains(got.Error(), writeErr.Error()) {
			t.Fatalf("reported error = %v, want %v", got, writeErr)
		}
	default:
		t.Fatal("connection write failure was not reported")
	}
}

func TestSessionStateCallbackCanCloseSession(t *testing.T) {
	events := &closingEvents{}
	sess, err := client.NewSession(client.Config{
		Protocol:  client.ProtocolTalariaUDP,
		ClientID:  "test-client",
		SecretKey: "test-secret",
	}, client.Deps{
		Dialer: canceledDialer{},
		Tun:    staticTunProvider{tun: newTestMemoryTun(4)},
		Events: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	events.session = sess

	done := make(chan error, 1)
	go func() { done <- sess.Start(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("state callback deadlocked while closing the session")
	}
}

func TestCloseDuringEndpointDialClosesLateEndpoint(t *testing.T) {
	endpoint := newFakeEndpoint()
	provider := &blockingEndpointProvider{
		endpoint: endpoint,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	tunProvider := &countingTunProvider{}
	sess, err := client.NewSession(client.Config{
		Protocol:  client.ProtocolTalariaUDP,
		ClientID:  "test-client",
		SecretKey: "test-secret",
	}, client.Deps{Endpoint: provider, Tun: tunProvider})
	if err != nil {
		t.Fatal(err)
	}
	startDone := make(chan error, 1)
	go func() { startDone <- sess.Start(context.Background()) }()
	<-provider.entered
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	close(provider.release)

	select {
	case err := <-startDone:
		if err == nil {
			t.Fatal("Start succeeded after the session was closed")
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after late endpoint completion")
	}
	select {
	case <-endpoint.closed:
	default:
		t.Fatal("endpoint returned after cancellation was leaked")
	}
	if got := tunProvider.calls.Load(); got != 0 {
		t.Fatalf("TUN establish calls = %d, want 0", got)
	}
}

func TestSessionDoesNotEstablishTunBeforeReady(t *testing.T) {
	tests := []struct {
		name     string
		response *vpnpacket.VpnPacket
	}{
		{
			name:     "server rejects session",
			response: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdErr, ErrorMessage: "session attach failed"},
		},
		{
			name:     "unexpected packet",
			response: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive, ClientId: 7},
		},
		{
			name:     "mismatched ready identity",
			response: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdSessionReady, ClientId: 8},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunProvider := &countingTunProvider{}
			sess, err := client.NewSession(client.Config{
				Protocol:    client.ProtocolTalariaUDP,
				ClientID:    "test-client",
				SecretKey:   "test-secret",
				AuthTimeout: time.Second,
			}, client.Deps{
				Dialer: testDialer{Handler: func(ctx context.Context, conn net.Conn) error {
					codec := dataplane.WireCodec{}
					buf := make([]byte, 2048)
					n, err := conn.Read(buf)
					if err != nil {
						return err
					}
					packet, _, err := codec.Decode(buf[:n])
					if err != nil {
						return err
					}
					if packet.Cmd != vpnpacket.CmdAuthRequest {
						return errors.New("expected auth request")
					}
					for _, response := range []*vpnpacket.VpnPacket{
						{Cmd: vpnpacket.CmdAuthSuccess, NewClientId: 7, Version: 1},
						tt.response,
					} {
						raw, err := codec.Encode(response)
						if err != nil {
							return err
						}
						if _, err := conn.Write(raw); err != nil {
							return err
						}
					}
					<-ctx.Done()
					return nil
				}},
				Tun: tunProvider,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.Start(context.Background()); err == nil {
				t.Fatal("Start succeeded without a valid session-ready response")
			}
			if got := tunProvider.calls.Load(); got != 0 {
				t.Fatalf("TUN establish calls = %d, want 0", got)
			}
		})
	}
}

func TestSessionRejectsAuthenticationDeadlineResetFailure(t *testing.T) {
	want := errors.New("synthetic authentication deadline reset failure")
	tunProvider := &countingTunProvider{}
	sess, err := client.NewSession(client.Config{
		Protocol:    client.ProtocolTalariaUDP,
		ClientID:    "test-client",
		SecretKey:   "test-secret",
		AuthTimeout: time.Second,
	}, client.Deps{
		Dialer: deadlineResetFailureDialer{
			err: want,
			handler: func(ctx context.Context, conn net.Conn) error {
				return servePacketEcho(ctx, conn, packetEchoOptions{
					ClientID:         "test-client",
					SecretKey:        "test-secret",
					AssignedClientID: 7,
					Version:          1,
				})
			},
		},
		Tun: tunProvider,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start error = %v, want %v", err, want)
	}
	if got := tunProvider.calls.Load(); got != 0 {
		t.Fatalf("TUN establish calls = %d, want 0", got)
	}
}

func TestNewSessionRejectsUnsafeConfiguration(t *testing.T) {
	deps := client.Deps{Dialer: canceledDialer{}, Tun: staticTunProvider{tun: newTestMemoryTun(4)}}
	for _, cfg := range []client.Config{
		{Protocol: client.Protocol("TalariaTCP ")},
		{Protocol: client.Protocol("unsupported")},
		{MTU: -1},
		{MTU: 9001},
		{UplinkQueueSize: -1},
		{UplinkQueueSize: 1<<16 + 1},
		{DownlinkQueueSize: -1},
		{DownlinkQueueSize: 1<<16 + 1},
		{AuthTimeout: -time.Second},
		{KeepAliveDuration: -time.Second},
		{ClientID: strings.Repeat("a", 256)},
		{SecretKey: strings.Repeat("b", 256)},
	} {
		if _, err := client.NewSession(cfg, deps); err == nil {
			t.Fatalf("unsafe config was accepted: %+v", cfg)
		}
	}
}

type failingWriteTun struct {
	*testMemoryTun
	err error
}

type blockingContextTun struct {
	readClosed    chan struct{}
	writeStarted  chan struct{}
	writeCanceled chan struct{}
	startOnce     sync.Once
	cancelOnce    sync.Once
	closeOnce     sync.Once
}

func newBlockingContextTun() *blockingContextTun {
	return &blockingContextTun{
		readClosed:    make(chan struct{}),
		writeStarted:  make(chan struct{}),
		writeCanceled: make(chan struct{}),
	}
}

func (t *blockingContextTun) Read([]byte) (int, error) {
	<-t.readClosed
	return 0, io.ErrClosedPipe
}

func (*blockingContextTun) Write([]byte) (int, error) {
	return 0, errors.New("non-context TUN write")
}

func (t *blockingContextTun) WriteContext(ctx context.Context, p []byte) (int, error) {
	t.startOnce.Do(func() { close(t.writeStarted) })
	<-ctx.Done()
	t.cancelOnce.Do(func() { close(t.writeCanceled) })
	return 0, ctx.Err()
}

func (t *blockingContextTun) WritePacketOffset(ctx context.Context, _ []byte, _ int, _ int) (int, error) {
	return t.WriteContext(ctx, nil)
}

func (t *blockingContextTun) Close() error {
	t.closeOnce.Do(func() { close(t.readClosed) })
	return nil
}

type failingDataWriteDialer struct {
	handler func(context.Context, net.Conn) error
	err     error
}

type deadlineResetFailureDialer struct {
	handler func(context.Context, net.Conn) error
	err     error
}

func (d deadlineResetFailureDialer) Dial(ctx context.Context, _ client.DialRequest) (net.Conn, error) {
	clientConn, serverConn := newPacketConnPair()
	go func() { _ = d.handler(ctx, serverConn) }()
	return &readDeadlineResetFailureConn{Conn: clientConn, err: d.err}, nil
}

type readDeadlineResetFailureConn struct {
	net.Conn
	err error
}

func (c *readDeadlineResetFailureConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return c.err
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (d failingDataWriteDialer) Dial(ctx context.Context, _ client.DialRequest) (net.Conn, error) {
	clientConn, serverConn := newPacketConnPair()
	go func() { _ = d.handler(ctx, serverConn) }()
	return &failAfterWriteConn{Conn: clientConn, successfulWrites: 1, err: d.err}, nil
}

type failAfterWriteConn struct {
	net.Conn
	mu               sync.Mutex
	successfulWrites int
	writes           int
	err              error
}

func (c *failAfterWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writes >= c.successfulWrites {
		return 0, c.err
	}
	c.writes++
	return c.Conn.Write(p)
}

func (t *failingWriteTun) Write([]byte) (int, error) {
	return 0, t.err
}

func (t *failingWriteTun) WriteContext(context.Context, []byte) (int, error) {
	return 0, t.err
}

func (t *failingWriteTun) WritePacketOffset(context.Context, []byte, int, int) (int, error) {
	return 0, t.err
}

type recordingEvents struct {
	errors chan error
}

func (*recordingEvents) OnStateChange(context.Context, client.State)               {}
func (*recordingEvents) OnConnectStage(context.Context, string, map[string]string) {}
func (e *recordingEvents) OnError(_ context.Context, err error) {
	select {
	case e.errors <- err:
	default:
	}
}

type closingEvents struct {
	session client.Session
	once    sync.Once
}

func (e *closingEvents) OnStateChange(_ context.Context, state client.State) {
	if state == client.StateDialing {
		e.once.Do(func() { _ = e.session.Close() })
	}
}
func (*closingEvents) OnConnectStage(context.Context, string, map[string]string) {}
func (*closingEvents) OnError(context.Context, error)                            {}

type canceledDialer struct{}

func (canceledDialer) Dial(ctx context.Context, _ client.DialRequest) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type blockingEndpointProvider struct {
	endpoint client.EndpointConn
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (p *blockingEndpointProvider) DialEndpoint(context.Context, client.EndpointDialRequest) (client.EndpointConn, error) {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.endpoint, nil
}

type countingTunProvider struct {
	calls atomic.Int32
}

func (p *countingTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	p.calls.Add(1)
	return nil, io.ErrClosedPipe
}

func TestCancelStartContextClosesSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tun := newTestMemoryTun(4)
	dialer := testDialer{
		Handler: func(ctx context.Context, conn net.Conn) error {
			return servePacketEcho(ctx, conn, packetEchoOptions{
				ClientID:         "test-client",
				SecretKey:        "test-secret",
				AssignedClientID: 7,
				Version:          1,
			})
		},
	}
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		MTU:        1500,
	}, client.Deps{
		Dialer: dialer,
		Tun:    staticTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sess.State(); got != client.StateConnected {
		t.Fatalf("state before cancel = %s, want %s", got, client.StateConnected)
	}

	cancel()

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not fire after the Start context was cancelled")
	}
	if got := sess.State(); got != client.StateClosed {
		t.Fatalf("state after cancel = %s, want %s", got, client.StateClosed)
	}
}

var _ client.EventSink = (*recordingEvents)(nil)
var _ client.EventSink = (*closingEvents)(nil)
var _ client.EndpointConn = (*fakeEndpoint)(nil)
var _ platform.Tun = (*failingWriteTun)(nil)
