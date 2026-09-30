// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestNewSessionRejectsTypedNilDependencies(t *testing.T) {
	var dialer *nilDialer
	if _, err := NewSession(Config{}, Deps{Dialer: dialer, Tun: inertTunProvider{}}); err == nil || !strings.Contains(err.Error(), "missing endpoint or dialer") {
		t.Fatalf("typed-nil dialer error = %v", err)
	}
	var tun *nilTunProvider
	if _, err := NewSession(Config{}, Deps{Dialer: panicDialer{}, Tun: tun}); err == nil || !strings.Contains(err.Error(), "missing tun provider") {
		t.Fatalf("typed-nil tun error = %v", err)
	}
}

func TestAuthenticationRequestWriteIsBounded(t *testing.T) {
	public, err := NewSession(Config{
		ClientID:    "id",
		SecretKey:   "secret",
		AuthTimeout: 20 * time.Millisecond,
	}, Deps{Dialer: panicDialer{}, Tun: inertTunProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	conn := &authWriteDeadlineConn{}
	started := time.Now()
	err = public.(*session).auth(context.Background(), conn)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("authentication write error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("authentication write took %s", elapsed)
	}
}

func TestAuthenticationFailureClearsSecretCopies(t *testing.T) {
	want := errors.New("synthetic auth write failure")
	public, err := NewSession(Config{ClientID: "id", SecretKey: "sensitive-secret"}, Deps{
		Dialer: panicDialer{},
		Tun:    inertTunProvider{},
	})
	if err != nil {
		t.Fatal(err)
	}
	internal := public.(*session)
	retainedSecret := internal.secretKey
	conn := &captureFailedAuthWriteConn{err: want}
	if err := internal.auth(context.Background(), conn); !errors.Is(err, want) {
		t.Fatalf("authentication error = %v, want %v", err, want)
	}
	if !bytes.Equal(retainedSecret, make([]byte, len(retainedSecret))) {
		t.Fatal("session secret bytes were not cleared after authentication failure")
	}
	if !bytes.Equal(conn.raw, make([]byte, len(conn.raw))) {
		t.Fatal("encoded authentication request was not cleared after write failure")
	}
	if internal.secretKey != nil || internal.cfg.SecretKey != "" {
		t.Fatal("session retained a secret key reference")
	}
}

func TestSessionCloseClearsUnusedSecret(t *testing.T) {
	public, err := NewSession(Config{ClientID: "id", SecretKey: "sensitive-secret"}, Deps{
		Dialer: panicDialer{},
		Tun:    inertTunProvider{},
	})
	if err != nil {
		t.Fatal(err)
	}
	internal := public.(*session)
	retainedSecret := internal.secretKey
	if err := internal.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retainedSecret, make([]byte, len(retainedSecret))) {
		t.Fatal("unused session secret bytes were not cleared on close")
	}
	if internal.secretKey != nil || internal.cfg.SecretKey != "" {
		t.Fatal("closed session retained a secret key reference")
	}
}

type captureFailedAuthWriteConn struct {
	raw []byte
	err error
}

func (*captureFailedAuthWriteConn) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }
func (c *captureFailedAuthWriteConn) Write(raw []byte) (int, error) {
	c.raw = raw
	return 0, c.err
}
func (*captureFailedAuthWriteConn) Close() error                     { return nil }
func (*captureFailedAuthWriteConn) LocalAddr() net.Addr              { return nil }
func (*captureFailedAuthWriteConn) RemoteAddr() net.Addr             { return nil }
func (*captureFailedAuthWriteConn) SetDeadline(time.Time) error      { return nil }
func (*captureFailedAuthWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*captureFailedAuthWriteConn) SetWriteDeadline(time.Time) error { return nil }

type authWriteDeadlineConn struct {
	mu       sync.Mutex
	deadline time.Time
}

func (*authWriteDeadlineConn) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }

func (c *authWriteDeadlineConn) Write([]byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	if deadline.IsZero() {
		return 0, errors.New("authentication write has no deadline")
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	<-timer.C
	return 0, os.ErrDeadlineExceeded
}

func (*authWriteDeadlineConn) Close() error                { return nil }
func (*authWriteDeadlineConn) LocalAddr() net.Addr         { return nil }
func (*authWriteDeadlineConn) RemoteAddr() net.Addr        { return nil }
func (*authWriteDeadlineConn) SetDeadline(time.Time) error { return nil }
func (*authWriteDeadlineConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *authWriteDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func TestEndpointProviderTypedNilResultIsRejected(t *testing.T) {
	sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
		Endpoint: typedNilEndpointProvider{},
		Tun:      inertTunProvider{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "returned nil endpoint") {
		t.Fatalf("Start error = %v", err)
	}
}

func TestStartConvertsProviderAndEventPanicsToErrors(t *testing.T) {
	tests := []struct {
		name string
		deps Deps
	}{
		{name: "dialer", deps: Deps{Dialer: panicDialer{}, Tun: inertTunProvider{}}},
		{name: "event", deps: Deps{Dialer: panicDialer{}, Tun: inertTunProvider{}, Events: panicEventSink{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, tt.deps)
			if err != nil {
				t.Fatal(err)
			}
			if err := sess.Start(context.Background()); !errors.Is(err, extension.ErrPanic) {
				t.Fatalf("Start error = %v, want extension panic", err)
			}
			select {
			case <-sess.Done():
			case <-time.After(time.Second):
				t.Fatal("session did not close after extension panic")
			}
		})
	}
}

func TestConnectedEventPanicClosesSession(t *testing.T) {
	sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
		Endpoint: fixedEndpointProvider{endpoint: &closeCountingEndpoint{}},
		Tun:      inertTunProvider{},
		Events:   connectedPanicEventSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Start error = %v, want extension panic", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not close after connected event panic")
	}
}

func TestAsynchronousEndpointPanicClosesOnlySession(t *testing.T) {
	tun := newPanicBoundaryTun()
	sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
		Endpoint: fixedEndpointProvider{endpoint: panicReadEndpoint{}},
		Tun:      inertTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not close after asynchronous endpoint panic")
	}
	if !errors.Is(sess.Err(), extension.ErrPanic) {
		t.Fatalf("session error = %v, want extension panic", sess.Err())
	}
}

func TestEndpointLoopsRejectNilPackets(t *testing.T) {
	s := &session{deps: Deps{Stats: noopStatsSink{}}}
	for _, endpoint := range []EndpointConn{&nilPacketEndpoint{}, &nilBufferedEndpoint{}} {
		if err := s.runEndpointConnToTun(context.Background(), &closeCountingTun{}, endpoint); err == nil || !strings.Contains(err.Error(), "nil packet") {
			t.Fatalf("endpoint loop error = %v, want nil-packet error", err)
		}
	}
}

func TestBorrowedPayloadReleasedAfterTunWritePanic(t *testing.T) {
	endpoint := &singleBorrowedEndpoint{}
	s := &session{deps: Deps{Stats: noopStatsSink{}}}
	err := extension.Do("test borrowed payload write", func() error {
		return s.runEndpointConnToTun(context.Background(), panicWriteTun{}, endpoint)
	})
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("borrowed payload write error = %v, want extension panic", err)
	}
	if releases := endpoint.releases; releases != 1 {
		t.Fatalf("borrowed payload releases = %d, want 1", releases)
	}
}

func TestEndpointClientIDPanicClosesEndpoint(t *testing.T) {
	endpoint := &panicClientIDEndpoint{}
	sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
		Endpoint: fixedEndpointProvider{endpoint: endpoint},
		Tun:      inertTunProvider{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Start() error = %v, want extension panic", err)
	}
	if endpoint.closes != 1 {
		t.Fatalf("endpoint closes = %d, want 1", endpoint.closes)
	}
}

func TestEndpointZeroClientIDClosesEndpoint(t *testing.T) {
	endpoint := &zeroClientIDEndpoint{}
	sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
		Endpoint: fixedEndpointProvider{endpoint: endpoint},
		Tun:      inertTunProvider{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "zero client ID") {
		t.Fatalf("Start() error = %v, want zero client ID error", err)
	}
	if endpoint.closes != 1 {
		t.Fatalf("endpoint closes = %d, want 1", endpoint.closes)
	}
}

func TestSessionCloseContinuesAfterExtensionPanic(t *testing.T) {
	endpoint := &closeCountingEndpoint{}
	tun := &closeCountingTun{}
	s := &session{
		state:    StateConnected,
		done:     make(chan struct{}),
		conn:     panicCloseConn{},
		endpoint: endpoint,
		tun:      tun,
	}
	err := s.Close()
	if !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("Close error = %v, want extension panic", err)
	}
	if endpoint.closes != 1 || tun.closes != 1 {
		t.Fatalf("endpoint/tun close calls = %d/%d, want 1/1", endpoint.closes, tun.closes)
	}
}

func TestSessionClosesResourcesReturnedWithErrors(t *testing.T) {
	want := errors.New("provider failed")
	t.Run("endpoint", func(t *testing.T) {
		endpoint := &closeCountingEndpoint{}
		sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
			Endpoint: errorEndpointProvider{endpoint: endpoint, err: want},
			Tun:      inertTunProvider{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.Start(context.Background()); !errors.Is(err, want) {
			t.Fatalf("Start() error = %v, want %v", err, want)
		}
		if endpoint.closes != 1 {
			t.Fatalf("endpoint closes = %d, want 1", endpoint.closes)
		}
	})

	t.Run("connection", func(t *testing.T) {
		conn := &closeCountingConn{}
		sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
			Dialer: errorDialer{conn: conn, err: want},
			Tun:    inertTunProvider{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.Start(context.Background()); !errors.Is(err, want) {
			t.Fatalf("Start() error = %v, want %v", err, want)
		}
		if conn.closes != 1 {
			t.Fatalf("connection closes = %d, want 1", conn.closes)
		}
	})

	t.Run("tun", func(t *testing.T) {
		endpoint := &closeCountingEndpoint{}
		tun := &closeCountingTun{}
		sess, err := NewSession(Config{ClientID: "id", SecretKey: "secret"}, Deps{
			Endpoint: fixedEndpointProvider{endpoint: endpoint},
			Tun:      errorTunProvider{tun: tun, err: want},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.Start(context.Background()); !errors.Is(err, want) {
			t.Fatalf("Start() error = %v, want %v", err, want)
		}
		if tun.closes != 1 {
			t.Fatalf("tun closes = %d, want 1", tun.closes)
		}
	})
}

type nilDialer struct{}

func (*nilDialer) Dial(context.Context, DialRequest) (net.Conn, error) { return nil, nil }

type nilTunProvider struct{}

func (*nilTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	return nil, nil
}

type panicDialer struct{}

func (panicDialer) Dial(context.Context, DialRequest) (net.Conn, error) { panic("dial panic") }

type typedNilEndpointProvider struct{}

func (typedNilEndpointProvider) DialEndpoint(context.Context, EndpointDialRequest) (EndpointConn, error) {
	var endpoint *closeCountingEndpoint
	return endpoint, nil
}

type fixedEndpointProvider struct{ endpoint EndpointConn }

func (p fixedEndpointProvider) DialEndpoint(context.Context, EndpointDialRequest) (EndpointConn, error) {
	return p.endpoint, nil
}

type errorEndpointProvider struct {
	endpoint EndpointConn
	err      error
}

func (p errorEndpointProvider) DialEndpoint(context.Context, EndpointDialRequest) (EndpointConn, error) {
	return p.endpoint, p.err
}

type errorDialer struct {
	conn net.Conn
	err  error
}

func (d errorDialer) Dial(context.Context, DialRequest) (net.Conn, error) {
	return d.conn, d.err
}

type inertTunProvider struct{ tun platform.Tun }

func (p inertTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	if p.tun == nil {
		return newPanicBoundaryTun(), nil
	}
	return p.tun, nil
}

type errorTunProvider struct {
	tun platform.Tun
	err error
}

func (p errorTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	return p.tun, p.err
}

type panicEventSink struct{}

func (panicEventSink) OnStateChange(context.Context, State)                      { panic("event panic") }
func (panicEventSink) OnConnectStage(context.Context, string, map[string]string) {}
func (panicEventSink) OnError(context.Context, error)                            {}

type connectedPanicEventSink struct{}

func (connectedPanicEventSink) OnStateChange(_ context.Context, state State) {
	if state == StateConnected {
		panic("connected event panic")
	}
}
func (connectedPanicEventSink) OnConnectStage(context.Context, string, map[string]string) {}
func (connectedPanicEventSink) OnError(context.Context, error)                            {}

type panicReadEndpoint struct{}

func (panicReadEndpoint) ReadPacket() (*vpnpacket.VpnPacket, error) { panic("endpoint read panic") }
func (panicReadEndpoint) WriteData([]byte) error                    { return nil }
func (panicReadEndpoint) WritePacket(*vpnpacket.VpnPacket) error    { return nil }
func (panicReadEndpoint) Close() error                              { return nil }
func (panicReadEndpoint) ClientID() uint64                          { return 1 }
func (panicReadEndpoint) LocalAddr() string                         { return "" }

type nilPacketEndpoint struct{ closeCountingEndpoint }

func (*nilPacketEndpoint) ReadPacket() (*vpnpacket.VpnPacket, error) { return nil, nil }

type nilBufferedEndpoint struct{ nilPacketEndpoint }

func (*nilBufferedEndpoint) ReadPacketBuffer(*dataplane.PacketBuffer) (*vpnpacket.VpnPacket, bool, error) {
	return nil, false, nil
}

func (*nilBufferedEndpoint) WriteDataBuffer(*dataplane.PacketBuffer) error { return nil }

type panicClientIDEndpoint struct{ closeCountingEndpoint }

func (*panicClientIDEndpoint) ClientID() uint64 { panic("endpoint client ID panic") }

type zeroClientIDEndpoint struct{ closeCountingEndpoint }

func (*zeroClientIDEndpoint) ClientID() uint64 { return 0 }

type singleBorrowedEndpoint struct {
	closeCountingEndpoint
	releases int
	read     bool
}

func (e *singleBorrowedEndpoint) ReadPayloadBorrowed() ([]byte, func(), error) {
	if e.read {
		return nil, nil, io.EOF
	}
	e.read = true
	return testIPv4Packet(), func() { e.releases++ }, nil
}

type panicBoundaryTun struct{ closed chan struct{} }

func newPanicBoundaryTun() *panicBoundaryTun { return &panicBoundaryTun{closed: make(chan struct{})} }
func (t *panicBoundaryTun) Read([]byte) (int, error) {
	<-t.closed
	return 0, io.ErrClosedPipe
}
func (*panicBoundaryTun) Write(p []byte) (int, error) { return len(p), nil }
func (*panicBoundaryTun) WriteContext(_ context.Context, p []byte) (int, error) {
	return len(p), nil
}
func (t *panicBoundaryTun) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

type panicWriteTun struct{}

func (panicWriteTun) Read([]byte) (int, error)  { return 0, io.EOF }
func (panicWriteTun) Write([]byte) (int, error) { panic("tun write panic") }
func (panicWriteTun) WriteContext(context.Context, []byte) (int, error) {
	panic("tun write panic")
}
func (panicWriteTun) Close() error { return nil }

type panicCloseConn struct{ net.Conn }

func (panicCloseConn) Close() error { panic("connection close panic") }

type closeCountingConn struct {
	net.Conn
	closes int
}

func (c *closeCountingConn) Close() error { c.closes++; return nil }

type closeCountingEndpoint struct{ closes int }

func (*closeCountingEndpoint) ReadPacket() (*vpnpacket.VpnPacket, error) { return nil, io.EOF }
func (*closeCountingEndpoint) WriteData([]byte) error                    { return nil }
func (*closeCountingEndpoint) WritePacket(*vpnpacket.VpnPacket) error    { return nil }
func (e *closeCountingEndpoint) Close() error                            { e.closes++; return nil }
func (*closeCountingEndpoint) ClientID() uint64                          { return 1 }
func (*closeCountingEndpoint) LocalAddr() string                         { return "" }

type closeCountingTun struct{ closes int }

func (*closeCountingTun) Read([]byte) (int, error)    { return 0, io.EOF }
func (*closeCountingTun) Write(p []byte) (int, error) { return len(p), nil }
func (*closeCountingTun) WriteContext(_ context.Context, p []byte) (int, error) {
	return len(p), nil
}
func (t *closeCountingTun) Close() error { t.closes++; return nil }
