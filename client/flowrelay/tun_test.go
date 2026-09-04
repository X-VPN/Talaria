// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package flowrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
)

func TestTUNWriteRunsSendCallbackBeforeFiltering(t *testing.T) {
	tun := &TUN{
		sendCallback: func(buf []byte) error {
			buf[0] = 0x45
			return nil
		},
		relay: &managedTunnelRelay{},
	}
	packet := []byte{0x40, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 8, 8, 8, 8}
	n, err := tun.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packet) || packet[0] != 0x45 {
		t.Fatalf("write result n=%d first=%#x", n, packet[0])
	}
}

func TestTUNReadRunsRecvCallback(t *testing.T) {
	relay := &managedTunnelRelay{outboundCh: make(chan managedOutboundPacket, 1)}
	relay.outboundCh <- managedOutboundPacket{data: []byte{1, 2, 3, 4}}
	tun := &TUN{
		recvCallback: func(buf []byte) error {
			buf[0] = 9
			return nil
		},
		relay: relay,
	}
	buf := make([]byte, 8)
	length := []int{0}
	n, err := tun.Read(buf, length)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || length[0] != 4 || buf[0] != 9 {
		t.Fatalf("read result n=%d length=%d first=%d", n, length[0], buf[0])
	}
}

func TestTUNContainsCallbackPanics(t *testing.T) {
	t.Run("send", func(t *testing.T) {
		tun := &TUN{
			sendCallback: func([]byte) error { panic("send callback panic") },
			relay:        &managedTunnelRelay{},
		}
		if _, err := tun.Write([]byte{1}); !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("Write() error = %v, want extension panic", err)
		}
	})

	t.Run("receive", func(t *testing.T) {
		relay := &managedTunnelRelay{outboundCh: make(chan managedOutboundPacket, 1)}
		relay.outboundCh <- managedOutboundPacket{data: []byte{1}}
		tun := &TUN{
			recvCallback: func([]byte) error { panic("receive callback panic") },
			relay:        relay,
		}
		if _, err := tun.ReadPacket(); !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("ReadPacket() error = %v, want extension panic", err)
		}
	})

	t.Run("borrowed receive", func(t *testing.T) {
		relay := &managedTunnelRelay{outboundCh: make(chan managedOutboundPacket, 1)}
		relay.outboundCh <- managedOutboundPacket{data: []byte{1}, pooled: true}
		tun := &TUN{
			recvCallback: func([]byte) error { panic("borrowed receive callback panic") },
			relay:        relay,
		}
		packet, release, err := tun.ReadPacketBorrowed()
		if packet != nil || release != nil || !errors.Is(err, extension.ErrPanic) {
			t.Fatalf("ReadPacketBorrowed() = %v, has release=%t, %v; want nil, false, extension panic", packet, release != nil, err)
		}
	})
}

func TestTUNInitClientEndpointRejectsNilTransport(t *testing.T) {
	tun := &TUN{}
	if err := tun.InitClientEndpoint(context.Background(), "TalariaTCP", nil); err == nil {
		t.Fatal("nil stream transport was accepted")
	}
	var typedNil *testStreamTransport
	if err := tun.InitClientEndpoint(context.Background(), "TalariaTCP", typedNil); err == nil {
		t.Fatal("typed-nil stream transport was accepted")
	}
}

func TestTUNInitClientEndpointUsesTransport(t *testing.T) {
	streamTransport := &testStreamTransport{}
	tun := &TUN{}
	if err := tun.InitClientEndpoint(context.Background(), "TalariaTCP", streamTransport); err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if got := tun.currentStreamTransport(); got != streamTransport {
		t.Fatalf("current transport = %p want %p", got, streamTransport)
	}
}

func TestTUNInitClientEndpointFollowsContext(t *testing.T) {
	restoreManagedTCPBackendFactory(t)
	backend := &fakeManagedTCPBackend{}
	managedNewGVisorTCPBackend = func(int, func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		return backend, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	tun := &TUN{}
	if err := tun.InitClientEndpoint(ctx, "TalariaTCP", &testStreamTransport{}); err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	tun.ctxLock.RLock()
	relay := tun.relay
	tun.ctxLock.RUnlock()
	cancel()
	select {
	case <-relay.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("endpoint context cancellation did not stop the relay")
	}
	if err := tun.QueuePacket([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("QueuePacket() after cancellation = %v, want %v", err, net.ErrClosed)
	}
}

func TestTUNInitClientEndpointIgnoresClosedOldRelay(t *testing.T) {
	restoreManagedTCPBackendFactory(t)
	newBackend := &fakeManagedTCPBackend{}
	managedNewGVisorTCPBackend = func(int, func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		return newBackend, nil
	}
	oldBackend := &fakeManagedTCPBackend{closeErr: errors.New("use of closed network connection")}
	tun := &TUN{
		ctx:              context.Background(),
		endpointProtocol: "TalariaTCP",
		streamTransport:  &testStreamTransport{},
		relay: &managedTunnelRelay{
			cancel:     func() {},
			tcpBackend: oldBackend,
			outboundCh: make(chan managedOutboundPacket),
			flows:      make(map[uint64]*managedTunnelFlow),
		},
	}
	if err := tun.InitClientEndpoint(context.Background(), "TalariaTCP", &testStreamTransport{}); err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if !oldBackend.closed {
		t.Fatal("old relay backend was not closed")
	}
}

func TestTUNCloseInvalidatesInFlightInitialization(t *testing.T) {
	restoreManagedTCPBackendFactory(t)
	started := make(chan struct{})
	proceed := make(chan struct{})
	backend := &fakeManagedTCPBackend{}
	managedNewGVisorTCPBackend = func(int, func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		close(started)
		<-proceed
		return backend, nil
	}

	tun := &TUN{}
	initDone := make(chan error, 1)
	go func() {
		initDone <- tun.InitClientEndpoint(context.Background(), "TalariaTCP", &testStreamTransport{})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("endpoint initialization did not start")
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	select {
	case err := <-initDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("InitClientEndpoint() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint initialization did not finish")
	}
	if !backend.closed {
		t.Fatal("relay created after Close was not released")
	}
	tun.ctxLock.RLock()
	relay := tun.relay
	tun.ctxLock.RUnlock()
	if relay != nil {
		t.Fatal("in-flight initialization restored relay after Close")
	}
}

func TestManagedTunnelRelayStartManagedFlowUsesStreamTransport(t *testing.T) {
	remoteConn, targetPeer := net.Pipe()
	observedRemote := &observedManagedFlowConn{Conn: remoteConn, closed: make(chan struct{})}
	defer targetPeer.Close()
	streamTransport := &testStreamTransport{
		conn:   observedRemote,
		target: make(chan coretransport.Destination, 1),
	}
	localConn, appPeer := net.Pipe()
	defer appPeer.Close()
	relay := &managedTunnelRelay{
		tun: &TUN{
			ctx:              context.Background(),
			endpointProtocol: "TalariaTCP",
			streamTransport:  streamTransport,
		},
		flows: make(map[uint64]*managedTunnelFlow),
	}
	destination := coretransport.Destination{Network: coretransport.NetworkTCP, Host: "8.8.8.8", Port: 443}
	relay.startManagedFlow(destination, localConn)
	select {
	case got := <-streamTransport.target:
		if got != destination {
			t.Fatalf("stream target = %+v want %+v", got, destination)
		}
	case <-time.After(time.Second):
		t.Fatal("stream transport was not dialed")
	}

	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 4)
		if _, err := io.ReadFull(targetPeer, buf); err != nil {
			return
		}
		_, _ = targetPeer.Write(buf)
	}()
	if _, err := appPeer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(appPeer, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("response = %q", response)
	}
	_ = appPeer.Close()
	_ = targetPeer.Close()
	<-echoDone
	select {
	case <-observedRemote.closed:
	case <-time.After(time.Second):
		t.Fatal("completed managed flow did not close its remote connection")
	}
}

func TestManagedTunnelFlowClosesLateRemoteConnection(t *testing.T) {
	local, localPeer := net.Pipe()
	defer localPeer.Close()
	remote, remotePeer := net.Pipe()
	defer remotePeer.Close()
	observedRemote := &observedManagedFlowConn{Conn: remote, closed: make(chan struct{})}
	flow := &managedTunnelFlow{localConn: local}
	if err := flow.close(); err != nil {
		t.Fatal(err)
	}
	if flow.setRemoteConn(observedRemote) {
		t.Fatal("closed flow accepted a late remote connection")
	}
	select {
	case <-observedRemote.closed:
	case <-time.After(time.Second):
		t.Fatal("late remote connection was not closed")
	}
}

func TestManagedTunnelFlowCloseContinuesAfterConnectionPanic(t *testing.T) {
	remote, remotePeer := net.Pipe()
	defer remotePeer.Close()
	observedRemote := &observedManagedFlowConn{Conn: remote, closed: make(chan struct{})}
	flow := &managedTunnelFlow{
		localConn:  panicCloseManagedConn{},
		remoteConn: observedRemote,
	}
	if err := flow.close(); !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("managed flow close error = %v, want extension panic", err)
	}
	select {
	case <-observedRemote.closed:
	case <-time.After(time.Second):
		t.Fatal("remote flow was not closed after local Close panic")
	}
}

func TestManagedTunnelRelayConvertsDialPanicToFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dialed := make(chan struct{})
	streamTransport := &testStreamTransport{panicDial: true, dialed: dialed}
	relay := &managedTunnelRelay{
		tun: &TUN{
			ctx:              ctx,
			endpointProtocol: "TalariaTCP",
			streamTransport:  streamTransport,
		},
		ctx:        ctx,
		cancel:     cancel,
		outboundCh: make(chan managedOutboundPacket),
		flows:      make(map[uint64]*managedTunnelFlow),
	}
	local, peer := net.Pipe()
	defer peer.Close()
	relay.startManagedFlow(coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    "8.8.8.8",
		Port:    443,
	}, local)
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("managed flow did not call the stream transport")
	}
	deadline := time.Now().Add(time.Second)
	for {
		relay.failureMu.Lock()
		err := relay.failureErr
		relay.failureMu.Unlock()
		if errors.Is(err, extension.ErrPanic) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("managed flow panic error = %v, want extension panic", err)
		}
		time.Sleep(time.Millisecond)
	}
	_ = relay.close()
}

func TestManagedTunnelRelayClosesConnectionReturnedWithDialError(t *testing.T) {
	remote, remotePeer := net.Pipe()
	defer remotePeer.Close()
	observed := &observedManagedFlowConn{Conn: remote, closed: make(chan struct{})}
	want := errors.New("stream dial failed")
	streamTransport := &testStreamTransport{conn: observed, dialErr: want}
	relay := &managedTunnelRelay{
		tun: &TUN{
			ctx:              context.Background(),
			endpointProtocol: "TalariaTCP",
			streamTransport:  streamTransport,
		},
		flows: make(map[uint64]*managedTunnelFlow),
	}
	local, localPeer := net.Pipe()
	defer localPeer.Close()
	relay.startManagedFlow(coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    "8.8.8.8",
		Port:    443,
	}, local)
	select {
	case <-observed.closed:
	case <-time.After(time.Second):
		t.Fatal("connection returned with stream dial error was not closed")
	}
	_ = relay.close()
}

type observedManagedFlowConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *observedManagedFlowConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type testStreamTransport struct {
	conn      net.Conn
	dialErr   error
	target    chan coretransport.Destination
	dialed    chan struct{}
	panicDial bool
}

func (t *testStreamTransport) DialControl(context.Context) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (t *testStreamTransport) Activate(context.Context, coretransport.SessionGrant) error {
	return nil
}

func (t *testStreamTransport) DialStream(_ context.Context, target coretransport.Destination) (net.Conn, error) {
	if t.dialed != nil {
		close(t.dialed)
	}
	if t.panicDial {
		panic("boom")
	}
	if t.target != nil {
		t.target <- target
	}
	if t.conn == nil {
		return nil, net.ErrClosed
	}
	return t.conn, t.dialErr
}

func (t *testStreamTransport) Close() error { return nil }

type panicCloseManagedConn struct{ net.Conn }

func (panicCloseManagedConn) Close() error { panic("boom") }
