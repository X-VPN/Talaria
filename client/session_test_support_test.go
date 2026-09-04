// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

type testDialer struct {
	Handler func(context.Context, net.Conn) error
}

type testMemoryTun struct {
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestMemoryTun(queueSize int) *testMemoryTun {
	if queueSize <= 0 {
		queueSize = 16
	}
	return &testMemoryTun{
		inbound:  make(chan []byte, queueSize),
		outbound: make(chan []byte, queueSize),
		closed:   make(chan struct{}),
	}
}

func (t *testMemoryTun) Read(p []byte) (int, error) {
	select {
	case packet := <-t.inbound:
		if len(packet) > len(p) {
			copy(p, packet[:len(p)])
			return len(p), io.ErrShortBuffer
		}
		return copy(p, packet), nil
	case <-t.closed:
		return 0, io.ErrClosedPipe
	}
}

func (t *testMemoryTun) Write(p []byte) (int, error) {
	return t.WriteContext(context.Background(), p)
}

func (t *testMemoryTun) WriteContext(ctx context.Context, p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	select {
	case t.outbound <- packet:
		return len(p), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.closed:
		return 0, io.ErrClosedPipe
	}
}

func (t *testMemoryTun) ReadPacketOffset(buf []byte, payloadOffset int) (int, error) {
	if payloadOffset < 0 || payloadOffset > len(buf) {
		return 0, io.ErrShortBuffer
	}
	return t.Read(buf[payloadOffset:])
}

func (t *testMemoryTun) WritePacketOffset(ctx context.Context, buf []byte, payloadOffset, payloadLen int) (int, error) {
	if payloadLen <= 0 {
		return 0, nil
	}
	if payloadOffset < 0 || payloadOffset > len(buf) || payloadLen > len(buf)-payloadOffset {
		return 0, io.ErrShortBuffer
	}
	return t.WriteContext(ctx, buf[payloadOffset:payloadOffset+payloadLen])
}

func (t *testMemoryTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil
}

func (t *testMemoryTun) Inject(packet []byte) error {
	packet = append([]byte(nil), packet...)
	select {
	case t.inbound <- packet:
		return nil
	case <-t.closed:
		return io.ErrClosedPipe
	}
}

func (t *testMemoryTun) ReadOutput(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-t.outbound:
		return append([]byte(nil), packet...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, io.ErrClosedPipe
	}
}

func (d testDialer) Dial(ctx context.Context, _ client.DialRequest) (net.Conn, error) {
	if d.Handler == nil {
		return nil, errors.New("test dialer has no handler")
	}
	clientConn, serverConn := newPacketConnPair()
	go func() {
		_ = d.Handler(ctx, serverConn)
	}()
	return clientConn, nil
}

type packetEchoOptions struct {
	ClientID         string
	SecretKey        string
	AssignedClientID uint64
	Version          byte
	InitialData      []byte
	RejectAfterData  bool
}

func servePacketEcho(ctx context.Context, conn net.Conn, opt packetEchoOptions) error {
	codec := dataplane.WireCodec{}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 64*1024)
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
	if packet.Id != opt.ClientID || packet.Sk != opt.SecretKey {
		return errors.New("authentication failed")
	}
	if err := writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
		Cmd:         vpnpacket.CmdAuthSuccess,
		NewClientId: opt.AssignedClientID,
		Version:     opt.Version,
	}); err != nil {
		return err
	}
	if err := writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
		Cmd:      vpnpacket.CmdSessionReady,
		ClientId: opt.AssignedClientID,
	}); err != nil {
		return err
	}
	if len(opt.InitialData) > 0 {
		if err := writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
			Cmd:      vpnpacket.CmdData,
			ClientId: opt.AssignedClientID,
			Data:     opt.InitialData,
		}); err != nil {
			return err
		}
	}
	if opt.RejectAfterData {
		return writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
			Cmd:          vpnpacket.CmdErr,
			ErrorMessage: "stop after data",
		})
	}

	for {
		n, err = conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		packet, _, err = codec.Decode(buf[:n])
		if err != nil {
			return err
		}
		switch packet.Cmd {
		case vpnpacket.CmdData:
			err = writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
				Cmd:            vpnpacket.CmdData,
				ClientId:       opt.AssignedClientID,
				DataSequenceId: packet.DataSequenceId,
				Data:           packet.Data,
			})
		case vpnpacket.CmdKeepAlive, vpnpacket.CmdServerKeepAlive:
			err = writeTestPacket(codec, conn, &vpnpacket.VpnPacket{
				Cmd:         packet.Cmd,
				ClientId:    opt.AssignedClientID,
				KeepAliveId: packet.KeepAliveId,
				SendTime:    packet.SendTime,
			})
		case vpnpacket.CmdClientClose:
			return nil
		default:
			return fmt.Errorf("unexpected packet command %d", packet.Cmd)
		}
		if err != nil {
			return err
		}
	}
}

func writeTestPacket(codec dataplane.Codec, conn net.Conn, packet *vpnpacket.VpnPacket) error {
	raw, err := codec.Encode(packet)
	if err != nil {
		return err
	}
	_, err = conn.Write(raw)
	return err
}

type testPacketConn struct {
	in        chan []byte
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	local     net.Addr
	remote    net.Addr
}

func newPacketConnPair() (net.Conn, net.Conn) {
	aToB := make(chan []byte, 64)
	bToA := make(chan []byte, 64)
	return &testPacketConn{
			in:     bToA,
			out:    aToB,
			closed: make(chan struct{}),
			local:  testPacketAddr("client"),
			remote: testPacketAddr("server"),
		}, &testPacketConn{
			in:     aToB,
			out:    bToA,
			closed: make(chan struct{}),
			local:  testPacketAddr("server"),
			remote: testPacketAddr("client"),
		}
}

func (c *testPacketConn) Read(p []byte) (int, error) {
	select {
	case packet := <-c.in:
		if len(packet) > len(p) {
			copy(p, packet[:len(p)])
			return len(p), io.ErrShortBuffer
		}
		return copy(p, packet), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *testPacketConn) Write(p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	select {
	case c.out <- packet:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *testPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr            { return c.local }
func (c *testPacketConn) RemoteAddr() net.Addr           { return c.remote }
func (*testPacketConn) SetDeadline(time.Time) error      { return nil }
func (*testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*testPacketConn) SetWriteDeadline(time.Time) error { return nil }

type testPacketAddr string

func (testPacketAddr) Network() string  { return "memory" }
func (a testPacketAddr) String() string { return string(a) }
