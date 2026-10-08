// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestMemorySessionEcho(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		payloadSize int
	}{
		{name: "default MTU", mtu: 1500, payloadSize: 24},
		{name: "jumbo MTU", mtu: 9000, payloadSize: 9000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tun := newOffsetCountingTun(4)
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
				MTU:        tt.mtu,
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

			payload := make([]byte, tt.payloadSize)
			payload[0], payload[9] = 0x45, 253
			binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
			if err := tun.Inject(payload); err != nil {
				t.Fatal(err)
			}
			out, err := tun.ReadOutput(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload mismatch: got %x want %x", out, payload)
			}
			if tun.readOffsetCalls.Load() == 0 {
				t.Fatal("expected session to read TUN with ReadPacketOffset")
			}
			if tun.writeOffsetCalls.Load() == 0 {
				t.Fatal("expected session to write TUN with WritePacketOffset")
			}
		})
	}
}

func TestEndpointSessionMovesPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tun := newTestMemoryTun(4)
	endpoint := newFakeEndpoint()
	requests := make(chan client.EndpointDialRequest, 1)
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		ServerIP:   "203.0.113.1",
		ServerPort: 443,
		MTU:        1500,
	}, client.Deps{
		Endpoint: fakeEndpointProvider{endpoint: endpoint, requests: requests},
		Tun:      staticTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if sess.LocalAddr() != "endpoint-local" {
		t.Fatalf("LocalAddr() = %q, want endpoint-local", sess.LocalAddr())
	}

	select {
	case req := <-requests:
		if req.ClientID != "test-client" || req.ServerPort != 443 {
			t.Fatalf("request = %+v", req)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	upload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	if err := tun.Inject(upload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-endpoint.writes:
		if !bytes.Equal(got, upload) {
			t.Fatalf("endpoint write = %x want %x", got, upload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	download := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 2, 0, 1, 10, 1, 0, 2}
	endpoint.incoming <- &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: download}
	out, err := tun.ReadOutput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, download) {
		t.Fatalf("tun output = %x want %x", out, download)
	}
}

func TestEndpointSessionUsesBufferedEndpointAndOffsetTun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tun := newOffsetCountingTun(4)
	endpoint := newFakeBufferedEndpoint()
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		ServerIP:   "203.0.113.1",
		ServerPort: 443,
		MTU:        1500,
	}, client.Deps{
		Endpoint: fakeEndpointProvider{endpoint: endpoint},
		Tun:      staticTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}

	upload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 1, 0, 2, 10, 2, 0, 1}
	if err := tun.Inject(upload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-endpoint.bufferedWrites:
		if !bytes.Equal(got, upload) {
			t.Fatalf("buffered endpoint write = %x want %x", got, upload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if tun.readOffsetCalls.Load() == 0 {
		t.Fatal("expected endpoint session to read TUN with ReadPacketOffset")
	}

	download := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 2, 0, 1, 10, 1, 0, 2}
	endpoint.bufferedPayloads <- download
	out, err := tun.ReadOutput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, download) {
		t.Fatalf("tun output = %x want %x", out, download)
	}
	if tun.writeOffsetCalls.Load() == 0 {
		t.Fatal("expected endpoint session to write TUN with WritePacketOffset")
	}
}

func TestEndpointSessionUsesBorrowedPayloadEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tun := newOffsetCountingTun(4)
	endpoint := newFakeBorrowedEndpoint()
	sess, err := client.NewSession(client.Config{
		Protocol:   client.ProtocolTalariaUDP,
		ClientID:   "test-client",
		SecretKey:  "test-secret",
		EntranceIP: "10.0.0.1",
		ExitIP:     "10.0.0.2",
		ServerIP:   "203.0.113.1",
		ServerPort: 443,
		MTU:        1500,
	}, client.Deps{
		Endpoint: fakeEndpointProvider{endpoint: endpoint},
		Tun:      staticTunProvider{tun: tun},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatal(err)
	}

	download := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0, 10, 2, 0, 1, 10, 1, 0, 2}
	endpoint.borrowedPayloads <- download
	out, err := tun.ReadOutput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, download) {
		t.Fatalf("tun output = %x want %x", out, download)
	}
	for endpoint.releaseCount.Load() != 1 {
		select {
		case <-ctx.Done():
			t.Fatalf("releaseCount = %d want 1", endpoint.releaseCount.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if tun.writeOffsetCalls.Load() != 1 {
		t.Fatalf("writeOffsetCalls = %d want 1", tun.writeOffsetCalls.Load())
	}
}

type staticTunProvider struct {
	tun platform.Tun
}

func (p staticTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	return p.tun, nil
}

type offsetCountingTun struct {
	*testMemoryTun
	readOffsetCalls  atomic.Int32
	writeOffsetCalls atomic.Int32
}

func newOffsetCountingTun(queueSize int) *offsetCountingTun {
	return &offsetCountingTun{testMemoryTun: newTestMemoryTun(queueSize)}
}

func (t *offsetCountingTun) ReadPacketOffset(buf []byte, payloadOffset int) (int, error) {
	t.readOffsetCalls.Add(1)
	return t.testMemoryTun.ReadPacketOffset(buf, payloadOffset)
}

func (t *offsetCountingTun) WritePacketOffset(ctx context.Context, buf []byte, payloadOffset int, payloadLen int) (int, error) {
	t.writeOffsetCalls.Add(1)
	return t.testMemoryTun.WritePacketOffset(ctx, buf, payloadOffset, payloadLen)
}

type fakeEndpointProvider struct {
	endpoint client.EndpointConn
	requests chan client.EndpointDialRequest
}

func (p fakeEndpointProvider) DialEndpoint(_ context.Context, req client.EndpointDialRequest) (client.EndpointConn, error) {
	if p.requests != nil {
		p.requests <- req
	}
	return p.endpoint, nil
}

type fakeEndpoint struct {
	incoming chan *vpnpacket.VpnPacket
	writes   chan []byte
	closed   chan struct{}
	once     sync.Once
}

func newFakeEndpoint() *fakeEndpoint {
	return &fakeEndpoint{
		incoming: make(chan *vpnpacket.VpnPacket, 4),
		writes:   make(chan []byte, 4),
		closed:   make(chan struct{}),
	}
}

func (e *fakeEndpoint) ReadPacket() (*vpnpacket.VpnPacket, error) {
	select {
	case packet := <-e.incoming:
		return packet, nil
	case <-e.closed:
		return nil, io.ErrClosedPipe
	}
}

func (e *fakeEndpoint) WriteData(payload []byte) error {
	out := append([]byte(nil), payload...)
	select {
	case e.writes <- out:
		return nil
	case <-e.closed:
		return io.ErrClosedPipe
	}
}

func (e *fakeEndpoint) WritePacket(*vpnpacket.VpnPacket) error {
	return nil
}

func (e *fakeEndpoint) Close() error {
	e.once.Do(func() {
		close(e.closed)
	})
	return nil
}

func (e *fakeEndpoint) ClientID() uint64 {
	return 99
}

func (e *fakeEndpoint) LocalAddr() string {
	return "endpoint-local"
}

type fakeBufferedEndpoint struct {
	*fakeEndpoint
	bufferedWrites   chan []byte
	bufferedPayloads chan []byte
}

func newFakeBufferedEndpoint() *fakeBufferedEndpoint {
	return &fakeBufferedEndpoint{
		fakeEndpoint:     newFakeEndpoint(),
		bufferedWrites:   make(chan []byte, 4),
		bufferedPayloads: make(chan []byte, 4),
	}
}

func (e *fakeBufferedEndpoint) WriteDataBuffer(pkt *dataplane.PacketBuffer) error {
	out := append([]byte(nil), pkt.Bytes()...)
	select {
	case e.bufferedWrites <- out:
		return nil
	case <-e.closed:
		return io.ErrClosedPipe
	}
}

func (e *fakeBufferedEndpoint) ReadPacketBuffer(pkt *dataplane.PacketBuffer) (*vpnpacket.VpnPacket, bool, error) {
	select {
	case payload := <-e.bufferedPayloads:
		if len(payload) > len(pkt.Raw)-pkt.Start {
			return nil, false, io.ErrShortBuffer
		}
		copy(pkt.Raw[pkt.Start:], payload)
		pkt.End = pkt.Start + len(payload)
		return &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, ClientId: e.ClientID(), Data: pkt.Bytes()}, true, nil
	case packet := <-e.incoming:
		return packet, false, nil
	case <-e.closed:
		return nil, false, io.ErrClosedPipe
	}
}

type fakeBorrowedEndpoint struct {
	*fakeEndpoint
	borrowedPayloads chan []byte
	releaseCount     atomic.Int32
}

func newFakeBorrowedEndpoint() *fakeBorrowedEndpoint {
	return &fakeBorrowedEndpoint{
		fakeEndpoint:     newFakeEndpoint(),
		borrowedPayloads: make(chan []byte, 4),
	}
}

func (e *fakeBorrowedEndpoint) ReadPayloadBorrowed() ([]byte, func(), error) {
	select {
	case payload := <-e.borrowedPayloads:
		return payload, func() {
			e.releaseCount.Add(1)
		}, nil
	case <-e.closed:
		return nil, nil, io.ErrClosedPipe
	}
}
