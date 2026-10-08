// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package flowrelay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
	gbuffer "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fakeManagedTCPBackend struct {
	injectedPackets [][]byte
	closed          bool
	closeErr        error
}

func (b *fakeManagedTCPBackend) injectIPv4Packet(packet []byte) error {
	copied := make([]byte, len(packet))
	copy(copied, packet)
	b.injectedPackets = append(b.injectedPackets, copied)
	return nil
}

func (b *fakeManagedTCPBackend) close() error {
	b.closed = true
	return b.closeErr
}

type fakeManagedTCPBackendWithReader struct {
	fakeManagedTCPBackend
	reader managedOutboundReader
}

func (b *fakeManagedTCPBackendWithReader) outboundReader() managedOutboundReader {
	return b.reader
}

type fakeManagedOutboundReader struct {
	packets chan *stack.PacketBuffer
}

func (r *fakeManagedOutboundReader) Read() *stack.PacketBuffer {
	return <-r.packets
}

func (r *fakeManagedOutboundReader) ReadContext(ctx context.Context) *stack.PacketBuffer {
	select {
	case pkt := <-r.packets:
		return pkt
	case <-ctx.Done():
		return nil
	}
}

func restoreManagedTCPBackendFactory(t *testing.T) {
	t.Helper()
	originalNewGVisor := managedNewGVisorTCPBackend
	t.Cleanup(func() {
		managedNewGVisorTCPBackend = originalNewGVisor
	})
}

func TestManagedTCPBackendFactoryUsesGVisor(t *testing.T) {
	restoreManagedTCPBackendFactory(t)

	gvisorBackend := &fakeManagedTCPBackend{}
	managedNewGVisorTCPBackend = func(maxPacket int, flowHandler func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		if maxPacket != TUN_MTU {
			t.Fatalf("maxPacket = %d want %d", maxPacket, TUN_MTU)
		}
		if flowHandler == nil {
			t.Fatal("flowHandler is nil")
		}
		return gvisorBackend, nil
	}

	backend, err := newManagedTCPBackend(TUN_MTU, &managedTunnelRelay{})
	if err != nil {
		t.Fatalf("newManagedTCPBackend() error = %v", err)
	}
	if backend != gvisorBackend {
		t.Fatalf("backend = %p want %p", backend, gvisorBackend)
	}
}

func TestManagedTunnelMTU(t *testing.T) {
	original := managedTunnelMTUOverride.Load()
	t.Cleanup(func() {
		managedTunnelMTUOverride.Store(original)
	})
	SetManagedTunnelMTU(0)

	if got := managedTunnelMTU(); got != TUN_MTU {
		t.Fatalf("managedTunnelMTU() = %d want %d", got, TUN_MTU)
	}

	SetManagedTunnelMTU(1460)
	if got := managedTunnelMTU(); got != 1460 {
		t.Fatalf("managedTunnelMTU() override = %d want 1460", got)
	}

	SetManagedTunnelMTU(100)
	if got := managedTunnelMTU(); got != TUN_MTU {
		t.Fatalf("managedTunnelMTU() low override = %d want %d", got, TUN_MTU)
	}

	SetManagedTunnelMTU(10000)
	if got := managedTunnelMTU(); got != managedTunnelMTUMax {
		t.Fatalf("managedTunnelMTU() high override = %d want %d", got, managedTunnelMTUMax)
	}

	SetManagedTunnelMTU(0)
	if got := managedTunnelMTU(); got != TUN_MTU {
		t.Fatalf("managedTunnelMTU() reset override = %d want %d", got, TUN_MTU)
	}
}

func TestManagedGVisorLinkMTU(t *testing.T) {
	original := managedGVisorLinkMTUOverride.Load()
	t.Cleanup(func() {
		managedGVisorLinkMTUOverride.Store(original)
	})
	SetManagedGVisorLinkMTU(0)

	if got := managedGVisorLinkMTU(1400); got != 1400 {
		t.Fatalf("managedGVisorLinkMTU() = %d want 1400", got)
	}

	if got := managedGVisorLinkMTU(100); got != TUN_MTU {
		t.Fatalf("managedGVisorLinkMTU() low default = %d want %d", got, TUN_MTU)
	}

	SetManagedGVisorLinkMTU(8196)
	if got := managedGVisorLinkMTU(1400); got != 8196 {
		t.Fatalf("managedGVisorLinkMTU() override = %d want 8196", got)
	}

	SetManagedGVisorLinkMTU(10000)
	if got := managedGVisorLinkMTU(1400); got != managedTunnelMTUMax {
		t.Fatalf("managedGVisorLinkMTU() high override = %d want %d", got, managedTunnelMTUMax)
	}

	SetManagedGVisorLinkMTU(0)
	if got := managedGVisorLinkMTU(1400); got != 1400 {
		t.Fatalf("managedGVisorLinkMTU() reset override = %d want 1400", got)
	}
}

func TestManagedTunnelOutboundBufferPoolToggle(t *testing.T) {
	original := managedTunnelOutboundBufferPoolEnabled()
	t.Cleanup(func() {
		SetManagedTunnelOutboundBufferPoolEnabled(original)
	})

	SetManagedTunnelOutboundBufferPoolEnabled(true)
	buf, pooled := getManagedTunnelOutboundBuffer(128)
	if len(buf) != 128 {
		t.Fatalf("pooled buffer len = %d want 128", len(buf))
	}
	if !pooled {
		t.Fatal("default outbound buffer should be pooled")
	}
	putManagedTunnelOutboundBuffer(buf)

	SetManagedTunnelOutboundBufferPoolEnabled(false)
	buf, pooled = getManagedTunnelOutboundBuffer(128)
	if len(buf) != 128 {
		t.Fatalf("disabled buffer len = %d want 128", len(buf))
	}
	if pooled {
		t.Fatal("disabled outbound buffer pool returned pooled=true")
	}
}

func TestNewManagedTunnelRelayStartsBackendOutboundReader(t *testing.T) {
	restoreManagedTCPBackendFactory(t)
	originalMTUOverride := managedTunnelMTUOverride.Load()
	t.Cleanup(func() {
		managedTunnelMTUOverride.Store(originalMTUOverride)
	})
	SetManagedTunnelMTU(1500)

	reader := &fakeManagedOutboundReader{packets: make(chan *stack.PacketBuffer, 1)}
	backend := &fakeManagedTCPBackendWithReader{reader: reader}
	managedNewGVisorTCPBackend = func(maxPacket int, flowHandler func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		if maxPacket != 1500 {
			t.Fatalf("maxPacket = %d want 1500", maxPacket)
		}
		if flowHandler == nil {
			t.Fatal("flowHandler is nil")
		}
		return backend, nil
	}

	relay, err := newManagedTunnelRelay(&TUN{
		ctx:              context.Background(),
		endpointProtocol: "TalariaTCP",
		streamTransport:  &testStreamTransport{},
	})
	if err != nil {
		t.Fatalf("newManagedTunnelRelay() error = %v", err)
	}
	if cap(relay.outboundCh) != managedTunnelOutboundQueueDefault {
		t.Fatalf("outbound queue cap = %d want %d", cap(relay.outboundCh), managedTunnelOutboundQueueDefault)
	}
	defer func() {
		if err := relay.close(); err != nil {
			t.Fatalf("relay.close() error = %v", err)
		}
	}()

	reader.packets <- stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: gbuffer.MakeWithData([]byte{1, 2, 3}),
	})

	buf := make([]byte, 8)
	n, err := relay.readPacket(buf)
	if err != nil {
		t.Fatalf("readPacket() error = %v", err)
	}
	if n != 3 || buf[0] != 1 || buf[1] != 2 || buf[2] != 3 {
		t.Fatalf("readPacket() = n:%d buf:%v, want [1 2 3]", n, buf[:n])
	}
}

func TestNewManagedTunnelRelayRejectsMissingStreamTransport(t *testing.T) {
	if _, err := newManagedTunnelRelay(&TUN{
		ctx:              context.Background(),
		endpointProtocol: "TalariaTCP",
	}); err == nil {
		t.Fatal("expected missing stream transport error")
	}
}

var _ coretransport.Client = (*testStreamTransport)(nil)

func TestManagedTunnelRelayCopyAndQueueOutboundPacketCopiesPacket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay := &managedTunnelRelay{
		ctx:        ctx,
		outboundCh: make(chan managedOutboundPacket, 1),
	}

	packet := []byte{1, 2, 3}
	if err := relay.copyAndQueueOutboundPacket(packet); err != nil {
		t.Fatalf("copyAndQueueOutboundPacket() error = %v", err)
	}
	packet[0] = 9

	got := <-relay.outboundCh
	defer got.release()
	if got.data[0] != 1 {
		t.Fatalf("queued packet was not copied, first byte = %d", got.data[0])
	}
}

func TestManagedTunnelRelayCloseUnblocksFullOutboundQueue(t *testing.T) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		relay := &managedTunnelRelay{
			ctx:        ctx,
			cancel:     cancel,
			outboundCh: make(chan managedOutboundPacket, 1),
			flows:      make(map[uint64]*managedTunnelFlow),
		}
		if err := relay.queueOutboundPacket([]byte{1}); err != nil {
			t.Fatal(err)
		}
		queued := make(chan error, 1)
		go func() {
			queued <- relay.queueOutboundPacket([]byte{2})
		}()

		closed := make(chan error, 1)
		go func() {
			closed <- relay.close()
		}()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("relay close blocked behind a full outbound queue")
		}
		select {
		case err := <-queued:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("blocked queue result = %v, want net.ErrClosed", err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked outbound writer was not released")
		}
		if err := relay.queueOutboundPacket([]byte{3}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("post-close queue result = %v, want net.ErrClosed", err)
		}
	}
}

func TestManagedTunnelRelayRejectsFlowsAfterClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	relay := &managedTunnelRelay{
		ctx:        ctx,
		cancel:     cancel,
		outboundCh: make(chan managedOutboundPacket, 1),
		flows:      make(map[uint64]*managedTunnelFlow),
	}
	if err := relay.close(); err != nil {
		t.Fatal(err)
	}
	if release, ok := relay.acquireFlowSlot(); ok {
		release()
		t.Fatal("closed relay accepted a new flow")
	}
}

func TestManagedTunnelRelayOutboundFailureClosesRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := &fakeManagedTCPBackend{}
	relay := &managedTunnelRelay{
		ctx:        ctx,
		cancel:     cancel,
		tcpBackend: backend,
		outboundCh: make(chan managedOutboundPacket),
		flows:      make(map[uint64]*managedTunnelFlow),
	}
	want := errors.New("synthetic outbound failure")
	relay.fail(want)

	packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 8, 8, 8, 8}
	if _, err := relay.writePacket(packet); !errors.Is(err, want) {
		t.Fatalf("writePacket() error = %v want %v", err, want)
	}
	if len(backend.injectedPackets) != 0 {
		t.Fatal("packet was injected after the outbound relay failed")
	}

	buf := make([]byte, 1)
	if _, err := relay.readPacket(buf); !errors.Is(err, want) {
		t.Fatalf("readPacket() error = %v want %v", err, want)
	}
	deadline := time.Now().Add(time.Second)
	for relay.closeState.Load() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("outbound failure did not finish closing the relay")
		}
		time.Sleep(time.Millisecond)
	}
	if !backend.closed {
		t.Fatal("outbound failure did not close the relay backend")
	}
	relay.flowMu.Lock()
	flowsClosed := relay.flowsClosed
	relay.flowMu.Unlock()
	if !flowsClosed {
		t.Fatal("outbound failure did not close managed flows")
	}
}

func TestManagedTunnelRelayEnforcesBufferByteBudget(t *testing.T) {
	relay := &managedTunnelRelay{}
	flowBytes := int64(2 * managedTunnelTCPBufferMax)
	wantFlows := int(managedTunnelTCPRelayByteLimit / flowBytes)
	releases := make([]func(), 0, wantFlows)
	for range wantFlows {
		release, ok := relay.acquireFlowSlot()
		if !ok {
			t.Fatalf("acquireFlowSlot() rejected flow %d of %d", len(releases)+1, wantFlows)
		}
		releases = append(releases, release)
	}
	if release, ok := relay.acquireFlowSlot(); ok {
		release()
		t.Fatal("acquireFlowSlot() exceeded relay byte budget")
	}
	if relay.flowBytes != managedTunnelTCPRelayByteLimit {
		t.Fatalf("relay flow bytes = %d want %d", relay.flowBytes, managedTunnelTCPRelayByteLimit)
	}

	releases[0]()
	release, ok := relay.acquireFlowSlot()
	if !ok {
		t.Fatal("acquireFlowSlot() did not restore released byte capacity")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
	if relay.flowBytes != 0 {
		t.Fatalf("relay flow bytes after release = %d want 0", relay.flowBytes)
	}
}

func TestPacketBufferToOutboundPacketCopiesHeaders(t *testing.T) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 8,
		Payload:            gbuffer.MakeWithData([]byte{9, 10}),
	})
	copy(pkt.TransportHeader().Push(4), []byte{5, 6, 7, 8})
	copy(pkt.NetworkHeader().Push(4), []byte{1, 2, 3, 4})
	defer pkt.DecRef()

	outbound, err := packetBufferToOutboundPacket(pkt)
	if err != nil {
		t.Fatalf("packetBufferToOutboundPacket() error = %v", err)
	}
	defer outbound.release()

	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if !bytes.Equal(outbound.data, want) {
		t.Fatalf("packetBufferToOutboundPacket() = %v want %v", outbound.data, want)
	}
}

func TestManagedTunnelRelayReadPacketDropsOversizePacket(t *testing.T) {
	tun := &TUN{}
	relay := &managedTunnelRelay{
		tun:        tun,
		outboundCh: make(chan managedOutboundPacket, 2),
	}
	relay.outboundCh <- managedOutboundPacket{data: []byte{1, 2, 3}}
	relay.outboundCh <- managedOutboundPacket{data: []byte{4, 5}}

	buf := make([]byte, 2)
	n, err := relay.readPacket(buf)
	if err != nil {
		t.Fatalf("readPacket() error = %v", err)
	}
	if n != len(buf) {
		t.Fatalf("readPacket() bytes = %d want %d", n, len(buf))
	}
	if buf[0] != 4 || buf[1] != 5 {
		t.Fatalf("readPacket() buf = %v want [4 5]", buf)
	}
	if got := tun.OversizePacketDrops(); got != 1 {
		t.Fatalf("OversizePacketDrops() = %d want 1", got)
	}
}

func TestManagedTunnelRelayWritePacketInjectsOnlyTCPIntoBackend(t *testing.T) {
	backend := &fakeManagedTCPBackend{}
	relay := &managedTunnelRelay{
		tcpBackend: backend,
	}

	tcpPacket := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 8, 8, 8, 8}
	n, err := relay.writePacket(tcpPacket)
	if err != nil {
		t.Fatalf("write tcp packet: %v", err)
	}
	if n != len(tcpPacket) {
		t.Fatalf("write tcp packet bytes = %d want %d", n, len(tcpPacket))
	}
	if len(backend.injectedPackets) != 1 {
		t.Fatalf("tcp backend inject count = %d want 1", len(backend.injectedPackets))
	}

	udpPacket := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 8, 8, 8, 8, 0, 53, 0, 53, 0, 8, 0, 0}
	n, err = relay.writePacket(udpPacket)
	if err != nil {
		t.Fatalf("write udp packet: %v", err)
	}
	if n != len(udpPacket) {
		t.Fatalf("write udp packet bytes = %d want %d", n, len(udpPacket))
	}
	if len(backend.injectedPackets) != 1 {
		t.Fatalf("udp packet entered tcp backend, inject count = %d want 1", len(backend.injectedPackets))
	}

}
