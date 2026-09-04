// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/ippacket"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestTunPacketHandlerRewritesIngressAndEgressIPv4(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	var sentMu sync.Mutex
	var sent []*vpnpacket.VpnPacket
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		Protocol: client.ProtocolTalariaUDP,
		ClientID: 10001,
	}, SessionWriters{
		Packet: func(packet *vpnpacket.VpnPacket) error {
			sentMu.Lock()
			defer sentMu.Unlock()
			sent = append(sent, packet)
			return nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	ingress := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: 10001}, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: ingress,
	}); err != nil {
		t.Fatal(err)
	}
	writes := waitForTunWrites(t, dev, 1)
	if len(writes) != 1 {
		t.Fatalf("tun writes = %d, want 1", len(writes))
	}
	packet, parseErr := ippacket.ParseIPPacket(writes[0])
	if parseErr != nil {
		t.Fatalf("parse rewritten ingress: %s", parseErr)
	}
	if got := packet.SrcAddr(); got != netip.MustParseAddr("172.21.100.2") {
		t.Fatalf("rewritten source = %s", got)
	}

	egress := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2})
	handler.handleTunPacket(egress)
	sent = waitForVPNPackets(t, &sentMu, &sent, 1)
	if len(sent) != 1 {
		t.Fatalf("sent packets = %d, want 1", len(sent))
	}
	packet, parseErr = ippacket.ParseIPPacket(sent[0].Data)
	if parseErr != nil {
		t.Fatalf("parse rewritten egress: %s", parseErr)
	}
	if got := packet.DstAddr(); got != netip.MustParseAddr("10.80.0.2") {
		t.Fatalf("rewritten destination = %s", got)
	}
}

func TestTunPacketHandlerRequiresExplicitClientToClientAccess(t *testing.T) {
	packet, err := ippacket.ParseIPPacket(makeIPv4TCPPacket(
		[4]byte{10, 80, 0, 2},
		[4]byte{172, 21, 100, 2},
	))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name  string
		allow bool
		want  error
	}{
		{name: "blocked by default", want: errTargetBlocked},
		{name: "explicitly allowed", allow: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
				Device:              discardTunDevice{batchSize: 1},
				VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
				AllowClientToClient: tt.allow,
				TargetPolicy:        allowPrivateTargetPolicy(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()

			err = handler.validatePacketTarget(context.Background(), SessionContext{ClientID: 1}, packet)
			if !errors.Is(err, tt.want) {
				t.Fatalf("validatePacketTarget() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestTunPacketHandlerClampsTCPMSS(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	var rawMu sync.Mutex
	var rawFrames [][]byte
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		Protocol: client.ProtocolTalariaUDP,
		ClientID: 10001,
	}, SessionWriters{
		RawBatch: func(bufs [][]byte, sizes []int) (int, error) {
			rawMu.Lock()
			defer rawMu.Unlock()
			for i := range bufs {
				if i >= len(sizes) || sizes[i] <= 0 {
					continue
				}
				rawFrames = append(rawFrames, append([]byte(nil), bufs[i][:sizes[i]]...))
			}
			return len(rawFrames), nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	ingress := makeIPv4TCPSYNPacketWithMSS([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}, 1460)
	if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: 10001}, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: ingress,
	}); err != nil {
		t.Fatal(err)
	}
	writes := waitForTunWrites(t, dev, 1)
	if len(writes) != 1 {
		t.Fatalf("tun writes = %d, want 1", len(writes))
	}
	if got := tcpMSSFromIPv4(t, writes[0]); got != dataplane.DefaultMSS {
		t.Fatalf("ingress MSS = %d, want %d", got, dataplane.DefaultMSS)
	}

	headroom := vpnpacket.RawCmdDataHeaderLen()
	buf := make([]byte, headroom+44)
	copy(buf[headroom:], makeIPv4TCPSYNPacketWithMSS([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}, 1460))
	handler.handleTunBatch([][]byte{buf}, []int{44}, 1, headroom)

	rawFrames = waitForRawFrames(t, &rawMu, &rawFrames, 1)
	if len(rawFrames) != 1 {
		t.Fatalf("raw frames = %d, want 1", len(rawFrames))
	}
	packet := &vpnpacket.VpnPacket{}
	if err := packet.ReadVpnPacketFromBytes(rawFrames[0]); err != nil {
		t.Fatalf("decode raw frame: %v", err)
	}
	if got := tcpMSSFromIPv4(t, packet.Data); got != dataplane.DefaultMSS {
		t.Fatalf("egress MSS = %d, want %d", got, dataplane.DefaultMSS)
	}
}

func TestTunPacketHandlerUsesRawBatchWriterForEgressIPv4(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	var packetWrites atomic.Int32
	var rawMu sync.Mutex
	var rawFrames [][]byte
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		Protocol: client.ProtocolTalariaUDP,
		ClientID: 10001,
	}, SessionWriters{
		Packet: func(packet *vpnpacket.VpnPacket) error {
			packetWrites.Add(1)
			return nil
		},
		RawBatch: func(bufs [][]byte, sizes []int) (int, error) {
			rawMu.Lock()
			defer rawMu.Unlock()
			for i := range bufs {
				if i >= len(sizes) || sizes[i] <= 0 {
					continue
				}
				rawFrames = append(rawFrames, append([]byte(nil), bufs[i][:sizes[i]]...))
			}
			return len(rawFrames), nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	ingress := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: 10001}, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: ingress,
	}); err != nil {
		t.Fatal(err)
	}

	headroom := vpnpacket.RawCmdDataHeaderLen()
	buf := make([]byte, headroom+40)
	copy(buf[headroom:], makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}))
	handler.handleTunBatch([][]byte{buf}, []int{40}, 1, headroom)

	rawFrames = waitForRawFrames(t, &rawMu, &rawFrames, 1)
	if packetWrites.Load() != 0 {
		t.Fatalf("packet writes = %d, want 0", packetWrites.Load())
	}
	if len(rawFrames) != 1 {
		t.Fatalf("raw frames = %d, want 1", len(rawFrames))
	}
	frame := rawFrames[0]
	if len(frame) != headroom+40 {
		t.Fatalf("raw frame len = %d, want %d", len(frame), headroom+40)
	}
	packet := &vpnpacket.VpnPacket{}
	if err := packet.ReadVpnPacketFromBytes(frame); err != nil {
		t.Fatalf("decode raw frame: %v", err)
	}
	if packet.Cmd != vpnpacket.CmdData {
		t.Fatalf("cmd = %d, want CmdData", packet.Cmd)
	}
	if packet.ClientId != 10001 {
		t.Fatalf("client id = %d, want 10001", packet.ClientId)
	}
	if packet.DataSequenceId == 0 {
		t.Fatal("data sequence id was not set")
	}
	parsed, parseErr := ippacket.ParseIPPacket(packet.Data)
	if parseErr != nil {
		t.Fatalf("parse payload: %s", parseErr)
	}
	if got := parsed.DstAddr(); got != netip.MustParseAddr("10.80.0.2") {
		t.Fatalf("rewritten destination = %s", got)
	}
}

func TestTunPacketHandlerCompletesPartialRawBatchWrites(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	var rawMu sync.Mutex
	var rawFrames [][]byte
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		Protocol: client.ProtocolTalariaUDP,
		ClientID: 10001,
	}, SessionWriters{
		RawBatch: func(bufs [][]byte, sizes []int) (int, error) {
			rawMu.Lock()
			defer rawMu.Unlock()
			limit := 2
			if len(bufs) < limit {
				limit = len(bufs)
			}
			for i := 0; i < limit; i++ {
				if i >= len(sizes) || sizes[i] <= 0 {
					continue
				}
				rawFrames = append(rawFrames, append([]byte(nil), bufs[i][:sizes[i]]...))
			}
			return limit, nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	ingress := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: 10001}, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: ingress,
	}); err != nil {
		t.Fatal(err)
	}
	waitForTunWrites(t, dev, 1)

	const count = 5
	headroom := vpnpacket.RawCmdDataHeaderLen()
	bufs := make([][]byte, count)
	sizes := make([]int, count)
	for i := range bufs {
		bufs[i] = make([]byte, headroom+40)
		copy(bufs[i][headroom:], makeIPv4TCPPacket([4]byte{10, 15, 20, byte(66 + i)}, [4]byte{172, 21, 100, 2}))
		sizes[i] = 40
	}

	handler.handleTunBatch(bufs, sizes, count, headroom)

	rawFrames = waitForRawFrames(t, &rawMu, &rawFrames, count)
	if len(rawFrames) != count {
		t.Fatalf("raw frames = %d, want %d", len(rawFrames), count)
	}
	for i, frame := range rawFrames {
		packet := &vpnpacket.VpnPacket{}
		if err := packet.ReadVpnPacketFromBytes(frame); err != nil {
			t.Fatalf("decode raw frame[%d]: %v", i, err)
		}
		if packet.DataSequenceId != uint32(i+1) {
			t.Fatalf("raw frame[%d] sequence = %d, want %d", i, packet.DataSequenceId, i+1)
		}
	}
}

func TestTunPacketHandlerCompactsBorrowedFixedV4IngressFrame(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		Protocol: client.ProtocolTalariaUDP,
		ClientID: 10001,
	}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			return nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	payload := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	frame := make([]byte, vpnpacket.FixedV4PayloadOffset()+len(payload))
	if !vpnpacket.WriteRawFixedV4DataHeader(frame[:vpnpacket.FixedV4PayloadOffset()], 10001, 1, []byte{10, 80, 0, 2}, []byte{10, 15, 20, 66}) {
		t.Fatal("write fixed v4 header failed")
	}
	copy(frame[vpnpacket.FixedV4PayloadOffset():], payload)

	handled, borrowed, responses, err := handler.HandleBorrowedRawFrame(context.Background(), SessionContext{ClientID: 10001}, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || borrowed || len(responses) != 0 {
		t.Fatalf("handled=%v borrowed=%v responses=%d", handled, borrowed, len(responses))
	}

	writes := waitForTunWrites(t, dev, 1)
	if len(writes) != 1 {
		t.Fatalf("tun writes = %d, want 1", len(writes))
	}
	offsets := dev.WriteOffsets()
	if len(offsets) != 1 || offsets[0] != dev.WriteHeadroom() {
		t.Fatalf("write offsets = %v, want [%d]", offsets, dev.WriteHeadroom())
	}
	packet, parseErr := ippacket.ParseIPPacket(writes[0])
	if parseErr != nil {
		t.Fatalf("parse rewritten ingress: %s", parseErr)
	}
	if got := packet.SrcAddr(); got != netip.MustParseAddr("172.21.100.2") {
		t.Fatalf("rewritten source = %s", got)
	}
}

func TestTunPacketHandlerRejectsSourceChangeAndBlockedTargetBeforeWrite(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	session := SessionContext{Protocol: client.ProtocolTalariaUDP, ClientID: 10001}
	detach, err := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:      vpnpacket.CmdData,
		ClientId: 99999,
		Data:     makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
	}); err != nil {
		t.Fatal(err)
	}
	waitForTunWrites(t, dev, 1)

	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 3}, [4]byte{10, 15, 20, 66}),
	}); err == nil {
		t.Fatal("changed inner source address was accepted")
	}
	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{169, 254, 169, 254}),
	}); err == nil {
		t.Fatal("link-local metadata target was accepted")
	}
	if got := len(dev.Writes()); got != 1 {
		t.Fatalf("tun writes = %d, want 1", got)
	}
}

func TestNewTunPacketHandlerRejectsCustomTargetPolicy(t *testing.T) {
	called := false
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device: discardTunDevice{batchSize: 1},
		TargetPolicy: TargetPolicyFunc(func(context.Context, TargetPolicyRequest) error {
			called = true
			return nil
		}),
	})
	if handler != nil || err == nil {
		t.Fatalf("handler result = %v, %v", handler, err)
	}
	if called {
		t.Fatal("custom target policy was called")
	}
}

func TestTunPacketHandlerKeepsDownlinkIsolatedBySessionVIP(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	type received struct {
		clientID uint64
		packet   *vpnpacket.VpnPacket
	}
	downlink := make(chan received, 2)
	attach := func(clientID uint64) func() {
		detach, attachErr := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: clientID}, SessionWriters{
			Packet: func(packet *vpnpacket.VpnPacket) error {
				downlink <- received{clientID: clientID, packet: packet}
				return nil
			},
			Close: func() {},
		})
		if attachErr != nil {
			t.Fatal(attachErr)
		}
		return detach
	}
	detachA := attach(10001)
	defer detachA()
	detachB := attach(10002)
	defer detachB()

	for _, tc := range []struct {
		clientID uint64
		source   [4]byte
	}{
		{clientID: 10001, source: [4]byte{10, 80, 0, 2}},
		{clientID: 10002, source: [4]byte{10, 80, 0, 3}},
	} {
		if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: tc.clientID}, &vpnpacket.VpnPacket{
			Cmd:      vpnpacket.CmdData,
			ClientId: 99999,
			Data:     makeIPv4TCPPacket(tc.source, [4]byte{10, 15, 20, 66}),
		}); err != nil {
			t.Fatal(err)
		}
	}
	waitForTunWrites(t, dev, 2)

	handler.handleTunPacket(makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}))
	handler.handleTunPacket(makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 3}))

	wantDestination := map[uint64]netip.Addr{
		10001: netip.MustParseAddr("10.80.0.2"),
		10002: netip.MustParseAddr("10.80.0.3"),
	}
	seen := make(map[uint64]bool)
	for i := 0; i < 2; i++ {
		select {
		case item := <-downlink:
			parsed, parseErr := ippacket.ParseIPPacket(item.packet.Data)
			if parseErr != nil {
				t.Fatalf("parse downlink: %s", parseErr)
			}
			if got := parsed.DstAddr(); got != wantDestination[item.clientID] {
				t.Fatalf("client %d destination = %s, want %s", item.clientID, got, wantDestination[item.clientID])
			}
			seen[item.clientID] = true
		case <-time.After(time.Second):
			t.Fatal("missing isolated downlink packet")
		}
	}
	if !seen[10001] || !seen[10002] {
		t.Fatalf("downlink sessions = %v", seen)
	}
}

func TestTunPacketHandlerRejectsPacketWriterWithoutCloseHook(t *testing.T) {
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        newFakeTunDevice(),
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	if _, err := handler.AttachSession(context.Background(), SessionContext{ClientID: 10001}, func(*vpnpacket.VpnPacket) error {
		return nil
	}); err == nil {
		t.Fatal("packet writer without an interruptible Close hook was accepted")
	}
	if _, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
	}); err == nil {
		t.Fatal("session writers without an interruptible Close hook were accepted")
	}
}

func TestTunPacketHandlerDetachInterruptsBlockedPacketWriter(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	writerStarted := make(chan struct{})
	unblockWriter := make(chan struct{})
	writerClosed := make(chan struct{})
	var closeWriter sync.Once
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			close(writerStarted)
			<-unblockWriter
			return nil
		},
		Close: func() {
			closeWriter.Do(func() {
				close(unblockWriter)
				close(writerClosed)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()

	session := handler.getSession(SessionContext{ClientID: 10001})
	session.bindClientIP(netip.MustParseAddr("10.80.0.2"))
	handler.handleTunPacket(makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}))
	select {
	case <-writerStarted:
	case <-time.After(time.Second):
		t.Fatal("packet writer did not start")
	}

	detach()
	select {
	case <-writerClosed:
	case <-time.After(time.Second):
		t.Fatal("detach did not close the blocked packet writer")
	}
	waitForSessionDownlinkReleased(t, session)
}

func TestTunPacketHandlerPacketWriterFallbackDoesNotBlockOtherSessions(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	unblockA := make(chan struct{})
	var closeA sync.Once
	closeWriterA := func() {
		closeA.Do(func() {
			close(unblockA)
		})
	}
	receivedB := make(chan struct{}, 1)
	detachA, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			<-unblockA
			return nil
		},
		Close: closeWriterA,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachA()
	detachB, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10002}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			receivedB <- struct{}{}
			return nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachB()

	handler.getSession(SessionContext{ClientID: 10001}).bindClientIP(netip.MustParseAddr("10.80.0.2"))
	handler.getSession(SessionContext{ClientID: 10002}).bindClientIP(netip.MustParseAddr("10.80.0.3"))
	headroom := vpnpacket.RawCmdDataHeaderLen()
	packetA := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2})
	packetB := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 3})
	bufs := [][]byte{
		append(make([]byte, headroom), packetA...),
		append(make([]byte, headroom), packetB...),
	}
	done := make(chan struct{})
	go func() {
		handler.handleTunBatch(bufs, []int{len(packetA), len(packetB)}, 2, headroom)
		close(done)
	}()

	select {
	case <-receivedB:
	case <-time.After(time.Second):
		closeWriterA()
		t.Fatal("session B was blocked by session A")
	}
	closeWriterA()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("downlink batch did not finish")
	}
}

func TestTunPacketHandlerPacketWriterFallbackDropsAtByteLimitWithoutDetaching(t *testing.T) {
	dev := newFakeTunDevice()
	packet := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2})
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          dev,
		VirtualIPBase:   netip.MustParseAddr("172.21.100.1"),
		DownlinkPackets: 2,
		DownlinkBytes:   len(packet),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	writerStarted := make(chan struct{})
	unblockWriter := make(chan struct{})
	writerClosed := make(chan struct{})
	var closeWriter sync.Once
	detach, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			close(writerStarted)
			<-unblockWriter
			return nil
		},
		Close: func() {
			closeWriter.Do(func() {
				close(unblockWriter)
				close(writerClosed)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()
	session := handler.getSession(SessionContext{ClientID: 10001})
	session.bindClientIP(netip.MustParseAddr("10.80.0.2"))

	handler.handleTunPacket(packet)
	select {
	case <-writerStarted:
	case <-time.After(time.Second):
		t.Fatal("packet writer did not start")
	}
	handler.handleTunPacket(makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}))
	if got := handler.getSession(SessionContext{ClientID: 10001}); got != session {
		t.Fatal("session was detached after exceeding its downlink byte limit")
	}
	select {
	case <-writerClosed:
		t.Fatal("downlink queue pressure closed the session writer")
	default:
	}

	detach()
	select {
	case <-writerClosed:
	case <-time.After(time.Second):
		t.Fatal("explicit detach did not close the session writer")
	}
	waitForSessionDownlinkReleased(t, session)
}

func TestTunPacketHandlerRawBatchOverflowDropsWithoutDetaching(t *testing.T) {
	const queuedPackets = 252
	const incomingPackets = 6

	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          newFakeTunDevice(),
		VirtualIPBase:   netip.MustParseAddr("172.21.100.1"),
		DownlinkPackets: 256,
		DownlinkBytes:   1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	writerStarted := make(chan struct{})
	unblockWriter := make(chan struct{})
	writerClosed := make(chan struct{})
	var startWriter sync.Once
	var closeWriter sync.Once
	sessionContext := SessionContext{Protocol: client.ProtocolTalariaUDP, ClientID: 10001, Generation: 1}
	detach, err := handler.AttachSessionWriters(context.Background(), sessionContext, SessionWriters{
		RawBatch: func(bufs [][]byte, _ []int) (int, error) {
			startWriter.Do(func() { close(writerStarted) })
			<-unblockWriter
			return len(bufs), nil
		},
		Close: func() {
			closeWriter.Do(func() {
				close(unblockWriter)
				close(writerClosed)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()
	session := handler.getSession(sessionContext)
	session.bindClientIP(netip.MustParseAddr("10.80.0.2"))

	headroom := vpnpacket.RawCmdDataHeaderLen()
	packet := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, session.vip.As4())
	queuedBufs := make([][]byte, queuedPackets)
	queuedSizes := make([]int, queuedPackets)
	for i := range queuedBufs {
		queuedBufs[i] = append(make([]byte, headroom), packet...)
		queuedSizes[i] = len(queuedBufs[i])
	}
	if err := handler.enqueueSessionDownlink(session, queuedBufs, queuedSizes); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writerStarted:
	case <-time.After(time.Second):
		t.Fatal("raw batch writer did not start")
	}

	incomingBufs := make([][]byte, incomingPackets)
	incomingSizes := make([]int, incomingPackets)
	for i := range incomingBufs {
		incomingBufs[i] = append(make([]byte, headroom), packet...)
		incomingSizes[i] = len(packet)
	}
	handler.handleTunBatch(incomingBufs, incomingSizes, incomingPackets, headroom)

	if got := handler.getSession(sessionContext); got != session {
		t.Fatal("session was detached after a transient raw batch overflow")
	}
	session.sendMu.Lock()
	packets, bytes := session.sendPackets, session.sendBytes
	session.sendMu.Unlock()
	if packets != queuedPackets || bytes <= 0 {
		t.Fatalf("retained downlink budget = %d packets/%d bytes, want %d queued packets", packets, bytes, queuedPackets)
	}
	select {
	case <-writerClosed:
		t.Fatal("raw batch overflow closed the session writer")
	default:
	}

	detach()
	select {
	case <-writerClosed:
	case <-time.After(time.Second):
		t.Fatal("explicit detach did not close the raw batch writer")
	}
	waitForSessionDownlinkReleased(t, session)
}

func TestTunPacketHandlerEnforcesGlobalDownlinkBudgetBeforeCopy(t *testing.T) {
	dev := newFakeTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:                dev,
		VirtualIPBase:         netip.MustParseAddr("172.21.100.1"),
		DownlinkPackets:       1,
		DownlinkBytes:         64,
		GlobalDownlinkPackets: 1,
		GlobalDownlinkBytes:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	writerStarted := make(chan struct{})
	unblockWriter := make(chan struct{})
	var closeWriter sync.Once
	detachFirst, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			close(writerStarted)
			<-unblockWriter
			return nil
		},
		Close: func() { closeWriter.Do(func() { close(unblockWriter) }) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachFirst()
	var secondWrites atomic.Int32
	detachSecond, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10002}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			secondWrites.Add(1)
			return nil
		},
		Close: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachSecond()

	first := handler.getSession(SessionContext{ClientID: 10001})
	second := handler.getSession(SessionContext{ClientID: 10002})
	packet := &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdDataReturn, Data: make([]byte, 32)}
	if err := handler.enqueueSessionPacketDownlink(first, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writerStarted:
	case <-time.After(time.Second):
		t.Fatal("first downlink writer did not start")
	}
	if err := handler.enqueueSessionPacketDownlink(second, packet); !errors.Is(err, ErrTunDownlinkQueueFull) {
		t.Fatalf("second session downlink = %v, want ErrTunDownlinkQueueFull", err)
	}
	if got := secondWrites.Load(); got != 0 {
		t.Fatalf("second session writes = %d, want 0", got)
	}
	handler.downlinkBudgetMu.Lock()
	packets, bytes := handler.downlinkPacketsUsed, handler.downlinkBytesUsed
	handler.downlinkBudgetMu.Unlock()
	if packets != 1 || bytes != len(packet.Data) {
		t.Fatalf("global downlink budget = %d packets/%d bytes, want 1/%d", packets, bytes, len(packet.Data))
	}

	detachFirst()
	waitForGlobalDownlinkReleased(t, handler)
}

func TestTunPacketHandlerGlobalDownlinkPressureDropsWithoutEvictingSessions(t *testing.T) {
	tests := []struct {
		name    string
		writers SessionWriters
		deliver func(*TunPacketHandler, []byte)
	}{
		{
			name: "packet fallback",
			writers: SessionWriters{
				Packet: func(*vpnpacket.VpnPacket) error { return nil },
				Close:  func() {},
			},
			deliver: func(handler *TunPacketHandler, packet []byte) {
				handler.handleTunPacket(packet)
			},
		},
		{
			name: "raw batch",
			writers: SessionWriters{
				RawBatch: func(bufs [][]byte, _ []int) (int, error) { return len(bufs), nil },
				Close:    func() {},
			},
			deliver: func(handler *TunPacketHandler, packet []byte) {
				headroom := vpnpacket.RawCmdDataHeaderLen()
				buf := append(make([]byte, headroom), packet...)
				handler.handleTunBatch([][]byte{buf}, []int{len(packet)}, 1, headroom)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
				Device:                newFakeTunDevice(),
				VirtualIPBase:         netip.MustParseAddr("172.21.100.1"),
				DownlinkPackets:       2,
				DownlinkBytes:         128,
				GlobalDownlinkPackets: 2,
				GlobalDownlinkBytes:   256,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()

			attachOwner := func(clientID uint64) (SessionContext, *tunHandlerSession, func()) {
				started := make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				session := SessionContext{ClientID: clientID}
				detach, attachErr := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
					Packet: func(*vpnpacket.VpnPacket) error {
						close(started)
						<-release
						return nil
					},
					Close: func() { releaseOnce.Do(func() { close(release) }) },
				})
				if attachErr != nil {
					t.Fatal(attachErr)
				}
				owner := handler.getSession(session)
				if err := handler.enqueueSessionPacketDownlink(owner, &vpnpacket.VpnPacket{Data: make([]byte, 32)}); err != nil {
					t.Fatal(err)
				}
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("capacity owner writer did not start")
				}
				return session, owner, detach
			}

			firstSession, _, detachFirst := attachOwner(10001)
			defer detachFirst()
			secondSession, _, detachSecond := attachOwner(10002)
			defer detachSecond()
			requesterSession := SessionContext{ClientID: 10003}
			detachRequester, err := handler.AttachSessionWriters(context.Background(), requesterSession, tt.writers)
			if err != nil {
				t.Fatal(err)
			}
			defer detachRequester()
			requester := handler.getSession(requesterSession)
			requester.bindClientIP(netip.MustParseAddr("10.80.0.3"))

			destination := requester.vip.As4()
			tt.deliver(handler, makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, destination))

			if got := handler.getSession(requesterSession); got != requester {
				t.Fatal("locally empty requester was detached by global pressure")
			}
			requester.sendMu.Lock()
			requesterPackets, requesterBytes := requester.sendPackets, requester.sendBytes
			requester.sendMu.Unlock()
			if requesterPackets != 0 || requesterBytes != 0 {
				t.Fatalf("requester retained downlink budget: %d packets/%d bytes", requesterPackets, requesterBytes)
			}
			for _, session := range []SessionContext{firstSession, secondSession} {
				if handler.getSession(session) == nil {
					t.Fatalf("capacity owner %d was detached by global pressure", session.ClientID)
				}
			}
		})
	}
}

func TestTunPacketHandlerCloseInterruptsBlockedDeviceWrite(t *testing.T) {
	dev := newBlockingWriteTunDevice()
	dev.holdWrite = make(chan struct{})
	var cleanupCalls atomic.Int32
	cleanupDone := make(chan struct{})
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		Cleanup:       func() error { cleanupCalls.Add(1); close(cleanupDone); return nil },
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.AttachSessionWriters(context.Background(), SessionContext{ClientID: 10001}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandlePacket(context.Background(), SessionContext{ClientID: 10001}, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dev.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("TUN write did not start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- handler.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = dev.Close()
		t.Fatal("handler Close deadlocked behind a blocked TUN write")
	}
	select {
	case <-cleanupDone:
		t.Fatal("cleanup ran before the blocked TUN write returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(dev.holdWrite)
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not run after closing the TUN device")
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls.Load())
	}
}

func TestTunPacketHandlerRetriesFailedCleanup(t *testing.T) {
	cleanupErr := errors.New("injected cleanup failure")
	var cleanupCalls atomic.Int32
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device: newFakeTunDevice(),
		Cleanup: func() error {
			if cleanupCalls.Add(1) == 1 {
				return cleanupErr
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := handler.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("first Close error = %v, want %v", err, cleanupErr)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("second Close did not retry cleanup: %v", err)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("third Close after successful cleanup: %v", err)
	}
	if cleanupCalls.Load() != 2 {
		t.Fatalf("cleanup calls = %d, want 2", cleanupCalls.Load())
	}
}

func TestTunPacketHandlerCloseExtensionsMayReenterClose(t *testing.T) {
	device := &reentrantCloseTunDevice{TunDevice: newFakeTunDevice()}
	var handler *TunPacketHandler
	var cleanupCalls int
	var err error
	handler, err = NewTunPacketHandler(TunPacketHandlerConfig{
		Device: device,
		Cleanup: func() error {
			cleanupCalls++
			return handler.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	device.onClose = func() { _ = handler.Close() }
	done := make(chan error, 1)
	go func() { done <- handler.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TunPacketHandler.Close deadlocked on a reentrant extension")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
}

type reentrantCloseTunDevice struct {
	TunDevice
	onClose func()
}

func (d *reentrantCloseTunDevice) Close() error {
	if d.onClose != nil {
		d.onClose()
	}
	return d.TunDevice.Close()
}

type blockingWriteTunDevice struct {
	writeStarted chan struct{}
	closed       chan struct{}
	holdWrite    chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingWriteTunDevice() *blockingWriteTunDevice {
	return &blockingWriteTunDevice{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (d *blockingWriteTunDevice) ReadPackets(ctx context.Context, _ [][]byte, _ []int, _ int) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *blockingWriteTunDevice) WritePackets(ctx context.Context, _ [][]byte, _ []int, _ int) (int, error) {
	d.writeOnce.Do(func() {
		close(d.writeStarted)
	})
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-d.closed:
		err = net.ErrClosed
	}
	if d.holdWrite != nil {
		<-d.holdWrite
	}
	return 0, err
}

func (*blockingWriteTunDevice) ReleaseVirtualIP(context.Context, netip.Addr) error { return nil }
func (*blockingWriteTunDevice) BatchSize() int                                     { return 1 }
func (*blockingWriteTunDevice) MTU() int                                           { return 1301 }
func (*blockingWriteTunDevice) WriteHeadroom() int                                 { return 0 }
func (d *blockingWriteTunDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

type fakeTunDevice struct {
	closed chan struct{}

	mu      sync.Mutex
	writes  [][]byte
	offsets []int
}

func newFakeTunDevice() *fakeTunDevice {
	return &fakeTunDevice{closed: make(chan struct{})}
}

func waitForSessionDownlinkReleased(t *testing.T, session *tunHandlerSession) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		session.sendMu.Lock()
		packets, bytes := session.sendPackets, session.sendBytes
		session.sendMu.Unlock()
		if packets == 0 && bytes == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("downlink counters were not released: packets=%d bytes=%d", packets, bytes)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForGlobalDownlinkReleased(t *testing.T, handler *TunPacketHandler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		handler.downlinkBudgetMu.Lock()
		packets, bytes := handler.downlinkPacketsUsed, handler.downlinkBytesUsed
		handler.downlinkBudgetMu.Unlock()
		if packets == 0 && bytes == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("global downlink counters were not released: packets=%d bytes=%d", packets, bytes)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForTunWrites(t *testing.T, dev *fakeTunDevice, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		writes := dev.Writes()
		if len(writes) >= want {
			return writes
		}
		if time.Now().After(deadline) {
			t.Fatalf("tun writes = %d, want at least %d", len(writes), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForRawFrames(t *testing.T, mu *sync.Mutex, frames *[][]byte, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(*frames) >= want {
			got := append([][]byte(nil), (*frames)...)
			mu.Unlock()
			return got
		}
		mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := append([][]byte(nil), (*frames)...)
	mu.Unlock()
	return got
}

func waitForVPNPackets(t *testing.T, mu *sync.Mutex, packets *[]*vpnpacket.VpnPacket, want int) []*vpnpacket.VpnPacket {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(*packets) >= want {
			got := append([]*vpnpacket.VpnPacket(nil), (*packets)...)
			mu.Unlock()
			return got
		}
		mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	got := append([]*vpnpacket.VpnPacket(nil), (*packets)...)
	mu.Unlock()
	return got
}

func (d *fakeTunDevice) ReadPackets(ctx context.Context, _ [][]byte, _ []int, _ int) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *fakeTunDevice) WritePackets(_ context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(sizes) < len(bufs) {
		return 0, errors.New("sizes underflow")
	}
	written := 0
	for i, buf := range bufs {
		size := sizes[i]
		if size <= 0 {
			continue
		}
		if offset > len(buf) || offset+size > len(buf) {
			return written, errors.New("offset overflows buffer")
		}
		copied := append([]byte(nil), buf[offset:offset+size]...)
		d.writes = append(d.writes, copied)
		d.offsets = append(d.offsets, offset)
		written++
	}
	return written, nil
}

func (*fakeTunDevice) ReleaseVirtualIP(context.Context, netip.Addr) error { return nil }
func (d *fakeTunDevice) BatchSize() int                                   { return 1 }
func (d *fakeTunDevice) MTU() int                                         { return 1301 }
func (d *fakeTunDevice) WriteHeadroom() int                               { return 0 }
func (d *fakeTunDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func (d *fakeTunDevice) Writes() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	copy(out, d.writes)
	return out
}

func (d *fakeTunDevice) WriteOffsets() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]int, len(d.offsets))
	copy(out, d.offsets)
	return out
}

func makeIPv4TCPPacket(src [4]byte, dst [4]byte) []byte {
	raw := make([]byte, 40)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = 6
	copy(raw[12:16], src[:])
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 5202)
	raw[32] = 0x50
	raw[33] = 0x18
	binary.BigEndian.PutUint16(raw[34:36], 65535)
	packet, parseErr := ippacket.ParseIPPacket(raw)
	if parseErr != nil {
		panic(parseErr)
	}
	packet.RecomputeChecksum()
	return raw
}

func makeIPv4TCPSYNPacketWithMSS(src [4]byte, dst [4]byte, mss uint16) []byte {
	raw := make([]byte, 44)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = 6
	copy(raw[12:16], src[:])
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 5202)
	raw[32] = 0x60
	raw[33] = 0x02
	binary.BigEndian.PutUint16(raw[34:36], 65535)
	raw[40] = 2
	raw[41] = 4
	binary.BigEndian.PutUint16(raw[42:44], mss)
	packet, parseErr := ippacket.ParseIPPacket(raw)
	if parseErr != nil {
		panic(parseErr)
	}
	packet.RecomputeChecksum()
	return raw
}

func tcpMSSFromIPv4(t *testing.T, raw []byte) int {
	t.Helper()
	packet, parseErr := ippacket.ParseIPPacket(raw)
	if parseErr != nil {
		t.Fatalf("parse packet: %s", parseErr)
	}
	if !packet.IsTCP() {
		t.Fatal("packet is not TCP")
	}
	tcpOff := packet.TransportOffset()
	tcpHeaderLen := int(raw[tcpOff+12]>>4) * 4
	opts := raw[tcpOff+20 : tcpOff+tcpHeaderLen]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return 0
		case 1:
			i++
		case 2:
			if i+4 > len(opts) || opts[i+1] != 4 {
				t.Fatal("invalid MSS option")
			}
			return int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
		default:
			if i+2 > len(opts) {
				return 0
			}
			optLen := int(opts[i+1])
			if optLen < 2 || i+optLen > len(opts) {
				return 0
			}
			i += optLen
		}
	}
	return 0
}
