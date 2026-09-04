// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package dataplane_test

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/udptls"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestWireCodecDecodeIntoClearsTargetOnError(t *testing.T) {
	packet := &vpnpacket.VpnPacket{
		Cmd:              vpnpacket.CmdAuthRequest,
		WireCmd:          vpnpacket.CmdDataForward,
		Id:               "old-id",
		Sk:               "old-secret",
		Data:             []byte("old-data"),
		SessionDataToken: []byte("old-token"),
	}
	if _, err := (dataplane.WireCodec{}).DecodeInto(packet, []byte{1, 2, 3}); err == nil {
		t.Fatal("malformed packet decoded successfully")
	}
	if !reflect.DeepEqual(packet, &vpnpacket.VpnPacket{}) {
		t.Fatalf("failed DecodeInto retained target fields: %+v", packet)
	}
}

func TestMTUAndBufferSizesMatchVpnCoreDefaults(t *testing.T) {
	if dataplane.DefaultMTU != 1314 {
		t.Fatalf("DefaultMTU = %d want 1314", dataplane.DefaultMTU)
	}
	if dataplane.DefaultMSS != 1274 {
		t.Fatalf("DefaultMSS = %d want 1274", dataplane.DefaultMSS)
	}
	const outerIPv6UDPOverhead = 40 + 8
	carrierPacketSize := dataplane.DefaultMTU + vpnpacket.MaxDataHeaderOverhead + udptls.SecureDataPacketOverhead + outerIPv6UDPOverhead
	if carrierPacketSize != dataplane.CarrierMTU {
		t.Fatalf("default carrier packet size = %d, want %d", carrierPacketSize, dataplane.CarrierMTU)
	}
	if got := dataplane.ConnReadBufferSize(dataplane.DefaultMTU); got != 2048 {
		t.Fatalf("ConnReadBufferSize() = %d want 2048", got)
	}
	if got := dataplane.DeviceTunReadPacketBufferSize("TalariaUDP"); got != 2048+dataplane.DefaultHeadroom {
		t.Fatalf("DeviceTunReadPacketBufferSize() = %d want %d", got, 2048+dataplane.DefaultHeadroom)
	}
	if runtime.GOOS == "windows" {
		if got := dataplane.TunReadBufferSize(dataplane.DefaultMTU); got != 65536 {
			t.Fatalf("windows TunReadBufferSize() = %d want 65536", got)
		}
		return
	}
	if got := dataplane.TunReadBufferSize(dataplane.DefaultMTU); got != 4096 {
		t.Fatalf("TunReadBufferSize(default) = %d want 4096", got)
	}
	if got := dataplane.TunReadBufferSize(8196); got != 8196+16 {
		t.Fatalf("TunReadBufferSize(8196) = %d want %d", got, 8196+16)
	}
}

func TestPacketBufferLenRejectsInvalidBounds(t *testing.T) {
	for _, pkt := range []*dataplane.PacketBuffer{
		{Raw: make([]byte, 4), Start: -1, End: 1},
		{Raw: make([]byte, 4), Start: 2, End: 1},
		{Raw: make([]byte, 4), Start: 1, End: 5},
	} {
		if got := pkt.Len(); got != 0 {
			t.Fatalf("invalid PacketBuffer.Len() = %d, want 0", got)
		}
	}
}

func TestConnReadBufferSizeCoversMTUAndWireHeader(t *testing.T) {
	maxHeader := vpnpacket.FixedV4PayloadOffset()
	if got := dataplane.ConnReadBufferSize(dataplane.MaxMTU); got != 9021 {
		t.Fatalf("maximum connection read buffer = %d want 9021", got)
	}
	tests := []struct {
		name string
		mtu  int
		want int
	}{
		{name: "default floor", mtu: dataplane.DefaultMTU, want: 2048},
		{name: "floor boundary", mtu: 2048 - maxHeader, want: 2048},
		{name: "above floor", mtu: 2049 - maxHeader, want: 2049},
		{name: "jumbo MTU", mtu: dataplane.MaxMTU, want: dataplane.MaxMTU + maxHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dataplane.ConnReadBufferSize(tt.mtu); got != tt.want {
				t.Fatalf("ConnReadBufferSize(%d) = %d want %d", tt.mtu, got, tt.want)
			}
		})
	}
}

func TestWriteDataHeaderUsesPacketHeadroom(t *testing.T) {
	payload := []byte{0x45, 0, 0, 20}
	pkt := dataplane.NewPacketBuffer(dataplane.DefaultHeadroom+len(payload), vpnpacket.RawCmdDataHeaderLen())
	copy(pkt.Raw[pkt.Start:], payload)
	pkt.End = pkt.Start + len(payload)

	if err := dataplane.WriteDataHeader(pkt, 99, 7, 1, nil, nil); err != nil {
		t.Fatal(err)
	}
	packet, err := vpnpacket.ReadVpnPacketFromBytes(pkt.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if packet.ClientId != 99 || packet.DataSequenceId != 7 || packet.Cmd != vpnpacket.CmdData {
		t.Fatalf("packet header = %+v", packet)
	}
	if !bytes.Equal(packet.Data, payload) {
		t.Fatalf("payload = %x want %x", packet.Data, payload)
	}
}

func TestWriteDataHeaderFixedV4(t *testing.T) {
	payload := []byte{0x45, 0, 0, 21, 1}
	pkt := dataplane.NewPacketBuffer(dataplane.DefaultHeadroom+len(payload), vpnpacket.FixedV4PayloadOffset())
	copy(pkt.Raw[pkt.Start:], payload)
	pkt.End = pkt.Start + len(payload)

	entranceIP := []byte{10, 0, 0, 1}
	exitIP := []byte{10, 0, 0, 2}
	if err := dataplane.WriteDataHeader(pkt, 101, 8, 7, entranceIP, exitIP); err != nil {
		t.Fatal(err)
	}
	packet, err := vpnpacket.ReadVpnPacketFromBytes(pkt.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if packet.ClientId != 101 || packet.DataSequenceId != 8 {
		t.Fatalf("packet header = %+v", packet)
	}
	if !bytes.Equal(packet.EntranceIp, entranceIP) || !bytes.Equal(packet.ExitIp, exitIP) {
		t.Fatalf("packet ips entrance=%v exit=%v", packet.EntranceIp, packet.ExitIp)
	}
	if !bytes.Equal(packet.Data, payload) {
		t.Fatalf("payload = %x want %x", packet.Data, payload)
	}
}
