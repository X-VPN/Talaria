// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"net"
	"reflect"
	"testing"
)

func TestDecodeFailureClearsReusedPacket(t *testing.T) {
	malformedAuth := make([]byte, 0, 16)
	malformedAuth = append(malformedAuth, 1, 0, 0, 0, 0, 0, 0, 0, CmdAuthRequest, 1)
	malformedAuth = append(malformedAuth, 2, 'i', 'd', 4, 'x')
	for _, raw := range [][]byte{{1, 2, 3}, malformedAuth} {
		packet := populatedPacket()
		if err := packet.ReadVpnPacketFromBytes(raw); err == nil {
			t.Fatalf("malformed packet %x decoded successfully", raw)
		}
		if !reflect.DeepEqual(packet, &VpnPacket{}) {
			t.Fatalf("failed decode retained packet fields: %+v", packet)
		}
	}
}

func TestResetClearsWireCommand(t *testing.T) {
	packet := populatedPacket()
	packet.Reset()
	if !reflect.DeepEqual(packet, &VpnPacket{}) {
		t.Fatalf("Reset retained packet fields: %+v", packet)
	}
}

func TestReadVpnPacketFromBytesReturnsNilOnError(t *testing.T) {
	packet, err := ReadVpnPacketFromBytes([]byte{1, 2, 3})
	if err == nil || packet != nil {
		t.Fatalf("malformed decode = packet %+v, error %v; want nil packet and error", packet, err)
	}
}

func populatedPacket() *VpnPacket {
	return &VpnPacket{
		Cmd:                 CmdAuthRequest,
		WireCmd:             CmdDataForward,
		Version:             1,
		RemoteVersion:       2,
		DataSequenceId:      4,
		KeepAliveId:         5,
		ClientId:            6,
		Id:                  "old-id",
		Sk:                  "old-secret",
		Data:                []byte("old-data"),
		ErrorMessage:        "old-error",
		NewClientId:         7,
		SendPacketTimes:     8,
		SendTime:            9,
		LastTimeOffset:      10,
		IsPing:              true,
		EntranceIp:          []byte{1, 2, 3, 4},
		ExitIp:              []byte{5, 6, 7, 8},
		KeepAliveRemoteIpv4: net.IPv4(9, 10, 11, 12),
		SessionGeneration:   11,
		SessionExpiresAt:    12,
		SessionDataToken:    []byte("old-token"),
	}
}
