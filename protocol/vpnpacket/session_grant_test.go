// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"bytes"
	"testing"
)

func TestSessionGrantRoundTrip(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, 32)
	raw, err := WriteVpnPacketToBytes(&VpnPacket{
		Cmd:               CmdSessionGrant,
		ClientId:          99,
		SessionGeneration: 7,
		SessionExpiresAt:  1_900_000_000,
		SessionDataToken:  token,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ReadVpnPacketFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Cmd != CmdSessionGrant || packet.ClientId != 99 || packet.SessionGeneration != 7 || packet.SessionExpiresAt != 1_900_000_000 {
		t.Fatalf("unexpected decoded grant: %+v", packet)
	}
	if !bytes.Equal(packet.SessionDataToken, token) {
		t.Fatal("decoded token does not match")
	}
}

func TestSessionGrantRejectsWrongTokenSize(t *testing.T) {
	_, err := WriteVpnPacketToBytes(&VpnPacket{
		Cmd:               CmdSessionGrant,
		ClientId:          99,
		SessionGeneration: 7,
		SessionExpiresAt:  1_900_000_000,
		SessionDataToken:  make([]byte, 31),
	})
	if err == nil {
		t.Fatal("short token was accepted")
	}
}

func TestSessionReadyRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		clientID uint64
		wantErr  bool
	}{
		{name: "valid", clientID: 99},
		{name: "missing client id", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := WriteVpnPacketToBytes(&VpnPacket{Cmd: CmdSessionReady, ClientId: tt.clientID})
			if err != nil {
				t.Fatal(err)
			}
			packet, err := ReadVpnPacketFromBytes(raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("invalid session-ready packet was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if packet.Cmd != CmdSessionReady || packet.ClientId != tt.clientID {
				t.Fatalf("unexpected decoded session-ready packet: %+v", packet)
			}
		})
	}
}
