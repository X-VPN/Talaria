// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"bytes"
	"testing"
)

func TestActiveCommandWireIDs(t *testing.T) {
	commands := []struct {
		name string
		got  byte
	}{
		{"data", CmdData},
		{"auth request", CmdAuthRequest},
		{"auth success", CmdAuthSuccess},
		{"error", CmdErr},
		{"keepalive", CmdKeepAlive},
		{"client close", CmdClientClose},
		{"fixed IPv4 data", cmdDataFixedIPv4},
		{"server keepalive", CmdServerKeepAlive},
		{"data forward", CmdDataForward},
		{"data return", CmdDataReturn},
		{"session grant", CmdSessionGrant},
		{"session ready", CmdSessionReady},
	}
	for i, command := range commands {
		want := byte(i + 1)
		if command.got != want {
			t.Errorf("%s command = %d, want %d", command.name, command.got, want)
		}
	}
}

func TestWireFormatGoldenFrames(t *testing.T) {
	tests := []struct {
		name   string
		packet VpnPacket
		want   []byte
	}{
		{
			name:   "data",
			packet: VpnPacket{Cmd: CmdData, ClientId: 1, DataSequenceId: 2, Data: []byte{0xaa}},
			want:   []byte{1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0xaa},
		},
		{
			name: "fixed IPv4 data",
			packet: VpnPacket{
				Cmd: CmdData, ClientId: 1, RemoteVersion: 5, DataSequenceId: 2,
				EntranceIp: []byte{192, 0, 2, 1}, ExitIp: []byte{198, 51, 100, 2}, Data: []byte{0xbb},
			},
			want: []byte{1, 0, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0xbb},
		},
		{
			name:   "server keepalive",
			packet: VpnPacket{Cmd: CmdServerKeepAlive, ClientId: 1, KeepAliveId: 3},
			want:   []byte{1, 0, 0, 0, 0, 0, 0, 0, 8, 3, 0, 0, 0},
		},
		{
			name: "data forward",
			packet: VpnPacket{
				Cmd: CmdDataForward, ClientId: 1, DataSequenceId: 2,
				EntranceIp: []byte{192, 0, 2, 1}, ExitIp: []byte{198, 51, 100, 2}, Data: []byte{0xcc},
			},
			want: []byte{1, 0, 0, 0, 0, 0, 0, 0, 9, 2, 0, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0xcc},
		},
		{
			name:   "data return",
			packet: VpnPacket{Cmd: CmdDataReturn, ClientId: 1, DataSequenceId: 2, Data: []byte{0xdd}},
			want:   []byte{1, 0, 0, 0, 0, 0, 0, 0, 10, 2, 0, 0, 0, 0xdd},
		},
		{
			name:   "session ready",
			packet: VpnPacket{Cmd: CmdSessionReady, ClientId: 1},
			want:   []byte{1, 0, 0, 0, 0, 0, 0, 0, 12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WriteVpnPacketToBytes(&tt.packet)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("wire frame = %v, want %v", got, tt.want)
			}
		})
	}
}
