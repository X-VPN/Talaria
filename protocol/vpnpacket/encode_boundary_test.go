// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestWriteVpnPacketRejectsInvalidInputsWithoutPanic(t *testing.T) {
	tests := []struct {
		name   string
		packet *VpnPacket
		buf    *BufWriter
	}{
		{name: "nil packet", buf: &BufWriter{}},
		{name: "nil buffer", packet: &VpnPacket{Cmd: CmdClientClose}},
		{name: "long auth id", packet: &VpnPacket{Cmd: CmdAuthRequest, Id: strings.Repeat("a", 256)}, buf: &BufWriter{}},
		{name: "long auth key", packet: &VpnPacket{Cmd: CmdAuthRequest, Id: "id", Sk: strings.Repeat("k", 256)}, buf: &BufWriter{}},
		{name: "long error", packet: &VpnPacket{Cmd: CmdErr, ErrorMessage: strings.Repeat("e", 256)}, buf: &BufWriter{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := WriteVpnPacketToBytesWithBuf(tt.packet, tt.buf); err == nil {
				t.Fatal("invalid encoder input was accepted")
			}
		})
	}
}

func TestWriteVpnPacketUsesLocalLegacyCommand(t *testing.T) {
	packet := &VpnPacket{
		Cmd:            CmdData,
		RemoteVersion:  5,
		EntranceIp:     []byte{10, 0, 0, 1},
		ExitIp:         []byte{10, 0, 0, 2},
		DataSequenceId: 7,
		Data:           []byte{1, 2, 3},
	}
	want, err := WriteVpnPacketToBytes(packet)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Cmd != CmdData {
		t.Fatalf("encoder mutated packet command to %d", packet.Cmd)
	}
	if want[8] != cmdDataFixedIPv4 {
		t.Fatalf("wire command = %d want %d", want[8], cmdDataFixedIPv4)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := WriteVpnPacketToBytes(packet)
			if err == nil && !bytes.Equal(got, want) {
				err = errors.New("concurrent encoding changed output")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if packet.Cmd != CmdData {
		t.Fatalf("concurrent encoder mutated packet command to %d", packet.Cmd)
	}
}

func TestWriteVpnPacketRejectsNonExactIPv4Fields(t *testing.T) {
	tests := []struct {
		name   string
		packet *VpnPacket
	}{
		{name: "legacy data short entrance", packet: &VpnPacket{Cmd: CmdData, RemoteVersion: 5, EntranceIp: []byte{1, 2, 3}, ExitIp: []byte{1, 2, 3, 4}}},
		{name: "forward long exit", packet: &VpnPacket{Cmd: CmdDataForward, EntranceIp: []byte{1, 2, 3, 4}, ExitIp: make([]byte, 16)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := WriteVpnPacketToBytes(tt.packet); err == nil {
				t.Fatal("encoder accepted non-exact IPv4 fields")
			}
		})
	}
}
