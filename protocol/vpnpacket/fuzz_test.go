// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import "testing"

func FuzzReadVpnPacketFromBytes(f *testing.F) {
	seeds := [][]byte{
		{},
		make([]byte, 9),
		{0, 0, 0, 0, 0, 0, 0, 0, CmdAuthRequest, 1, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, CmdData, 0, 0, 0, 0},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64*1024 {
			t.Skip()
		}
		packet, err := ReadVpnPacketFromBytes(raw)
		if err != nil || packet == nil {
			return
		}
		_, _ = WriteVpnPacketToBytes(packet)
	})
}
