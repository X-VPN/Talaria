// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestClientClassifiesAllNonPingKeepAlivesAsReplies(t *testing.T) {
	s := &session{}
	for _, id := range []uint32{0, 1, ^uint32(0)} {
		if !s.isClientKeepAliveReply(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive, KeepAliveId: id}) {
			t.Fatalf("non-ping keepalive %d was not classified as a reply", id)
		}
	}
	if s.isClientKeepAliveReply(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive, IsPing: true}) {
		t.Fatal("ping keepalive was classified as a reply")
	}
}
