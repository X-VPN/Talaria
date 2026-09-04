// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"testing"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestServerPacketHandlersDoNotReplyToKeepAliveV2Replies(t *testing.T) {
	handlers := []struct {
		name    string
		handler PacketHandler
	}{
		{name: "tun", handler: &TunPacketHandler{}},
	}
	for _, tt := range handlers {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := tt.handler.HandlePacket(context.Background(), SessionContext{ClientID: 7}, &vpnpacket.VpnPacket{
				Cmd:         vpnpacket.CmdServerKeepAlive,
				KeepAliveId: 9,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(responses) != 0 {
				t.Fatalf("V2 reply produced %d responses, want 0", len(responses))
			}
		})
	}
}

func TestServerPacketHandlersReplyOnceToClientKeepAlive(t *testing.T) {
	handlers := []struct {
		name    string
		handler PacketHandler
	}{
		{name: "tun", handler: &TunPacketHandler{}},
	}
	for _, tt := range handlers {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := tt.handler.HandlePacket(context.Background(), SessionContext{ClientID: 7}, &vpnpacket.VpnPacket{
				Cmd:         vpnpacket.CmdKeepAlive,
				KeepAliveId: 9,
				IsPing:      true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(responses) != 1 || responses[0].Cmd != vpnpacket.CmdKeepAlive || responses[0].KeepAliveId != 9 {
				t.Fatalf("keepalive responses = %+v, want one matching reply", responses)
			}
		})
	}
}

func TestServerPacketHandlersDoNotReplyToClientKeepAliveReplies(t *testing.T) {
	handlers := []struct {
		name    string
		handler PacketHandler
	}{
		{name: "tun", handler: &TunPacketHandler{}},
	}
	for _, tt := range handlers {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := tt.handler.HandlePacket(context.Background(), SessionContext{ClientID: 7}, &vpnpacket.VpnPacket{
				Cmd:         vpnpacket.CmdKeepAlive,
				KeepAliveId: 9,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(responses) != 0 {
				t.Fatalf("keepalive reply produced %d responses, want 0", len(responses))
			}
		})
	}
}
