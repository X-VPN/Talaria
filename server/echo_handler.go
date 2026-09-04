// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

type EchoPacketHandler struct{}

func (EchoPacketHandler) HandlePacket(_ context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	if packet == nil {
		return nil, errors.New("nil packet")
	}
	switch packet.Cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
		return []*vpnpacket.VpnPacket{{
			Cmd:            vpnpacket.CmdData,
			ClientId:       session.ClientID,
			DataSequenceId: packet.DataSequenceId,
			Data:           packet.Data,
		}}, nil
	case vpnpacket.CmdKeepAlive, vpnpacket.CmdServerKeepAlive:
		return []*vpnpacket.VpnPacket{{
			Cmd:         packet.Cmd,
			ClientId:    session.ClientID,
			KeepAliveId: packet.KeepAliveId,
			SendTime:    packet.SendTime,
		}}, nil
	default:
		return nil, fmt.Errorf("unexpected packet cmd=%d", packet.Cmd)
	}
}
