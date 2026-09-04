// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"errors"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

type Codec interface {
	Encode(packet *vpnpacket.VpnPacket) ([]byte, error)
	Decode(raw []byte) (*vpnpacket.VpnPacket, int, error)
}

type ReusableCodec interface {
	Codec
	DecodeInto(packet *vpnpacket.VpnPacket, raw []byte) (int, error)
}

type WireCodec struct{}

func (WireCodec) Encode(packet *vpnpacket.VpnPacket) ([]byte, error) {
	return vpnpacket.WriteVpnPacketToBytes(packet)
}

func (WireCodec) Decode(raw []byte) (*vpnpacket.VpnPacket, int, error) {
	packet := &vpnpacket.VpnPacket{}
	if err := packet.ReadVpnPacketFromBytes(raw); err != nil {
		return nil, 0, err
	}
	return packet, payloadOffset(raw), nil
}

func (WireCodec) DecodeInto(packet *vpnpacket.VpnPacket, raw []byte) (int, error) {
	if packet == nil {
		return 0, errors.New("nil vpn packet")
	}
	if err := packet.ReadVpnPacketFromBytes(raw); err != nil {
		return 0, err
	}
	return payloadOffset(raw), nil
}

func payloadOffset(raw []byte) int {
	if len(raw) < 9 {
		return 0
	}
	switch raw[8] {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
		return vpnpacket.RawCmdDataHeaderLen()
	}
	if vpnpacket.IsFixedV4DataWireCmd(raw[8]) {
		return vpnpacket.FixedV4PayloadOffset()
	}
	return 0
}
