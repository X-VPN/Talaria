// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package vpnpacket encodes and decodes the Talaria VPN wire packet.
//
// Every field this package parses arrives from the network, in some cases before
// the peer has authenticated, so decoding is written to be total: lengths and
// command values are bounds-checked, strings are validated as UTF-8, and a
// malformed packet returns an error rather than panicking or allocating from an
// attacker-supplied length. The String method redacts credentials so a packet
// dump cannot leak them into logs.
package vpnpacket

import (
	"bytes"
	"net"
	"strconv"
)

const (
	CmdData            byte = 1
	CmdAuthRequest     byte = 2
	CmdAuthSuccess     byte = 3
	CmdErr             byte = 4
	CmdKeepAlive       byte = 5 // Client-originated ping; the server replies once.
	CmdClientClose     byte = 6
	cmdDataFixedIPv4   byte = 7  // Data with ingress and egress IPv4 addresses for routing.
	CmdServerKeepAlive byte = 8  // Server-originated ping; the client replies once.
	CmdDataForward     byte = 9  // Uplink IP data with ingress and egress addresses.
	CmdDataReturn      byte = 10 // Downlink IP data returned by the server.
	CmdSessionGrant    byte = 11 // Short-lived data credential issued after control authentication.
	CmdSessionReady    byte = 12 // Confirms that server session resources and packet handling are ready.
)

// WriteVpnPacketToBytes does not retain references to packet after returning.
func WriteVpnPacketToBytes(packet *VpnPacket) (b []byte, err error) {
	// The returned buffer is caller-owned, so it cannot be pooled here.
	buf := BufWriter{}
	return WriteVpnPacketToBytesWithBuf(packet, &buf)
}

func ReadVpnPacketFromBytes(b []byte) (packet *VpnPacket, err error) {
	packet = &VpnPacket{}
	if err = packet.ReadVpnPacketFromBytes(b); err != nil {
		return nil, err
	}
	return packet, nil
}

type VpnPacket struct {
	Cmd                 byte
	WireCmd             byte
	Version             byte   // Local wire version advertised during authentication.
	RemoteVersion       byte   // Peer wire version.
	DataSequenceId      uint32 // Data sequence echoed by replies to CmdData.
	KeepAliveId         uint32 // Keepalive sequence echoed by the peer.
	ClientId            uint64 // len = 8 byte
	Id                  string
	Sk                  string
	Data                []byte
	ErrorMessage        string
	NewClientId         uint64 // len = 8 byte
	SendPacketTimes     uint8  // CmdAuthRequest retransmission hint.
	SendTime            int64  // Sender timestamp.
	LastTimeOffset      int64  // Previous keepalive time offset; the peer negates it.
	IsPing              bool   // Distinguishes a keepalive request from its reply.
	EntranceIp          []byte // IPv4 entrance address.
	ExitIp              []byte
	KeepAliveRemoteIpv4 net.IP // Remote IPv4 address carried by keepalive packets.
	SessionGeneration   uint64
	SessionExpiresAt    int64
	SessionDataToken    []byte
}

func (packet *VpnPacket) String() string {
	if packet == nil {
		return "[packet] nil"
	}
	_buf := bytes.Buffer{}
	_buf.WriteString("[packet] ")
	_buf.WriteString(cmdToString(packet.Cmd))
	_buf.WriteString(" ")
	switch packet.Cmd {
	case CmdAuthRequest:
		_buf.WriteString(" credentials: [redacted]")
		if packet.Version != 0 {
			_buf.WriteString(" Version: " + strconv.Itoa(int(packet.Version)))
		}
		if packet.SendPacketTimes != 0 {
			_buf.WriteString(" SendPacketTimes: " + strconv.Itoa(int(packet.SendPacketTimes)))
		}
	case CmdData, cmdDataFixedIPv4:
		_buf.WriteString(" datalen: " + strconv.Itoa(len(packet.Data)))
		if packet.SendTime != 0 {
			_buf.WriteString(" SendTime: " + strconv.FormatUint(uint64(packet.SendTime), 16))
		}
		if packet.DataSequenceId != 0 {
			_buf.WriteString(" DataSequenceId: " + strconv.FormatUint(uint64(packet.DataSequenceId), 16))
		}
	default:
	}
	return _buf.String()
}

func cmdToString(cmd byte) string {
	switch cmd {
	case CmdData:
		return "CmdData"
	case CmdAuthRequest:
		return "CmdAuthRequest"
	case CmdAuthSuccess:
		return "CmdAuthSuccess"
	case CmdErr:
		return "CmdErr"
	case CmdKeepAlive:
		return "CmdKeepAlive"
	case CmdClientClose:
		return "CmdClientClose"
	case cmdDataFixedIPv4:
		return "cmdDataFixedIPv4"
	case CmdServerKeepAlive:
		return "CmdServerKeepAlive"
	case CmdDataForward:
		return "CmdDataForward"
	case CmdDataReturn:
		return "CmdDataReturn"
	case CmdSessionGrant:
		return "CmdSessionGrant"
	case CmdSessionReady:
		return "CmdSessionReady"
	default:
		return "Cmd" + strconv.Itoa(int(cmd))
	}
}

func (packet *VpnPacket) GetSendPacketTimes() int {
	if packet.SendPacketTimes > 4 {
		return 4
	}
	if packet.SendPacketTimes < 1 {
		return 1
	}
	return int(packet.SendPacketTimes)
}

func (packet *VpnPacket) Reset() {
	*packet = VpnPacket{}
}
