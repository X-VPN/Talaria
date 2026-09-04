// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"fmt"
	"net"
	"sync"
)

var (
	gProtocolEncodeRandomBufOnce sync.Once
	gProtocolEncodeRandomBuf     []byte
	gProtocolEncodeRandomLen     int
)

// WriteVpnPacketToBytesWithBuf writes into buf and returns a slice owned by buf.
// It does not retain references to packet fields.
func WriteVpnPacketToBytesWithBuf(packet *VpnPacket, buf *BufWriter) (b []byte, err error) {
	if packet == nil {
		return nil, fmt.Errorf("vpnpacket: nil packet")
	}
	if buf == nil {
		return nil, fmt.Errorf("vpnpacket: nil buffer")
	}
	gProtocolEncodeRandomBufOnce.Do(func() {
		const max = 20
		gProtocolEncodeRandomBuf = make([]byte, max)
		gProtocolEncodeRandomLen = randomIntBetween(1, max)
	})
	buf.Reset()
	cmd := packet.Cmd
	if cmd == CmdData {
		if packet.RemoteVersion >= 5 && packet.RemoteVersion <= 7 {
			cmd = cmdDataFixedIPv4
		}
	}
	switch cmd {
	case cmdDataFixedIPv4, CmdDataForward:
		if len(packet.EntranceIp) != net.IPv4len || len(packet.ExitIp) != net.IPv4len {
			return nil, fmt.Errorf("vpnpacket: command %d requires 4-byte entrance and exit IPs", cmd)
		}
	}
	buf.WriteLittleEndUint64(packet.ClientId)
	//buf.Write(packet.ClientId)
	buf.WriteByte_(cmd)
	switch cmd {
	case CmdData:
		buf.WriteLittleEndUint32(uint32(packet.DataSequenceId))
		buf.Write_(packet.Data)
	case cmdDataFixedIPv4:
		buf.WriteLittleEndUint32(uint32(packet.DataSequenceId))
		buf.Write_(packet.EntranceIp)
		buf.Write_(packet.ExitIp)
		buf.Write_(packet.Data)
	case CmdDataForward:
		buf.WriteLittleEndUint32(uint32(packet.DataSequenceId))
		buf.Write_(packet.EntranceIp)
		buf.Write_(packet.ExitIp)
		buf.Write_(packet.Data)
	case CmdDataReturn:
		buf.WriteLittleEndUint32(uint32(packet.DataSequenceId))
		buf.Write_(packet.Data)
	case CmdAuthRequest:
		buf.WriteByte_(packet.Version)
		if err := buf.WriteString255(packet.Id); err != nil {
			return nil, err
		}
		if err := buf.WriteString255(packet.Sk); err != nil {
			return nil, err
		}
		buf.WriteByte_(packet.SendPacketTimes)
		buf.Write_(gProtocolEncodeRandomBuf[:gProtocolEncodeRandomLen])
		buf.Write_(gProtocolEncodeRandomBuf[:randomIntBetween(1, 20)])
	case CmdAuthSuccess:
		buf.WriteLittleEndUint64(packet.NewClientId)
		//buf.Write(packet.NewClientId)
		buf.WriteByte_(packet.Version)
		buf.Write_(gProtocolEncodeRandomBuf[:gProtocolEncodeRandomLen])
		buf.Write_(gProtocolEncodeRandomBuf[:randomIntBetween(1, 20)])
	case CmdSessionGrant:
		if len(packet.SessionDataToken) != 32 {
			return nil, fmt.Errorf("CmdSessionGrant token length is %d, want 32", len(packet.SessionDataToken))
		}
		buf.WriteLittleEndUint64(packet.SessionGeneration)
		buf.WriteLittleEndUint64(uint64(packet.SessionExpiresAt))
		buf.Write_(packet.SessionDataToken)
	case CmdClientClose, CmdSessionReady:
	case CmdErr:
		if err := validateDisplayString(packet.ErrorMessage); err != nil {
			return nil, err
		}
		if err := buf.WriteString255(packet.ErrorMessage); err != nil {
			return nil, err
		}
	case CmdKeepAlive:
		buf.WriteLittleEndUint32(uint32(packet.KeepAliveId))
		buf.WriteLittleEndUint64(uint64(packet.SendTime))
		buf.WriteLittleEndUint64(uint64(packet.LastTimeOffset))
		buf.WriteBool(packet.IsPing)
		ipv4 := packet.KeepAliveRemoteIpv4.To4()
		if ipv4 != nil {
			buf.Write_(ipv4)
		} else {
			buf.Write_(net.IPv4zero.To4())
		}
		buf.Write_(gProtocolEncodeRandomBuf[:gProtocolEncodeRandomLen])
		buf.Write_(gProtocolEncodeRandomBuf[:randomIntBetween(1, 20)])
	case CmdServerKeepAlive:
		buf.WriteLittleEndUint32(uint32(packet.KeepAliveId))
	default:
		return nil, fmt.Errorf("vpnpacket: unsupported packet command %d", cmd)
	}
	return buf.GetBytes(), nil
}
