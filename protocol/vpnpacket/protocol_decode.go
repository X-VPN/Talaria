// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

func (packet *VpnPacket) readVpnPacketFromBytesL1(b []byte) (err error) {
	if len(b) < 9 {
		return fmt.Errorf("vpnpacket: packet length %d is less than 9", len(b))
	}
	packet.Reset()
	packet.ClientId = binary.LittleEndian.Uint64(b[:8])
	packet.Cmd = b[8]
	packet.WireCmd = packet.Cmd
	switch packet.Cmd {
	case CmdData, CmdDataReturn:
		if len(b) < dataHeaderOverHeadV1 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdData len(b)[%d]<"+strconv.Itoa(dataHeaderOverHeadV1), len(b))
		}
		packet.DataSequenceId = binary.LittleEndian.Uint32(b[9:dataHeaderOverHeadV1])
		packet.Data = b[dataHeaderOverHeadV1:]
		return nil
	case cmdDataFixedIPv4, CmdDataForward:
		packet.Cmd = CmdData
		if len(b) < dataHeaderOverHeadFixedIPv4 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] fixed IPv4 data len(b)[%d]<"+strconv.Itoa(dataHeaderOverHeadFixedIPv4), len(b))
		}
		packet.DataSequenceId = binary.LittleEndian.Uint32(b[9:13])
		packet.EntranceIp = b[13:17]
		packet.ExitIp = b[17:21]
		packet.Data = b[dataHeaderOverHeadFixedIPv4:]
		return nil
	case CmdAuthRequest:
		if len(b) < 9+1+1+1 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdAuthRequest len(b)[%d]<[%d]", len(b), 9+1+1+1)
		}
		packet.Version = b[9]
		packet.Id, err = readString255(b[10:])
		if err != nil {
			return err
		}
		if validUTF8String(packet.Id) == false {
			return errors.New("[ReadVpnPacketFromBytes] packet.Id include invalid utf8 code")
		}
		pos := 10 + len(packet.Id) + 1
		packet.Sk, err = readString255(b[pos:])
		if err != nil {
			return err
		}
		if validUTF8String(packet.Sk) == false {
			return errors.New("[ReadVpnPacketFromBytes] packet.Sk include invalid utf8 code")
		}
		pos = pos + len(packet.Sk) + 1
		if len(b) > pos {
			// Version 1 omitted this optional field.
			packet.SendPacketTimes = b[pos]
		}
		return nil
	case CmdAuthSuccess:
		if len(b) < 17 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdAuthSuccess len(b)[%d]<17", len(b))
		}
		packet.NewClientId = binary.LittleEndian.Uint64(b[9:17])
		if len(b) > 17 {
			packet.Version = b[17]
		}
		return nil
	case CmdSessionGrant:
		const sessionGrantSize = 9 + 8 + 8 + 32
		if len(b) != sessionGrantSize {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdSessionGrant len(b)[%d]!=%d", len(b), sessionGrantSize)
		}
		packet.SessionGeneration = binary.LittleEndian.Uint64(b[9:17])
		packet.SessionExpiresAt = int64(binary.LittleEndian.Uint64(b[17:25]))
		packet.SessionDataToken = b[25:sessionGrantSize]
		if packet.ClientId == 0 || packet.SessionGeneration == 0 {
			return errors.New("[ReadVpnPacketFromBytes] invalid session grant identity")
		}
		return nil
	case CmdClientClose:
		return nil
	case CmdSessionReady:
		if len(b) != 9 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdSessionReady len(b)[%d]!=9", len(b))
		}
		if packet.ClientId == 0 {
			return errors.New("[ReadVpnPacketFromBytes] invalid ready client id")
		}
		return nil
	case CmdErr:
		packet.ErrorMessage, err = readDisplayString255(b[9:])
		if err != nil {
			return err
		}
		return nil
	case CmdKeepAlive:
		if len(b) < 8+1+4 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdKeepAlive len(b)[%d]<13", len(b))
		}
		packet.KeepAliveId = binary.LittleEndian.Uint32(b[9:13])
		if len(b) >= 21 {
			packet.SendTime = int64(binary.LittleEndian.Uint64(b[13:21]))
		}
		if len(b) >= 29 {
			packet.LastTimeOffset = int64(binary.LittleEndian.Uint64(b[21:29]))
		}
		if len(b) >= 30 {
			packet.IsPing = readBool(b[29])
		}
		if len(b) >= 34 {
			packet.KeepAliveRemoteIpv4 = net.IP(b[30:34])
		}
		return nil
	case CmdServerKeepAlive:
		if len(b) < 13 {
			return fmt.Errorf("[ReadVpnPacketFromBytes] CmdServerKeepAlive len(b)[%d]<13", len(b))
		}
		packet.KeepAliveId = binary.LittleEndian.Uint32(b[9:13])
		return nil
	default:
		return fmt.Errorf("vpnpacket: unsupported packet command %d", packet.Cmd)
	}
}

func (packet *VpnPacket) ReadVpnPacketFromBytes(b []byte) (err error) {
	if packet == nil {
		return errors.New("vpnpacket: nil decode target")
	}
	packet.Reset()
	decoded := VpnPacket{}
	err = decoded.readVpnPacketFromBytesL1(b)
	if err == nil {
		*packet = decoded
	}
	return err
}
