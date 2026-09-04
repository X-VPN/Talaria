// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import "encoding/binary"

const fixedV4HeaderPayloadOffset = dataHeaderOverHeadFixedIPv4

func FixedV4PayloadOffset() int {
	return fixedV4HeaderPayloadOffset
}

func WriteRawFixedV4DataHeader(buf []byte, clientID uint64, dataSequenceID uint32, entranceIP []byte, exitIP []byte) bool {
	if len(buf) < fixedV4HeaderPayloadOffset || len(entranceIP) < 4 || len(exitIP) < 4 {
		return false
	}
	binary.LittleEndian.PutUint64(buf[:8], clientID)
	buf[8] = cmdDataFixedIPv4
	binary.LittleEndian.PutUint32(buf[9:13], dataSequenceID)
	copy(buf[13:17], entranceIP[:4])
	copy(buf[17:21], exitIP[:4])
	return true
}

func IsFixedV4DataWireCmd(cmd byte) bool {
	return cmd == cmdDataFixedIPv4 || cmd == CmdDataForward
}

func IsFixedV4DataCmd(buf []byte, size int) bool {
	if size < fixedV4HeaderPayloadOffset || len(buf) < fixedV4HeaderPayloadOffset {
		return false
	}
	if size > len(buf) {
		return false
	}
	return IsFixedV4DataWireCmd(buf[8])
}

func GetFixedV4WireCmd(buf []byte) byte {
	if len(buf) < 9 {
		return 0
	}
	return buf[8]
}

func SetFixedV4WireCmd(buf []byte, cmd byte) {
	if len(buf) < 9 {
		return
	}
	buf[8] = cmd
}

func GetFixedV4ClientID(buf []byte) uint64 {
	if len(buf) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:8])
}

func GetFixedV4DataSequenceID(buf []byte) uint32 {
	if len(buf) < 13 {
		return 0
	}
	return binary.LittleEndian.Uint32(buf[9:13])
}

func SetFixedV4DataSequenceID(buf []byte, v uint32) {
	if len(buf) < 13 {
		return
	}
	binary.LittleEndian.PutUint32(buf[9:13], v)
}

func GetFixedV4EntranceIPv4(buf []byte) []byte {
	if len(buf) < 17 {
		return nil
	}
	return buf[13:17]
}

func SetFixedV4EntranceIPv4(buf []byte, ip []byte) {
	if len(buf) < 17 || len(ip) < 4 {
		return
	}
	copy(buf[13:17], ip[:4])
}

func GetFixedV4ExitIPv4(buf []byte) []byte {
	if len(buf) < 21 {
		return nil
	}
	return buf[17:21]
}

func SetFixedV4ExitIPv4(buf []byte, ip []byte) {
	if len(buf) < 21 || len(ip) < 4 {
		return
	}
	copy(buf[17:21], ip[:4])
}

func GetFixedV4Payload(buf []byte, size int) []byte {
	if size < fixedV4HeaderPayloadOffset || len(buf) < fixedV4HeaderPayloadOffset {
		return nil
	}
	if size > len(buf) {
		return nil
	}
	return buf[fixedV4HeaderPayloadOffset:size]
}
