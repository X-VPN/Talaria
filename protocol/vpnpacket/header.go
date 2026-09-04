// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import "encoding/binary"

const (
	rawCmdDataHeaderLen       = dataHeaderOverHeadV1
	rawCmdDataReturnHeaderLen = dataHeaderOverHeadV1
)

func RawCmdDataHeaderLen() int {
	return rawCmdDataHeaderLen
}

func RawCmdDataReturnHeaderLen() int {
	return rawCmdDataReturnHeaderLen
}

func WriteRawCmdDataHeader(buf []byte, clientID uint64, dataSequenceID uint32) bool {
	if len(buf) < rawCmdDataHeaderLen {
		return false
	}
	binary.LittleEndian.PutUint64(buf[:8], clientID)
	buf[8] = CmdData
	binary.LittleEndian.PutUint32(buf[9:13], dataSequenceID)
	return true
}

func WriteRawCmdDataReturnHeader(buf []byte, clientID uint64, dataSequenceID uint32) bool {
	if len(buf) < rawCmdDataReturnHeaderLen {
		return false
	}
	binary.LittleEndian.PutUint64(buf[:8], clientID)
	buf[8] = CmdDataReturn
	binary.LittleEndian.PutUint32(buf[9:13], dataSequenceID)
	return true
}
