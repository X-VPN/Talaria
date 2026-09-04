// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

// Data packet header sizes by wire format.
// cmdData   8(packet.ClientId)+1(packet.Cmd)+4(packet.DataSequenceId) = 13
// cmdDataFixedIPv4 8(packet.ClientId)+1(packet.Cmd)+4(packet.DataSequenceId)+4(packet.EntranceIp)+4(packet.Exit) = 21
const (
	dataHeaderOverHeadV1        = 8 + 1 + 4         // 13
	dataHeaderOverHeadFixedIPv4 = 8 + 1 + 4 + 4 + 4 // 21

	// MaxDataHeaderOverhead is the largest data header emitted or accepted by
	// the current codec.
	MaxDataHeaderOverhead = dataHeaderOverHeadFixedIPv4
)
