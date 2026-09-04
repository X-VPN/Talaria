// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"errors"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

var (
	ErrPacketBufferNoHeadroom     = errors.New("packet buffer has no headroom")
	ErrPacketBufferInvalidFixedV4 = errors.New("invalid fixed v4 data header")
)

func WriteDataHeader(pkt *PacketBuffer, clientID uint64, dataSequenceID uint32, remoteVersion byte, entranceIP []byte, exitIP []byte) error {
	if pkt == nil {
		return errors.New("nil packet buffer")
	}
	headerLen := vpnpacket.RawCmdDataHeaderLen()
	useFixedV4 := remoteVersion >= 5 && remoteVersion <= 7
	if useFixedV4 {
		headerLen = vpnpacket.FixedV4PayloadOffset()
		if len(entranceIP) < 4 || len(exitIP) < 4 {
			return ErrPacketBufferInvalidFixedV4
		}
	}
	header := pkt.ReserveHead(headerLen)
	if header == nil {
		return ErrPacketBufferNoHeadroom
	}
	if useFixedV4 {
		if !vpnpacket.WriteRawFixedV4DataHeader(header, clientID, dataSequenceID, entranceIP, exitIP) {
			return ErrPacketBufferNoHeadroom
		}
		return nil
	}
	if !vpnpacket.WriteRawCmdDataHeader(header, clientID, dataSequenceID) {
		return ErrPacketBufferNoHeadroom
	}
	return nil
}
