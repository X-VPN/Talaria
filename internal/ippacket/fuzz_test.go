// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package ippacket

import (
	"encoding/binary"
	"testing"
)

func TestParseIPPacketRejectsMismatchedUDPLength(t *testing.T) {
	raw := makeIPv4UDPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(raw[24:26], 8)
	if _, errText := ParseIPPacket(raw); errText == nil {
		t.Fatal("mismatched IPv4 UDP length was accepted")
	}
}

func TestParseIPPacketRejectsTruncatedIPv6ExtensionHeader(t *testing.T) {
	raw := make([]byte, ipv6HeaderLen+4)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], 4)
	raw[6] = ipv6HopByHop
	if _, err := ParseIPPacket(raw); err == nil {
		t.Fatal("truncated IPv6 extension header was accepted")
	}
}

func TestParseIPPacketRejectsIPv6Fragments(t *testing.T) {
	raw := make([]byte, ipv6HeaderLen+8)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], 8)
	raw[6] = ipv6Fragment
	if _, err := ParseIPPacket(raw); err == nil {
		t.Fatal("IPv6 fragment was accepted")
	}
}

func FuzzParseIPPacket(f *testing.F) {
	f.Add(makeIPv4UDPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 1}))
	f.Add(makeIPv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			t.Skip()
		}
		packet, errText := ParseIPPacket(raw)
		if errText != nil {
			return
		}
		_ = packet.SrcAddr()
		_ = packet.DstAddr()
		_ = packet.SrcPort()
		_ = packet.DstPort()
		packet.ClampTCPMSS(1261)
		packet.RecomputeChecksum()
	})
}
