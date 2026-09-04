// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package ippacket

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRewriteIPv4AddressUpdatesTransportChecksum(t *testing.T) {
	raw := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		t.Fatalf("ParseIPPacket error: %s", parseErr)
	}
	origIPChecksum := binary.BigEndian.Uint16(raw[10:12])
	origTCPChecksum := binary.BigEndian.Uint16(raw[36:38])

	if !packet.RewriteSource(netip.MustParseAddr("172.21.100.2")) {
		t.Fatal("RewriteSource returned false")
	}
	if got := packet.SrcAddr(); got != netip.MustParseAddr("172.21.100.2") {
		t.Fatalf("SrcAddr = %s", got)
	}
	if got := binary.BigEndian.Uint16(raw[10:12]); got == origIPChecksum {
		t.Fatal("IPv4 header checksum did not change after source rewrite")
	}
	if got := binary.BigEndian.Uint16(raw[36:38]); got == origTCPChecksum {
		t.Fatal("TCP checksum did not change after source rewrite")
	}

	rewrittenTCPChecksum := binary.BigEndian.Uint16(raw[36:38])
	if !packet.RewriteDestination(netip.MustParseAddr("10.80.0.2")) {
		t.Fatal("RewriteDestination returned false")
	}
	if got := packet.DstAddr(); got != netip.MustParseAddr("10.80.0.2") {
		t.Fatalf("DstAddr = %s", got)
	}
	if got := binary.BigEndian.Uint16(raw[36:38]); got == rewrittenTCPChecksum {
		t.Fatal("TCP checksum did not change after destination rewrite")
	}
}

func TestRewriteIPv4AddressIncrementalMatchesFullRecompute(t *testing.T) {
	tests := []struct {
		name      string
		raw       []byte
		source    bool
		newIP     netip.Addr
		addrStart int
	}{
		{
			name:      "tcp source",
			raw:       makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
			source:    true,
			newIP:     netip.MustParseAddr("172.21.100.2"),
			addrStart: 12,
		},
		{
			name:      "tcp destination",
			raw:       makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}),
			source:    false,
			newIP:     netip.MustParseAddr("10.80.0.2"),
			addrStart: 16,
		},
		{
			name:      "udp source",
			raw:       makeIPv4UDPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
			source:    true,
			newIP:     netip.MustParseAddr("172.21.100.2"),
			addrStart: 12,
		},
		{
			name:      "udp destination",
			raw:       makeIPv4UDPPacket([4]byte{10, 15, 20, 66}, [4]byte{172, 21, 100, 2}),
			source:    false,
			newIP:     netip.MustParseAddr("10.80.0.2"),
			addrStart: 16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incremental := append([]byte(nil), tt.raw...)
			packet, parseErr := ParseIPPacket(incremental)
			if parseErr != nil {
				t.Fatalf("ParseIPPacket incremental error: %s", parseErr)
			}
			if tt.source {
				if !packet.RewriteSource(tt.newIP) {
					t.Fatal("RewriteSource returned false")
				}
			} else if !packet.RewriteDestination(tt.newIP) {
				t.Fatal("RewriteDestination returned false")
			}

			expected := append([]byte(nil), tt.raw...)
			addr := tt.newIP.As4()
			copy(expected[tt.addrStart:tt.addrStart+4], addr[:])
			expectedPacket, parseErr := ParseIPPacket(expected)
			if parseErr != nil {
				t.Fatalf("ParseIPPacket expected error: %s", parseErr)
			}
			expectedPacket.RecomputeChecksum()
			if !bytes.Equal(incremental, expected) {
				t.Fatalf("incremental rewrite differs from full recompute\ninc=%x\nexp=%x", incremental, expected)
			}
		})
	}
}

func TestClampTCPMSS(t *testing.T) {
	raw := makeIPv4TCPSYNPacketWithMSS([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}, 1460)
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		t.Fatalf("ParseIPPacket error: %s", parseErr)
	}
	origTCPChecksum := binary.BigEndian.Uint16(raw[36:38])

	if !packet.ClampTCPMSS(1261) {
		t.Fatal("ClampTCPMSS returned false")
	}
	if got := binary.BigEndian.Uint16(raw[42:44]); got != 1261 {
		t.Fatalf("MSS = %d, want 1261", got)
	}
	if got := binary.BigEndian.Uint16(raw[36:38]); got == origTCPChecksum {
		t.Fatal("TCP checksum did not change after MSS clamp")
	}
	if packet.ClampTCPMSS(1261) {
		t.Fatal("ClampTCPMSS should return false when MSS already fits")
	}
}

func TestClampTCPMSSIgnoresNonSYN(t *testing.T) {
	raw := makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66})
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		t.Fatalf("ParseIPPacket error: %s", parseErr)
	}
	if packet.ClampTCPMSS(1261) {
		t.Fatal("ClampTCPMSS should ignore non-SYN packet")
	}
}

func makeIPv4TCPPacket(src [4]byte, dst [4]byte) []byte {
	raw := make([]byte, 40)
	raw[0] = 0x45
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = ipProtocolTCP
	copy(raw[12:16], src[:])
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 5202)
	raw[32] = 0x50
	raw[33] = 0x18
	binary.BigEndian.PutUint16(raw[34:36], 65535)
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		panic(parseErr)
	}
	packet.RecomputeChecksum()
	return raw
}

func makeIPv4TCPSYNPacketWithMSS(src [4]byte, dst [4]byte, mss uint16) []byte {
	raw := make([]byte, 44)
	raw[0] = 0x45
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = ipProtocolTCP
	copy(raw[12:16], src[:])
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 5202)
	raw[32] = 0x60
	raw[33] = 0x02
	binary.BigEndian.PutUint16(raw[34:36], 65535)
	raw[40] = 2
	raw[41] = 4
	binary.BigEndian.PutUint16(raw[42:44], mss)
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		panic(parseErr)
	}
	packet.RecomputeChecksum()
	return raw
}

func makeIPv4UDPPacket(src [4]byte, dst [4]byte) []byte {
	raw := make([]byte, 32)
	raw[0] = 0x45
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[8] = 64
	raw[9] = ipProtocolUDP
	copy(raw[12:16], src[:])
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 12345)
	binary.BigEndian.PutUint16(raw[22:24], 5202)
	binary.BigEndian.PutUint16(raw[24:26], uint16(len(raw)-20))
	copy(raw[28:], []byte{1, 2, 3, 4})
	packet, parseErr := ParseIPPacket(raw)
	if parseErr != nil {
		panic(parseErr)
	}
	packet.RecomputeChecksum()
	return raw
}
