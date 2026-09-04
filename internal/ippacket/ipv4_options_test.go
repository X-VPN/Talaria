// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package ippacket

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4RejectsSourceRouteOptions(t *testing.T) {
	for _, protocol := range []byte{ipProtocolTCP, ipProtocolUDP, ipProtocolICMP} {
		for _, option := range []byte{ipv4OptionLSRR, ipv4OptionSSRR} {
			raw := makeIPv4PacketWithOptions(protocol, []byte{option, 7, 4, 10, 0, 0, 1, 0})
			recomputeIPv4Checksum(raw)
			if _, err := ParseIPPacket(raw); err == nil {
				t.Fatalf("protocol %d option %d was accepted", protocol, option)
			}
		}
	}
}

func TestParseIPv4ValidatesOptionsBeforeTransport(t *testing.T) {
	maxOptions := make([]byte, 40)
	for i := range maxOptions[:32] {
		maxOptions[i] = ipv4OptionNOP
	}
	copy(maxOptions[32:], []byte{ipv4OptionLSRR, 7, 4, 10, 0, 0, 1, 0})

	tests := []struct {
		name    string
		options []byte
		wantErr bool
	}{
		{name: "unknown option", options: []byte{0x9e, 4, 0, 0}},
		{name: "truncated option", options: []byte{0x9e, 1, 0, 0}, wantErr: true},
		{name: "option overrun", options: []byte{0x9e, 8, 0, 0}, wantErr: true},
		{name: "route after unknown", options: []byte{0x9e, 4, 0, 0, ipv4OptionSSRR, 7, 4, 10, 0, 0, 1, 0}, wantErr: true},
		{name: "duplicate routes", options: []byte{ipv4OptionLSRR, 7, 4, 10, 0, 0, 1, 1, ipv4OptionSSRR, 7, 4, 10, 0, 0, 2, 0}, wantErr: true},
		{name: "maximum ihl", options: maxOptions, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIPPacket(makeIPv4PacketWithOptions(ipProtocolTCP, tt.options))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIPPacket() error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func makeIPv4PacketWithOptions(protocol byte, options []byte) []byte {
	headerLen := 20 + len(options)
	transportLen := 8
	if protocol == ipProtocolTCP {
		transportLen = 20
	}
	raw := make([]byte, headerLen+transportLen)
	raw[0] = 0x40 | byte(headerLen/4)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = protocol
	copy(raw[12:16], []byte{10, 80, 0, 2})
	copy(raw[16:20], []byte{10, 15, 20, 66})
	copy(raw[20:headerLen], options)
	if protocol == ipProtocolTCP {
		raw[headerLen+12] = 0x50
	}
	if protocol == ipProtocolUDP {
		binary.BigEndian.PutUint16(raw[headerLen+4:headerLen+6], uint16(transportLen))
	}
	return raw
}
