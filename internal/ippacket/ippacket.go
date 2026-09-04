// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package ippacket parses and rewrites IPv4 and IPv6 packets.
//
// It is used on the forwarding path, where addresses must be translated between
// a session's virtual address and the server's, which means recomputing the IP
// header checksum and the transport checksums that cover the pseudo-header. All
// input is untrusted: a truncated or inconsistent packet is reported rather
// than parsed past its bounds.
package ippacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	ipProtocolTCP      = 6
	ipProtocolUDP      = 17
	ipProtocolICMP     = 1
	ipv4OptionEnd      = 0
	ipv4OptionNOP      = 1
	ipv4OptionLSRR     = 131
	ipv4OptionSSRR     = 137
	ipv6ProtocolICMPv6 = 58
	ipv6HeaderLen      = 40
	ipv6HopByHop       = 0
	ipv6Routing        = 43
	ipv6Fragment       = 44
	ipv6ESP            = 50
	ipv6AH             = 51
	ipv6Destination    = 60
)

type IPPacket struct {
	buf            []byte
	version        uint8
	transportOff   int
	transportProto byte
}

func ParseIPPacket(buf []byte) (IPPacket, error) {
	if len(buf) < 20 {
		return IPPacket{}, fmt.Errorf("ip packet too short: %d", len(buf))
	}

	switch ver := buf[0] >> 4; ver {
	case 4:
		return parseIPv4Packet(buf)
	case 6:
		return parseIPv6Packet(buf)
	default:
		return IPPacket{}, fmt.Errorf("unsupported ip version: %d", int(ver))
	}
}

func parseIPv4Packet(buf []byte) (IPPacket, error) {
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 {
		return IPPacket{}, fmt.Errorf("ipv4 ihl too small: %d", ihl)
	}
	if len(buf) < ihl {
		return IPPacket{}, fmt.Errorf("ipv4 buf shorter than ihl: %d<%d", len(buf), ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen != len(buf) {
		return IPPacket{}, fmt.Errorf("ipv4 total length mismatch: %d!=%d", totalLen, len(buf))
	}
	if buf[6]&0x3f > 0 || buf[7] != 0 {
		return IPPacket{}, errors.New("ipv4 fragmented packet not supported")
	}
	if err := validateIPv4Options(buf[20:ihl]); err != nil {
		return IPPacket{}, err
	}

	proto := buf[9]
	switch proto {
	case ipProtocolTCP:
		if len(buf) < ihl+20 {
			return IPPacket{}, errors.New("ipv4 tcp header too short")
		}
		tcpHeaderLen := int(buf[ihl+12]>>4) * 4
		if tcpHeaderLen < 20 || len(buf) < ihl+tcpHeaderLen {
			return IPPacket{}, errors.New("ipv4 tcp data offset invalid")
		}
	case ipProtocolUDP:
		if len(buf) < ihl+8 {
			return IPPacket{}, errors.New("ipv4 udp header too short")
		}
		udpLen := int(binary.BigEndian.Uint16(buf[ihl+4 : ihl+6]))
		if udpLen < 8 || udpLen != len(buf)-ihl {
			return IPPacket{}, errors.New("ipv4 udp length mismatch")
		}
	case ipProtocolICMP:
		if len(buf) < ihl+2 {
			return IPPacket{}, errors.New("ipv4 icmp header too short")
		}
	}

	return IPPacket{
		buf:            buf,
		version:        4,
		transportOff:   ihl,
		transportProto: proto,
	}, nil
}

func validateIPv4Options(options []byte) error {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case ipv4OptionEnd:
			return nil
		case ipv4OptionNOP:
			offset++
		case ipv4OptionLSRR, ipv4OptionSSRR:
			return errors.New("ipv4 source route option not supported")
		default:
			if offset+2 > len(options) {
				return errors.New("ipv4 option header is truncated")
			}
			length := int(options[offset+1])
			if length < 2 || offset+length > len(options) {
				return errors.New("ipv4 option length is invalid")
			}
			offset += length
		}
	}
	return nil
}

func parseIPv6Packet(buf []byte) (IPPacket, error) {
	if len(buf) < ipv6HeaderLen {
		return IPPacket{}, fmt.Errorf("ipv6 packet too short: %d", len(buf))
	}
	payloadLen := int(binary.BigEndian.Uint16(buf[4:6]))
	if ipv6HeaderLen+payloadLen != len(buf) {
		return IPPacket{}, fmt.Errorf("ipv6 payload length mismatch: %d != %d", ipv6HeaderLen+payloadLen, len(buf))
	}

	transportOff, proto, ok, err := findIPv6TransportOffset(buf)
	if err != nil {
		return IPPacket{}, err
	}
	if !ok {
		return IPPacket{
			buf:            buf,
			version:        6,
			transportOff:   0,
			transportProto: 0,
		}, nil
	}

	switch proto {
	case ipProtocolTCP:
		if len(buf)-transportOff < 20 {
			return IPPacket{}, errors.New("ipv6 tcp header too short")
		}
		tcpHeaderLen := int(buf[transportOff+12]>>4) * 4
		if tcpHeaderLen < 20 || len(buf)-transportOff < tcpHeaderLen {
			return IPPacket{}, errors.New("ipv6 tcp data offset invalid")
		}
	case ipProtocolUDP:
		if len(buf)-transportOff < 8 {
			return IPPacket{}, errors.New("ipv6 udp header too short")
		}
		udpLen := int(binary.BigEndian.Uint16(buf[transportOff+4 : transportOff+6]))
		if udpLen < 8 || udpLen != len(buf)-transportOff {
			return IPPacket{}, errors.New("ipv6 udp length mismatch")
		}
	case ipv6ProtocolICMPv6:
		if len(buf)-transportOff < 4 {
			return IPPacket{}, errors.New("ipv6 icmpv6 header too short")
		}
	}

	return IPPacket{
		buf:            buf,
		version:        6,
		transportOff:   transportOff,
		transportProto: proto,
	}, nil
}

func findIPv6TransportOffset(buf []byte) (int, byte, bool, error) {
	if len(buf) < ipv6HeaderLen || buf[0]>>4 != 6 {
		return 0, 0, false, errors.New("invalid ipv6 header")
	}
	nextHeader := buf[6]
	offset := ipv6HeaderLen
	for {
		switch nextHeader {
		case ipProtocolTCP, ipProtocolUDP, ipv6ProtocolICMPv6:
			return offset, nextHeader, true, nil
		case ipv6HopByHop, ipv6Routing, ipv6Destination:
			if len(buf) < offset+8 {
				return 0, 0, false, errors.New("ipv6 extension header is truncated")
			}
			nextHeader = buf[offset]
			extLen := (int(buf[offset+1]) + 1) * 8
			if extLen < 8 || len(buf) < offset+extLen {
				return 0, 0, false, errors.New("ipv6 extension header length is invalid")
			}
			offset += extLen
		case ipv6AH:
			if len(buf) < offset+8 {
				return 0, 0, false, errors.New("ipv6 authentication header is truncated")
			}
			nextHeader = buf[offset]
			extLen := (int(buf[offset+1]) + 2) * 4
			if extLen < 8 || len(buf) < offset+extLen {
				return 0, 0, false, errors.New("ipv6 authentication header length is invalid")
			}
			offset += extLen
		case ipv6Fragment:
			return 0, 0, false, errors.New("ipv6 fragmented packet not supported")
		case ipv6ESP:
			return 0, 0, false, nil
		default:
			return 0, 0, false, nil
		}
	}
}

func (p *IPPacket) IsIPv4() bool         { return p.version == 4 }
func (p *IPPacket) IsIPv6() bool         { return p.version == 6 }
func (p *IPPacket) Version() uint8       { return p.version }
func (p *IPPacket) Buf() []byte          { return p.buf }
func (p *IPPacket) Len() int             { return len(p.buf) }
func (p *IPPacket) TransportProto() byte { return p.transportProto }
func (p *IPPacket) TransportOffset() int { return p.transportOff }

func (p *IPPacket) IsTCP() bool {
	return p.transportProto == ipProtocolTCP
}

func (p *IPPacket) IsUDP() bool {
	return p.transportProto == ipProtocolUDP
}

func (p *IPPacket) IsICMP() bool {
	return p.transportProto == ipProtocolICMP || p.transportProto == ipv6ProtocolICMPv6
}

func (p *IPPacket) SrcAddr() netip.Addr {
	if p.version == 6 {
		var addr [16]byte
		copy(addr[:], p.buf[8:24])
		return netip.AddrFrom16(addr)
	}
	var addr [4]byte
	copy(addr[:], p.buf[12:16])
	return netip.AddrFrom4(addr)
}

func (p *IPPacket) DstAddr() netip.Addr {
	if p.version == 6 {
		var addr [16]byte
		copy(addr[:], p.buf[24:40])
		return netip.AddrFrom16(addr)
	}
	var addr [4]byte
	copy(addr[:], p.buf[16:20])
	return netip.AddrFrom4(addr)
}

func (p *IPPacket) RewriteSource(addr netip.Addr) bool {
	return p.rewriteAddr(addr, true)
}

func (p *IPPacket) RewriteDestination(addr netip.Addr) bool {
	return p.rewriteAddr(addr, false)
}

func (p *IPPacket) ClampTCPMSS(maxMSS int) bool {
	if p == nil || maxMSS <= 0 || p.transportProto != ipProtocolTCP {
		return false
	}
	tcpOff := p.transportOff
	if tcpOff < 0 || len(p.buf) < tcpOff+20 {
		return false
	}
	flags := p.buf[tcpOff+13]
	if flags&0x02 == 0 {
		return false
	}
	tcpHeaderLen := int(p.buf[tcpOff+12]>>4) * 4
	if tcpHeaderLen < 20 || len(p.buf) < tcpOff+tcpHeaderLen {
		return false
	}
	opts := p.buf[tcpOff+20 : tcpOff+tcpHeaderLen]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return false
		case 1:
			i++
			continue
		case 2:
			if i+4 > len(opts) || opts[i+1] != 4 {
				return false
			}
			current := int(binary.BigEndian.Uint16(opts[i+2 : i+4]))
			if current <= maxMSS {
				return false
			}
			binary.BigEndian.PutUint16(opts[i+2:i+4], uint16(maxMSS))
			p.RecomputeChecksum()
			return true
		default:
			if i+2 > len(opts) {
				return false
			}
			optLen := int(opts[i+1])
			if optLen < 2 || i+optLen > len(opts) {
				return false
			}
			i += optLen
		}
	}
	return false
}

func (p *IPPacket) rewriteAddr(addr netip.Addr, source bool) bool {
	if p == nil || !addr.IsValid() {
		return false
	}
	switch p.version {
	case 4:
		if !addr.Is4() {
			return false
		}
		addr4 := addr.As4()
		if source {
			p.rewriteIPv4AddrIncremental(addr4, 12)
		} else {
			p.rewriteIPv4AddrIncremental(addr4, 16)
		}
		return true
	case 6:
		if !addr.Is6() {
			return false
		}
		addr16 := addr.As16()
		if source {
			copy(p.buf[8:24], addr16[:])
		} else {
			copy(p.buf[24:40], addr16[:])
		}
	default:
		return false
	}
	p.RecomputeChecksum()
	return true
}

func (p *IPPacket) rewriteIPv4AddrIncremental(addr [4]byte, off int) {
	if len(p.buf) < off+4 {
		return
	}
	old0 := binary.BigEndian.Uint16(p.buf[off : off+2])
	old1 := binary.BigEndian.Uint16(p.buf[off+2 : off+4])
	new0 := binary.BigEndian.Uint16(addr[:2])
	new1 := binary.BigEndian.Uint16(addr[2:4])

	updateIPv4HeaderChecksum(p.buf, old0, new0, old1, new1)
	updateIPv4TransportChecksum(p.buf, p.transportOff, p.transportProto, old0, new0, old1, new1)
	copy(p.buf[off:off+4], addr[:])
}

func (p *IPPacket) SrcPort() uint16 {
	if p.transportProto != ipProtocolTCP && p.transportProto != ipProtocolUDP {
		return 0
	}
	return binary.BigEndian.Uint16(p.buf[p.transportOff : p.transportOff+2])
}

func (p *IPPacket) DstPort() uint16 {
	if p.transportProto != ipProtocolTCP && p.transportProto != ipProtocolUDP {
		return 0
	}
	return binary.BigEndian.Uint16(p.buf[p.transportOff+2 : p.transportOff+4])
}

func (p *IPPacket) RecomputeChecksum() {
	switch p.version {
	case 4:
		recomputeIPv4Checksum(p.buf)
	case 6:
		recomputeIPv6TransportChecksum(p.buf, p.transportOff, p.transportProto)
	}
}

func recomputeIPv4Checksum(buf []byte) {
	if len(buf) < 20 || buf[0]>>4 != 4 {
		return
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl {
		return
	}

	buf[10], buf[11] = 0, 0
	sum := checksumBytes(buf[:ihl])
	binary.BigEndian.PutUint16(buf[10:12], ^foldChecksum(sum))

	if buf[6]&0x3f > 0 || buf[7] != 0 {
		return
	}
	switch buf[9] {
	case ipProtocolTCP:
		recomputeIPv4TCPChecksum(buf, ihl)
	case ipProtocolUDP:
		recomputeIPv4UDPChecksum(buf, ihl)
	}
}

func recomputeIPv4TCPChecksum(buf []byte, ihl int) {
	if len(buf) < ihl+20 {
		return
	}
	buf[ihl+16], buf[ihl+17] = 0, 0
	tcpLen := len(buf) - ihl
	sum := pseudoHeaderSumIPv4(buf, ipProtocolTCP, tcpLen)
	sum += checksumBytes(buf[ihl:])
	binary.BigEndian.PutUint16(buf[ihl+16:ihl+18], ^foldChecksum(sum))
}

func recomputeIPv4UDPChecksum(buf []byte, ihl int) {
	if len(buf) < ihl+8 {
		return
	}
	buf[ihl+6], buf[ihl+7] = 0, 0
	udpLen := len(buf) - ihl
	sum := pseudoHeaderSumIPv4(buf, ipProtocolUDP, udpLen)
	sum += checksumBytes(buf[ihl:])
	result := ^foldChecksum(sum)
	if result == 0 {
		result = 0xffff
	}
	binary.BigEndian.PutUint16(buf[ihl+6:ihl+8], result)
}

func pseudoHeaderSumIPv4(buf []byte, proto byte, transportLen int) uint64 {
	var sum uint64
	sum += uint64(buf[12])<<8 | uint64(buf[13])
	sum += uint64(buf[14])<<8 | uint64(buf[15])
	sum += uint64(buf[16])<<8 | uint64(buf[17])
	sum += uint64(buf[18])<<8 | uint64(buf[19])
	sum += uint64(proto)
	sum += uint64(transportLen)
	return sum
}

func recomputeIPv6TransportChecksum(buf []byte, transportOff int, proto byte) {
	if transportOff <= 0 || proto == 0 {
		return
	}

	switch proto {
	case ipProtocolTCP:
		recomputeIPv6TCPChecksum(buf, transportOff)
	case ipProtocolUDP:
		recomputeIPv6UDPChecksum(buf, transportOff)
	case ipv6ProtocolICMPv6:
		recomputeIPv6ICMPv6Checksum(buf, transportOff)
	}
}

func recomputeIPv6TCPChecksum(buf []byte, transportOff int) {
	if len(buf) < transportOff+20 {
		return
	}
	buf[transportOff+16], buf[transportOff+17] = 0, 0
	transportLen := len(buf) - transportOff
	sum := pseudoHeaderSumIPv6(buf, ipProtocolTCP, transportLen)
	sum += checksumBytes(buf[transportOff:])
	binary.BigEndian.PutUint16(buf[transportOff+16:transportOff+18], ^foldChecksum(sum))
}

func recomputeIPv6UDPChecksum(buf []byte, transportOff int) {
	if len(buf) < transportOff+8 {
		return
	}
	buf[transportOff+6], buf[transportOff+7] = 0, 0
	transportLen := len(buf) - transportOff
	sum := pseudoHeaderSumIPv6(buf, ipProtocolUDP, transportLen)
	sum += checksumBytes(buf[transportOff:])
	result := ^foldChecksum(sum)
	if result == 0 {
		result = 0xffff
	}
	binary.BigEndian.PutUint16(buf[transportOff+6:transportOff+8], result)
}

func recomputeIPv6ICMPv6Checksum(buf []byte, transportOff int) {
	if len(buf) < transportOff+4 {
		return
	}
	buf[transportOff+2], buf[transportOff+3] = 0, 0
	transportLen := len(buf) - transportOff
	sum := pseudoHeaderSumIPv6(buf, ipv6ProtocolICMPv6, transportLen)
	sum += checksumBytes(buf[transportOff:])
	binary.BigEndian.PutUint16(buf[transportOff+2:transportOff+4], ^foldChecksum(sum))
}

func pseudoHeaderSumIPv6(buf []byte, proto byte, transportLen int) uint64 {
	var sum uint64
	for i := 8; i < 24; i += 2 {
		sum += uint64(buf[i])<<8 | uint64(buf[i+1])
	}
	for i := 24; i < 40; i += 2 {
		sum += uint64(buf[i])<<8 | uint64(buf[i+1])
	}
	sum += uint64(transportLen >> 16)
	sum += uint64(transportLen & 0xffff)
	sum += uint64(proto)
	return sum
}

func checksumBytes(data []byte) uint64 {
	var sum uint64
	for len(data) >= 2 {
		sum += uint64(data[0])<<8 | uint64(data[1])
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint64(data[0]) << 8
	}
	return sum
}

func foldChecksum(sum uint64) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

func updateIPv4HeaderChecksum(buf []byte, old0, new0, old1, new1 uint16) {
	if len(buf) < 12 {
		return
	}
	sum := updateChecksumWord(binary.BigEndian.Uint16(buf[10:12]), old0, new0)
	sum = updateChecksumWord(sum, old1, new1)
	binary.BigEndian.PutUint16(buf[10:12], sum)
}

func updateIPv4TransportChecksum(buf []byte, transportOff int, proto byte, old0, new0, old1, new1 uint16) {
	var checksumOff int
	switch proto {
	case ipProtocolTCP:
		if len(buf) < transportOff+18 {
			return
		}
		checksumOff = transportOff + 16
	case ipProtocolUDP:
		if len(buf) < transportOff+8 {
			return
		}
		checksumOff = transportOff + 6
		if binary.BigEndian.Uint16(buf[checksumOff:checksumOff+2]) == 0 {
			return
		}
	default:
		return
	}
	sum := updateChecksumWord(binary.BigEndian.Uint16(buf[checksumOff:checksumOff+2]), old0, new0)
	sum = updateChecksumWord(sum, old1, new1)
	if proto == ipProtocolUDP && sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(buf[checksumOff:checksumOff+2], sum)
}

func updateChecksumWord(checksum uint16, oldWord uint16, newWord uint16) uint16 {
	sum := uint32(^checksum&0xffff) + uint32(^oldWord&0xffff) + uint32(newWord)
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

func (p *IPPacket) String() string {
	var b strings.Builder
	b.WriteString("IPPacket{version=")
	b.WriteString(strconv.Itoa(int(p.version)))
	b.WriteString(", proto=")
	b.WriteString(strconv.Itoa(int(p.transportProto)))
	b.WriteString(", src=")
	b.WriteString(p.SrcAddr().String())
	b.WriteString(", dst=")
	b.WriteString(p.DstAddr().String())
	b.WriteByte('}')
	return b.String()
}
