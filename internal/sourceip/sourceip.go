// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package sourceip

import (
	"errors"
	"net/netip"
	"strings"
)

const DefaultIPv6PrefixBits = 64

func NormalizePrefixBits(bits int) (int, error) {
	if bits == 0 {
		return DefaultIPv6PrefixBits, nil
	}
	if bits < 0 || bits > 128 {
		return 0, errors.New("IPv6 source prefix bits must be between 1 and 128")
	}
	return bits, nil
}

func MaskIPv6(ip *[16]byte, bits int) {
	if ip == nil {
		return
	}
	if bits <= 0 {
		bits = DefaultIPv6PrefixBits
	} else if bits > 128 {
		bits = 128
	}
	full := bits / 8
	if rem := bits % 8; rem != 0 {
		ip[full] &= byte(0xff << (8 - rem))
		full++
	}
	clear(ip[full:])
}

func Key(host string, ipv6PrefixBits int) string {
	host = strings.TrimSpace(host)
	zone := ""
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		zone, host = host[i:], host[:i]
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return strings.ToLower(host) + zone
	}
	ip = ip.Unmap()
	if ip.Is6() {
		if ipv6PrefixBits <= 0 {
			ipv6PrefixBits = DefaultIPv6PrefixBits
		} else if ipv6PrefixBits > 128 {
			ipv6PrefixBits = 128
		}
		ip = netip.PrefixFrom(ip, ipv6PrefixBits).Masked().Addr()
	}
	return ip.String() + zone
}
