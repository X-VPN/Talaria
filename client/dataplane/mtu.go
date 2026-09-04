// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"runtime"

	"github.com/X-VPN/Talaria/protocol/udptls"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

const (
	CarrierMTU = 1460
	// The default must fit the largest supported VPN data header inside the
	// secure TalariaUDP envelope on an IPv6 UDP carrier.
	outerIPv6UDPOverhead = 40 + 8
	// MaxMTU is the largest TUN MTU accepted by a Talaria client session.
	MaxMTU     = 9000
	DefaultMTU = CarrierMTU - outerIPv6UDPOverhead - vpnpacket.MaxDataHeaderOverhead - udptls.SecureDataPacketOverhead
	DefaultMSS = DefaultMTU - 40

	defaultConnReadBufferSize = 2048
	windowsTunReadBufferSize  = 65536
)

func EffectiveTunMTU() int {
	return EffectiveTunMTUForProtocol("")
}

func EffectiveTCPMSS() int {
	return EffectiveTunMTU() - 40
}

func TunReadBufferSize(mtu int) int {
	if runtime.GOOS == "windows" {
		return windowsTunReadBufferSize
	}
	size := normalizeMTU(mtu) + 16
	if size < 4096 {
		return 4096
	}
	return size
}

// ConnReadBufferSize covers the configured MTU and the largest supported VPN data header.
func ConnReadBufferSize(mtu int) int {
	return max(defaultConnReadBufferSize, normalizeMTU(mtu)+vpnpacket.FixedV4PayloadOffset())
}

func TunReadPacketBufferSize(mtu int) int {
	return TunReadBufferSize(mtu) + DefaultHeadroom
}

func ConnReadPacketBufferSize(mtu int) int {
	return ConnReadBufferSize(mtu) + DefaultHeadroom
}

func DeviceTunReadPacketBufferSize(protocol string) int {
	mtu := EffectiveTunMTUForProtocol(protocol)
	if mtu < defaultConnReadBufferSize {
		mtu = defaultConnReadBufferSize
	}
	return mtu + DefaultHeadroom
}

func EndpointReadPacketBufferSize(mtu int, protocol string) int {
	effective := EffectiveTunMTUForProtocol(protocol)
	if mtu > effective {
		effective = mtu
	}
	if effective < defaultConnReadBufferSize {
		effective = defaultConnReadBufferSize
	}
	return effective + DefaultHeadroom
}

func normalizeMTU(mtu int) int {
	if mtu <= 0 {
		return DefaultMTU
	}
	return mtu
}
