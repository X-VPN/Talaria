// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build android

package dataplane

import "sync/atomic"

const (
	AndroidHighThroughputTunMTU = 8196
	tunMTUOverrideMin           = 576
	tunMTUOverrideMax           = 9000
)

var tunMTUOverride atomic.Int64

func EffectiveTunMTUForProtocol(protocol string) int {
	if !isAndroidHighThroughputMTUProtocol(protocol) {
		return DefaultMTU
	}
	if override := int(tunMTUOverride.Load()); override > 0 {
		return clampTunMTUOverride(override)
	}
	return AndroidHighThroughputTunMTU
}

func SetTunMTUOverride(mtu int) {
	if mtu <= 0 {
		tunMTUOverride.Store(0)
		return
	}
	tunMTUOverride.Store(int64(clampTunMTUOverride(mtu)))
}

func isAndroidHighThroughputMTUProtocol(protocol string) bool {
	switch protocol {
	case "TalariaTCP":
		return true
	default:
		return false
	}
}

func clampTunMTUOverride(mtu int) int {
	if mtu < tunMTUOverrideMin {
		return DefaultMTU
	}
	if mtu > tunMTUOverrideMax {
		return tunMTUOverrideMax
	}
	return mtu
}
