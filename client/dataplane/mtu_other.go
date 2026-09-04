// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !android

package dataplane

func EffectiveTunMTUForProtocol(_ string) int {
	return DefaultMTU
}

func SetTunMTUOverride(_ int) {}
