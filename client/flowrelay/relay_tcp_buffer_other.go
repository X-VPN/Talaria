// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !ios && !android

package flowrelay

const (
	managedTunnelTCPBufferMin     = 256 * 1024
	managedTunnelTCPBufferDefault = 1024 * 1024
	managedTunnelTCPBufferMax     = 1024 * 1024
)
