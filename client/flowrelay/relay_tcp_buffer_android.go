// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build android

package flowrelay

const (
	// Android keeps a smaller minimum buffer while bounding the capacity that
	// each relayed flow reserves from the process-wide memory budget.
	managedTunnelTCPBufferMin     = 128 * 1024
	managedTunnelTCPBufferDefault = 1024 * 1024
	managedTunnelTCPBufferMax     = 1024 * 1024
)
