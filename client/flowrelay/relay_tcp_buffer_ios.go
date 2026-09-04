// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build ios

package flowrelay

const (
	// iOS network extensions have a tight memory budget, so keep gVisor TCP
	// autotuning bounded while leaving enough window for normal mobile latency.
	managedTunnelTCPBufferMin     = 32 * 1024
	managedTunnelTCPBufferDefault = 256 * 1024
	managedTunnelTCPBufferMax     = 1024 * 1024
)
