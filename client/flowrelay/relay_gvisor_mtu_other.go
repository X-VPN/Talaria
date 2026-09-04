// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !android

package flowrelay

func managedGVisorLinkMTU(maxPacket int) int {
	return managedGVisorLinkMTUWithDefault(maxPacket)
}
