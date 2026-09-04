// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build android

package flowrelay

const managedGVisorAndroidLinkMTU = 8196

func managedGVisorLinkMTU(_ int) int {
	return managedGVisorLinkMTUWithDefault(managedGVisorAndroidLinkMTU)
}
