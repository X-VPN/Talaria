// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build ios

package flowrelay

import "testing"

func TestManagedTunnelTCPBufferRangeIOS(t *testing.T) {
	if managedTunnelTCPBufferMin != 32*1024 {
		t.Fatalf("managedTunnelTCPBufferMin = %d want %d", managedTunnelTCPBufferMin, 32*1024)
	}
	if managedTunnelTCPBufferDefault != 256*1024 {
		t.Fatalf("managedTunnelTCPBufferDefault = %d want %d", managedTunnelTCPBufferDefault, 256*1024)
	}
	if managedTunnelTCPBufferMax != 1024*1024 {
		t.Fatalf("managedTunnelTCPBufferMax = %d want %d", managedTunnelTCPBufferMax, 1024*1024)
	}
}
