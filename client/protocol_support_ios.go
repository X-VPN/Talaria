// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build ios

package client

// ProtocolSupportedOnCurrentPlatform reports whether protocol is valid and supported on iOS.
func ProtocolSupportedOnCurrentPlatform(protocol Protocol) bool {
	protocol, err := ParseProtocol(string(protocol))
	return err == nil && protocol == ProtocolTalariaUDP
}
