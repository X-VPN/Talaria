// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !ios

package client

// ProtocolSupportedOnCurrentPlatform reports whether protocol is valid and supported on this platform.
func ProtocolSupportedOnCurrentPlatform(protocol Protocol) bool {
	_, err := ParseProtocol(string(protocol))
	return err == nil
}
