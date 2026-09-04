// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package udpsession

import "net"

func udpControlSize() int {
	return 0
}

func enableUDPGSO(_ *net.UDPConn) bool {
	return false
}

func enableUDPGRO(_ *net.UDPConn) bool {
	return false
}

func buildUDPSegmentOOB(_ int, _ []byte) []byte {
	return nil
}

func parseUDPGROSegmentSize(_ []byte) int {
	return 0
}

func isUDPSegmentUnsupported(_ error) bool {
	return false
}
