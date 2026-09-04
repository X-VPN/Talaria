// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package flowrelay

import "fmt"

type managedTCPBackend interface {
	injectIPv4Packet([]byte) error
	close() error
}

type managedTCPBackendOutboundReader interface {
	outboundReader() managedOutboundReader
}

var (
	managedNewGVisorTCPBackend = func(maxPacket int, flowHandler func(managedTCPForwardedFlow)) (managedTCPBackend, error) {
		return newManagedGVisorTCPBackend(maxPacket, flowHandler)
	}
)

func newManagedTCPBackend(maxPacket int, relay *managedTunnelRelay) (managedTCPBackend, error) {
	if relay == nil {
		return nil, fmt.Errorf("nil TalariaTCP relay")
	}
	return managedNewGVisorTCPBackend(maxPacket, relay.handleTCPForwarder)
}
