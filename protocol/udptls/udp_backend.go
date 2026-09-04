// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"net"

	"github.com/X-VPN/Talaria/internal/udpsession"
)

const defaultUDPBatchSize = 32

type udpSharedStats struct {
	inner *udpDebugStats
}

func newUDPSharedStats(enabled bool, name string, local net.Addr, remote net.Addr) udpsession.Stats {
	stats := newUDPDebugStats(enabled, name, local, remote)
	if stats == nil {
		return nil
	}
	return udpSharedStats{inner: stats}
}

func (s udpSharedStats) Close() {
	if s.inner != nil {
		s.inner.Close()
	}
}

func (s udpSharedStats) AddRX(packets int, bytes int) {
	if s.inner != nil {
		s.inner.addRX(packets, bytes)
	}
}

func (s udpSharedStats) AddTX(packets int, bytes int) {
	if s.inner != nil {
		s.inner.addTX(packets, bytes)
	}
}

func (s udpSharedStats) AddGSO(msgs int, segments int, wireBytes int) {
	if s.inner != nil {
		s.inner.addGSO(msgs, segments, wireBytes)
	}
}

func (s udpSharedStats) AddGSOFallback(groups int) {
	if s.inner != nil {
		s.inner.addGSOFallback(groups)
	}
}

func (s udpSharedStats) AddGRO(msgs int, segments int, wireBytes int) {
	if s.inner != nil {
		s.inner.addGRO(msgs, segments, wireBytes)
	}
}

func (s udpSharedStats) AddQueueDrops(packets int) {
	if s.inner != nil {
		s.inner.addQueueDrops(packets)
	}
}
