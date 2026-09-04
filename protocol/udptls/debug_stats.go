// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const udpDebugStatsInterval = time.Second

type udpDebugStats struct {
	name   string
	local  string
	remote string

	closeCh   chan struct{}
	closeOnce sync.Once

	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txPackets atomic.Uint64
	txBytes   atomic.Uint64

	gsoMsgs      atomic.Uint64
	gsoSegments  atomic.Uint64
	gsoWireBytes atomic.Uint64
	gsoFallback  atomic.Uint64

	groMsgs      atomic.Uint64
	groSegments  atomic.Uint64
	groWireBytes atomic.Uint64

	queueDrops atomic.Uint64
}

type udpDebugSnapshot struct {
	rxPackets uint64
	rxBytes   uint64
	txPackets uint64
	txBytes   uint64

	gsoMsgs      uint64
	gsoSegments  uint64
	gsoWireBytes uint64
	gsoFallback  uint64

	groMsgs      uint64
	groSegments  uint64
	groWireBytes uint64

	queueDrops uint64
}

func newUDPDebugStats(enabled bool, name string, local, remote net.Addr) *udpDebugStats {
	if !enabled {
		return nil
	}
	s := &udpDebugStats{
		name:    name,
		local:   addrString(local),
		remote:  addrString(remote),
		closeCh: make(chan struct{}),
	}
	go s.logLoop()
	return s
}

func (s *udpDebugStats) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

func (s *udpDebugStats) addRX(packets int, bytes int) {
	if s == nil || packets <= 0 || bytes <= 0 {
		return
	}
	s.rxPackets.Add(uint64(packets))
	s.rxBytes.Add(uint64(bytes))
}

func (s *udpDebugStats) addTX(packets int, bytes int) {
	if s == nil || packets <= 0 || bytes <= 0 {
		return
	}
	s.txPackets.Add(uint64(packets))
	s.txBytes.Add(uint64(bytes))
}

func (s *udpDebugStats) addGSO(msgs int, segments int, wireBytes int) {
	if s == nil || msgs <= 0 || segments <= 1 || wireBytes <= 0 {
		return
	}
	s.gsoMsgs.Add(uint64(msgs))
	s.gsoSegments.Add(uint64(segments))
	s.gsoWireBytes.Add(uint64(wireBytes))
}

func (s *udpDebugStats) addGSOFallback(groups int) {
	if s == nil || groups <= 0 {
		return
	}
	s.gsoFallback.Add(uint64(groups))
}

func (s *udpDebugStats) addGRO(msgs int, segments int, wireBytes int) {
	if s == nil || msgs <= 0 || segments <= 1 || wireBytes <= 0 {
		return
	}
	s.groMsgs.Add(uint64(msgs))
	s.groSegments.Add(uint64(segments))
	s.groWireBytes.Add(uint64(wireBytes))
}

func (s *udpDebugStats) addQueueDrops(packets int) {
	if s == nil || packets <= 0 {
		return
	}
	s.queueDrops.Add(uint64(packets))
}

func (s *udpDebugStats) logLoop() {
	ticker := time.NewTicker(udpDebugStatsInterval)
	defer ticker.Stop()

	lastAt := time.Now()
	last := s.snapshot()
	for {
		select {
		case <-s.closeCh:
			return
		case now := <-ticker.C:
			cur := s.snapshot()
			elapsed := now.Sub(lastAt).Seconds()
			lastAt = now
			if elapsed <= 0 {
				last = cur
				continue
			}
			delta := cur.diff(last)
			last = cur
			if delta.isZero() {
				continue
			}

			rxAvg := uint64(0)
			if delta.rxPackets > 0 {
				rxAvg = delta.rxBytes / delta.rxPackets
			}
			txAvg := uint64(0)
			if delta.txPackets > 0 {
				txAvg = delta.txBytes / delta.txPackets
			}

			slog.Info("udp stats",
				"name", s.name,
				"local", s.local,
				"remote", s.remote,
				"rx_packets", delta.rxPackets,
				"rx_B", delta.rxBytes,
				"rx_gbps", bytesToGbps(delta.rxBytes, elapsed),
				"rx_pps", perSecond(delta.rxPackets, elapsed),
				"rx_avg_B", rxAvg,
				"tx_packets", delta.txPackets,
				"tx_B", delta.txBytes,
				"tx_gbps", bytesToGbps(delta.txBytes, elapsed),
				"tx_pps", perSecond(delta.txPackets, elapsed),
				"tx_avg_B", txAvg,
				"gso_msg", delta.gsoMsgs,
				"gso_seg", delta.gsoSegments,
				"gso_merge", saturatedSub(delta.gsoSegments, delta.gsoMsgs),
				"gso_B", delta.gsoWireBytes,
				"gso_fallback", delta.gsoFallback,
				"gro_msg", delta.groMsgs,
				"gro_seg", delta.groSegments,
				"gro_merge", saturatedSub(delta.groSegments, delta.groMsgs),
				"gro_B", delta.groWireBytes,
				"queue_drop", delta.queueDrops,
			)
		}
	}
}

func (s *udpDebugStats) snapshot() udpDebugSnapshot {
	if s == nil {
		return udpDebugSnapshot{}
	}
	return udpDebugSnapshot{
		rxPackets: s.rxPackets.Load(),
		rxBytes:   s.rxBytes.Load(),
		txPackets: s.txPackets.Load(),
		txBytes:   s.txBytes.Load(),

		gsoMsgs:      s.gsoMsgs.Load(),
		gsoSegments:  s.gsoSegments.Load(),
		gsoWireBytes: s.gsoWireBytes.Load(),
		gsoFallback:  s.gsoFallback.Load(),

		groMsgs:      s.groMsgs.Load(),
		groSegments:  s.groSegments.Load(),
		groWireBytes: s.groWireBytes.Load(),

		queueDrops: s.queueDrops.Load(),
	}
}

func (s udpDebugSnapshot) diff(prev udpDebugSnapshot) udpDebugSnapshot {
	return udpDebugSnapshot{
		rxPackets: s.rxPackets - prev.rxPackets,
		rxBytes:   s.rxBytes - prev.rxBytes,
		txPackets: s.txPackets - prev.txPackets,
		txBytes:   s.txBytes - prev.txBytes,

		gsoMsgs:      s.gsoMsgs - prev.gsoMsgs,
		gsoSegments:  s.gsoSegments - prev.gsoSegments,
		gsoWireBytes: s.gsoWireBytes - prev.gsoWireBytes,
		gsoFallback:  s.gsoFallback - prev.gsoFallback,

		groMsgs:      s.groMsgs - prev.groMsgs,
		groSegments:  s.groSegments - prev.groSegments,
		groWireBytes: s.groWireBytes - prev.groWireBytes,

		queueDrops: s.queueDrops - prev.queueDrops,
	}
}

func (s udpDebugSnapshot) isZero() bool {
	return s.rxPackets == 0 &&
		s.rxBytes == 0 &&
		s.txPackets == 0 &&
		s.txBytes == 0 &&
		s.gsoMsgs == 0 &&
		s.gsoSegments == 0 &&
		s.gsoWireBytes == 0 &&
		s.gsoFallback == 0 &&
		s.groMsgs == 0 &&
		s.groSegments == 0 &&
		s.groWireBytes == 0 &&
		s.queueDrops == 0
}

func bytesToGbps(bytes uint64, elapsedSeconds float64) float64 {
	return (float64(bytes) * 8) / elapsedSeconds / 1e9
}

func perSecond(v uint64, elapsedSeconds float64) float64 {
	return float64(v) / elapsedSeconds
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func saturatedSub(a, b uint64) uint64 {
	if a <= b {
		return 0
	}
	return a - b
}

func udpDebugEnabled() bool {
	return false
}
