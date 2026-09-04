// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package dataplane holds the buffer and framing machinery shared by the client
// data path: pooled packet buffers with headroom for protocol headers, MTU
// derivation per protocol, and the codec that turns VPN packets into wire bytes.
//
// Headroom exists so a packet read from the TUN can have its Talaria header
// prepended without copying, and so a packet received from the network can have
// the header stripped the same way. Buffer sizes are derived from the configured
// MTU rather than assumed.
package dataplane

import "sync"

const DefaultHeadroom = 128

type PacketBuffer struct {
	Raw   []byte
	Start int
	End   int
}

func NewPacketBuffer(size int, headroom int) *PacketBuffer {
	if headroom <= 0 {
		headroom = DefaultHeadroom
	}
	if size < headroom {
		size = headroom
	}
	return &PacketBuffer{
		Raw:   make([]byte, size),
		Start: headroom,
		End:   headroom,
	}
}

func (p *PacketBuffer) Bytes() []byte {
	if p == nil || p.Start < 0 || p.End < p.Start || p.End > len(p.Raw) {
		return nil
	}
	return p.Raw[p.Start:p.End]
}

func (p *PacketBuffer) Len() int {
	if p == nil || p.Start < 0 || p.End < p.Start || p.End > len(p.Raw) {
		return 0
	}
	return p.End - p.Start
}

func (p *PacketBuffer) ResetToHeadroom(headroom int) bool {
	return p.Reset(headroom, headroom)
}

func (p *PacketBuffer) ReserveHead(n int) []byte {
	if p == nil || n < 0 || p.Start < n || p.End > len(p.Raw) {
		return nil
	}
	p.Start -= n
	return p.Raw[p.Start : p.Start+n]
}

func (p *PacketBuffer) ConsumeHead(n int) bool {
	if p == nil || n < 0 || p.Start+n > p.End {
		return false
	}
	p.Start += n
	return true
}

func (p *PacketBuffer) Reset(start int, end int) bool {
	if p == nil || start < 0 || end < start || end > len(p.Raw) {
		return false
	}
	p.Start = start
	p.End = end
	return true
}

type Pool struct {
	size     int
	headroom int
	pool     sync.Pool
}

func NewPool(size int, headroom int) *Pool {
	if headroom <= 0 {
		headroom = DefaultHeadroom
	}
	if size < headroom {
		size = headroom
	}
	p := &Pool{size: size, headroom: headroom}
	p.pool.New = func() any {
		return NewPacketBuffer(size, headroom)
	}
	return p
}

func (p *Pool) Get() *PacketBuffer {
	if p == nil {
		return nil
	}
	pkt := p.pool.Get().(*PacketBuffer)
	if cap(pkt.Raw) < p.size {
		pkt.Raw = make([]byte, p.size)
	} else {
		pkt.Raw = pkt.Raw[:p.size]
	}
	pkt.ResetToHeadroom(p.headroom)
	return pkt
}

func (p *Pool) Put(pkt *PacketBuffer) {
	if p == nil || pkt == nil {
		return
	}
	if cap(pkt.Raw) < p.size {
		return
	}
	pkt.Raw = pkt.Raw[:p.size]
	pkt.ResetToHeadroom(p.headroom)
	p.pool.Put(pkt)
}
