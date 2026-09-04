// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"net"

	"github.com/X-VPN/Talaria/internal/udpsession"
)

type batchConn = udpsession.BatchConn

func wrapBatchConn(conn net.Conn) batchConn {
	return udpsession.WrapBatchConn(conn)
}

type udptlsMode int

const (
	udptlsModeClient udptlsMode = iota + 1
	udptlsModeServer
)

type udpConfig struct {
	Listen       string
	ListenPacket func(network, address string) (net.PacketConn, error)
	PacketConn   net.PacketConn
	MaxPacket    int
	IOTimeout    int
	InboundQueue int
}
