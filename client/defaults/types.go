// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package defaults

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/lifecycle"
	coretransport "github.com/X-VPN/Talaria/transport"
)

const DefaultAuthVersion = byte(1)

type ClientOptions struct {
	ParentDial func(network, address string) (net.Conn, error)
	Closer     lifecycle.Closer
	Domain     string
	// TLSConfig is cloned. Talaria preserves verification callbacks and trust
	// settings while enforcing TLS 1.3 and transport-specific carrier policy.
	TLSConfig *tls.Config
	// TalariaUDPWireSecret configures the deployment-wide secret that hides and
	// authenticates TalariaUDP framing. It must contain at least 32 bytes.
	TalariaUDPWireSecret string
	// TalariaUDPWireIdentity identifies the TalariaUDP endpoint on the wire.
	TalariaUDPWireIdentity string
	// TalariaTCPWireSecret configures authentication and randomization for the
	// complete TalariaTCP stream.
	// It must match the server and contain at least 32 bytes.
	TalariaTCPWireSecret string
	// TalariaTCPWireIdentity identifies the TalariaTCP endpoint and must match the
	// server.
	TalariaTCPWireIdentity string
	Events                 client.EventSink
	Stats                  client.StatsSink
	// EstablishmentTimeout bounds TCP, TLS, role, and SOCKS setup.
	// Zero selects the transport default.
	EstablishmentTimeout time.Duration

	// Transport is an optional per-session TalariaTCP transport. The session
	// owns it.
	Transport coretransport.Client
}
