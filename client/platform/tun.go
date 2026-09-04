// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package platform defines the TUN contracts an embedding application
// implements so Talaria can move IP packets without depending on any particular
// operating system or VPN framework.
//
// This is the one seam every client integration must supply. Talaria owns the
// session, the wire protocol and the buffers; the application owns creating the
// interface, installing routes and DNS, and tearing them down. Implementations
// live in the application because the privileged work differs per platform: a
// utun socket on macOS, a VpnService file descriptor on Android, a
// NEPacketTunnelFlow on iOS, /dev/net/tun on Linux.
package platform

import (
	"context"
	"io"
)

// Tun carries plaintext IP packets between the host network stack and Talaria.
//
// It is packet-oriented, not stream-oriented, which is the part the
// io.ReadWriteCloser signature does not convey:
//
//   - Read must return exactly one complete IP packet per call, starting at the
//     IP header. A partial packet, several packets in one call, or any framing
//     of its own will be rejected as malformed. Returning (0, nil) is treated as
//     "nothing right now" and is not an error.
//   - WriteContext receives exactly one complete IP packet, starting at the IP
//     header. It must return when ctx is canceled. A short write is an error;
//     the implementation must not report success for a partially written packet.
//   - Buffers passed to Read and Write are owned by Talaria and reused after the
//     call returns. An implementation that needs to keep the bytes must copy
//     them.
//   - Close must interrupt a blocked Read. Talaria closes the Tun to stop its
//     copy loops, so an implementation whose Read cannot be interrupted will
//     leak a goroutine for the lifetime of the process.
//   - Read and WriteContext are each called from a single goroutine, but from
//     two different ones, so the two directions must be safe to use concurrently
//     with each other. Close may be called from a third.
//
// Talaria never writes a packet larger than the MTU it was given in TunConfig,
// and sizes its read buffers from the same value, so an implementation may size
// its own buffers from TunConfig.MTU.
type Tun interface {
	io.ReadWriteCloser
	WriteContext(ctx context.Context, p []byte) (n int, err error)
}

// NamedTun is a Tun that can report the interface name it created. Talaria uses
// the name only for diagnostics; implementing it is optional.
type NamedTun interface {
	Tun
	Name() string
}

// TunConfig describes the interface Talaria needs. It is derived from the
// client configuration and the negotiated protocol.
type TunConfig struct {
	// Protocol is the Talaria protocol identifier the session is using. It is
	// informational; the packet format on the TUN is plain IP either way.
	Protocol string

	// InterfaceName is a requested name. Platforms that assign names themselves
	// may ignore it; report the real name through NamedTun.
	InterfaceName string

	// SourceIP is the address to assign to the interface, and DestinationIP is
	// the tunnel peer address. Both are the tunnel-local virtual addresses, not
	// the physical server address.
	SourceIP      string
	DestinationIP string

	// MTU is the interface MTU. Talaria never writes a larger packet and sizes
	// its read buffers from this value.
	MTU int
}

// TunProvider creates the TUN for a session.
//
// Establish is called once per session, after the transport and application
// authentication have both succeeded and the server has confirmed the session is
// ready, so a provider that prompts the user or installs routes does that work
// only for a session that is actually usable. Returning an error fails the
// session. The returned Tun must be non-nil.
//
// Talaria closes the returned Tun when the session ends. A provider that also
// installed routes, DNS or firewall state should undo it from the Tun's Close.
type TunProvider interface {
	Establish(ctx context.Context, cfg TunConfig) (Tun, error)
}

// PacketOffsetReader is an optional Tun extension that lets Talaria read a
// packet into the middle of a buffer, leaving room for the protocol header it
// has to prepend. Implementing it avoids a copy per packet on the uplink.
//
// ReadPacketOffset writes exactly one IP packet at buf[payloadOffset:] and
// returns its length, following the same rules as Tun.Read otherwise.
type PacketOffsetReader interface {
	ReadPacketOffset(buf []byte, payloadOffset int) (payloadLen int, err error)
}

// PacketOffsetWriter is the downlink counterpart of PacketOffsetReader: it lets
// Talaria hand over a buffer whose IP packet starts partway in, so the protocol
// header does not have to be stripped by copying.
//
// WritePacketOffset writes the single IP packet held in
// buf[payloadOffset:payloadOffset+payloadLen], following the same rules as
// Tun.WriteContext otherwise.
type PacketOffsetWriter interface {
	WritePacketOffset(ctx context.Context, buf []byte, payloadOffset int, payloadLen int) (n int, err error)
}
