// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package client implements the Talaria VPN client session: the state machine
// that dials a transport, authenticates, establishes the TUN, and copies packets
// in both directions until the session ends.
//
// A Session is single-use and deliberately does not reconnect itself. Reconnect
// scheduling, network-change handling and retry policy belong to the embedding
// application, which creates a new Session when it decides to. Err reports why a
// session ended so that decision can be made; see the Err sentinels in this
// package.
//
// The application supplies the platform pieces through Deps: a TunProvider from
// client/platform, and either an EndpointProvider or a DialerProvider. The
// built-in transports live in client/defaults.
package client

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

type Protocol string

const (
	ProtocolTalariaUDP Protocol = "TalariaUDP"
	ProtocolTalariaTCP Protocol = "TalariaTCP"
)

// ParseProtocol returns the exact supported protocol, with an empty value selecting TalariaUDP.
func ParseProtocol(value string) (Protocol, error) {
	protocol := Protocol(value)
	if protocol == "" {
		return ProtocolTalariaUDP, nil
	}
	switch protocol {
	case ProtocolTalariaUDP, ProtocolTalariaTCP:
		return protocol, nil
	default:
		return "", errors.New("unsupported Talaria protocol")
	}
}

// Config describes a single client VPN session. Protocol, ClientID and
// SecretKey are always required. ServerIP, ServerPort and Domain are required
// unless the embedding application supplies its own EndpointProvider or
// DialerProvider that already knows how to reach the server.
type Config struct {
	// Protocol selects the tunnel protocol. It must be ProtocolTalariaUDP or
	// ProtocolTalariaTCP.
	Protocol Protocol

	// ClientID and SecretKey are the credentials presented to the server.
	// Each is limited to 255 bytes by the wire format.
	ClientID  string
	SecretKey string

	// EntranceIP and ExitIP are the tunnel-local addresses reported to the
	// server; they describe the virtual endpoints, not the physical ones.
	EntranceIP string
	ExitIP     string

	// ServerIP, ServerPort and Domain locate the server and name it for
	// certificate verification. Domain is used as the TLS server name and is
	// required by every protocol, because certificate verification cannot be
	// disabled.
	ServerIP   string
	Domain     string
	ServerPort uint16

	// MTU is the TUN MTU. Zero derives a protocol-appropriate default and the
	// maximum accepted value is 9000.
	MTU int
	// UplinkQueueSize bounds TalariaUDP packets waiting to be written to the
	// transport. Zero selects the default.
	UplinkQueueSize int
	// DownlinkQueueSize bounds packets waiting to be written to the TUN. Zero
	// selects the default.
	DownlinkQueueSize int

	// KeepAliveDuration is the tunnel keepalive interval. Zero selects the
	// default; values below the default are raised to it.
	KeepAliveDuration time.Duration

	// AuthTimeout bounds the authentication exchange. Zero selects the default.
	AuthTimeout time.Duration

	// RSTWhenReconnecting asks the endpoint to reset a previous connection
	// instead of closing it gracefully when reconnecting.
	RSTWhenReconnecting bool
}

// Errors a caller is expected to branch on. Match them with errors.Is rather
// than comparing strings: the wrapped error usually carries detail that is
// useful in a log but not stable enough to depend on.
//
// The distinction that matters operationally is whether retrying can help.
// ErrInvalidConfig and ErrUnsupportedProtocol never resolve on their own, and
// ErrAuthRejected will not resolve until the credentials or the account state
// change, so retrying those with the same inputs only produces load. The
// remaining failures are transport-level and a new session may succeed.
var (
	// ErrInvalidConfig reports a Config or Deps value that cannot be used.
	// It is returned by NewSession, before any I/O.
	ErrInvalidConfig = errors.New("talaria client: invalid configuration")

	// ErrUnsupportedProtocol reports a protocol that is unknown or not
	// available on the current platform.
	ErrUnsupportedProtocol = errors.New("talaria client: unsupported protocol")

	// ErrAlreadyStarted reports a second call to Start on the same session.
	// A Session is single-use; construct a new one to reconnect.
	ErrAlreadyStarted = errors.New("talaria client: session already started")

	// ErrAuthRejected reports that the server refused the credentials or the
	// session grant. Retrying with the same credentials will not help.
	ErrAuthRejected = errors.New("talaria client: authentication rejected")

	// ErrServerRejected reports an error the server reported after the session
	// was established. The wrapped message is server-supplied text.
	ErrServerRejected = errors.New("talaria client: server reported an error")

	// ErrKeepAliveTimeout reports that no traffic arrived within the keepalive
	// window. This is a liveness failure, so a new session may succeed.
	ErrKeepAliveTimeout = errors.New("talaria client: keepalive timeout")

	// ErrProtocolViolation reports a malformed or unexpected message from the
	// server, such as an out-of-sequence session response.
	ErrProtocolViolation = errors.New("talaria client: protocol violation")
)

type State string

const (
	StateIdle      State = "idle"
	StateDialing   State = "dialing"
	StateConnected State = "connected"
	StateClosed    State = "closed"
	StateFailed    State = "failed"
)

// Session is a single VPN session. It is single-use: once it reaches
// StateClosed or StateFailed it cannot be restarted, and the caller creates a
// new Session to reconnect according to its own retry policy.
type Session interface {
	// Start establishes the tunnel and returns once it is connected, or with an
	// error if it could not be. Cancelling ctx closes the session.
	Start(ctx context.Context) error

	// Close tears the session down and is safe to call more than once, and
	// before Start. It does not block on the I/O goroutines; wait on Done for
	// that. The returned error reports failures encountered while closing the
	// transport, not the reason the session ended - use Err for that.
	Close() error

	// Done is closed once the session has fully stopped and its goroutines have
	// returned.
	Done() <-chan struct{}

	// State reports the current lifecycle state.
	State() State

	// Err reports why the session terminated, or nil if it is still running or
	// was closed deliberately by the caller. It is set before Done is closed,
	// so it is safe to read after Done fires. Match it against the Err
	// sentinels in this package to decide whether reconnecting is worthwhile.
	Err() error

	// LocalAddr reports the local address of the underlying transport, or an
	// empty string before one exists.
	LocalAddr() string
}

type DialRequest struct {
	Protocol   Protocol
	ServerIP   string
	Domain     string
	ServerPort uint16
}

type DialerProvider interface {
	Dial(ctx context.Context, req DialRequest) (net.Conn, error)
}

type EndpointDialRequest struct {
	Protocol Protocol

	ClientID  string
	SecretKey string

	EntranceIP string
	ExitIP     string
	ServerIP   string
	Domain     string
	ServerPort uint16

	MTU                 int
	KeepAliveDuration   time.Duration
	AuthTimeout         time.Duration
	RSTWhenReconnecting bool
}

type EndpointConn interface {
	ReadPacket() (*vpnpacket.VpnPacket, error)
	WriteData(payload []byte) error
	WritePacket(packet *vpnpacket.VpnPacket) error
	Close() error
	ClientID() uint64
	LocalAddr() string
}

type BufferedEndpointConn interface {
	EndpointConn
	ReadPacketBuffer(pkt *dataplane.PacketBuffer) (packet *vpnpacket.VpnPacket, dataReady bool, err error)
	WriteDataBuffer(pkt *dataplane.PacketBuffer) error
}

type BorrowedPayloadEndpointConn interface {
	EndpointConn
	ReadPayloadBorrowed() (payload []byte, release func(), err error)
}

type EndpointProvider interface {
	DialEndpoint(ctx context.Context, req EndpointDialRequest) (EndpointConn, error)
}

type TunConfig = platform.TunConfig
type TunProvider = platform.TunProvider

type EventSink interface {
	OnStateChange(ctx context.Context, state State)
	OnConnectStage(ctx context.Context, stage string, fields map[string]string)
	OnError(ctx context.Context, err error)
}

type StatsSink interface {
	OnUploadBytes(ctx context.Context, n int)
	OnDownloadBytes(ctx context.Context, n int)
	OnTunRead(ctx context.Context, n int)
	OnTunWrite(ctx context.Context, n int)
}

type Deps struct {
	Dialer      DialerProvider
	Endpoint    EndpointProvider
	Tun         TunProvider
	PacketCodec dataplane.Codec
	Events      EventSink
	Stats       StatsSink
}
