// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package server implements the Talaria VPN server: listener orchestration for
// both protocols, application authentication, active-session tracking with
// generation-bound revocation, destination policy, resource limits, and packet
// or stream forwarding.
//
// The server has no built-in credentials or forwarding behaviour. Start requires
// an AuthProvider and a PacketHandler, and it will not run without them, so
// there is no configuration in which an unauthenticated client is served.
// Destination policy defaults to ReferenceTargetPolicy, which denies private
// address space unless the deployment opts in.
//
// Each authenticated session receives a monotonically increasing generation.
// Revocation is generation-exact, so a stale control connection or a late policy
// response cannot terminate or authorize a newer session for the same client.
package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/udptls"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
	"github.com/X-VPN/Talaria/transport/socks5tls"
)

const (
	DefaultAuthVersion = byte(1)
)

// TalariaTCPAdmissionLimits bounds TalariaTCP transport admission.
type TalariaTCPAdmissionLimits = socks5tls.AdmissionLimits

// TalariaUDPAdmissionLimits bounds TalariaUDP transport admission.
type TalariaUDPAdmissionLimits = udptls.AdmissionLimits

// ResourceLimits bounds authentication attempts, pre-authentication
// connections, authenticated sessions, streams, and outbound operations.
// Zero values select finite defaults.
type ResourceLimits struct {
	MaxSessions              int
	MaxStreams               int
	MaxStreamsPerClient      int
	MaxPendingDials          int
	MaxPendingDialsPerClient int
	DialTimeout              time.Duration
	// MaxPendingAuth bounds transport-ready connections that have not yet
	// completed Talaria application authentication.
	MaxPendingAuth                    int
	MaxPendingAuthPerSource           int
	MaxAuthAttemptsPerWindow          int
	MaxAuthAttemptsPerSourcePerWindow int
	AuthAttemptWindow                 time.Duration
	IPv6SourcePrefixBits              int
}

type Config struct {
	Protocol client.Protocol

	Host string
	Port int

	// CertPEM and KeyPEM are the server certificate chain and private key.
	CertPEM string
	KeyPEM  string

	GetCertificate           func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	CacheGetCertificate      bool
	CachePureGetCertificate  bool
	CertificateCacheScope    []byte
	AllowCertificateFallback bool
	// TalariaUDPWireSecret configures authentication and encryption for the outer
	// TalariaUDP framing. It must match clients and contain at least 32 bytes.
	TalariaUDPWireSecret string
	// TalariaUDPWireIdentity identifies the TalariaUDP endpoint on the wire.
	TalariaUDPWireIdentity string
	// TalariaTCPWireSecret configures authentication and randomization for the
	// complete TalariaTCP stream.
	// It must match clients and contain at least 32 bytes.
	TalariaTCPWireSecret string
	// TalariaTCPWireIdentity identifies the TalariaTCP endpoint and must match
	// clients.
	TalariaTCPWireIdentity string

	Auth           AuthProvider
	PacketHandler  PacketHandler
	ForwardHandler ForwardHandler
	TargetPolicy   TargetPolicy
	DialContext    DialContextFunc
	LookupNetIP    LookupNetIPFunc
	Transport      coretransport.Server
	PacketCodec    dataplane.Codec
	// TalariaTCPAdmissionLimits bounds TalariaTCP connections and pending TLS
	// handshakes.
	// It applies when Talaria creates the built-in TalariaTCP transport.
	TalariaTCPAdmissionLimits TalariaTCPAdmissionLimits
	// TalariaUDPAdmissionLimits bounds unauthenticated TalariaUDP sessions, TLS
	// handshakes, and retained receive buffers.
	TalariaUDPAdmissionLimits TalariaUDPAdmissionLimits
	ResourceLimits            ResourceLimits

	ReadBufferSize int
	AuthTimeout    time.Duration
	// SessionIdleTimeout closes a control or packet session that receives no
	// traffic or keepalive. Zero selects the two-minute default.
	SessionIdleTimeout time.Duration
	// SessionWriteTimeout bounds each normal TalariaTCP session write. Zero selects
	// a finite default.
	SessionWriteTimeout time.Duration
	// SessionTTL is an optional maximum session age. Zero disables fixed expiry.
	SessionTTL time.Duration
	ErrorLog   func(scope string, err error)
}

type Server struct {
	protocol client.Protocol
	codec    dataplane.Codec
	auth     AuthProvider
	handler  PacketHandler

	addr string

	cancel          context.CancelFunc
	logErr          func(scope string, err error)
	errorLogs       *errorLogLimiter
	errorLogMu      sync.Mutex
	errorLogQueue   chan serverErrorLog
	errorLogStop    chan struct{}
	errorLogStart   sync.Once
	errorLogWG      sync.WaitGroup
	errorLogStopped bool
	dial            DialContextFunc
	ttl             time.Duration
	writeTimeout    time.Duration
	forward         ForwardHandler
	policy          TargetPolicy
	resources       *resourceLimiter
	authSlots       chan struct{}
	outboundSlots   chan struct{}
	boundedOutbound bool
	lookupIP        LookupNetIPFunc
	interfaceAddrs  func() ([]net.Addr, error)

	sessionGeneration atomic.Uint64
	sessionLocks      clientSessionLocks
	packetAttachMu    sync.Mutex

	talariaUDPListener interface {
		Addr() net.Addr
		Close() error
	}
	streamServer          coretransport.Server
	closeState            atomic.Uint32
	closeErrMu            sync.Mutex
	closeErr              error
	closeDone             chan struct{}
	runWG                 sync.WaitGroup
	done                  chan struct{}
	sessionReclaimMu      sync.Mutex
	sessionReclaimQueue   chan sessionReclaimTask
	sessionReclaimSlots   chan struct{}
	sessionReclaimStop    chan struct{}
	sessionReclaimStart   sync.Once
	sessionReclaimWG      sync.WaitGroup
	sessionReclaimStopped bool

	activeSessionsOnce sync.Once
	activeSessions     *activeSessionRegistry
}

type AuthRequest struct {
	Protocol client.Protocol

	Packet            *vpnpacket.VpnPacket
	RequestedClientID uint64
	ClientID          string
	SecretKey         string
	Version           byte
	EntranceIP        []byte
	ExitIP            []byte

	RemoteAddr string
	RemoteIP   string
	LocalAddr  string
}

type AuthResult struct {
	ClientID uint64
	Version  byte
}

type AuthProvider interface {
	Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error)
}

type AuthProviderFunc func(ctx context.Context, req AuthRequest) (AuthResult, error)

func (fn AuthProviderFunc) Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error) {
	return fn(ctx, req)
}

type SessionContext struct {
	Protocol client.Protocol
	ClientID uint64
	// Generation identifies the exact authenticated connection for ClientID.
	// Packet handlers must not treat two generations as the same session.
	Generation uint64

	RemoteAddr string
	RemoteIP   string
	LocalAddr  string
}

func (s SessionContext) Ref() coretransport.SessionRef {
	return coretransport.SessionRef{ClientID: s.ClientID, Generation: s.Generation}
}

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type LookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

type TargetPolicyRequest struct {
	Session SessionContext
	Network coretransport.Network
	Host    string
	Port    uint16
	IP      netip.Addr
}

// TargetPolicy is evaluated against each resolved address before an outbound
// connection or raw-IP write is allowed.
type TargetPolicy interface {
	ValidateTarget(ctx context.Context, req TargetPolicyRequest) error
}

type TargetPolicyFunc func(ctx context.Context, req TargetPolicyRequest) error

func (fn TargetPolicyFunc) ValidateTarget(ctx context.Context, req TargetPolicyRequest) error {
	return fn(ctx, req)
}

type ForwardRequest struct {
	Session SessionContext
	Target  coretransport.Destination
	Source  net.Addr
	Local   net.Addr
}

type ForwardDecision struct {
	Block  bool
	Target coretransport.Destination
}

type ForwardHandler interface {
	Forward(ctx context.Context, req ForwardRequest) (ForwardDecision, error)
}

type ForwardHandlerFunc func(ctx context.Context, req ForwardRequest) (ForwardDecision, error)

func (fn ForwardHandlerFunc) Forward(ctx context.Context, req ForwardRequest) (ForwardDecision, error) {
	return fn(ctx, req)
}

// ControlSessionActivator prepares a session and returns its commit, finalize,
// and revoke operations. Finalize completes before SessionReady is written.
type ControlSessionActivator interface {
	ActivateControlSession(ctx context.Context, conn net.Conn, session SessionContext, write PacketWriter, onRevoke func()) (commit func() error, finalize func() error, revoke func(), err error)
}

// SessionController is the host seam for subscription, quota, and
// administrative disconnect decisions.
type SessionController interface {
	CurrentSession(clientID uint64) (coretransport.SessionRef, bool)
	RevokeClient(clientID uint64, reason string) bool
	RevokeSession(ref coretransport.SessionRef, reason string) bool
}

// PacketHandler processes one authenticated client packet. packet and all of
// its slices are borrowed only for the duration of HandlePacket; implementations
// must copy data they retain. Ownership of returned response packets transfers
// to the server, so implementations must not mutate them after returning.
// The server validates commands, normalizes client identity, and applies fixed
// response-count and encoded-byte limits at this boundary.
type PacketHandler interface {
	HandlePacket(ctx context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error)
}

// RawFrameHandler is an optional fast path for authenticated wire frames. raw
// is read-only and borrowed only until HandleRawFrame returns; copy it to retain
// it. The server validates the client-direction command and normalizes its
// client ID before this method is called. Returned responses follow the same
// ownership and quota rules as PacketHandler responses.
type RawFrameHandler interface {
	HandleRawFrame(ctx context.Context, session SessionContext, raw []byte) (handled bool, responses []*vpnpacket.VpnPacket, err error)
}

type PacketHandlerFunc func(ctx context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error)

func (fn PacketHandlerFunc) HandlePacket(ctx context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return fn(ctx, session, packet)
}

type PacketWriter func(packet *vpnpacket.VpnPacket) error

type RawPacketWriter func(raw []byte) error

type RawPacketBatchWriter func(bufs [][]byte, sizes []int) (int, error)

type SessionWriters struct {
	// Packet, Raw, and RawBatch synchronously consume their arguments and do not
	// retain them after returning. Callers may reuse their buffers afterwards.
	Packet   PacketWriter
	Raw      RawPacketWriter
	RawBatch RawPacketBatchWriter
	// Close must interrupt any in-progress writer call and may be called
	// asynchronously when the session is detached.
	Close func()
}

type SessionPacketHandler interface {
	PacketHandler
	AttachSession(ctx context.Context, session SessionContext, writer PacketWriter) (detach func(), err error)
}

type SessionWritersHandler interface {
	PacketHandler
	AttachSessionWriters(ctx context.Context, session SessionContext, writers SessionWriters) (detach func(), err error)
}
