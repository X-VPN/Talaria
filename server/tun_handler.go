// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/ippacket"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

const (
	defaultServerTunReadBufferExtra     = 512
	defaultServerTunReadPrefetchPackets = 512
	minServerTunReadPrefetchBatches     = 2
	maxServerTunReadPrefetchBatches     = 64
	maxServerTunReadBufferSize          = 65535
	defaultServerTunVirtualIPBase       = "172.21.100.2"
	defaultServerTunWriteQueueSize      = 16384
	defaultSessionTunWritePackets       = 4096
	defaultSessionDownlinkPackets       = 8192
	defaultGlobalDownlinkPackets        = 16384
	maxServerTunWriteQueueBytes         = 256 << 20
	maxSessionTunWriteBytes             = 64 << 20
	maxSessionDownlinkBytes             = 64 << 20
	maxGlobalDownlinkPackets            = 1 << 20
	maxGlobalDownlinkBytes              = 256 << 20
	maxServerTunWriteHeadroom           = 4096
	serverTunIdleReadBackoff            = 100 * time.Microsecond
)

// ErrTunWriteQueueFull reports that one TUN write request cannot fit within
// the configured global or per-session write budget.
var ErrTunWriteQueueFull = errors.New("Talaria server tun: write queue full")

// ErrTunDownlinkQueueFull reports that a downlink batch cannot fit within the
// configured global or per-session retained-memory budget.
var ErrTunDownlinkQueueFull = errors.New("Talaria server tun: downlink queue full")

type TunDevice interface {
	// ReadPackets and WritePackets return packet counts, not byte counts.
	// BatchSize is the maximum number of packets accepted by either method.
	// MTU, BatchSize, and WriteHeadroom must remain stable for the lifetime of
	// the device. Implementations must observe ctx cancellation, and Close
	// must interrupt any blocked operation.
	ReadPackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error)
	WritePackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error)
	// ReleaseVirtualIP removes queued packets and network state left by a
	// detached session before the address can be reused.
	ReleaseVirtualIP(ctx context.Context, vip netip.Addr) error
	BatchSize() int
	MTU() int
	WriteHeadroom() int
	Close() error
}

type TunPacketHandlerConfig struct {
	Device        TunDevice
	Cleanup       func() error
	VirtualIPBase netip.Addr
	// VirtualIPPrefix bounds per-session virtual IP allocation. It must be the
	// same prefix that is routed to the TUN and used as the egress NAT source
	// range, because an address outside it is neither routed back nor
	// translated. When unset it defaults to the /24 containing VirtualIPBase,
	// which matches the reference deployment.
	VirtualIPPrefix     netip.Prefix
	VirtualIPReuseDelay time.Duration

	ReadBufferSize int
	// WriteQueueSize limits all queued and in-flight TUN packets.
	WriteQueueSize int
	// WriteQueueBytes limits retained bytes for all queued and in-flight TUN
	// writes, including device headroom. Zero derives it from WriteQueueSize,
	// the TUN MTU, and device headroom.
	WriteQueueBytes int
	// SessionWritePackets and SessionWriteBytes prevent one session from
	// consuming the complete global TUN write budget. SessionWriteBytes also
	// includes device headroom; zero derives it from SessionWritePackets.
	SessionWritePackets int
	SessionWriteBytes   int

	// DownlinkPackets and DownlinkBytes bound one session's queued and in-flight
	// downlink payload. The global limits bound their aggregate across sessions.
	// Zero byte limits derive from the corresponding packet limits and TUN MTU.
	DownlinkPackets       int
	DownlinkBytes         int
	GlobalDownlinkPackets int
	GlobalDownlinkBytes   int
	DropNonIPv4Data       bool
	// AllowClientToClient permits destinations inside VirtualIPPrefix to reach
	// TargetPolicy. It is false by default so clients remain isolated even when
	// the policy allows private targets.
	AllowClientToClient bool
	TargetPolicy        TargetPolicy
}

type TunPacketHandler struct {
	device                TunDevice
	cleanup               func() error
	virtualIPBase         netip.Addr
	readBufferSize        int
	dropNonIPv4           bool
	allowPeers            bool
	policy                TargetPolicy
	writeHeadroom         int
	writePacketsMax       int
	writeBytesMax         int
	sessionPackets        int
	sessionBytes          int
	downlinkPackets       int
	downlinkBytes         int
	globalDownlinkPackets int
	globalDownlinkBytes   int

	ctx    context.Context
	cancel context.CancelFunc

	readOnce sync.Once

	writeQueue          chan *serverTunWriteReq
	writeDone           chan struct{}
	writeStateMu        sync.Mutex
	writeClosing        bool
	writeEnqueueWG      sync.WaitGroup
	writeCloseOnce      sync.Once
	writeReqPool        sync.Pool
	tunIOErr            atomic.Pointer[tunIOError]
	writeActive         atomic.Bool
	workerMu            sync.Mutex
	workerWG            sync.WaitGroup
	workersDone         bool
	writeBudgetMu       sync.Mutex
	writeBudgetWake     chan struct{}
	writePackets        int
	writeBytes          int
	downlinkBudgetMu    sync.Mutex
	downlinkPacketsUsed int
	downlinkBytesUsed   int
	closeState          atomic.Uint32
	deviceClosed        atomic.Bool
	closeErrMu          sync.Mutex
	closeErr            error
	cleanupMu           sync.Mutex
	cleanupRunning      bool
	cleanupDone         bool
	cleanupStart        sync.Once

	mu          sync.RWMutex
	readStopped bool
	nextVIP     uint32
	vipEpoch    atomic.Uint64
	sessions    map[coretransport.SessionRef]*tunHandlerSession
	byVIP       map[netip.Addr]*tunHandlerSession
	vipBindings map[netip.Addr]uint64
	vipByClient map[uint64]netip.Addr
	vipCleanups map[netip.Addr]uint32
	releasedVIP map[netip.Addr]releasedTunVIP
	// virtualIPMax is the largest offset from virtualIPBase that still lands on
	// an assignable host inside virtualIPPrefix.
	virtualIPPrefix netip.Prefix
	virtualIPMax    uint32
}

type releasedTunVIP struct {
	clientID  uint64
	reusable  bool
	releasing bool
}

type tunHandlerSession struct {
	handler        *TunPacketHandler
	id             uint64
	ref            coretransport.SessionRef
	vip            netip.Addr
	vipEpoch       uint64
	writer         PacketWriter
	rawWriter      RawPacketWriter
	rawBatchWriter RawPacketBatchWriter
	closeWriter    func()
	dataSeq        uint32

	mu       sync.RWMutex
	clientIP netip.Addr

	tunWriteMu         sync.RWMutex
	tunWriteActive     bool
	tunWritePackets    int
	tunWriteBytes      int
	tunWriteCtx        context.Context
	tunWriteCancel     context.CancelFunc
	tunWriteCancelOnce sync.Once
	tunWriteWake       chan struct{}

	sendQueue   chan *sessionDownlinkBatch
	sendDone    chan struct{}
	sendOnce    sync.Once
	closed      atomic.Bool
	sendMu      sync.Mutex
	sendStopped bool
	sendPackets int
	sendBytes   int
}

type sessionDownlinkBatch struct {
	bufs       [][]byte
	sizes      []int
	vpnPackets []*vpnpacket.VpnPacket
	packets    int
	bytes      int
}

type serverTunWriteReq struct {
	owner  *tunHandlerSession
	bufs   [][]byte
	sizes  []int
	offset int

	budgeted bool
	packets  int
	bytes    int
}

type serverTunReadBatch struct {
	bufs     [][]byte
	sizes    []int
	owners   []*tunHandlerSession
	n        int
	headroom int
}

type tunIOError struct {
	err error
}

func deriveTunQueueBytes(label string, packets int, packetBytes int, maximum int) (int, error) {
	required := int64(packets) * int64(packetBytes)
	if required > int64(maximum) {
		return 0, fmt.Errorf(
			"Talaria server tun: %s requires %d bytes, exceeding maximum %d",
			label,
			required,
			maximum,
		)
	}
	return int(required), nil
}

func NewTunPacketHandler(cfg TunPacketHandlerConfig) (handler *TunPacketHandler, err error) {
	defer extension.Recover("Talaria server tun configuration extension", &err)
	if extension.IsNil(cfg.Device) {
		return nil, errors.New("Talaria server tun: missing device")
	}
	if !cfg.VirtualIPBase.IsValid() {
		cfg.VirtualIPBase = netip.MustParseAddr(defaultServerTunVirtualIPBase)
	}
	if !cfg.VirtualIPBase.Is4() {
		return nil, fmt.Errorf("Talaria server tun: virtual ip base must be IPv4: %s", cfg.VirtualIPBase)
	}
	if !cfg.VirtualIPPrefix.IsValid() {
		cfg.VirtualIPPrefix = netip.PrefixFrom(cfg.VirtualIPBase, 24).Masked()
	}
	if !cfg.VirtualIPPrefix.Addr().Is4() {
		return nil, fmt.Errorf("Talaria server tun: virtual ip prefix must be IPv4: %s", cfg.VirtualIPPrefix)
	}
	if !cfg.VirtualIPPrefix.Contains(cfg.VirtualIPBase) {
		return nil, fmt.Errorf(
			"Talaria server tun: virtual ip base %s is outside prefix %s",
			cfg.VirtualIPBase,
			cfg.VirtualIPPrefix,
		)
	}
	if cfg.VirtualIPReuseDelay != 0 {
		return nil, errors.New("Talaria server tun: virtual IP reuse delay is not supported")
	}
	virtualIPMax := virtualIPMaxOffset(cfg.VirtualIPBase, cfg.VirtualIPPrefix)
	if virtualIPMax == 0 {
		return nil, fmt.Errorf(
			"Talaria server tun: prefix %s leaves no assignable virtual IP above base %s",
			cfg.VirtualIPPrefix,
			cfg.VirtualIPBase,
		)
	}
	deviceMTU := cfg.Device.MTU()
	if deviceMTU <= 0 || deviceMTU > maxServerTunReadBufferSize {
		return nil, fmt.Errorf("Talaria server tun: invalid device MTU %d", deviceMTU)
	}
	writeHeadroom := cfg.Device.WriteHeadroom()
	if writeHeadroom < 0 || writeHeadroom > maxServerTunWriteHeadroom {
		return nil, fmt.Errorf(
			"Talaria server tun: device write headroom %d is outside range 0-%d",
			writeHeadroom,
			maxServerTunWriteHeadroom,
		)
	}
	writePacketBytes := deviceMTU + writeHeadroom
	if cfg.ReadBufferSize < 0 {
		return nil, errors.New("Talaria server tun: read buffer size cannot be negative")
	}
	if cfg.ReadBufferSize == 0 {
		cfg.ReadBufferSize = min(deviceMTU+defaultServerTunReadBufferExtra, maxServerTunReadBufferSize)
	}
	if cfg.ReadBufferSize > maxServerTunReadBufferSize {
		return nil, fmt.Errorf("Talaria server tun: read buffer size %d exceeds maximum %d", cfg.ReadBufferSize, maxServerTunReadBufferSize)
	}
	if cfg.ReadBufferSize < deviceMTU {
		return nil, fmt.Errorf("Talaria server tun: read buffer size %d is smaller than device MTU %d", cfg.ReadBufferSize, deviceMTU)
	}
	if cfg.WriteQueueSize < 0 {
		return nil, errors.New("Talaria server tun: write queue packet limit cannot be negative")
	}
	if cfg.WriteQueueSize == 0 {
		cfg.WriteQueueSize = defaultServerTunWriteQueueSize
	}
	if cfg.WriteQueueSize > 1<<16 {
		return nil, fmt.Errorf("Talaria server tun: write queue size %d exceeds maximum %d", cfg.WriteQueueSize, 1<<16)
	}
	if cfg.WriteQueueBytes < 0 {
		return nil, errors.New("Talaria server tun: write queue byte limit cannot be negative")
	}
	if cfg.WriteQueueBytes == 0 {
		cfg.WriteQueueBytes, err = deriveTunQueueBytes("write queue", cfg.WriteQueueSize, writePacketBytes, maxServerTunWriteQueueBytes)
		if err != nil {
			return nil, err
		}
	}
	if cfg.WriteQueueBytes > maxServerTunWriteQueueBytes {
		return nil, fmt.Errorf("Talaria server tun: write queue byte limit %d exceeds maximum %d", cfg.WriteQueueBytes, maxServerTunWriteQueueBytes)
	}
	if cfg.SessionWritePackets < 0 {
		return nil, errors.New("Talaria server tun: session write packet limit cannot be negative")
	}
	if cfg.SessionWritePackets == 0 {
		cfg.SessionWritePackets = min(defaultSessionTunWritePackets, cfg.WriteQueueSize)
	}
	if cfg.SessionWritePackets > cfg.WriteQueueSize {
		return nil, fmt.Errorf("Talaria server tun: session write packet limit %d exceeds global limit %d", cfg.SessionWritePackets, cfg.WriteQueueSize)
	}
	if cfg.SessionWriteBytes < 0 {
		return nil, errors.New("Talaria server tun: session write byte limit cannot be negative")
	}
	if cfg.SessionWriteBytes == 0 {
		cfg.SessionWriteBytes, err = deriveTunQueueBytes("session write queue", cfg.SessionWritePackets, writePacketBytes, maxSessionTunWriteBytes)
		if err != nil {
			return nil, err
		}
	}
	if cfg.SessionWriteBytes > maxSessionTunWriteBytes {
		return nil, fmt.Errorf("Talaria server tun: session write byte limit %d exceeds maximum %d", cfg.SessionWriteBytes, maxSessionTunWriteBytes)
	}
	if cfg.SessionWriteBytes > cfg.WriteQueueBytes {
		return nil, fmt.Errorf("Talaria server tun: session write byte limit %d exceeds global limit %d", cfg.SessionWriteBytes, cfg.WriteQueueBytes)
	}
	if cfg.DownlinkPackets < 0 {
		return nil, errors.New("Talaria server tun: downlink packet limit cannot be negative")
	}
	if cfg.DownlinkPackets == 0 {
		cfg.DownlinkPackets = defaultSessionDownlinkPackets
	}
	if cfg.DownlinkPackets > 1<<16 {
		return nil, fmt.Errorf("Talaria server tun: downlink packet limit %d exceeds maximum %d", cfg.DownlinkPackets, 1<<16)
	}
	if cfg.DownlinkBytes < 0 {
		return nil, errors.New("Talaria server tun: downlink byte limit cannot be negative")
	}
	if cfg.DownlinkBytes == 0 {
		cfg.DownlinkBytes, err = deriveTunQueueBytes("session downlink queue", cfg.DownlinkPackets, deviceMTU, maxSessionDownlinkBytes)
		if err != nil {
			return nil, err
		}
	}
	if cfg.DownlinkBytes > maxSessionDownlinkBytes {
		return nil, fmt.Errorf("Talaria server tun: downlink byte limit %d exceeds maximum %d", cfg.DownlinkBytes, maxSessionDownlinkBytes)
	}
	if cfg.GlobalDownlinkPackets < 0 {
		return nil, errors.New("Talaria server tun: global downlink packet limit cannot be negative")
	}
	if cfg.GlobalDownlinkPackets == 0 {
		cfg.GlobalDownlinkPackets = max(defaultGlobalDownlinkPackets, cfg.DownlinkPackets)
	}
	if cfg.GlobalDownlinkPackets > maxGlobalDownlinkPackets {
		return nil, fmt.Errorf("Talaria server tun: global downlink packet limit %d exceeds maximum %d", cfg.GlobalDownlinkPackets, maxGlobalDownlinkPackets)
	}
	if cfg.DownlinkPackets > cfg.GlobalDownlinkPackets {
		return nil, fmt.Errorf("Talaria server tun: session downlink packet limit %d exceeds global limit %d", cfg.DownlinkPackets, cfg.GlobalDownlinkPackets)
	}
	if cfg.GlobalDownlinkBytes < 0 {
		return nil, errors.New("Talaria server tun: global downlink byte limit cannot be negative")
	}
	if cfg.GlobalDownlinkBytes == 0 {
		cfg.GlobalDownlinkBytes, err = deriveTunQueueBytes("global downlink queue", cfg.GlobalDownlinkPackets, deviceMTU, maxGlobalDownlinkBytes)
		if err != nil {
			return nil, err
		}
	}
	if cfg.GlobalDownlinkBytes > maxGlobalDownlinkBytes {
		return nil, fmt.Errorf("Talaria server tun: global downlink byte limit %d exceeds maximum %d", cfg.GlobalDownlinkBytes, maxGlobalDownlinkBytes)
	}
	if cfg.DownlinkBytes > cfg.GlobalDownlinkBytes {
		return nil, fmt.Errorf("Talaria server tun: session downlink byte limit %d exceeds global limit %d", cfg.DownlinkBytes, cfg.GlobalDownlinkBytes)
	}
	batchSize := cfg.Device.BatchSize()
	if batchSize <= 0 {
		return nil, fmt.Errorf("Talaria server tun: device batch size %d must be positive", batchSize)
	}
	if batchSize > 256 {
		return nil, fmt.Errorf("Talaria server tun: device batch size %d exceeds maximum 256", batchSize)
	}
	if extension.IsNil(cfg.TargetPolicy) {
		cfg.TargetPolicy = ReferenceTargetPolicy()
	}
	if !isReferenceTargetPolicy(cfg.TargetPolicy) {
		return nil, errors.New("Talaria server tun: TargetPolicy must use NewReferenceTargetPolicy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &TunPacketHandler{
		device:                cfg.Device,
		cleanup:               cfg.Cleanup,
		virtualIPBase:         cfg.VirtualIPBase,
		virtualIPPrefix:       cfg.VirtualIPPrefix,
		virtualIPMax:          virtualIPMax,
		readBufferSize:        cfg.ReadBufferSize,
		dropNonIPv4:           cfg.DropNonIPv4Data,
		allowPeers:            cfg.AllowClientToClient,
		policy:                cfg.TargetPolicy,
		writeHeadroom:         writeHeadroom,
		writePacketsMax:       cfg.WriteQueueSize,
		writeBytesMax:         cfg.WriteQueueBytes,
		sessionPackets:        cfg.SessionWritePackets,
		sessionBytes:          cfg.SessionWriteBytes,
		downlinkPackets:       cfg.DownlinkPackets,
		downlinkBytes:         cfg.DownlinkBytes,
		globalDownlinkPackets: cfg.GlobalDownlinkPackets,
		globalDownlinkBytes:   cfg.GlobalDownlinkBytes,
		ctx:                   ctx,
		cancel:                cancel,
		writeQueue:            make(chan *serverTunWriteReq, cfg.WriteQueueSize),
		writeDone:             make(chan struct{}),
		writeBudgetWake:       make(chan struct{}, 1),
		sessions:              make(map[coretransport.SessionRef]*tunHandlerSession),
		byVIP:                 make(map[netip.Addr]*tunHandlerSession),
		vipBindings:           make(map[netip.Addr]uint64),
		vipByClient:           make(map[uint64]netip.Addr),
		vipCleanups:           make(map[netip.Addr]uint32),
		releasedVIP:           make(map[netip.Addr]releasedTunVIP),
	}
	h.startWorker(h.writeLoop)
	return h, nil
}

func (h *TunPacketHandler) sealBoundedPolicy() error {
	if h == nil {
		return net.ErrClosed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) != 0 {
		return errors.New("Talaria server tun: cannot start with attached sessions")
	}
	if !isReferenceTargetPolicy(h.policy) {
		return errors.New("Talaria server tun: TargetPolicy must use NewReferenceTargetPolicy")
	}
	return nil
}

func (h *TunPacketHandler) AttachSession(ctx context.Context, session SessionContext, writer PacketWriter) (func(), error) {
	return nil, errors.New("Talaria server tun: PacketWriter requires an interruptible Close hook; use AttachSessionWriters")
}

func (h *TunPacketHandler) AttachSessionWriters(_ context.Context, session SessionContext, writers SessionWriters) (func(), error) {
	if h == nil {
		return nil, net.ErrClosed
	}
	if writers.Packet == nil && writers.Raw == nil && writers.RawBatch == nil {
		return nil, errors.New("Talaria server tun: missing session writer")
	}
	if writers.Close == nil {
		return nil, errors.New("Talaria server tun: session writer requires an interruptible Close hook")
	}
	if session.ClientID == 0 {
		return nil, errors.New("Talaria server tun: missing client id")
	}
	h.readOnce.Do(func() {
		if !h.startWorker(h.readLoop) {
			h.mu.Lock()
			h.readStopped = true
			h.mu.Unlock()
		}
	})

	h.mu.Lock()
	if h.readStopped || h.ctx.Err() != nil {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	for ref := range h.sessions {
		if ref.ClientID == session.ClientID && session.Generation <= ref.Generation {
			h.mu.Unlock()
			return nil, errors.New("Talaria server tun: session generation is not newer")
		}
	}
	// Allocate before mutating any session state so an exhausted pool leaves the
	// existing session untouched.
	vip, err := h.allocateVIPLocked(session.ClientID)
	if err != nil {
		h.mu.Unlock()
		return nil, err
	}
	tunWriteCtx, tunWriteCancel := context.WithCancel(h.ctx)
	ts := &tunHandlerSession{
		handler:        h,
		id:             session.ClientID,
		ref:            session.Ref(),
		vip:            vip,
		writer:         writers.Packet,
		rawWriter:      writers.Raw,
		rawBatchWriter: writers.RawBatch,
		closeWriter:    writers.Close,
		tunWriteActive: true,
		tunWriteCtx:    tunWriteCtx,
		tunWriteCancel: tunWriteCancel,
		tunWriteWake:   make(chan struct{}, 1),
		sendQueue:      make(chan *sessionDownlinkBatch, h.downlinkPackets),
		sendDone:       make(chan struct{}),
	}
	h.sessions[session.Ref()] = ts
	if h.byVIP[ts.vip] == nil {
		ts.vipEpoch = h.vipEpoch.Add(1)
		h.byVIP[ts.vip] = ts
	}
	h.mu.Unlock()
	if !h.startWorker(func() { h.runSessionSender(ts) }) {
		finish, _ := h.detachSessionForReclaim(session.Ref(), ts)
		if finish != nil {
			finish()
		}
		return nil, net.ErrClosed
	}

	return func() {
		h.detachSession(session.Ref(), ts)
	}, nil
}

func (h *TunPacketHandler) HandlePacket(ctx context.Context, session SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	if h == nil {
		return nil, net.ErrClosed
	}
	if packet == nil {
		return nil, errors.New("nil packet")
	}
	switch packet.Cmd {
	case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
		return nil, h.handleDataPayload(ctx, session, packet.Data)
	case vpnpacket.CmdKeepAlive:
		if !packet.IsPing {
			return nil, nil
		}
		return []*vpnpacket.VpnPacket{{
			Cmd:         packet.Cmd,
			ClientId:    session.ClientID,
			KeepAliveId: packet.KeepAliveId,
			SendTime:    packet.SendTime,
		}}, nil
	case vpnpacket.CmdServerKeepAlive:
		// V2 is initiated by the server. This packet is the client's reply, so
		// consuming it without another response terminates the exchange.
		return nil, nil
	case vpnpacket.CmdClientClose:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected packet cmd=%d", packet.Cmd)
	}
}

func (h *TunPacketHandler) HandleRawFrame(ctx context.Context, session SessionContext, raw []byte) (bool, []*vpnpacket.VpnPacket, error) {
	if h == nil {
		return true, nil, net.ErrClosed
	}
	if !vpnpacket.IsFixedV4DataCmd(raw, len(raw)) {
		return false, nil, nil
	}
	payload := vpnpacket.GetFixedV4Payload(raw, len(raw))
	if len(payload) == 0 {
		return true, nil, nil
	}
	return true, nil, h.handleDataPayload(ctx, session, payload)
}

func (h *TunPacketHandler) HandleBorrowedRawFrame(ctx context.Context, session SessionContext, raw []byte) (bool, bool, []*vpnpacket.VpnPacket, error) {
	if h == nil {
		return true, false, nil, net.ErrClosed
	}
	if !vpnpacket.IsFixedV4DataCmd(raw, len(raw)) {
		return false, false, nil, nil
	}
	payloadOffset := vpnpacket.FixedV4PayloadOffset()
	payload := vpnpacket.GetFixedV4Payload(raw, len(raw))
	if len(payload) == 0 {
		return true, false, nil, nil
	}
	err := h.handleBorrowedDataPayload(ctx, session, raw, payloadOffset, len(payload))
	return true, false, nil, err
}

func (h *TunPacketHandler) handleDataPayload(ctx context.Context, session SessionContext, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	ipPacket, parseErr := ippacket.ParseIPPacket(payload)
	if parseErr != nil {
		return nil
	}
	if !ipPacket.IsIPv4() {
		if h.dropNonIPv4 {
			return nil
		}
		return fmt.Errorf("Talaria server tun: unsupported non-IPv4 packet: %s", ipPacket.String())
	}
	ts, attached := h.getDataSession(session)
	if !attached {
		return errors.New("Talaria server tun: session is not attached")
	}
	if ts == nil {
		return nil
	}
	if err := h.validatePacketTarget(ctx, session, ipPacket); err != nil {
		return err
	}
	if !ts.bindClientIP(ipPacket.SrcAddr()) {
		return errors.New("Talaria server tun: inner source address changed")
	}
	if !ipPacket.RewriteSource(ts.vip) {
		return errors.New("Talaria server tun: rewrite source failed")
	}
	ipPacket.ClampTCPMSS(dataplane.DefaultMSS)
	return h.enqueuePayloadWrite(ctx, ts, payload)
}

func (h *TunPacketHandler) handleBorrowedDataPayload(ctx context.Context, session SessionContext, frame []byte, payloadOffset int, payloadSize int) error {
	if payloadSize <= 0 {
		return nil
	}
	if !validTunPacketRange(frame, payloadOffset, payloadSize) {
		return fmt.Errorf("Talaria server tun: invalid borrowed payload size %d", payloadSize)
	}
	payload := frame[payloadOffset : payloadOffset+payloadSize]
	ipPacket, parseErr := ippacket.ParseIPPacket(payload)
	if parseErr != nil {
		return nil
	}
	if !ipPacket.IsIPv4() {
		if h.dropNonIPv4 {
			return nil
		}
		return fmt.Errorf("Talaria server tun: unsupported non-IPv4 packet: %s", ipPacket.String())
	}
	ts, attached := h.getDataSession(session)
	if !attached {
		return errors.New("Talaria server tun: session is not attached")
	}
	if ts == nil {
		return nil
	}
	if err := h.validatePacketTarget(ctx, session, ipPacket); err != nil {
		return err
	}
	if !ts.bindClientIP(ipPacket.SrcAddr()) {
		return errors.New("Talaria server tun: inner source address changed")
	}
	if !ipPacket.RewriteSource(ts.vip) {
		return errors.New("Talaria server tun: rewrite source failed")
	}
	ipPacket.ClampTCPMSS(dataplane.DefaultMSS)
	// Queue a compact copy so the batch reader can reuse its fixed frame and the
	// write budget matches the retained allocation rather than ReadBufferSize.
	return h.enqueuePayloadWrite(ctx, ts, payload)
}

func (h *TunPacketHandler) validatePacketTarget(ctx context.Context, session SessionContext, packet ippacket.IPPacket) error {
	if h == nil || h.policy == nil {
		return errTargetBlocked
	}
	if h.virtualIPPrefix.Contains(packet.DstAddr()) && !h.allowPeers {
		return fmt.Errorf("%w: client-to-client destination %s is not allowed", errTargetBlocked, packet.DstAddr())
	}
	network := coretransport.NetworkIP
	port := uint16(0)
	if packet.IsTCP() {
		network = coretransport.NetworkTCP
		port = packet.DstPort()
	} else if packet.IsUDP() {
		network = coretransport.NetworkUDP
		port = packet.DstPort()
	}
	request := TargetPolicyRequest{
		Session: session,
		Network: network,
		Host:    packet.DstAddr().String(),
		Port:    port,
		IP:      packet.DstAddr(),
	}
	if err := h.policy.ValidateTarget(ctx, request); err != nil {
		return err
	}
	return ctx.Err()
}

func (h *TunPacketHandler) Close() error {
	if h == nil {
		return nil
	}
	if h.closeState.CompareAndSwap(0, 1) {
		if h.cancel != nil {
			h.cancel()
		}
		h.stopWriteLoop()
		h.closeDevice()
		h.closeState.Store(2)
	} else if h.closeState.Load() != 2 {
		return nil
	}
	h.closeErrMu.Lock()
	closeErr := h.closeErr
	h.closeErrMu.Unlock()
	if h.writeActive.Load() {
		h.cleanupStart.Do(func() {
			cleanup := func() {
				<-h.writeDone
				_ = h.runCleanup()
			}
			if !h.startWorker(cleanup) {
				cleanup()
			}
		})
		return closeErr
	}
	return errors.Join(closeErr, h.runCleanup())
}

func (h *TunPacketHandler) startWorker(work func()) bool {
	if h == nil || work == nil {
		return false
	}
	h.workerMu.Lock()
	if h.workersDone {
		h.workerMu.Unlock()
		return false
	}
	h.workerWG.Add(1)
	h.workerMu.Unlock()
	go func() {
		defer h.workerWG.Done()
		work()
	}()
	return true
}

func (h *TunPacketHandler) waitWorkers() {
	if h == nil {
		return
	}
	h.workerMu.Lock()
	h.workersDone = true
	h.workerMu.Unlock()
	h.workerWG.Wait()
}

func (h *TunPacketHandler) runCleanup() error {
	if h.cleanup == nil {
		return nil
	}
	h.cleanupMu.Lock()
	if h.cleanupDone || h.cleanupRunning {
		h.cleanupMu.Unlock()
		return nil
	}
	h.cleanupRunning = true
	h.cleanupMu.Unlock()
	err := extension.Do("Talaria server tun cleanup", h.cleanup)
	h.cleanupMu.Lock()
	h.cleanupRunning = false
	h.cleanupDone = err == nil
	h.cleanupMu.Unlock()
	return err
}

func (h *TunPacketHandler) closeDevice() {
	if h == nil {
		return
	}
	if !h.deviceClosed.CompareAndSwap(false, true) || h.device == nil {
		return
	}
	err := extension.Do("Talaria server tun device close", h.device.Close)
	h.closeErrMu.Lock()
	h.closeErr = err
	h.closeErrMu.Unlock()
}

// Err returns the first fatal TUN I/O error observed by the handler.
func (h *TunPacketHandler) Err() error {
	if h == nil {
		return net.ErrClosed
	}
	return h.getTunIOErr()
}

// Done is closed when the handler stops because of Close or fatal TUN I/O.
func (h *TunPacketHandler) Done() <-chan struct{} {
	if h == nil || h.ctx == nil {
		return nil
	}
	return h.ctx.Done()
}

func (h *TunPacketHandler) getWriteReq() *serverTunWriteReq {
	if v := h.writeReqPool.Get(); v != nil {
		if req, ok := v.(*serverTunWriteReq); ok && req != nil {
			req.bufs = req.bufs[:0]
			req.sizes = req.sizes[:0]
			req.offset = 0
			req.owner = nil
			req.budgeted = false
			req.packets = 0
			req.bytes = 0
			return req
		}
	}
	return &serverTunWriteReq{}
}

func (h *TunPacketHandler) putWriteReq(req *serverTunWriteReq) {
	if req == nil {
		return
	}
	for i := range req.bufs {
		req.bufs[i] = nil
	}
	h.releaseWriteBudget(req)
	req.bufs = req.bufs[:0]
	req.sizes = req.sizes[:0]
	req.offset = 0
	req.owner = nil
	req.budgeted = false
	req.packets = 0
	req.bytes = 0
	h.writeReqPool.Put(req)
}

func (h *TunPacketHandler) reserveWriteBudget(ctx context.Context, owner *tunHandlerSession, packets int, bytes int) error {
	if h == nil || owner == nil {
		return net.ErrClosed
	}
	if packets <= 0 || bytes <= 0 {
		return errors.New("Talaria server tun: invalid write budget request")
	}
	if packets > h.writePacketsMax || bytes > h.writeBytesMax ||
		packets > h.sessionPackets || bytes > h.sessionBytes {
		return ErrTunWriteQueueFull
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var ownerDone <-chan struct{}
	if owner.tunWriteCtx != nil {
		ownerDone = owner.tunWriteCtx.Done()
	}

	for {
		if err := h.getTunIOErr(); err != nil {
			return err
		}
		if h.ctx == nil || h.ctx.Err() != nil {
			return h.writeStopErr()
		}

		h.writeBudgetMu.Lock()
		sessionBlocked := owner.tunWritePackets+packets > h.sessionPackets ||
			owner.tunWriteBytes+bytes > h.sessionBytes
		globalBlocked := h.writePackets+packets > h.writePacketsMax ||
			h.writeBytes+bytes > h.writeBytesMax
		if !sessionBlocked && !globalBlocked {
			h.writePackets += packets
			h.writeBytes += bytes
			owner.tunWritePackets += packets
			owner.tunWriteBytes += bytes
			h.writeBudgetMu.Unlock()
			return nil
		}
		globalWake := (<-chan struct{})(nil)
		if globalBlocked {
			globalWake = h.writeBudgetWake
		}
		sessionWake := (<-chan struct{})(nil)
		if sessionBlocked {
			sessionWake = owner.tunWriteWake
		}
		h.writeBudgetMu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.ctx.Done():
			return h.writeStopErr()
		case <-ownerDone:
			return net.ErrClosed
		case <-globalWake:
		case <-sessionWake:
		}
	}
}

func (h *TunPacketHandler) releaseWriteBudget(req *serverTunWriteReq) {
	if h == nil || req == nil || !req.budgeted {
		return
	}
	h.writeBudgetMu.Lock()
	h.writePackets -= req.packets
	h.writeBytes -= req.bytes
	if req.owner != nil {
		req.owner.tunWritePackets -= req.packets
		req.owner.tunWriteBytes -= req.bytes
	}
	notifyTunWriteBudget(h.writeBudgetWake)
	if req.owner != nil {
		notifyTunWriteBudget(req.owner.tunWriteWake)
	}
	h.writeBudgetMu.Unlock()
}

func notifyTunWriteBudget(wake chan struct{}) {
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (h *TunPacketHandler) recordTunIOErr(err error) {
	if err == nil {
		return
	}
	h.tunIOErr.CompareAndSwap(nil, &tunIOError{err: err})
}

func (h *TunPacketHandler) getTunIOErr() error {
	value := h.tunIOErr.Load()
	if value == nil {
		return nil
	}
	return value.err
}

func (h *TunPacketHandler) enqueuePayloadWrite(ctx context.Context, owner *tunHandlerSession, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	retainedBytes := h.writeHeadroom + len(payload)
	if err := h.reserveWriteBudget(ctx, owner, 1, retainedBytes); err != nil {
		return err
	}
	copied := make([]byte, retainedBytes)
	copy(copied[h.writeHeadroom:], payload)
	req := h.getWriteReq()
	req.owner = owner
	req.bufs = append(req.bufs, copied)
	req.sizes = append(req.sizes, len(payload))
	req.offset = h.writeHeadroom
	req.budgeted = true
	req.packets = 1
	req.bytes = retainedBytes
	if err := h.enqueueWriteReq(ctx, req); err != nil {
		h.putWriteReq(req)
		return err
	}
	return nil
}

func (h *TunPacketHandler) enqueueWriteReq(ctx context.Context, req *serverTunWriteReq) error {
	if req == nil || len(req.bufs) == 0 {
		return nil
	}
	if !req.budgeted || req.packets != len(req.bufs) || req.bytes <= 0 {
		return errors.New("Talaria server tun: invalid unbudgeted write request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := h.getTunIOErr(); err != nil {
		return err
	}
	if !h.beginWriteEnqueue() {
		return h.writeStopErr()
	}
	defer h.writeEnqueueWG.Done()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.ctx.Done():
		return h.writeStopErr()
	case h.writeQueue <- req:
		return nil
	}
}

func (h *TunPacketHandler) stopWriteLoop() {
	if h == nil {
		return
	}
	h.writeCloseOnce.Do(func() {
		h.writeStateMu.Lock()
		h.writeClosing = true
		h.writeStateMu.Unlock()
		h.writeEnqueueWG.Wait()
		close(h.writeQueue)
	})
}

func (h *TunPacketHandler) beginWriteEnqueue() bool {
	h.writeStateMu.Lock()
	defer h.writeStateMu.Unlock()
	if h.writeClosing {
		return false
	}
	h.writeEnqueueWG.Add(1)
	return true
}

func (h *TunPacketHandler) writeStopErr() error {
	if err := h.getTunIOErr(); err != nil {
		return err
	}
	return net.ErrClosed
}

func (h *TunPacketHandler) failTunIO(err error) {
	if err == nil {
		return
	}
	h.recordTunIOErr(err)
	if h.cancel != nil {
		h.cancel()
	}
	h.closeDevice()
	h.stopWriteLoop()
}

func (h *TunPacketHandler) writeLoop() {
	defer func() {
		h.writeActive.Store(false)
		if recovered := recover(); recovered != nil {
			h.failTunIO(extension.PanicError("Talaria server tun write loop extension", recovered))
		}
		close(h.writeDone)
	}()

	pending := make([]*serverTunWriteReq, 0, cap(h.writeQueue))
	writeBufs := make([][]byte, h.device.BatchSize())
	writeSizes := make([]int, h.device.BatchSize())
	queueOpen := true
	for queueOpen || len(pending) > 0 {
		if len(pending) == 0 {
			req, ok := <-h.writeQueue
			if !ok {
				return
			}
			if req != nil {
				pending = append(pending, req)
			}
		}

	drain:
		for queueOpen && len(pending) < cap(pending) {
			select {
			case req, ok := <-h.writeQueue:
				if !ok {
					queueOpen = false
					break drain
				}
				if req != nil {
					pending = append(pending, req)
				}
			default:
				break drain
			}
		}

		var writeErr error
		h.writeActive.Store(true)
		if h.ctx.Err() == nil {
			writeErr = h.flushWritePending(pending, writeBufs, writeSizes)
		} else {
			h.releaseWritePending(pending)
		}
		h.writeActive.Store(false)
		clear(pending)
		pending = pending[:0]
		if writeErr != nil && h.ctx.Err() == nil {
			h.failTunIO(fmt.Errorf("Talaria server tun: write packets: %w", writeErr))
		}
	}
}

func (h *TunPacketHandler) releaseWritePending(pending []*serverTunWriteReq) {
	for _, req := range pending {
		h.putWriteReq(req)
	}
}

func (h *TunPacketHandler) flushWritePending(pending []*serverTunWriteReq, writeBufs [][]byte, writeSizes []int) error {
	var firstErr error
	for start := 0; start < len(pending); {
		owner := pending[start].owner
		offset := pending[start].offset
		end := start
		for end < len(pending) && pending[end].owner == owner && pending[end].offset == offset {
			end++
		}
		if firstErr == nil && h.ctx.Err() == nil && owner != nil {
			writeCtx, active := owner.beginTunWrite()
			if active {
				writeErr := h.writePendingGroup(writeCtx, pending[start:end], offset, writeBufs, writeSizes)
				owner.endTunWrite()
				if writeErr != nil && !h.isCanceledSessionWrite(writeCtx, writeErr) {
					firstErr = writeErr
				}
			}
		}
		for i := start; i < end; i++ {
			h.putWriteReq(pending[i])
		}
		start = end
	}
	return firstErr
}

func (h *TunPacketHandler) isCanceledSessionWrite(writeCtx context.Context, err error) bool {
	if writeCtx == nil || err == nil || h.ctx.Err() != nil {
		return false
	}
	ctxErr := writeCtx.Err()
	return ctxErr != nil && errors.Is(err, ctxErr)
}

func (h *TunPacketHandler) writePendingGroup(ctx context.Context, pending []*serverTunWriteReq, offset int, writeBufs [][]byte, writeSizes []int) error {
	if len(writeBufs) == 0 || len(writeSizes) < len(writeBufs) {
		return errors.New("Talaria server tun: invalid write scratch buffers")
	}
	defer clear(writeBufs)
	count := 0
	for _, req := range pending {
		if req == nil || len(req.sizes) < len(req.bufs) {
			return errors.New("Talaria server tun: invalid queued write buffers")
		}
		for i, buf := range req.bufs {
			size := req.sizes[i]
			if size <= 0 {
				continue
			}
			if !validTunPacketRange(buf, offset, size) {
				return fmt.Errorf("Talaria server tun: invalid queued packet size %d", size)
			}
			writeBufs[count] = buf
			writeSizes[count] = size
			count++
			if count == len(writeBufs) {
				err := h.writeTunBatch(ctx, writeBufs[:count], writeSizes[:count], offset)
				clear(writeBufs[:count])
				count = 0
				if err != nil {
					return err
				}
			}
		}
	}
	if count == 0 {
		return nil
	}
	err := h.writeTunBatch(ctx, writeBufs[:count], writeSizes[:count], offset)
	clear(writeBufs[:count])
	return err
}

func (h *TunPacketHandler) writeTunBatch(ctx context.Context, bufs [][]byte, sizes []int, offset int) error {
	if ctx == nil {
		ctx = h.ctx
	}
	for written := 0; written < len(bufs); {
		var n int
		err := extension.Do("Talaria server tun device write", func() error {
			var writeErr error
			n, writeErr = h.device.WritePackets(ctx, bufs[written:], sizes[written:], offset)
			return writeErr
		})
		if err != nil {
			return err
		}
		remaining := len(bufs) - written
		if n <= 0 || n > remaining {
			return fmt.Errorf("Talaria server tun: invalid write progress %d for %d packets", n, remaining)
		}
		written += n
	}
	return nil
}

func (h *TunPacketHandler) readLoop() {
	defer h.stopSessions()
	defer func() {
		if recovered := recover(); recovered != nil {
			h.failTunIO(extension.PanicError("Talaria server tun read loop extension", recovered))
		}
	}()
	batchSize := h.device.BatchSize()
	headroom := vpnpacket.RawCmdDataHeaderLen()
	queue := make(chan *serverTunReadBatch, serverTunReadPrefetchBatches(batchSize))
	readPool := sync.Pool{New: func() any {
		return newServerTunReadBatch(batchSize, headroom, h.readBufferSize)
	}}
	if !h.startWorker(func() { h.produceTunReadBatches(queue, &readPool) }) {
		close(queue)
	}

	rawBufs := make([][]byte, 0, batchSize)
	rawSizes := make([]int, 0, batchSize)
	for batch := range queue {
		h.handleTunBatchWithScratch(batch.bufs, batch.sizes, batch.owners, batch.n, batch.headroom, rawBufs, rawSizes)
		batch.reset()
		readPool.Put(batch)
	}
}

func serverTunReadPrefetchBatches(batchSize int) int {
	if batchSize <= 0 {
		return minServerTunReadPrefetchBatches
	}
	batches := (defaultServerTunReadPrefetchPackets + batchSize - 1) / batchSize
	return max(minServerTunReadPrefetchBatches, min(batches, maxServerTunReadPrefetchBatches))
}

func newServerTunReadBatch(batchSize int, headroom int, readBufferSize int) *serverTunReadBatch {
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, headroom+readBufferSize)
	}
	return &serverTunReadBatch{
		bufs:     bufs,
		sizes:    sizes,
		owners:   make([]*tunHandlerSession, batchSize),
		headroom: headroom,
	}
}

func (b *serverTunReadBatch) reset() {
	if b == nil {
		return
	}
	for i := range b.sizes {
		b.sizes[i] = 0
	}
	clear(b.owners)
	b.n = 0
}

func (h *TunPacketHandler) produceTunReadBatches(queue chan<- *serverTunReadBatch, readPool *sync.Pool) {
	defer close(queue)
	for {
		if h.ctx.Err() != nil {
			return
		}
		batch := readPool.Get().(*serverTunReadBatch)
		vipEpoch := h.snapshotVIPEpoch()
		var n int
		err := extension.Do("Talaria server tun device read", func() error {
			var readErr error
			n, readErr = h.device.ReadPackets(h.ctx, batch.bufs, batch.sizes, batch.headroom)
			return readErr
		})
		if err != nil {
			batch.reset()
			readPool.Put(batch)
			if h.ctx.Err() != nil {
				return
			}
			h.failTunIO(fmt.Errorf("Talaria server tun: read packets: %w", err))
			return
		}
		if n < 0 || n > len(batch.bufs) || n > len(batch.sizes) {
			batch.reset()
			readPool.Put(batch)
			h.failTunIO(fmt.Errorf("Talaria server tun: invalid read packet count %d", n))
			return
		}
		if n == 0 {
			batch.reset()
			readPool.Put(batch)
			time.Sleep(serverTunIdleReadBackoff)
			continue
		}
		batch.n = n
		h.captureTunBatchOwnersAtEpoch(batch, vipEpoch)
		select {
		case <-h.ctx.Done():
			batch.reset()
			readPool.Put(batch)
			return
		case queue <- batch:
		}
	}
}

func (h *TunPacketHandler) snapshotVIPEpoch() uint64 {
	h.mu.RLock()
	epoch := h.vipEpoch.Load()
	h.mu.RUnlock()
	return epoch
}

func (h *TunPacketHandler) stopSessions() {
	h.mu.Lock()
	h.readStopped = true
	sessions := make([]*tunHandlerSession, 0, len(h.sessions))
	for _, ts := range h.sessions {
		sessions = append(sessions, ts)
	}
	clear(h.sessions)
	clear(h.byVIP)
	clear(h.vipBindings)
	clear(h.vipByClient)
	clear(h.vipCleanups)
	clear(h.releasedVIP)
	h.mu.Unlock()
	for _, ts := range sessions {
		ts.deactivateTunWrites()
		ts.stopSender()
		ts.close()
	}
}

func (h *TunPacketHandler) handleTunPacket(raw []byte) {
	h.handleTunPacketBuffer(raw, 0, len(raw))
}

func (h *TunPacketHandler) handleTunBatch(bufs [][]byte, sizes []int, n int, headroom int) {
	h.handleTunBatchWithScratch(bufs, sizes, nil, n, headroom, nil, nil)
}

func (h *TunPacketHandler) handleTunBatchWithScratch(bufs [][]byte, sizes []int, owners []*tunHandlerSession, n int, headroom int, rawBufs [][]byte, rawSizes []int) {
	if n > len(bufs) {
		n = len(bufs)
	}
	if n > len(sizes) {
		n = len(sizes)
	}
	rawBufs = rawBufs[:0]
	rawSizes = rawSizes[:0]
	var current *tunHandlerSession
	flush := func() {
		if current == nil || len(rawBufs) == 0 {
			rawBufs = rawBufs[:0]
			rawSizes = rawSizes[:0]
			return
		}
		if err := h.enqueueSessionDownlink(current, rawBufs, rawSizes); err != nil {
			h.handleSessionDownlinkError(current, err)
		}
		rawBufs = rawBufs[:0]
		rawSizes = rawSizes[:0]
	}
	for i := 0; i < n; i++ {
		var owner *tunHandlerSession
		if owners != nil && i < len(owners) {
			owner = owners[i]
		}
		ts, frame, frameSize, ok := h.prepareTunPacketFrameForOwner(bufs[i], headroom, sizes[i], owner, owners != nil)
		if !ok {
			continue
		}
		if current != nil && current != ts {
			flush()
		}
		current = ts
		rawBufs = append(rawBufs, frame)
		rawSizes = append(rawSizes, frameSize)
	}
	flush()
}

func (h *TunPacketHandler) handleTunPacketBuffer(buf []byte, offset int, size int) {
	ts, frame, frameSize, ok := h.prepareTunPacketFrame(buf, offset, size)
	if !ok {
		return
	}
	if err := ts.writeRaw(frame[:frameSize]); err != nil {
		h.detachSession(ts.ref, ts)
	}
}

func (h *TunPacketHandler) prepareTunPacketFrame(buf []byte, offset int, size int) (*tunHandlerSession, []byte, int, bool) {
	return h.prepareTunPacketFrameForOwner(buf, offset, size, nil, false)
}

func (h *TunPacketHandler) prepareTunPacketFrameForOwner(buf []byte, offset int, size int, owner *tunHandlerSession, ownerCaptured bool) (*tunHandlerSession, []byte, int, bool) {
	if size <= 0 || !validTunPacketRange(buf, offset, size) {
		return nil, nil, 0, false
	}
	raw := buf[offset : offset+size]
	ipPacket, parseErr := ippacket.ParseIPPacket(raw)
	if parseErr != nil || !ipPacket.IsIPv4() {
		return nil, nil, 0, false
	}
	vip := ipPacket.DstAddr()
	ts := owner
	if !ownerCaptured {
		ts = h.getSessionByVIP(vip)
	} else if ts == nil || ts.vip != vip || h.getSessionByVIP(vip) != ts {
		return nil, nil, 0, false
	}
	if ts == nil {
		return nil, nil, 0, false
	}
	clientIP := ts.getClientIP()
	if !clientIP.IsValid() {
		return nil, nil, 0, false
	}
	if !ipPacket.RewriteDestination(clientIP) {
		return nil, nil, 0, false
	}
	ipPacket.ClampTCPMSS(dataplane.DefaultMSS)
	seq := atomic.AddUint32(&ts.dataSeq, 1)
	headerLen := vpnpacket.RawCmdDataHeaderLen()
	if offset >= headerLen && (ts.rawWriter != nil || ts.rawBatchWriter != nil) {
		frame := buf[offset-headerLen : offset+size]
		if !vpnpacket.WriteRawCmdDataHeader(frame[:headerLen], ts.id, seq) {
			return nil, nil, 0, false
		}
		return ts, frame, headerLen + size, true
	}
	if ts.writer == nil {
		return nil, nil, 0, false
	}
	if err := h.enqueueSessionPacketDownlink(ts, &vpnpacket.VpnPacket{
		Cmd:            vpnpacket.CmdData,
		ClientId:       ts.id,
		DataSequenceId: seq,
		Data:           raw,
	}); err != nil {
		h.handleSessionDownlinkError(ts, err)
	}
	return nil, nil, 0, false
}

func (h *TunPacketHandler) captureTunBatchOwners(batch *serverTunReadBatch) {
	h.captureTunBatchOwnersAtEpoch(batch, h.vipEpoch.Load())
}

func (h *TunPacketHandler) captureTunBatchOwnersAtEpoch(batch *serverTunReadBatch, vipEpoch uint64) {
	if h == nil || batch == nil || batch.n <= 0 {
		return
	}
	n := min(batch.n, len(batch.bufs), len(batch.sizes), len(batch.owners))
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := 0; i < n; i++ {
		if !validTunPacketRange(batch.bufs[i], batch.headroom, batch.sizes[i]) {
			continue
		}
		raw := batch.bufs[i][batch.headroom : batch.headroom+batch.sizes[i]]
		packet, err := ippacket.ParseIPPacket(raw)
		if err != nil || !packet.IsIPv4() {
			continue
		}
		owner := h.byVIP[packet.DstAddr()]
		if owner != nil && owner.vipEpoch <= vipEpoch {
			batch.owners[i] = owner
		}
	}
}

func validTunPacketRange(buf []byte, offset int, size int) bool {
	return offset >= 0 && size >= 0 && offset <= len(buf) && size <= len(buf)-offset
}

func (h *TunPacketHandler) allocateVIPLocked(clientID uint64) (netip.Addr, error) {
	if vip, ok := h.vipByClient[clientID]; ok {
		if h.vipBindings[vip] != clientID {
			return netip.Addr{}, errors.New("Talaria server tun: inconsistent virtual IP binding")
		}
		if owner := h.byVIP[vip]; owner != nil && owner.id != clientID {
			return netip.Addr{}, errors.New("Talaria server tun: inconsistent virtual IP owner")
		}
		if released, ok := h.releasedVIP[vip]; ok {
			if released.clientID != clientID {
				return netip.Addr{}, errors.New("Talaria server tun: inconsistent virtual IP release")
			}
			if !released.reusable || h.vipCleanups[vip] != 0 {
				return netip.Addr{}, errors.New("Talaria server tun: previous virtual IP release is still in progress")
			}
			delete(h.releasedVIP, vip)
		}
		if h.byVIP[vip] == nil && h.vipCleanups[vip] != 0 {
			return netip.Addr{}, errors.New("Talaria server tun: previous virtual IP cleanup is still in progress")
		}
		return vip, nil
	}
	for i := uint32(0); i < h.virtualIPMax; i++ {
		h.nextVIP++
		if h.nextVIP > h.virtualIPMax {
			h.nextVIP = 1
		}
		vip := addIPv4(h.virtualIPBase, h.nextVIP)
		if _, used := h.byVIP[vip]; used {
			continue
		}
		if _, bound := h.vipBindings[vip]; bound {
			continue
		}
		h.vipBindings[vip] = clientID
		h.vipByClient[clientID] = vip
		return vip, nil
	}
	return netip.Addr{}, fmt.Errorf(
		"Talaria server tun: virtual IP pool %s is exhausted (%d assignable addresses)",
		h.virtualIPPrefix,
		h.virtualIPMax,
	)
}

func (h *TunPacketHandler) releaseVIPLocked(vip netip.Addr, clientID uint64) {
	if h == nil || !vip.IsValid() || clientID == 0 {
		return
	}
	h.releasedVIP[vip] = releasedTunVIP{clientID: clientID}
}

func (h *TunPacketHandler) newestSessionForVIPLocked(vip netip.Addr) *tunHandlerSession {
	var newest *tunHandlerSession
	for _, candidate := range h.sessions {
		if candidate.vip == vip && (newest == nil || candidate.ref.Generation > newest.ref.Generation) {
			newest = candidate
		}
	}
	return newest
}

// virtualIPMaxOffset reports how many addresses above base remain assignable
// inside prefix, excluding the network and broadcast addresses.
func virtualIPMaxOffset(base netip.Addr, prefix netip.Prefix) uint32 {
	bits := prefix.Bits()
	if bits < 0 || bits > 30 {
		// A /31 or /32 has no room for a gateway plus assignable clients.
		return 0
	}
	networkOffset := ipv4ToUint32(prefix.Masked().Addr())
	baseOffset := ipv4ToUint32(base)
	if baseOffset < networkOffset {
		return 0
	}
	// Highest assignable offset within the prefix, one below the broadcast address.
	lastAssignable := networkOffset + (uint32(1) << (32 - uint(bits))) - 2
	if baseOffset >= lastAssignable {
		return 0
	}
	return lastAssignable - baseOffset
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	v := addr.As4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func (h *TunPacketHandler) detachSession(ref coretransport.SessionRef, ts *tunHandlerSession) {
	finish, async := h.detachSessionForReclaim(ref, ts)
	if finish == nil {
		return
	}
	if async {
		if !h.startWorker(finish) {
			finish()
		}
	} else {
		finish()
	}
}

func (h *TunPacketHandler) detachSessionRefForReclaim(ref coretransport.SessionRef) func() {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	ts := h.sessions[ref]
	h.mu.RUnlock()
	finish, _ := h.detachSessionForReclaim(ref, ts)
	return finish
}

func (h *TunPacketHandler) detachSessionForReclaim(ref coretransport.SessionRef, ts *tunHandlerSession) (func(), bool) {
	if h == nil || ts == nil {
		return nil, false
	}
	h.mu.Lock()
	if h.sessions[ref] != ts {
		h.mu.Unlock()
		return nil, false
	}
	delete(h.sessions, ref)
	if h.byVIP[ts.vip] == ts {
		delete(h.byVIP, ts.vip)
		h.releaseVIPLocked(ts.vip, ts.id)
	} else if h.byVIP[ts.vip] == nil {
		if _, releasing := h.releasedVIP[ts.vip]; !releasing {
			h.releaseVIPLocked(ts.vip, ts.id)
		}
	}
	h.vipCleanups[ts.vip]++
	h.mu.Unlock()
	deactivated := ts.tryDeactivateTunWrites()
	ts.stopSender()
	return func() {
		if !deactivated {
			ts.deactivateTunWrites()
		}
		h.finishDetachSession(ts)
	}, !deactivated
}

func (h *TunPacketHandler) finishDetachSession(ts *tunHandlerSession) {
	ts.close()
	if !h.completeVIPCleanup(ts.vip, ts.id) {
		return
	}

	err := extension.Do("Talaria server tun release virtual IP", func() error {
		return h.device.ReleaseVirtualIP(h.ctx, ts.vip)
	})
	if err != nil {
		if h.ctx.Err() == nil {
			h.failTunIO(fmt.Errorf("Talaria server tun: release virtual IP %s: %w", ts.vip, err))
		}
		return
	}
	h.mu.Lock()
	if released, ok := h.releasedVIP[ts.vip]; ok && released.clientID == ts.id && released.releasing {
		if replacement := h.newestSessionForVIPLocked(ts.vip); replacement != nil {
			delete(h.releasedVIP, ts.vip)
			replacement.vipEpoch = h.vipEpoch.Add(1)
			h.byVIP[ts.vip] = replacement
		} else {
			released.reusable = true
			released.releasing = false
			h.releasedVIP[ts.vip] = released
		}
	}
	h.mu.Unlock()
}

func (h *TunPacketHandler) completeVIPCleanup(vip netip.Addr, clientID uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := h.vipCleanups[vip]
	if pending == 0 {
		return false
	}
	if pending == 1 {
		delete(h.vipCleanups, vip)
	} else {
		h.vipCleanups[vip] = pending - 1
		return false
	}
	if h.byVIP[vip] != nil {
		return false
	}
	released, ok := h.releasedVIP[vip]
	if !ok || released.clientID != clientID || released.reusable || released.releasing {
		return false
	}
	released.releasing = true
	h.releasedVIP[vip] = released
	return true
}

func (s *tunHandlerSession) beginTunWrite() (context.Context, bool) {
	if s == nil {
		return nil, false
	}
	s.tunWriteMu.RLock()
	if !s.tunWriteActive {
		s.tunWriteMu.RUnlock()
		return nil, false
	}
	return s.tunWriteCtx, true
}

func (s *tunHandlerSession) endTunWrite() {
	s.tunWriteMu.RUnlock()
}

func (s *tunHandlerSession) deactivateTunWrites() {
	if s == nil {
		return
	}
	s.cancelTunWrites()
	s.tunWriteMu.Lock()
	s.tunWriteActive = false
	s.tunWriteMu.Unlock()
}

func (s *tunHandlerSession) tryDeactivateTunWrites() bool {
	if s == nil {
		return true
	}
	s.cancelTunWrites()
	if !s.tunWriteMu.TryLock() {
		return false
	}
	s.tunWriteActive = false
	s.tunWriteMu.Unlock()
	return true
}

func (s *tunHandlerSession) cancelTunWrites() {
	s.tunWriteCancelOnce.Do(func() {
		if s.tunWriteCancel != nil {
			s.tunWriteCancel()
		}
	})
}

func (h *TunPacketHandler) enqueueSessionDownlink(ts *tunHandlerSession, bufs [][]byte, sizes []int) error {
	if ts == nil || len(bufs) == 0 {
		return nil
	}
	packets := 0
	bytes := 0
	for i, buf := range bufs {
		if i >= len(sizes) || sizes[i] <= 0 {
			continue
		}
		if sizes[i] > len(buf) {
			return errors.New("Talaria server tun: invalid downlink packet size")
		}
		packets++
		bytes += sizes[i]
	}
	if packets == 0 {
		return nil
	}
	if err := h.reserveSessionDownlink(ts, packets, bytes); err != nil {
		return err
	}
	batch := &sessionDownlinkBatch{
		bufs:    make([][]byte, 0, packets),
		sizes:   make([]int, 0, packets),
		packets: packets,
		bytes:   bytes,
	}
	for i, buf := range bufs {
		if i >= len(sizes) || sizes[i] <= 0 {
			continue
		}
		copied := make([]byte, sizes[i])
		copy(copied, buf[:sizes[i]])
		batch.bufs = append(batch.bufs, copied)
		batch.sizes = append(batch.sizes, sizes[i])
	}
	return h.enqueueReservedSessionDownlink(ts, batch)
}

func (h *TunPacketHandler) enqueueSessionPacketDownlink(ts *tunHandlerSession, packet *vpnpacket.VpnPacket) error {
	if ts == nil || packet == nil {
		return nil
	}
	if err := h.reserveSessionDownlink(ts, 1, len(packet.Data)); err != nil {
		return err
	}
	copied := *packet
	copied.Data = make([]byte, len(packet.Data))
	copy(copied.Data, packet.Data)
	batch := &sessionDownlinkBatch{
		vpnPackets: []*vpnpacket.VpnPacket{&copied},
		packets:    1,
		bytes:      len(copied.Data),
	}
	return h.enqueueReservedSessionDownlink(ts, batch)
}

func (h *TunPacketHandler) reserveSessionDownlink(ts *tunHandlerSession, packets int, bytes int) error {
	if h == nil || ts == nil {
		return net.ErrClosed
	}
	if packets <= 0 || bytes < 0 {
		return errors.New("Talaria server tun: invalid downlink budget request")
	}
	if packets > h.downlinkPackets || bytes > h.downlinkBytes {
		return ErrTunDownlinkQueueFull
	}
	if packets > h.globalDownlinkPackets || bytes > h.globalDownlinkBytes {
		return ErrTunDownlinkQueueFull
	}
	h.downlinkBudgetMu.Lock()
	ts.sendMu.Lock()
	if ts.sendStopped {
		ts.sendMu.Unlock()
		h.downlinkBudgetMu.Unlock()
		return net.ErrClosed
	}
	if ts.sendPackets+packets > h.downlinkPackets || ts.sendBytes+bytes > h.downlinkBytes {
		ts.sendMu.Unlock()
		h.downlinkBudgetMu.Unlock()
		return ErrTunDownlinkQueueFull
	}
	if h.downlinkPacketsUsed+packets > h.globalDownlinkPackets ||
		h.downlinkBytesUsed+bytes > h.globalDownlinkBytes {
		ts.sendMu.Unlock()
		h.downlinkBudgetMu.Unlock()
		return ErrTunDownlinkQueueFull
	}
	ts.sendPackets += packets
	ts.sendBytes += bytes
	h.downlinkPacketsUsed += packets
	h.downlinkBytesUsed += bytes
	ts.sendMu.Unlock()
	h.downlinkBudgetMu.Unlock()
	return nil
}

func (h *TunPacketHandler) handleSessionDownlinkError(requester *tunHandlerSession, err error) {
	if errors.Is(err, ErrTunDownlinkQueueFull) {
		// The packets have already been consumed from TUN and cannot be retried.
		// Treat bounded queue pressure like normal IP congestion: drop the newest
		// batch so one slow client cannot block the reader or lose its session.
		return
	}
	if requester != nil {
		h.detachSession(requester.ref, requester)
	}
}

func (h *TunPacketHandler) enqueueReservedSessionDownlink(ts *tunHandlerSession, batch *sessionDownlinkBatch) error {
	if h == nil || ts == nil || batch == nil || batch.packets == 0 {
		return nil
	}
	ts.sendMu.Lock()
	if ts.sendStopped {
		ts.sendMu.Unlock()
		ts.releaseDownlink(batch)
		return net.ErrClosed
	}
	select {
	case ts.sendQueue <- batch:
		ts.sendMu.Unlock()
		return nil
	default:
		ts.sendMu.Unlock()
		ts.releaseDownlink(batch)
		return ErrTunDownlinkQueueFull
	}
}

func (h *TunPacketHandler) runSessionSender(ts *tunHandlerSession) {
	for {
		select {
		case <-ts.sendDone:
			return
		default:
		}
		select {
		case <-ts.sendDone:
			return
		case batch := <-ts.sendQueue:
			select {
			case <-ts.sendDone:
				ts.releaseDownlink(batch)
				return
			default:
			}
			err := extension.Do("Talaria server tun session writer", func() error {
				return ts.writeDownlinkBatch(batch)
			})
			ts.releaseDownlink(batch)
			if err != nil {
				h.detachSession(ts.ref, ts)
				return
			}
		}
	}
}

func (s *tunHandlerSession) writeDownlinkBatch(batch *sessionDownlinkBatch) error {
	if batch == nil {
		return nil
	}
	if len(batch.vpnPackets) > 0 {
		if s.writer == nil {
			return errors.New("Talaria server tun: missing packet writer")
		}
		for _, packet := range batch.vpnPackets {
			if packet == nil {
				continue
			}
			if err := s.writer(packet); err != nil {
				return err
			}
		}
		return nil
	}
	return s.writeRawBatch(batch.bufs, batch.sizes)
}

func (s *tunHandlerSession) releaseDownlink(batch *sessionDownlinkBatch) {
	if batch == nil {
		return
	}
	h := s.handler
	if h != nil {
		h.downlinkBudgetMu.Lock()
		defer h.downlinkBudgetMu.Unlock()
	}
	s.sendMu.Lock()
	s.sendPackets -= batch.packets
	s.sendBytes -= batch.bytes
	s.sendMu.Unlock()
	if h != nil {
		h.downlinkPacketsUsed -= batch.packets
		h.downlinkBytesUsed -= batch.bytes
	}
}

func (s *tunHandlerSession) stopSender() {
	if s == nil {
		return
	}
	s.sendOnce.Do(func() {
		s.sendMu.Lock()
		s.sendStopped = true
		close(s.sendDone)
		s.sendMu.Unlock()
		for {
			select {
			case batch := <-s.sendQueue:
				s.releaseDownlink(batch)
			default:
				return
			}
		}
	})
}

func (s *tunHandlerSession) close() {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.closeWriter != nil {
		_ = extension.Run("Talaria server tun session close writer", s.closeWriter)
	}
}

func (h *TunPacketHandler) getSession(session SessionContext) *tunHandlerSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[session.Ref()]
}

func (h *TunPacketHandler) getDataSession(session SessionContext) (*tunHandlerSession, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ts := h.sessions[session.Ref()]
	if ts == nil {
		return nil, false
	}
	if h.byVIP[ts.vip] != ts {
		return nil, true
	}
	return ts, true
}

func (h *TunPacketHandler) getSessionByVIP(vip netip.Addr) *tunHandlerSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.byVIP[vip]
}

func (s *tunHandlerSession) bindClientIP(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientIP.IsValid() {
		return s.clientIP == ip
	}
	s.clientIP = ip
	return true
}

func (s *tunHandlerSession) getClientIP() netip.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientIP
}

func (s *tunHandlerSession) writeRaw(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	if s.rawWriter != nil {
		return s.rawWriter(frame)
	}
	if s.rawBatchWriter != nil {
		return writeAllRawBatch(s.rawBatchWriter, [][]byte{frame}, []int{len(frame)})
	}
	return errors.New("Talaria server tun: missing raw writer")
}

func (s *tunHandlerSession) writeRawBatch(bufs [][]byte, sizes []int) error {
	if len(bufs) == 0 {
		return nil
	}
	if s.rawBatchWriter != nil {
		return writeAllRawBatch(s.rawBatchWriter, bufs, sizes)
	}
	for i := range bufs {
		if i >= len(sizes) || sizes[i] <= 0 {
			continue
		}
		if sizes[i] > len(bufs[i]) {
			return fmt.Errorf("Talaria server tun: raw packet size overflows buffer: %d", sizes[i])
		}
		if err := s.writeRaw(bufs[i][:sizes[i]]); err != nil {
			return err
		}
	}
	return nil
}

func writeAllRawBatch(writer RawPacketBatchWriter, bufs [][]byte, sizes []int) error {
	if writer == nil {
		return errors.New("Talaria server tun: missing raw batch writer")
	}
	if len(sizes) < len(bufs) {
		return errors.New("Talaria server tun: raw batch sizes too small")
	}
	for off := 0; off < len(bufs); {
		written, err := writer(bufs[off:], sizes[off:])
		remaining := len(bufs) - off
		if written < 0 || written > remaining {
			return fmt.Errorf("Talaria server tun: invalid raw batch write count: %d", written)
		}
		off += written
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("Talaria server tun: raw batch write made no progress")
		}
	}
	return nil
}

func addIPv4(base netip.Addr, delta uint32) netip.Addr {
	addr := base.As4()
	v := uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	v += delta
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
