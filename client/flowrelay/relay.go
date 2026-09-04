// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package flowrelay converts the client TUN's IP packets into TCP flows for
// TalariaTCP.
//
// TalariaTCP carries each TCP connection as its own protected stream rather than
// forwarding raw IP, so the client terminates TCP locally with a gVisor
// userspace network stack and relays the resulting flows. Packets that are not
// TCP stay on the authenticated control connection as raw IP.
package flowrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	managedTunnelNICID                    tcpip.NICID = 1
	managedTunnelOutboundQueueDefault                 = 2048
	managedTunnelGVisorLinkQueueDefault               = 2048
	managedTunnelTCPMaxInFlight                       = 1024
	managedTunnelTCPGlobalLimit                       = 4096
	managedTunnelTCPRelayByteLimit        int64       = 128 * 1024 * 1024
	managedTunnelTCPGlobalByteLimit       int64       = 512 * 1024 * 1024
	managedTunnelMTUMin                               = 576
	managedTunnelMTUMax                               = 9000
	managedTunnelOutboundBufferPoolMaxCap             = managedTunnelMTUMax
	managedTunnelTCPRecoveryDefault                   = 0
)

var (
	managedTunnelOutboundBufferPool  sync.Pool
	managedTunnelOutboundPoolEnabled atomic.Bool
	managedTunnelMTUOverride         atomic.Int64
	managedGVisorLinkMTUOverride     atomic.Int64
	managedTunnelTCPGlobalSlots      = make(chan struct{}, managedTunnelTCPGlobalLimit)
	managedTunnelTCPGlobalBytes      atomic.Int64
)

func init() {
	managedTunnelOutboundPoolEnabled.Store(managedTunnelOutboundBufferPoolDefaultEnabled())
}

type managedTunnelRelay struct {
	tun             *TUN
	parentCtx       context.Context
	streamTransport coretransport.Client

	ctx    context.Context
	cancel context.CancelFunc

	tcpBackend     managedTCPBackend
	outboundCh     chan managedOutboundPacket
	outboundMu     sync.RWMutex
	outboundClosed bool
	copyWG         sync.WaitGroup

	flowMu      sync.Mutex
	flows       map[uint64]*managedTunnelFlow
	flowSlots   chan struct{}
	flowBytes   int64
	flowsClosed bool
	nextFlowID  atomic.Uint64

	closeState atomic.Uint32
	closeErrMu sync.Mutex
	closeErr   error
	failureMu  sync.Mutex
	failureErr error
}

type managedTunnelFlow struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	localConn  net.Conn
	remoteConn net.Conn
	closed     bool
}

type managedOutboundPacket struct {
	data   []byte
	pooled bool
}

func (p managedOutboundPacket) len() int {
	return len(p.data)
}

func (p managedOutboundPacket) release() {
	if p.pooled {
		putManagedTunnelOutboundBuffer(p.data)
	}
}

func (p managedOutboundPacket) releaseFunc() func() {
	if !p.pooled {
		return nil
	}
	return p.release
}

type managedOutboundReader interface {
	Read() *stack.PacketBuffer
	ReadContext(ctx context.Context) *stack.PacketBuffer
}

type managedTCPOpenResult struct {
	localConn net.Conn
	dest      coretransport.Destination
}

type managedTCPForwardedFlow interface {
	open() (*managedTCPOpenResult, error)
	reject()
}

type managedGVisorTCPBackend struct {
	stack        *stack.Stack
	linkEP       *channel.Endpoint
	linkQueueCap int
}

type managedGVisorTCPForwardedFlow struct {
	req *gtcp.ForwarderRequest
}

func newManagedTunnelRelay(tun *TUN) (*managedTunnelRelay, error) {
	if tun == nil {
		return nil, fmt.Errorf("nil TalariaTCP device")
	}
	return newManagedTunnelRelayWithConfig(tun, tun.currentContext(), tun.currentProtocol(), tun.currentStreamTransport())
}

func newManagedTunnelRelayWithConfig(tun *TUN, parentCtx context.Context, protocol string, streamTransport coretransport.Client) (*managedTunnelRelay, error) {
	if tun == nil {
		return nil, fmt.Errorf("nil TalariaTCP device")
	}
	if extension.IsNil(streamTransport) {
		return nil, fmt.Errorf("stream transport is required for %s", protocol)
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	relay := &managedTunnelRelay{
		tun:             tun,
		parentCtx:       parentCtx,
		streamTransport: streamTransport,
		ctx:             ctx,
		cancel:          cancel,
		outboundCh:      make(chan managedOutboundPacket, managedTunnelOutboundQueueSize()),
		flows:           make(map[uint64]*managedTunnelFlow, 64),
		flowSlots:       make(chan struct{}, managedTunnelTCPMaxInFlight),
	}

	tcpBackend, err := newManagedTCPBackend(managedTunnelMTU(), relay)
	if err != nil {
		cancel()
		return nil, err
	}
	relay.tcpBackend = tcpBackend

	if backendReader, ok := tcpBackend.(managedTCPBackendOutboundReader); ok {
		if reader := backendReader.outboundReader(); reader != nil {
			relay.copyWG.Add(1)
			go relay.copyOutboundLoop(reader)
		}
	}

	return relay, nil
}

func managedTunnelOutboundQueueSize() int {
	return managedTunnelOutboundQueueDefault
}

func managedTunnelGVisorLinkQueueSize() int {
	return managedTunnelGVisorLinkQueueDefault
}

// managedTunnelTCPRecovery returns the gVisor TCP loss-recovery option mask.
// The default disables RACK and uses RFC 6582 NewReno with duplicate ACKs.
func managedTunnelTCPRecovery() tcpip.TCPRecovery {
	return tcpip.TCPRecovery(managedTunnelTCPRecoveryDefault)
}

func managedTunnelMTU() int {
	if override := int(managedTunnelMTUOverride.Load()); override > 0 {
		return clampManagedTunnelMTU(override)
	}
	return TUN_MTU
}

func clampManagedTunnelMTU(n int) int {
	if n < managedTunnelMTUMin {
		return TUN_MTU
	}
	if n > managedTunnelMTUMax {
		return managedTunnelMTUMax
	}
	return n
}

func SetManagedTunnelMTU(mtu int) {
	if mtu <= 0 {
		managedTunnelMTUOverride.Store(0)
		return
	}
	managedTunnelMTUOverride.Store(int64(clampManagedTunnelMTU(mtu)))
}

func managedGVisorLinkMTUWithDefault(defaultMTU int) int {
	if override := int(managedGVisorLinkMTUOverride.Load()); override > 0 {
		return clampManagedTunnelMTU(override)
	}
	return clampManagedTunnelMTU(defaultMTU)
}

// SetManagedGVisorLinkMTU overrides the gVisor link endpoint MTU.
func SetManagedGVisorLinkMTU(mtu int) {
	if mtu <= 0 {
		managedGVisorLinkMTUOverride.Store(0)
		return
	}
	managedGVisorLinkMTUOverride.Store(int64(clampManagedTunnelMTU(mtu)))
}

func managedTunnelOutboundBufferPoolEnabled() bool {
	return managedTunnelOutboundPoolEnabled.Load()
}

func SetManagedTunnelOutboundBufferPoolEnabled(enable bool) {
	managedTunnelOutboundPoolEnabled.Store(enable)
}

func (r *managedTunnelRelay) close() error {
	if r == nil {
		return nil
	}
	if !r.closeState.CompareAndSwap(0, 1) {
		if r.closeState.Load() != 2 {
			return nil
		}
		r.closeErrMu.Lock()
		err := r.closeErr
		r.closeErrMu.Unlock()
		return err
	}
	var closeErr error
	if r.cancel != nil {
		r.cancel()
	}
	r.outboundMu.Lock()
	r.outboundClosed = true
	r.outboundMu.Unlock()
	if r.tcpBackend != nil {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP backend close", r.tcpBackend.close))
	}
	r.flowMu.Lock()
	r.flowsClosed = true
	flows := make([]*managedTunnelFlow, 0, len(r.flows))
	for id, flow := range r.flows {
		flows = append(flows, flow)
		delete(r.flows, id)
	}
	r.flowMu.Unlock()
	for _, flow := range flows {
		closeErr = errors.Join(closeErr, flow.close())
	}

	r.copyWG.Wait()
	draining := true
	for draining {
		select {
		case packet, ok := <-r.outboundCh:
			if !ok {
				draining = false
				continue
			}
			packet.release()
		default:
			draining = false
		}
	}
	if isUnexpectedManagedTunnelCloseError(closeErr) {
		r.closeErrMu.Lock()
		r.closeErr = closeErr
		r.closeErrMu.Unlock()
		r.closeState.Store(2)
		return closeErr
	}
	r.closeErrMu.Lock()
	r.closeErr = nil
	r.closeErrMu.Unlock()
	r.closeState.Store(2)
	return nil
}

func isUnexpectedManagedTunnelCloseError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if isUnexpectedManagedTunnelCloseError(child) {
				return true
			}
		}
		return false
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		inner := wrapped.Unwrap()
		if inner != nil {
			return isUnexpectedManagedTunnelCloseError(inner)
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return !(strings.Contains(msg, "read/write on closed pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "endpoint is closed for send") ||
		strings.Contains(msg, "endpoint is closed for receive") ||
		strings.Contains(msg, "endpoint not connected"))
}

func (r *managedTunnelRelay) writePacket(packet []byte) (n int, err error) {
	if r == nil {
		return 0, net.ErrClosed
	}
	if r.ctx != nil {
		select {
		case <-r.ctx.Done():
			return 0, r.readError()
		default:
		}
	}
	if proto, ok := ipv4PacketProtocol(packet); ok {
		switch proto {
		case 6:
			if r.tcpBackend == nil {
				return 0, net.ErrClosed
			}
			if err = r.tcpBackend.injectIPv4Packet(packet); err != nil {
				return 0, err
			}
			return len(packet), nil
		}
	}
	return len(packet), nil
}

func (r *managedTunnelRelay) readPacket(buf []byte) (int, error) {
	for {
		var done <-chan struct{}
		if r.ctx != nil {
			done = r.ctx.Done()
		}
		select {
		case <-done:
			return 0, r.readError()
		default:
		}
		var packet managedOutboundPacket
		var ok bool
		select {
		case packet, ok = <-r.outboundCh:
		case <-done:
			return 0, r.readError()
		}
		if !ok {
			return 0, r.readError()
		}
		if packet.len() == 0 {
			packet.release()
			continue
		}
		if packet.len() > len(buf) {
			if r.tun != nil {
				r.tun.oversizePacketDrops.Add(1)
			}
			packet.release()
			continue
		}
		n := copy(buf, packet.data)
		packet.release()
		return n, nil
	}
}

func (r *managedTunnelRelay) readPacketSlice() ([]byte, error) {
	packet, release, err := r.readPacketBorrowed()
	if err != nil {
		return nil, err
	}
	if release == nil {
		return packet, nil
	}
	copied := make([]byte, len(packet))
	copy(copied, packet)
	release()
	return copied, nil
}

func (r *managedTunnelRelay) readPacketBorrowed() ([]byte, func(), error) {
	for {
		var done <-chan struct{}
		if r.ctx != nil {
			done = r.ctx.Done()
		}
		select {
		case <-done:
			return nil, nil, r.readError()
		default:
		}
		var packet managedOutboundPacket
		var ok bool
		select {
		case packet, ok = <-r.outboundCh:
		case <-done:
			return nil, nil, r.readError()
		}
		if !ok {
			return nil, nil, r.readError()
		}
		if packet.len() == 0 {
			packet.release()
			continue
		}
		return packet.data, packet.releaseFunc(), nil
	}
}

func (r *managedTunnelRelay) queueOutboundPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	return r.queueManagedOutboundPacket(managedOutboundPacket{data: packet})
}

func (r *managedTunnelRelay) queueManagedOutboundPacket(packet managedOutboundPacket) error {
	if packet.len() == 0 {
		packet.release()
		return nil
	}
	var done <-chan struct{}
	if r.ctx != nil {
		done = r.ctx.Done()
	}
	select {
	case <-done:
		packet.release()
		return net.ErrClosed
	default:
	}
	r.outboundMu.RLock()
	if r.outboundClosed {
		r.outboundMu.RUnlock()
		packet.release()
		return net.ErrClosed
	}
	defer r.outboundMu.RUnlock()
	// Fast path: avoid cancellation overhead unless the outbound queue is full.
	select {
	case r.outboundCh <- packet:
		return nil
	default:
	}
	select {
	case r.outboundCh <- packet:
		return nil
	case <-done:
		packet.release()
		return net.ErrClosed
	}
}

func (r *managedTunnelRelay) copyAndQueueOutboundPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	copied, pooled := getManagedTunnelOutboundBuffer(len(packet))
	copy(copied, packet)
	return r.queueManagedOutboundPacket(managedOutboundPacket{data: copied, pooled: pooled})
}

func (r *managedTunnelRelay) copyOutboundLoop(reader managedOutboundReader) {
	defer r.copyWG.Done()
	if err := copyOutboundPacketsToChannel(r.ctx, reader, r); isUnexpectedManagedTunnelCloseError(err) {
		r.fail(err)
	}
}

func (r *managedTunnelRelay) fail(err error) {
	if err == nil {
		return
	}
	r.failureMu.Lock()
	if r.failureErr == nil {
		r.failureErr = err
	}
	r.failureMu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	// close waits for the outbound copy goroutine, so it must not run inline
	// from that goroutine's failure path.
	go func() { _ = r.close() }()
}

func (r *managedTunnelRelay) readError() error {
	r.failureMu.Lock()
	defer r.failureMu.Unlock()
	if r.failureErr != nil {
		return r.failureErr
	}
	return net.ErrClosed
}

func (r *managedTunnelRelay) handleTCPForwarder(flowReq managedTCPForwardedFlow) {
	if flowReq == nil {
		return
	}
	release, ok := r.acquireFlowSlot()
	if !ok {
		flowReq.reject()
		return
	}
	go r.startTCPFlow(flowReq, release)
}

func (r *managedTunnelRelay) startTCPFlow(flowReq managedTCPForwardedFlow, release func()) {
	openResult, err := flowReq.open()
	if err != nil {
		release()
		flowReq.reject()
		return
	}
	r.startManagedFlowWithSlot(openResult.dest, openResult.localConn, release)
}

func (r *managedTunnelRelay) startManagedFlow(dest coretransport.Destination, localConn net.Conn) {
	release, ok := r.acquireFlowSlot()
	if !ok {
		if !extension.IsNil(localConn) {
			_ = extension.Do("TalariaTCP local flow close", localConn.Close)
		}
		return
	}
	r.startManagedFlowWithSlot(dest, localConn, release)
}

func (r *managedTunnelRelay) startManagedFlowWithSlot(dest coretransport.Destination, localConn net.Conn, release func()) {
	if extension.IsNil(localConn) {
		release()
		return
	}
	streamTransport := r.streamTransport
	if extension.IsNil(streamTransport) && r.tun != nil {
		streamTransport = r.tun.currentStreamTransport()
	}
	if extension.IsNil(streamTransport) {
		_ = extension.Do("TalariaTCP local flow close", localConn.Close)
		release()
		return
	}
	parentCtx := r.parentCtx
	if parentCtx == nil && r.tun != nil {
		parentCtx = r.tun.currentContext()
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	flowCtx, cancel := context.WithCancel(parentCtx)
	flow := &managedTunnelFlow{
		cancel:    cancel,
		localConn: localConn,
	}
	flowID := r.nextFlowID.Add(1)

	r.flowMu.Lock()
	if r.flowsClosed {
		r.flowMu.Unlock()
		_ = flow.close()
		release()
		return
	}
	r.flows[flowID] = flow
	r.flowMu.Unlock()

	go func() {
		defer func() {
			r.flowMu.Lock()
			delete(r.flows, flowID)
			r.flowMu.Unlock()
			_ = flow.close()
			release()
		}()
		var remoteConn net.Conn
		err := extension.Do("TalariaTCP stream dial", func() error {
			var dialErr error
			remoteConn, dialErr = streamTransport.DialStream(flowCtx, dest)
			return dialErr
		})
		if err != nil {
			if !extension.IsNil(remoteConn) {
				_ = extension.Do("TalariaTCP failed remote flow close", remoteConn.Close)
			}
			if errors.Is(err, extension.ErrPanic) {
				r.fail(err)
			}
			return
		}
		if extension.IsNil(remoteConn) {
			r.fail(errors.New("TalariaTCP stream transport returned a nil connection"))
			return
		}
		if !flow.setRemoteConn(remoteConn) {
			return
		}
		_ = coretransport.Relay(flowCtx, localConn, remoteConn)
	}()
}

func (r *managedTunnelRelay) acquireFlowSlot() (func(), bool) {
	flowBytes := int64(2 * managedTunnelTCPBufferMax)
	r.flowMu.Lock()
	if r.flowsClosed {
		r.flowMu.Unlock()
		return nil, false
	}
	if flowBytes > managedTunnelTCPRelayByteLimit-r.flowBytes {
		r.flowMu.Unlock()
		return nil, false
	}
	if r.flowSlots == nil {
		r.flowSlots = make(chan struct{}, managedTunnelTCPMaxInFlight)
	}
	flowSlots := r.flowSlots
	r.flowBytes += flowBytes
	r.flowMu.Unlock()
	releaseRelayBytes := func() {
		r.flowMu.Lock()
		r.flowBytes -= flowBytes
		r.flowMu.Unlock()
	}
	select {
	case managedTunnelTCPGlobalSlots <- struct{}{}:
	default:
		releaseRelayBytes()
		return nil, false
	}
	if !reserveManagedTunnelTCPGlobalBytes(flowBytes) {
		<-managedTunnelTCPGlobalSlots
		releaseRelayBytes()
		return nil, false
	}
	select {
	case flowSlots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-flowSlots
				managedTunnelTCPGlobalBytes.Add(-flowBytes)
				<-managedTunnelTCPGlobalSlots
				releaseRelayBytes()
			})
		}, true
	default:
		managedTunnelTCPGlobalBytes.Add(-flowBytes)
		<-managedTunnelTCPGlobalSlots
		releaseRelayBytes()
		return nil, false
	}
}

func reserveManagedTunnelTCPGlobalBytes(n int64) bool {
	for {
		used := managedTunnelTCPGlobalBytes.Load()
		if n > managedTunnelTCPGlobalByteLimit-used {
			return false
		}
		if managedTunnelTCPGlobalBytes.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (f *managedTunnelFlow) close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	cancel := f.cancel
	localConn := f.localConn
	remoteConn := f.remoteConn
	f.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if !extension.IsNil(localConn) {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP local flow close", localConn.Close))
	}
	if !extension.IsNil(remoteConn) {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP remote flow close", remoteConn.Close))
	}
	return closeErr
}

func (f *managedTunnelFlow) setRemoteConn(conn net.Conn) bool {
	if extension.IsNil(conn) {
		return false
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = extension.Do("TalariaTCP late remote flow close", conn.Close)
		return false
	}
	f.remoteConn = conn
	f.mu.Unlock()
	return true
}

func newManagedGVisorTCPBackend(maxPacket int, flowHandler func(managedTCPForwardedFlow)) (*managedGVisorTCPBackend, error) {
	linkQueueCap := managedTunnelGVisorLinkQueueSize()
	linkEP := channel.New(linkQueueCap, uint32(managedGVisorLinkMTU(maxPacket)), "")
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			gipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			gtcp.NewProtocol,
		},
	})
	if err := toStdError(stk.CreateNIC(managedTunnelNICID, linkEP)); err != nil {
		linkEP.Close()
		return nil, fmt.Errorf("create TalariaTCP nic: %w", err)
	}
	if err := toStdError(stk.SetPromiscuousMode(managedTunnelNICID, true)); err != nil {
		linkEP.Close()
		return nil, fmt.Errorf("enable TalariaTCP promiscuous mode: %w", err)
	}
	if err := toStdError(stk.SetSpoofing(managedTunnelNICID, true)); err != nil {
		linkEP.Close()
		return nil, fmt.Errorf("enable TalariaTCP spoofing: %w", err)
	}
	if err := configureManagedTCPStack(stk); err != nil {
		linkEP.Close()
		return nil, err
	}
	stk.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         managedTunnelNICID,
	}})
	tcpForwarder := gtcp.NewForwarder(stk, 0, managedTunnelTCPMaxInFlight, func(req *gtcp.ForwarderRequest) {
		if flowHandler != nil {
			flowHandler(&managedGVisorTCPForwardedFlow{req: req})
		}
	})
	stk.SetTransportProtocolHandler(gtcp.ProtocolNumber, tcpForwarder.HandlePacket)
	return &managedGVisorTCPBackend{
		stack:        stk,
		linkEP:       linkEP,
		linkQueueCap: linkQueueCap,
	}, nil
}

func (b *managedGVisorTCPBackend) injectIPv4Packet(raw []byte) error {
	if b == nil || b.linkEP == nil {
		return net.ErrClosed
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	b.linkEP.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
	return nil
}

func (b *managedGVisorTCPBackend) outboundReader() managedOutboundReader {
	if b == nil {
		return nil
	}
	return b.linkEP
}

func (b *managedGVisorTCPBackend) linkQueueStats() (int, int) {
	if b == nil || b.linkEP == nil {
		return 0, 0
	}
	return b.linkEP.NumQueued(), b.linkQueueCap
}

func (b *managedGVisorTCPBackend) close() error {
	if b == nil {
		return nil
	}
	if b.linkEP != nil {
		b.linkEP.Close()
	}
	if b.stack != nil {
		b.stack.Close()
		b.stack.Wait()
	}
	return nil
}

func (f *managedGVisorTCPForwardedFlow) open() (*managedTCPOpenResult, error) {
	if f == nil || f.req == nil {
		return nil, fmt.Errorf("nil TalariaTCP flow")
	}
	id := f.req.ID()
	dstAddr, dstPort, ok := transportEndpointLocal(id)
	if !ok {
		return nil, fmt.Errorf("invalid destination endpoint")
	}

	var wq waiter.Queue
	ep, epErr := f.req.CreateEndpoint(&wq)
	if epErr != nil {
		return nil, fmt.Errorf("create endpoint: %w", toStdError(epErr))
	}
	f.req.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	return &managedTCPOpenResult{
		localConn: gonet.NewTCPConn(&wq, ep),
		dest: coretransport.Destination{
			Network: coretransport.NetworkTCP,
			Host:    dstAddr.String(),
			Port:    dstPort,
		},
	}, nil
}

func (f *managedGVisorTCPForwardedFlow) reject() {
	if f == nil || f.req == nil {
		return
	}
	f.req.Complete(true)
}

func copyOutboundPacketsToChannel(ctx context.Context, reader managedOutboundReader, relay *managedTunnelRelay) error {
	if relay == nil {
		return net.ErrClosed
	}
	for {
		pkt := reader.ReadContext(ctx)
		if pkt == nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}
		outbound, err := packetBufferToOutboundPacket(pkt)
		pkt.DecRef()
		if err != nil {
			return err
		}
		if outbound.len() == 0 {
			continue
		}
		if err := relay.queueManagedOutboundPacket(outbound); err != nil {
			return err
		}
	}
}

func packetBufferToOutboundPacket(pkt *stack.PacketBuffer) (managedOutboundPacket, error) {
	if pkt == nil {
		return managedOutboundPacket{}, nil
	}
	total := pkt.Size()
	if total <= 0 {
		return managedOutboundPacket{}, nil
	}
	out, pooled := getManagedTunnelOutboundBuffer(total)
	offset := copyPacketBufferData(out, pkt, total)
	if offset != total {
		if pooled {
			putManagedTunnelOutboundBuffer(out)
		}
		return managedOutboundPacket{}, fmt.Errorf("unexpected packet size %d != %d", offset, total)
	}
	return managedOutboundPacket{data: out, pooled: pooled}, nil
}

func copyPacketBufferData(dst []byte, pkt *stack.PacketBuffer, total int) int {
	views, skip := pkt.AsViewList()
	offset := 0
	for view := views.Front(); view != nil && offset < total; view = view.Next() {
		src := view.AsSlice()
		if skip >= len(src) {
			skip -= len(src)
			continue
		}
		if skip > 0 {
			src = src[skip:]
			skip = 0
		}
		remain := total - offset
		if len(src) > remain {
			src = src[:remain]
		}
		offset += copy(dst[offset:], src)
	}
	return offset
}

func getManagedTunnelOutboundBuffer(size int) ([]byte, bool) {
	if size <= 0 {
		return nil, false
	}
	if size > managedTunnelOutboundBufferPoolMaxCap || !managedTunnelOutboundBufferPoolEnabled() {
		return make([]byte, size), false
	}
	for {
		raw := managedTunnelOutboundBufferPool.Get()
		if raw == nil {
			return make([]byte, size), true
		}
		buf, ok := raw.([]byte)
		if ok && cap(buf) >= size {
			return buf[:size], true
		}
	}
}

func putManagedTunnelOutboundBuffer(buf []byte) {
	if cap(buf) == 0 || cap(buf) > managedTunnelOutboundBufferPoolMaxCap {
		return
	}
	managedTunnelOutboundBufferPool.Put(buf[:0])
}

func ipv4PacketProtocol(pkt []byte) (byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	headerLen := int(pkt[0]&0x0f) * 4
	if headerLen < 20 || len(pkt) < headerLen {
		return 0, false
	}
	totalLen := int(pkt[2])<<8 | int(pkt[3])
	if totalLen < headerLen || len(pkt) < totalLen {
		return 0, false
	}
	return pkt[9], true
}

func transportEndpointLocal(id stack.TransportEndpointID) (netip.Addr, uint16, bool) {
	addr, ok := tcpipAddrToNetip(id.LocalAddress)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr, id.LocalPort, true
}

func tcpipAddrToNetip(addr tcpip.Address) (netip.Addr, bool) {
	raw := addr.AsSlice()
	if len(raw) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
}

func toStdError(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return errors.New(err.String())
}

func configureManagedTCPStack(stk *stack.Stack) error {
	if stk == nil {
		return fmt.Errorf("nil TalariaTCP stack")
	}

	sendRange := tcpip.TCPSendBufferSizeRangeOption{
		Min:     managedTunnelTCPBufferMin,
		Default: managedTunnelTCPBufferDefault,
		Max:     managedTunnelTCPBufferMax,
	}
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &sendRange)); err != nil {
		return fmt.Errorf("set TalariaTCP send buffer range: %w", err)
	}

	recvRange := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     managedTunnelTCPBufferMin,
		Default: managedTunnelTCPBufferDefault,
		Max:     managedTunnelTCPBufferMax,
	}
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &recvRange)); err != nil {
		return fmt.Errorf("set TalariaTCP receive buffer range: %w", err)
	}

	moderateReceiveBuffer := tcpip.TCPModerateReceiveBufferOption(true)
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &moderateReceiveBuffer)); err != nil {
		return fmt.Errorf("enable TalariaTCP receive buffer moderation: %w", err)
	}

	sackEnabled := tcpip.TCPSACKEnabled(true)
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &sackEnabled)); err != nil {
		return fmt.Errorf("enable TalariaTCP sack: %w", err)
	}

	recovery := managedTunnelTCPRecovery()
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &recovery)); err != nil {
		return fmt.Errorf("set TalariaTCP recovery: %w", err)
	}

	delayEnabled := tcpip.TCPDelayEnabled(false)
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &delayEnabled)); err != nil {
		return fmt.Errorf("disable TalariaTCP nagle: %w", err)
	}

	congestionControl := tcpip.CongestionControlOption("cubic")
	if err := toStdError(stk.SetTransportProtocolOption(gtcp.ProtocolNumber, &congestionControl)); err != nil {
		return fmt.Errorf("set TalariaTCP congestion control: %w", err)
	}

	return nil
}
