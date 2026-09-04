// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package defaults provides the built-in Talaria client transport adapters.
package defaults

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	talariaTCPDevice "github.com/X-VPN/Talaria/client/flowrelay"
	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/lifecycle"
	"github.com/X-VPN/Talaria/protocol/udptls"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
	"github.com/X-VPN/Talaria/transport/socks5tls"
)

const (
	authReadTimeout                 = 6 * time.Second
	defaultControlKeepAliveInterval = time.Second
)

// NewSession constructs a client session with the built-in transport selected by cfg.Protocol.
func NewSession(cfg client.Config, tun client.TunProvider, opt ClientOptions) (client.Session, error) {
	protocol, err := client.ParseProtocol(string(cfg.Protocol))
	if err != nil {
		return nil, fmt.Errorf("Talaria client: %w", err)
	}
	cfg.Protocol = protocol
	return client.NewSession(cfg, NewDeps(cfg, tun, opt))
}

// NewDeps selects only the dependencies for an exact supported protocol.
func NewDeps(cfg client.Config, tun client.TunProvider, opt ClientOptions) client.Deps {
	deps := client.Deps{
		Tun:    tun,
		Events: opt.Events,
		Stats:  opt.Stats,
	}
	protocol, err := client.ParseProtocol(string(cfg.Protocol))
	if err != nil {
		return deps
	}
	switch protocol {
	case client.ProtocolTalariaTCP:
		deps.Endpoint = TalariaTCPEndpointProvider{Options: opt}
	case client.ProtocolTalariaUDP:
		deps.Dialer = TalariaUDPDialerProvider{Options: opt}
	}
	return deps
}

// TalariaUDPDialerProvider supplies the built-in TalariaUDP transport.
type TalariaUDPDialerProvider struct {
	Options ClientOptions
}

// Dial opens an authenticated TalariaUDP connection for an exact TalariaUDP request.
func (p TalariaUDPDialerProvider) Dial(ctx context.Context, req client.DialRequest) (net.Conn, error) {
	protocol, err := client.ParseProtocol(string(req.Protocol))
	if err != nil {
		return nil, fmt.Errorf("TalariaUDP client dialer: %w", err)
	}
	if protocol != client.ProtocolTalariaUDP {
		return nil, errors.New("TalariaUDP client dialer requires TalariaUDP")
	}
	closer := p.Options.Closer
	if closer == nil {
		closer = lifecycle.NewCloser()
	}
	parentDial := p.Options.ParentDial
	if parentDial == nil {
		parentDial = defaultNetDialer(ctx)
	}
	domain := firstNonEmpty(p.Options.Domain, req.Domain)
	if domain == "" {
		return nil, errors.New("TalariaUDP client requires a TLS server name")
	}
	tlsConfig := clientTLSConfig(p.Options.TLSConfig, domain)
	if tlsConfig.InsecureSkipVerify {
		return nil, errors.New("TalariaUDP client requires certificate verification")
	}
	dialer := udptls.NewDialer(udptls.NewDialerReq{
		ParentDial:                  parentDial,
		ParentDialAlreadyHasTimeout: true,
		Closer:                      closer,
		TLSConfig:                   tlsConfig,
		MaxPacket:                   dataplane.ConnReadBufferSize(dataplane.MaxMTU),
		WireSecret:                  []byte(p.Options.TalariaUDPWireSecret),
		WireIdentity:                p.Options.TalariaUDPWireIdentity,
		WireProfile:                 udptls.WireProfileSecure,
	})
	host := firstNonEmpty(req.ServerIP, req.Domain, "127.0.0.1")
	port := req.ServerPort
	if port == 0 {
		return nil, errors.New("TalariaUDP client: missing server port")
	}
	return dialer("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// TalariaTCPEndpointProvider supplies the built-in TalariaTCP endpoint.
type TalariaTCPEndpointProvider struct {
	Options ClientOptions
}

// DialEndpoint opens an authenticated TalariaTCP endpoint.
func (p TalariaTCPEndpointProvider) DialEndpoint(ctx context.Context, req client.EndpointDialRequest) (client.EndpointConn, error) {
	protocol, err := client.ParseProtocol(string(req.Protocol))
	if err != nil {
		return nil, fmt.Errorf("TalariaTCP client endpoint: %w", err)
	}
	if !client.ProtocolSupportedOnCurrentPlatform(protocol) {
		return nil, fmt.Errorf("TalariaTCP client endpoint: protocol %s is not supported on this platform", protocol)
	}
	domain := firstNonEmpty(p.Options.Domain, req.Domain)
	if domain == "" {
		return nil, errors.New("TalariaTCP client endpoint requires a TLS server name")
	}
	if req.ServerPort == 0 {
		return nil, errors.New("TalariaTCP client endpoint: missing server port")
	}
	serverAddr := net.JoinHostPort(firstNonEmpty(req.ServerIP, req.Domain, "127.0.0.1"), strconv.Itoa(int(req.ServerPort)))
	var dialContext socks5tls.DialContextFunc
	if p.Options.ParentDial != nil {
		dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
			return p.Options.ParentDial(network, address)
		}
	}
	streamTransport := p.Options.Transport
	if streamTransport == nil {
		streamTransport, err = socks5tls.NewClient(socks5tls.ClientConfig{
			Address:              serverAddr,
			TLSConfig:            clientTLSConfig(p.Options.TLSConfig, domain),
			DialContext:          dialContext,
			EstablishmentTimeout: p.Options.EstablishmentTimeout,
			WireIdentity:         p.Options.TalariaTCPWireIdentity,
			WireSecret:           []byte(p.Options.TalariaTCPWireSecret),
		})
		if err != nil {
			return nil, err
		}
	}
	if extension.IsNil(streamTransport) {
		return nil, errors.New("TalariaTCP client endpoint: transport is nil")
	}
	var ctrlConn net.Conn
	err = extension.Do("TalariaTCP client control dial", func() error {
		var dialErr error
		ctrlConn, dialErr = streamTransport.DialControl(ctx)
		return dialErr
	})
	if err != nil {
		closeTalariaTCPDialResources(ctrlConn, streamTransport)
		return nil, err
	}
	if extension.IsNil(ctrlConn) {
		_ = extension.Do("TalariaTCP client transport close", streamTransport.Close)
		return nil, errors.New("TalariaTCP client endpoint: transport returned nil control connection")
	}
	var grant coretransport.SessionGrant
	err = extension.Do("TalariaTCP client control authentication", func() error {
		var authErr error
		grant, authErr = authenticateControlConn(ctx, ctrlConn, req)
		return authErr
	})
	if err != nil {
		closeTalariaTCPDialResources(ctrlConn, streamTransport)
		return nil, err
	}
	defer clear(grant.DataToken[:])
	if err := extension.Do("TalariaTCP client transport activation", func() error {
		return streamTransport.Activate(ctx, grant)
	}); err != nil {
		closeTalariaTCPDialResources(ctrlConn, streamTransport)
		return nil, err
	}
	deviceTun := new(talariaTCPDevice.TUN)
	if err := deviceTun.InitClientEndpoint(ctx, string(protocol), streamTransport); err != nil {
		closeTalariaTCPDialResources(ctrlConn, streamTransport)
		return nil, err
	}
	endpointCtx, cancel := context.WithCancel(ctx)
	endpoint := &talariaTCPEndpoint{
		ctrlConn:          ctrlConn,
		transport:         streamTransport,
		device:            deviceTun,
		clientID:          grant.ClientID,
		cancel:            cancel,
		keepAliveInterval: defaultControlKeepAliveInterval,
		keepAliveTimeout:  req.KeepAliveDuration,
	}
	endpoint.markControlReceive(time.Now())
	go endpoint.runControlLoop(endpointCtx)
	go endpoint.runControlKeepAlive(endpointCtx)
	return endpoint, nil
}

func closeTalariaTCPDialResources(conn net.Conn, transport coretransport.Client) {
	if !extension.IsNil(conn) {
		_ = extension.Do("TalariaTCP client control close", conn.Close)
	}
	if !extension.IsNil(transport) {
		_ = extension.Do("TalariaTCP client transport close", transport.Close)
	}
}

// authenticateControlConn authenticates, validates the data grant, and waits for the final server-ready barrier.
func authenticateControlConn(ctx context.Context, conn net.Conn, req client.EndpointDialRequest) (coretransport.SessionGrant, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	codec := dataplane.WireCodec{}
	authPacket := &vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      req.ClientID,
		Sk:      req.SecretKey,
		Version: DefaultAuthVersion,
	}
	authRaw, err := codec.Encode(authPacket)
	authPacket.Sk = ""
	req.SecretKey = ""
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	defer clear(authRaw)
	authTimeout := req.AuthTimeout
	if authTimeout <= 0 {
		authTimeout = authReadTimeout
	}
	authCtx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	deadline, _ := authCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return coretransport.SessionGrant{}, fmt.Errorf("set control auth deadline: %w", err)
	}
	stopCloseOnAuthDone := context.AfterFunc(authCtx, func() {
		_ = extension.Do("TalariaTCP client canceled auth close", conn.Close)
	})
	defer stopCloseOnAuthDone()
	deadlineCleared := false
	defer func() {
		if !deadlineCleared {
			_ = conn.SetDeadline(time.Time{})
		}
	}()
	if err := writeControlFrame(conn, authRaw); err != nil {
		if ctxErr := authCtx.Err(); ctxErr != nil {
			return coretransport.SessionGrant{}, ctxErr
		}
		return coretransport.SessionGrant{}, err
	}
	if err := authCtx.Err(); err != nil {
		return coretransport.SessionGrant{}, err
	}
	clear(authRaw)
	authRaw = nil
	buf := make([]byte, 2048)
	n, err := readControlFrame(conn, buf)
	if err != nil {
		if ctxErr := authCtx.Err(); ctxErr != nil {
			return coretransport.SessionGrant{}, ctxErr
		}
		return coretransport.SessionGrant{}, err
	}
	if err := authCtx.Err(); err != nil {
		return coretransport.SessionGrant{}, err
	}
	packet, _, err := codec.Decode(buf[:n])
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("%w: %s", client.ErrAuthRejected, packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdAuthSuccess {
		return coretransport.SessionGrant{}, fmt.Errorf("unexpected auth response cmd=%d", packet.Cmd)
	}
	clientID := packet.NewClientId
	n, err = readControlFrame(conn, buf)
	if err != nil {
		if ctxErr := authCtx.Err(); ctxErr != nil {
			return coretransport.SessionGrant{}, ctxErr
		}
		return coretransport.SessionGrant{}, fmt.Errorf("read session grant: %w", err)
	}
	if err := authCtx.Err(); err != nil {
		return coretransport.SessionGrant{}, err
	}
	packet, _, err = codec.Decode(buf[:n])
	if err != nil {
		return coretransport.SessionGrant{}, fmt.Errorf("decode session grant: %w", err)
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("%w: %s", client.ErrAuthRejected, packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdSessionGrant {
		return coretransport.SessionGrant{}, fmt.Errorf("unexpected session grant cmd=%d", packet.Cmd)
	}
	if packet.ClientId != clientID {
		return coretransport.SessionGrant{}, errors.New("session grant client id does not match authentication")
	}
	if len(packet.SessionDataToken) != coretransport.DataTokenSize {
		return coretransport.SessionGrant{}, errors.New("session grant token has invalid length")
	}
	grant := coretransport.SessionGrant{
		SessionRef: coretransport.SessionRef{
			ClientID:   clientID,
			Generation: packet.SessionGeneration,
		},
	}
	defer clear(grant.DataToken[:])
	if packet.SessionExpiresAt > 0 {
		grant.ExpiresAt = time.Unix(packet.SessionExpiresAt, 0)
	}
	copy(grant.DataToken[:], packet.SessionDataToken)
	clear(packet.SessionDataToken)
	packet.SessionDataToken = nil
	if err := grant.Validate(time.Now()); err != nil {
		return coretransport.SessionGrant{}, err
	}
	ready := false
	defer func() {
		if !ready {
			clear(grant.DataToken[:])
		}
	}()
	n, err = readControlFrame(conn, buf)
	if err != nil {
		if ctxErr := authCtx.Err(); ctxErr != nil {
			return coretransport.SessionGrant{}, ctxErr
		}
		return coretransport.SessionGrant{}, fmt.Errorf("read session ready: %w", err)
	}
	if err := authCtx.Err(); err != nil {
		return coretransport.SessionGrant{}, err
	}
	packet, _, err = codec.Decode(buf[:n])
	if err != nil {
		return coretransport.SessionGrant{}, fmt.Errorf("decode session ready: %w", err)
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("%w: %s", client.ErrAuthRejected, packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdSessionReady {
		return coretransport.SessionGrant{}, fmt.Errorf("unexpected session ready cmd=%d", packet.Cmd)
	}
	if packet.ClientId != grant.ClientID {
		return coretransport.SessionGrant{}, errors.New("session ready client id does not match grant")
	}
	if err := authCtx.Err(); err != nil {
		return coretransport.SessionGrant{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return coretransport.SessionGrant{}, fmt.Errorf("reset control auth deadline: %w", err)
	}
	deadlineCleared = true
	ready = true
	return grant, nil
}

type talariaTCPEndpoint struct {
	ctrlConn     net.Conn
	transport    coretransport.Client
	device       *talariaTCPDevice.TUN
	clientID     uint64
	cancel       context.CancelFunc
	dataSeq      atomic.Uint32
	keepAliveSeq atomic.Uint32
	closeState   atomic.Uint32
	closeErr     error

	keepAliveInterval time.Duration
	keepAliveTimeout  time.Duration
	lastControlRecv   atomic.Int64

	errMu      sync.RWMutex
	controlErr error
}

func (e *talariaTCPEndpoint) ReadPacket() (*vpnpacket.VpnPacket, error) {
	packet, err := e.device.ReadPacket()
	if err != nil {
		return nil, err
	}
	return &vpnpacket.VpnPacket{
		Cmd:      vpnpacket.CmdData,
		ClientId: e.clientID,
		Data:     packet,
	}, nil
}

func (e *talariaTCPEndpoint) WriteData(payload []byte) error {
	if !isIPv4TCPPacket(payload) {
		return e.writeControlData(payload)
	}
	_, err := e.device.Write(payload)
	return err
}

func (e *talariaTCPEndpoint) ReadPayloadBorrowed() ([]byte, func(), error) {
	payload, release, err := e.device.ReadPacketBorrowed()
	return payload, release, e.preferControlError(err)
}

func (e *talariaTCPEndpoint) ReadPacketBuffer(pkt *dataplane.PacketBuffer) (*vpnpacket.VpnPacket, bool, error) {
	if pkt == nil {
		return nil, false, errors.New("nil packet buffer")
	}
	packet, release, err := e.device.ReadPacketBorrowed()
	if err != nil {
		return nil, false, e.preferControlError(err)
	}
	defer releasePacket(release)
	if len(packet) == 0 {
		return &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, ClientId: e.clientID}, false, nil
	}
	if len(packet) > len(pkt.Raw)-pkt.Start {
		return nil, false, io.ErrShortBuffer
	}
	copy(pkt.Raw[pkt.Start:], packet)
	pkt.End = pkt.Start + len(packet)
	return &vpnpacket.VpnPacket{
		Cmd:      vpnpacket.CmdData,
		ClientId: e.clientID,
		Data:     pkt.Bytes(),
	}, true, nil
}

func (e *talariaTCPEndpoint) WriteDataBuffer(pkt *dataplane.PacketBuffer) error {
	if pkt == nil || pkt.Len() == 0 {
		return nil
	}
	return e.WriteData(pkt.Bytes())
}

func (e *talariaTCPEndpoint) WritePacket(packet *vpnpacket.VpnPacket) error {
	raw, err := dataplane.WireCodec{}.Encode(packet)
	if err != nil {
		return err
	}
	return writeControlFrame(e.ctrlConn, raw)
}

func (e *talariaTCPEndpoint) Close() error {
	if e == nil {
		return nil
	}
	if !e.closeState.CompareAndSwap(0, 1) {
		if e.closeState.Load() != 2 {
			return nil
		}
		e.errMu.RLock()
		err := e.closeErr
		e.errMu.RUnlock()
		return err
	}
	if e.cancel != nil {
		e.cancel()
	}
	var closeErr error
	if e.device != nil {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP client device close", e.device.Close))
	}
	if !extension.IsNil(e.ctrlConn) {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP client control close", e.ctrlConn.Close))
	}
	if !extension.IsNil(e.transport) {
		closeErr = errors.Join(closeErr, extension.Do("TalariaTCP client transport close", e.transport.Close))
	}
	e.errMu.Lock()
	e.closeErr = closeErr
	e.errMu.Unlock()
	e.closeState.Store(2)
	return closeErr
}

func (e *talariaTCPEndpoint) writeControlData(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	raw, err := dataplane.WireCodec{}.Encode(&vpnpacket.VpnPacket{
		Cmd:            vpnpacket.CmdData,
		ClientId:       e.clientID,
		DataSequenceId: e.dataSeq.Add(1),
		Data:           payload,
	})
	if err != nil {
		return err
	}
	return writeControlFrame(e.ctrlConn, raw)
}

func (e *talariaTCPEndpoint) runControlLoop(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			e.failControl(ctx, extension.PanicError("TalariaTCP client control loop", recovered))
		}
	}()
	buf := make([]byte, 64*1024)
	codec := dataplane.WireCodec{}
	for {
		n, err := readControlFrame(e.ctrlConn, buf)
		if err != nil {
			e.failControl(ctx, err)
			return
		}
		packet, _, err := codec.Decode(buf[:n])
		if err != nil {
			e.failControl(ctx, err)
			return
		}
		e.markControlReceive(time.Now())
		switch packet.Cmd {
		case vpnpacket.CmdData, vpnpacket.CmdDataReturn:
			if err := e.device.QueuePacket(packet.Data); err != nil {
				e.failControl(ctx, err)
				return
			}
		case vpnpacket.CmdKeepAlive:
			if packet.IsPing {
				if err := e.WritePacket(&vpnpacket.VpnPacket{
					Cmd:         vpnpacket.CmdKeepAlive,
					ClientId:    e.clientID,
					KeepAliveId: packet.KeepAliveId,
					SendTime:    packet.SendTime,
				}); err != nil {
					e.failControl(ctx, err)
					return
				}
			}
		case vpnpacket.CmdServerKeepAlive:
			if err := e.WritePacket(&vpnpacket.VpnPacket{
				Cmd:         vpnpacket.CmdServerKeepAlive,
				ClientId:    e.clientID,
				KeepAliveId: packet.KeepAliveId,
			}); err != nil {
				e.failControl(ctx, err)
				return
			}
		case vpnpacket.CmdErr:
			e.failControl(ctx, errors.New(packet.ErrorMessage))
			return
		}
	}
}

func (e *talariaTCPEndpoint) runControlKeepAlive(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			e.failControl(ctx, extension.PanicError("TalariaTCP client keepalive loop", recovered))
		}
	}()
	interval := e.keepAliveInterval
	if interval <= 0 {
		interval = defaultControlKeepAliveInterval
	}
	timeout := e.keepAliveTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if age := e.controlReceiveAge(now); age >= timeout {
				e.failControl(ctx, fmt.Errorf("TalariaTCP control keepalive timeout after %s", age.Truncate(time.Millisecond)))
				return
			}
			if err := e.WritePacket(&vpnpacket.VpnPacket{
				Cmd:         vpnpacket.CmdKeepAlive,
				ClientId:    e.clientID,
				KeepAliveId: e.keepAliveSeq.Add(1),
				SendTime:    now.UnixNano(),
				IsPing:      true,
			}); err != nil {
				e.failControl(ctx, fmt.Errorf("TalariaTCP control keepalive: %w", err))
				return
			}
		}
	}
}

func (e *talariaTCPEndpoint) markControlReceive(now time.Time) {
	e.lastControlRecv.Store(now.UnixNano())
}

func (e *talariaTCPEndpoint) controlReceiveAge(now time.Time) time.Duration {
	last := e.lastControlRecv.Load()
	if last == 0 {
		return 0
	}
	age := now.Sub(time.Unix(0, last))
	if age < 0 {
		return 0
	}
	return age
}

func (e *talariaTCPEndpoint) failControl(ctx context.Context, err error) {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	e.errMu.Lock()
	if e.controlErr == nil {
		e.controlErr = err
	}
	e.errMu.Unlock()
	_ = e.Close()
}

func (e *talariaTCPEndpoint) preferControlError(err error) error {
	if err == nil {
		return nil
	}
	e.errMu.RLock()
	controlErr := e.controlErr
	e.errMu.RUnlock()
	if controlErr != nil {
		return controlErr
	}
	return err
}

func isIPv4TCPPacket(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return false
	}
	totalLen := int(packet[2])<<8 | int(packet[3])
	return totalLen >= headerLen && totalLen <= len(packet) && packet[9] == 6
}

func clientTLSConfig(cfg *tls.Config, domain string) *tls.Config {
	if cfg != nil {
		clone := cfg.Clone()
		if clone.ServerName == "" {
			clone.ServerName = domain
		}
		if clone.RootCAs == nil {
			clone.RootCAs = systemCertPool()
		}
		return clone
	}
	return &tls.Config{ServerName: domain, RootCAs: systemCertPool()}
}

func systemCertPool() *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return x509.NewCertPool()
	}
	return roots
}

func (e *talariaTCPEndpoint) ClientID() uint64 {
	return e.clientID
}

func (e *talariaTCPEndpoint) LocalAddr() string {
	if e == nil || extension.IsNil(e.ctrlConn) {
		return ""
	}
	var local net.Addr
	if extension.Run("TalariaTCP client local address", func() { local = e.ctrlConn.LocalAddr() }) != nil || extension.IsNil(local) {
		return ""
	}
	var address string
	_ = extension.Run("TalariaTCP client local address string", func() { address = local.String() })
	return address
}

func defaultNetDialer(ctx context.Context) func(network, address string) (net.Conn, error) {
	return func(network string, address string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: authReadTimeout}
		return dialer.DialContext(ctx, network, address)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func releasePacket(release func()) {
	if release != nil {
		release()
	}
}

func writeControlFrame(conn net.Conn, frame []byte) error {
	if extension.IsNil(conn) {
		return net.ErrClosed
	}
	n, err := conn.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func readControlFrame(conn net.Conn, frame []byte) (int, error) {
	n, err := conn.Read(frame)
	if n < 0 || n > len(frame) {
		return 0, fmt.Errorf("TalariaTCP client control returned invalid read size %d for %d-byte buffer", n, len(frame))
	}
	return n, err
}
