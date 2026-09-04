// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package flowrelay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/X-VPN/Talaria/internal/extension"
	coretransport "github.com/X-VPN/Talaria/transport"
)

type TUN struct {
	ctxLock sync.RWMutex

	ctx              context.Context
	endpointProtocol string
	streamTransport  coretransport.Client
	generation       uint64

	sendCallback func([]byte) error
	recvCallback func([]byte) error

	oversizePacketDrops atomic.Uint64

	relay *managedTunnelRelay
}

func (t *TUN) InitClientEndpoint(ctx context.Context, vpnNetworkProtocol string, streamTransport coretransport.Client) error {
	if t == nil {
		return net.ErrClosed
	}
	if extension.IsNil(streamTransport) {
		return fmt.Errorf("stream transport is required for %s", vpnNetworkProtocol)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.ctxLock.Lock()
	oldRelay := t.relay
	t.relay = nil
	t.generation++
	generation := t.generation
	t.ctx = ctx
	t.endpointProtocol = vpnNetworkProtocol
	t.streamTransport = streamTransport
	t.ctxLock.Unlock()
	if oldRelay != nil {
		if err := oldRelay.close(); err != nil {
			return err
		}
	}
	relay, err := newManagedTunnelRelayWithConfig(t, ctx, vpnNetworkProtocol, streamTransport)
	if err != nil {
		return err
	}
	t.ctxLock.Lock()
	if t.generation != generation || t.relay != nil {
		t.ctxLock.Unlock()
		_ = relay.close()
		return net.ErrClosed
	}
	t.relay = relay
	t.ctxLock.Unlock()
	return nil
}

func (t *TUN) Close() error {
	if t == nil {
		return nil
	}
	t.ctxLock.Lock()
	relay := t.relay
	t.relay = nil
	t.generation++
	t.ctxLock.Unlock()
	if relay == nil {
		return nil
	}
	return relay.close()
}

func (t *TUN) SetCtx(ctx context.Context) {
	t.ctxLock.Lock()
	t.ctx = ctx
	t.ctxLock.Unlock()
}

func (t *TUN) SetDialer(_ func(network, address string) (net.Conn, error)) {}

func (t *TUN) SetForceTag(_ string) {}

func (t *TUN) SetCallbacks(send func([]byte) error, recv func([]byte) error) {
	t.ctxLock.Lock()
	t.sendCallback = send
	t.recvCallback = recv
	t.ctxLock.Unlock()
}

// OversizePacketDrops reports packets discarded because the caller-provided
// Read buffer was too small. The count is cumulative for this TUN instance.
func (t *TUN) OversizePacketDrops() uint64 {
	if t == nil {
		return 0
	}
	return t.oversizePacketDrops.Load()
}

func (t *TUN) AddProtocolAddress(_ net.IP) error {
	return nil
}

func (t *TUN) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	t.ctxLock.RLock()
	sendCallback := t.sendCallback
	relay := t.relay
	t.ctxLock.RUnlock()
	if sendCallback != nil {
		if err := extension.Do("TalariaTCP TUN send callback", func() error {
			return sendCallback(buf)
		}); err != nil {
			return 0, err
		}
	}
	if relay == nil {
		return 0, net.ErrClosed
	}
	return relay.writePacket(buf)
}

func (t *TUN) Read(buf []byte, length []int) (int, error) {
	t.ctxLock.RLock()
	relay := t.relay
	recvCallback := t.recvCallback
	t.ctxLock.RUnlock()
	if relay == nil {
		return 0, net.ErrClosed
	}
	n, err := relay.readPacket(buf)
	if err != nil {
		return 0, err
	}
	if len(length) > 0 {
		length[0] = n
	}
	if recvCallback != nil {
		if err := extension.Do("TalariaTCP TUN receive callback", func() error {
			return recvCallback(buf[:n])
		}); err != nil {
			return 0, err
		}
	}
	return 1, nil
}

func (t *TUN) ReadPacket() ([]byte, error) {
	t.ctxLock.RLock()
	relay := t.relay
	recvCallback := t.recvCallback
	t.ctxLock.RUnlock()
	if relay == nil {
		return nil, net.ErrClosed
	}
	packet, err := relay.readPacketSlice()
	if err != nil {
		return nil, err
	}
	if recvCallback != nil {
		if err := extension.Do("TalariaTCP TUN receive callback", func() error {
			return recvCallback(packet)
		}); err != nil {
			return nil, err
		}
	}
	return packet, nil
}

func (t *TUN) ReadPacketBorrowed() ([]byte, func(), error) {
	t.ctxLock.RLock()
	relay := t.relay
	recvCallback := t.recvCallback
	t.ctxLock.RUnlock()
	if relay == nil {
		return nil, nil, net.ErrClosed
	}
	packet, release, err := relay.readPacketBorrowed()
	if err != nil {
		return nil, nil, err
	}
	if recvCallback != nil {
		if err := extension.Do("TalariaTCP TUN borrowed receive callback", func() error {
			return recvCallback(packet)
		}); err != nil {
			if release != nil {
				_ = extension.Run("TalariaTCP TUN borrowed packet release", release)
			}
			return nil, nil, err
		}
	}
	return packet, release, nil
}

func (t *TUN) QueuePacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	t.ctxLock.RLock()
	relay := t.relay
	t.ctxLock.RUnlock()
	if relay == nil {
		return net.ErrClosed
	}
	return relay.copyAndQueueOutboundPacket(packet)
}

func (t *TUN) currentContext() context.Context {
	t.ctxLock.RLock()
	defer t.ctxLock.RUnlock()
	if t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}

func (t *TUN) currentProtocol() string {
	t.ctxLock.RLock()
	defer t.ctxLock.RUnlock()
	return t.endpointProtocol
}

func (t *TUN) currentStreamTransport() coretransport.Client {
	t.ctxLock.RLock()
	defer t.ctxLock.RUnlock()
	return t.streamTransport
}
