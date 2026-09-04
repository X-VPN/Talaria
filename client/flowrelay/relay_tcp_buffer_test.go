// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package flowrelay

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	gipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestConfigureManagedTCPStackUsesPlatformBufferRange(t *testing.T) {
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			gipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			gtcp.NewProtocol,
		},
	})
	defer func() {
		stk.Close()
		stk.Wait()
	}()

	if err := configureManagedTCPStack(stk); err != nil {
		t.Fatalf("configureManagedTCPStack() error = %v", err)
	}

	expected := tcpip.TCPSendBufferSizeRangeOption{
		Min:     managedTunnelTCPBufferMin,
		Default: managedTunnelTCPBufferDefault,
		Max:     managedTunnelTCPBufferMax,
	}
	var sendRange tcpip.TCPSendBufferSizeRangeOption
	if err := toStdError(stk.TransportProtocolOption(gtcp.ProtocolNumber, &sendRange)); err != nil {
		t.Fatalf("read TCP send buffer range: %v", err)
	}
	if sendRange != expected {
		t.Fatalf("send buffer range = %+v want %+v", sendRange, expected)
	}

	var recvRange tcpip.TCPReceiveBufferSizeRangeOption
	if err := toStdError(stk.TransportProtocolOption(gtcp.ProtocolNumber, &recvRange)); err != nil {
		t.Fatalf("read TCP receive buffer range: %v", err)
	}
	expectedRecv := tcpip.TCPReceiveBufferSizeRangeOption(expected)
	if recvRange != expectedRecv {
		t.Fatalf("receive buffer range = %+v want %+v", recvRange, expectedRecv)
	}
}
