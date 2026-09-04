// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"net"
	"strings"
	"testing"
)

func TestVpnPacketStringRedactsCredentialsAndInnerAddresses(t *testing.T) {
	authText := (&VpnPacket{
		Cmd: CmdAuthRequest,
		Id:  "sensitive-client-id",
		Sk:  "sensitive-secret-key",
	}).String()
	for _, secret := range []string{"sensitive-client-id", "sensitive-secret-key"} {
		if strings.Contains(authText, secret) {
			t.Fatalf("auth packet string leaked %q: %s", secret, authText)
		}
	}

	dataText := (&VpnPacket{
		Cmd:        cmdDataFixedIPv4,
		EntranceIp: net.ParseIP("10.20.30.40").To4(),
		ExitIp:     net.ParseIP("203.0.113.50").To4(),
		Data:       []byte("sensitive-inner-payload"),
	}).String()
	for _, sensitive := range []string{"10.20.30.40", "203.0.113.50", "sensitive-inner-payload"} {
		if strings.Contains(dataText, sensitive) {
			t.Fatalf("data packet string leaked %q: %s", sensitive, dataText)
		}
	}
}
