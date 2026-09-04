// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket_test

import (
	"bytes"
	"testing"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestWriteRawCmdHeaders(t *testing.T) {
	t.Parallel()

	clientID := uint64(42)
	dataSequenceID := uint32(7)

	dataBuf := make([]byte, vpnpacket.RawCmdDataHeaderLen()+3)
	if !vpnpacket.WriteRawCmdDataHeader(dataBuf, clientID, dataSequenceID) {
		t.Fatal("expected raw data header write to succeed")
	}
	copy(dataBuf[vpnpacket.RawCmdDataHeaderLen():], []byte("abc"))
	packet, err := vpnpacket.ReadVpnPacketFromBytes(dataBuf)
	if err != nil {
		t.Fatalf("ReadVpnPacketFromBytes(data) error = %v", err)
	}
	if packet.ClientId != clientID {
		t.Fatalf("client id = %d, want %d", packet.ClientId, clientID)
	}
	if packet.Cmd != vpnpacket.CmdData {
		t.Fatalf("cmd = %d, want %d", packet.Cmd, vpnpacket.CmdData)
	}
	if packet.WireCmd != vpnpacket.CmdData {
		t.Fatalf("wire cmd = %d, want %d", packet.WireCmd, vpnpacket.CmdData)
	}
	if packet.DataSequenceId != dataSequenceID {
		t.Fatalf("sequence id = %d, want %d", packet.DataSequenceId, dataSequenceID)
	}
	if !bytes.Equal(packet.Data, []byte("abc")) {
		t.Fatalf("payload = %q, want %q", packet.Data, []byte("abc"))
	}

	returnBuf := make([]byte, vpnpacket.RawCmdDataReturnHeaderLen()+3)
	if !vpnpacket.WriteRawCmdDataReturnHeader(returnBuf, clientID, dataSequenceID) {
		t.Fatal("expected raw data return header write to succeed")
	}
	copy(returnBuf[vpnpacket.RawCmdDataReturnHeaderLen():], []byte("xyz"))
	packet, err = vpnpacket.ReadVpnPacketFromBytes(returnBuf)
	if err != nil {
		t.Fatalf("ReadVpnPacketFromBytes(return) error = %v", err)
	}
	if packet.Cmd != vpnpacket.CmdDataReturn {
		t.Fatalf("return cmd = %d, want %d", packet.Cmd, vpnpacket.CmdDataReturn)
	}
	if packet.WireCmd != vpnpacket.CmdDataReturn {
		t.Fatalf("return wire cmd = %d, want %d", packet.WireCmd, vpnpacket.CmdDataReturn)
	}

	shortBuf := make([]byte, vpnpacket.RawCmdDataHeaderLen()-1)
	if vpnpacket.WriteRawCmdDataHeader(shortBuf, clientID, dataSequenceID) {
		t.Fatal("expected short raw data buffer write to fail")
	}
	if vpnpacket.WriteRawCmdDataReturnHeader(shortBuf, clientID, dataSequenceID) {
		t.Fatal("expected short raw data return buffer write to fail")
	}
}

func TestFixedV4Helpers(t *testing.T) {
	t.Parallel()

	clientID := uint64(64)
	dataSequenceID := uint32(9)
	entranceIP := []byte{10, 0, 0, 1}
	exitIP := []byte{10, 0, 0, 2}
	payload := []byte("hi")

	buf := make([]byte, vpnpacket.FixedV4PayloadOffset()+len(payload))
	if !vpnpacket.WriteRawFixedV4DataHeader(buf, clientID, dataSequenceID, entranceIP, exitIP) {
		t.Fatal("expected raw fixed v4 data header write to succeed")
	}
	copy(vpnpacket.GetFixedV4Payload(buf, len(buf)), payload)

	if !vpnpacket.IsFixedV4DataWireCmd(vpnpacket.GetFixedV4WireCmd(buf)) {
		t.Fatal("expected fixed v4 data wire cmd to be recognized")
	}
	if !vpnpacket.IsFixedV4DataCmd(buf, len(buf)) {
		t.Fatal("expected fixed v4 data command to be recognized")
	}
	if got := vpnpacket.GetFixedV4ClientID(buf); got != clientID {
		t.Fatalf("client id = %d, want %d", got, clientID)
	}
	if got := vpnpacket.GetFixedV4DataSequenceID(buf); got != dataSequenceID {
		t.Fatalf("sequence id = %d, want %d", got, dataSequenceID)
	}
	if got := vpnpacket.GetFixedV4EntranceIPv4(buf); !bytes.Equal(got, entranceIP) {
		t.Fatalf("entrance ip = %v, want %v", got, entranceIP)
	}
	if got := vpnpacket.GetFixedV4ExitIPv4(buf); !bytes.Equal(got, exitIP) {
		t.Fatalf("exit ip = %v, want %v", got, exitIP)
	}
	if got := vpnpacket.GetFixedV4Payload(buf, len(buf)); !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}

	packet, err := vpnpacket.ReadVpnPacketFromBytes(buf)
	if err != nil {
		t.Fatalf("ReadVpnPacketFromBytes(fixed v4) error = %v", err)
	}
	if packet.Cmd != vpnpacket.CmdData {
		t.Fatalf("cmd = %d, want %d", packet.Cmd, vpnpacket.CmdData)
	}
	if !bytes.Equal(packet.Data, payload) {
		t.Fatalf("packet payload = %q, want %q", packet.Data, payload)
	}

	if vpnpacket.IsFixedV4DataCmd(buf, len(buf)+1) {
		t.Fatal("expected oversized fixed v4 size to be rejected")
	}
	if vpnpacket.GetFixedV4WireCmd([]byte{1, 2, 3}) != 0 {
		t.Fatal("expected short wire cmd buffer to return 0")
	}
	if vpnpacket.GetFixedV4Payload([]byte{1, 2, 3}, 3) != nil {
		t.Fatal("expected short payload buffer to return nil")
	}
	if vpnpacket.WriteRawFixedV4DataHeader(buf[:vpnpacket.FixedV4PayloadOffset()-1], clientID, dataSequenceID, entranceIP, exitIP) {
		t.Fatal("expected short raw fixed v4 buffer write to fail")
	}
	if vpnpacket.WriteRawFixedV4DataHeader(buf, clientID, dataSequenceID, entranceIP[:3], exitIP) {
		t.Fatal("expected short entrance ip write to fail")
	}
}

func TestReadVpnPacketRejectsMalformedFramesWithoutPanic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		buf  []byte
	}{
		{
			name: "server keepalive too short",
			buf:  malformedPacket(vpnpacket.CmdServerKeepAlive, 12),
		},
		{
			name: "session grant too short",
			buf:  malformedPacket(vpnpacket.CmdSessionGrant, 9),
		},
		{
			name: "unknown command",
			buf:  malformedPacket(0xff, 9),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var err error
			func() {
				defer func() {
					if panicValue := recover(); panicValue != nil {
						t.Fatalf("ReadVpnPacketFromBytes panic = %v", panicValue)
					}
				}()
				_, err = vpnpacket.ReadVpnPacketFromBytes(tt.buf)
			}()
			if err == nil {
				t.Fatal("expected malformed packet to return error")
			}
		})
	}
}

func malformedPacket(cmd byte, size int) []byte {
	buf := make([]byte, size)
	if size > 8 {
		buf[8] = cmd
	}
	return buf
}
