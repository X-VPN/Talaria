// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestHandlerErrorsSentToPeerAreGeneric(t *testing.T) {
	want := errors.New("database password sensitive-handler-detail")
	for _, tt := range []struct {
		name    string
		handler PacketHandler
		handle  func(*Server, PacketWriter, SessionContext) error
	}{
		{
			name: "packet handler",
			handler: PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
				return nil, want
			}),
			handle: func(s *Server, write PacketWriter, session SessionContext) error {
				return s.handleAndWriteResponses(context.Background(), write, session, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData})
			},
		},
		{
			name:    "raw frame handler",
			handler: sensitiveRawFrameHandler{err: want},
			handle: func(s *Server, write PacketWriter, session SessionContext) error {
				raw := make([]byte, vpnpacket.RawCmdDataHeaderLen())
				vpnpacket.WriteRawCmdDataHeader(raw, session.ClientID, 1)
				return s.handleRawPacketFrame(context.Background(), write, session, raw)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{handler: tt.handler}
			session := SessionContext{ClientID: 42, Generation: 1}
			binding, err := srv.activateSession(activeServerSessionConfig{Ref: session.Ref(), Context: session})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.releaseSession(binding)
			var response *vpnpacket.VpnPacket
			err = tt.handle(srv, func(packet *vpnpacket.VpnPacket) error {
				response = packet
				return nil
			}, session)
			if !errors.Is(err, want) {
				t.Fatalf("handler error = %v, want original internal error", err)
			}
			assertGenericPeerError(t, response, peerPacketHandlingErrorMessage)
		})
	}
}

func TestSessionSetupErrorsSentToPeerAreGeneric(t *testing.T) {
	want := errors.New("redis://admin:password@internal sensitive-setup-detail")
	for _, tt := range []struct {
		name     string
		handler  PacketHandler
		sessions ControlSessionActivator
	}{
		{name: "control activator", handler: EchoPacketHandler{}, sessions: failingControlSessionActivator{err: want}},
		{name: "packet attach", handler: failingSessionPacketHandler{err: want}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			srv := &Server{
				protocol: client.ProtocolTalariaTCP,
				codec:    dataplane.WireCodec{},
				auth: StaticAuthProvider{
					ClientID:         "client",
					SecretKey:        "secret",
					AssignedClientID: 42,
				},
				handler: tt.handler,
			}
			result := make(chan error, 1)
			go func() {
				result <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{
					Protocol:    client.ProtocolTalariaTCP,
					AuthTimeout: time.Second,
					Sessions:    tt.sessions,
				})
			}()
			writeTestPacket(t, srv.codec, clientConn, &vpnpacket.VpnPacket{
				Cmd: vpnpacket.CmdAuthRequest,
				Id:  "client",
				Sk:  "secret",
			})
			if response := readTestPacket(t, srv.codec, clientConn); response.Cmd != vpnpacket.CmdAuthSuccess {
				t.Fatalf("first response command = %d, want authentication success", response.Cmd)
			}
			assertGenericPeerError(t, readTestPacket(t, srv.codec, clientConn), peerSessionSetupErrorMessage)
			if err := <-result; !errors.Is(err, want) {
				t.Fatalf("serve error = %v, want original internal error", err)
			}
		})
	}
}

func TestControlSessionCleansRevokeReturnedWithActivatorError(t *testing.T) {
	want := errors.New("synthetic activator failure")
	cleanupCalls := 0
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	srv := &Server{
		protocol: client.ProtocolTalariaTCP,
		codec:    dataplane.WireCodec{},
		auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
		},
		handler: EchoPacketHandler{},
	}
	result := make(chan error, 1)
	go func() {
		result <- srv.ServeControlConn(context.Background(), serverConn, ServeOptions{
			Protocol:    client.ProtocolTalariaTCP,
			AuthTimeout: time.Second,
			Sessions: failingControlSessionActivator{
				err: want,
				revoke: func() {
					cleanupCalls++
					panic("synthetic activator cleanup failure")
				},
			},
		})
	}()
	writeTestPacket(t, srv.codec, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	if response := readTestPacket(t, srv.codec, clientConn); response.Cmd != vpnpacket.CmdAuthSuccess {
		t.Fatalf("first response command = %d, want authentication success", response.Cmd)
	}
	assertGenericPeerError(t, readTestPacket(t, srv.codec, clientConn), peerSessionSetupErrorMessage)
	if err := <-result; !errors.Is(err, want) {
		t.Fatalf("serve error = %v, want original activator error", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("activator cleanup calls = %d, want 1", cleanupCalls)
	}
}

func assertGenericPeerError(t *testing.T, packet *vpnpacket.VpnPacket, want string) {
	t.Helper()
	if packet == nil || packet.Cmd != vpnpacket.CmdErr || packet.ErrorMessage != want {
		t.Fatalf("peer error = %+v, want CmdErr %q", packet, want)
	}
	if strings.Contains(packet.ErrorMessage, "sensitive") || strings.Contains(packet.ErrorMessage, "password") {
		t.Fatalf("peer error leaked internal detail: %q", packet.ErrorMessage)
	}
}

type sensitiveRawFrameHandler struct{ err error }

func (h sensitiveRawFrameHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, errors.New("unexpected packet handler call")
}

func (h sensitiveRawFrameHandler) HandleRawFrame(context.Context, SessionContext, []byte) (bool, []*vpnpacket.VpnPacket, error) {
	return true, nil, h.err
}

type failingControlSessionActivator struct {
	err    error
	revoke func()
}

func (a failingControlSessionActivator) ActivateControlSession(context.Context, net.Conn, SessionContext, PacketWriter, func()) (func() error, func() error, func(), error) {
	return nil, nil, a.revoke, a.err
}

type failingSessionPacketHandler struct{ err error }

func (h failingSessionPacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (h failingSessionPacketHandler) AttachSession(context.Context, SessionContext, PacketWriter) (func(), error) {
	return nil, h.err
}
