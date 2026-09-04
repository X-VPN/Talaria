// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestPacketHandlerBoundaryRejectsClientDirectionCommands(t *testing.T) {
	handler := &countingPacketHandler{}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	raw, err := srv.codec.Encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthSuccess, NewClientId: 99})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.handleRawPacketFrame(context.Background(), nil, session, raw); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("client-direction command error = %v, want not allowed", err)
	}
	if handler.calls != 0 {
		t.Fatalf("handler calls = %d, want 0", handler.calls)
	}
}

func TestPacketHandlerBoundaryNormalizesPacketIdentity(t *testing.T) {
	handler := &capturingPacketHandler{}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	packet := &vpnpacket.VpnPacket{
		Cmd:               vpnpacket.CmdData,
		ClientId:          999,
		Id:                "spoofed-id",
		Sk:                "spoofed-secret",
		NewClientId:       1000,
		EntranceIp:        []byte{1, 2, 3, 4},
		ExitIp:            []byte{5, 6, 7, 8},
		SessionGeneration: 1001,
		SessionDataToken:  []byte("spoofed-token"),
	}
	if err := srv.handleAndWriteResponses(context.Background(), nil, session, packet); err != nil {
		t.Fatal(err)
	}
	got := handler.packet
	if got == nil || got.ClientId != session.ClientID {
		t.Fatalf("handler client id = %v, want %d", got, session.ClientID)
	}
	if got.Id != "" || got.Sk != "" || got.NewClientId != 0 || got.SessionGeneration != 0 || got.SessionDataToken != nil {
		t.Fatalf("handler received spoofed identity fields: %+v", got)
	}
	if got.EntranceIp != nil || got.ExitIp != nil {
		t.Fatalf("handler received unbound route metadata: entrance=%v exit=%v", got.EntranceIp, got.ExitIp)
	}
}

func TestPacketHandlerCancellationDoesNotWaitForCallback(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	callbackDone := make(chan struct{}, 2)
	handler := PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
		entered <- struct{}{}
		<-release
		callbackDone <- struct{}{}
		return nil, nil
	})
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	srv.outboundSlots = make(chan struct{}, 2)
	srv.resources = newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
	assertHandlerCancellationRetainsWorker(t, func(ctx context.Context) error {
		return srv.handleAndWriteResponses(ctx, nil, session, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive})
	}, entered, release, callbackDone)
}

func TestRawFrameHandlerBoundaryNormalizesIdentity(t *testing.T) {
	handler := &capturingRawFrameHandler{}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	raw := make([]byte, vpnpacket.FixedV4PayloadOffset()+1)
	if !vpnpacket.WriteRawFixedV4DataHeader(raw, 999, 1, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}) {
		t.Fatal("failed to build fixed-v4 frame")
	}
	if err := srv.handleRawPacketFrame(context.Background(), nil, session, raw); err != nil {
		t.Fatal(err)
	}
	if handler.clientID != session.ClientID {
		t.Fatalf("raw handler client id = %d, want %d", handler.clientID, session.ClientID)
	}
	if !bytes.Equal(handler.routeMetadata, make([]byte, 8)) {
		t.Fatalf("raw handler received unbound route metadata: %v", handler.routeMetadata)
	}
}

func TestRawFrameHandlerCancellationDoesNotWaitForCallback(t *testing.T) {
	handler := &blockingRawFrameHandler{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
		done:    make(chan struct{}, 2),
	}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	srv.outboundSlots = make(chan struct{}, 2)
	srv.resources = newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
	makeRaw := func() []byte {
		raw, err := srv.codec.Encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: []byte("payload")})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	assertHandlerCancellationRetainsWorker(t, func(ctx context.Context) error {
		return srv.handleRawPacketFrame(ctx, nil, session, makeRaw())
	}, handler.entered, handler.release, handler.done)
}

func TestEmbeddedBuiltInHandlerDoesNotBypassWorkerLimits(t *testing.T) {
	for _, tt := range []struct {
		name   string
		invoke func(*Server, SessionContext, context.Context) error
	}{
		{
			name: "packet",
			invoke: func(srv *Server, session SessionContext, ctx context.Context) error {
				return srv.handleAndWriteResponses(ctx, nil, session, &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive})
			},
		},
		{
			name: "raw frame",
			invoke: func(srv *Server, session SessionContext, ctx context.Context) error {
				raw, err := srv.codec.Encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, Data: []byte("payload")})
				if err != nil {
					return err
				}
				return srv.handleRawPacketFrame(ctx, nil, session, raw)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler := &embeddedBlockingPacketHandler{
				TunPacketHandler: &TunPacketHandler{},
				entered:          make(chan struct{}, 2),
				release:          make(chan struct{}),
				done:             make(chan struct{}, 2),
			}
			srv, session, cleanup := newPacketBoundaryServer(t, handler)
			defer cleanup()
			srv.outboundSlots = make(chan struct{}, 2)
			srv.resources = newResourceLimiter(ResourceLimits{MaxPendingDialsPerClient: 1})
			assertHandlerCancellationRetainsWorker(t, func(ctx context.Context) error {
				return tt.invoke(srv, session, ctx)
			}, handler.entered, handler.release, handler.done)
		})
	}
}

func TestPacketHandlerBoundaryNormalizesAndLimitsResponses(t *testing.T) {
	srv, session, cleanup := newPacketBoundaryServer(t, EchoPacketHandler{})
	defer cleanup()
	t.Run("identity", func(t *testing.T) {
		response := &vpnpacket.VpnPacket{
			Cmd:               vpnpacket.CmdData,
			ClientId:          999,
			Id:                "cross-client",
			Sk:                "secret",
			NewClientId:       1000,
			SessionGeneration: 1001,
			SessionDataToken:  []byte("token"),
			Data:              []byte("payload"),
		}
		var written *vpnpacket.VpnPacket
		if err := srv.writeResponses(context.Background(), func(packet *vpnpacket.VpnPacket) error {
			written = packet
			return nil
		}, session, []*vpnpacket.VpnPacket{response}); err != nil {
			t.Fatal(err)
		}
		if written == nil || written.ClientId != session.ClientID || written.Id != "" || written.Sk != "" || written.NewClientId != 0 || written.SessionGeneration != 0 || written.SessionDataToken != nil {
			t.Fatalf("response identity was not normalized: %+v", written)
		}
	})

	for _, tt := range []struct {
		name      string
		responses []*vpnpacket.VpnPacket
	}{
		{
			name: "command",
			responses: []*vpnpacket.VpnPacket{{
				Cmd:               vpnpacket.CmdSessionGrant,
				SessionGeneration: 1,
				SessionDataToken:  make([]byte, 32),
			}},
		},
		{name: "count", responses: make([]*vpnpacket.VpnPacket, maxPacketHandlerResponses+1)},
		{
			name: "total bytes",
			responses: []*vpnpacket.VpnPacket{
				{Cmd: vpnpacket.CmdData, Data: make([]byte, maxPacketHandlerResponseBytes/2)},
				{Cmd: vpnpacket.CmdData, Data: make([]byte, maxPacketHandlerResponseBytes/2)},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writes := 0
			if err := srv.writeResponses(context.Background(), func(*vpnpacket.VpnPacket) error {
				writes++
				return nil
			}, session, tt.responses); err == nil {
				t.Fatal("invalid handler responses were accepted")
			}
			if writes != 0 {
				t.Fatalf("writes before full response validation = %d, want 0", writes)
			}
		})
	}
}

func TestPacketHandlerBoundaryRejectsOversizedPayloadBeforeEncoding(t *testing.T) {
	handler := EchoPacketHandler{}
	srv, session, cleanup := newPacketBoundaryServer(t, handler)
	defer cleanup()
	srv.codec = panicEncodeCodec{}
	err := srv.writeResponses(context.Background(), nil, session, []*vpnpacket.VpnPacket{{
		Cmd:  vpnpacket.CmdData,
		Data: make([]byte, maxPacketHandlerResponseBytes+1),
	}})
	if err == nil {
		t.Fatal("oversized handler payload was accepted")
	}
}

func TestPacketHandlerResponsesReusePreflightEncoding(t *testing.T) {
	srv, session, cleanup := newPacketBoundaryServer(t, EchoPacketHandler{})
	defer cleanup()
	codec := &countingEncodeCodec{Codec: dataplane.WireCodec{}}
	srv.codec = codec
	var written [][]byte
	err := srv.writeResponsesWithWriters(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			t.Fatal("packet response was encoded a second time")
			return nil
		},
		Raw: func(raw []byte) error {
			written = append(written, append([]byte(nil), raw...))
			return nil
		},
	}, session, []*vpnpacket.VpnPacket{
		{Cmd: vpnpacket.CmdData, Data: []byte("first")},
		{Cmd: vpnpacket.CmdData, Data: []byte("second")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if codec.calls != 2 || len(written) != 2 {
		t.Fatalf("encode/raw write calls = %d/%d, want 2/2", codec.calls, len(written))
	}
}

func TestPacketHandlerKeepAliveResponseUsesEncodedResponseWriter(t *testing.T) {
	srv, session, cleanup := newPacketBoundaryServer(t, &TunPacketHandler{})
	defer cleanup()
	codec := &countingEncodeCodec{Codec: dataplane.WireCodec{}}
	srv.codec = codec
	var written []byte
	gate, handlerWriters := newSessionWriterGate(SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error {
			t.Fatal("keepalive response was encoded a second time")
			return nil
		},
		Raw: func(raw []byte) error {
			written = append([]byte(nil), raw...)
			return nil
		},
	}, nil, session.ClientID)
	gate.open.Store(true)

	handlerRaw, err := (dataplane.WireCodec{}).Encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdKeepAlive})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlerWriters.Raw(handlerRaw); err == nil {
		t.Fatal("handler raw writer accepted a keepalive frame")
	}

	err = srv.handleAndWriteResponsesWithWriters(context.Background(), gate.responseWriters(handlerWriters), session, &vpnpacket.VpnPacket{
		Cmd:         vpnpacket.CmdKeepAlive,
		KeepAliveId: 9,
		IsPing:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if codec.calls != 1 {
		t.Fatalf("encode calls = %d, want 1", codec.calls)
	}
	response, _, err := codec.Decode(written)
	if err != nil {
		t.Fatal(err)
	}
	if response.Cmd != vpnpacket.CmdKeepAlive || response.ClientId != session.ClientID || response.KeepAliveId != 9 {
		t.Fatalf("keepalive response = %+v, want command %d for client %d with id 9", response, vpnpacket.CmdKeepAlive, session.ClientID)
	}
}

func TestSessionWritersHandlerOutputBoundary(t *testing.T) {
	var packetWrite *vpnpacket.VpnPacket
	var rawWrite []byte
	gate, writers := newSessionWriterGate(SessionWriters{
		Packet: func(packet *vpnpacket.VpnPacket) error {
			packetWrite = packet
			return nil
		},
		Raw: func(raw []byte) error {
			rawWrite = raw
			return nil
		},
		RawBatch: func(bufs [][]byte, _ []int) (int, error) { return len(bufs), nil },
	}, nil, 42)
	gate.open.Store(true)
	if err := writers.Packet(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdSessionGrant}); err == nil {
		t.Fatal("session writer accepted a server-only control command")
	}
	response := &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdData, ClientId: 999, Data: []byte("payload")}
	if err := writers.Packet(response); err != nil {
		t.Fatal(err)
	}
	if packetWrite == nil || packetWrite.ClientId != 42 {
		t.Fatalf("session writer packet identity = %+v, want client 42", packetWrite)
	}
	authRaw, err := (dataplane.WireCodec{}).Encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthSuccess, NewClientId: 99})
	if err != nil {
		t.Fatal(err)
	}
	if err := writers.Raw(authRaw); err == nil {
		t.Fatal("session writer accepted non-data raw output")
	}
	dataRaw := make([]byte, vpnpacket.RawCmdDataHeaderLen())
	vpnpacket.WriteRawCmdDataHeader(dataRaw, 999, 1)
	if err := writers.Raw(dataRaw); err != nil {
		t.Fatal(err)
	}
	if rawWrite == nil || vpnpacket.GetFixedV4ClientID(rawWrite) != 42 {
		t.Fatalf("session writer raw identity = %d, want 42", vpnpacket.GetFixedV4ClientID(rawWrite))
	}
	packetWrite = nil
	if err := writers.Packet(&vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: make([]byte, maxPacketHandlerResponseBytes+1),
	}); err == nil {
		t.Fatal("session writer accepted an oversized packet payload")
	}
	if packetWrite != nil {
		t.Fatal("session writer forwarded an oversized packet payload")
	}
}

func newPacketBoundaryServer(t *testing.T, handler PacketHandler) (*Server, SessionContext, func()) {
	t.Helper()
	srv := &Server{codec: dataplane.WireCodec{}, handler: handler}
	session := SessionContext{ClientID: 42, Generation: 1}
	binding, err := srv.activateSession(activeServerSessionConfig{Ref: session.Ref(), Context: session})
	if err != nil {
		t.Fatal(err)
	}
	return srv, session, func() { srv.releaseSession(binding) }
}

func assertHandlerCancellationRetainsWorker(
	t *testing.T,
	invoke func(context.Context) error,
	entered <-chan struct{},
	release chan struct{},
	done <-chan struct{},
) {
	t.Helper()
	defer func() {
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("handler callback did not finish")
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- invoke(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler callback did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler call did not stop after cancellation")
	}
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelSecond()
	if err := invoke(secondCtx); !errors.Is(err, errResourceLimit) {
		t.Fatalf("second handler error = %v, want resource limit", err)
	}
}

type countingPacketHandler struct{ calls int }

func (h *countingPacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	h.calls++
	return nil, nil
}

type capturingPacketHandler struct{ packet *vpnpacket.VpnPacket }

func (h *capturingPacketHandler) HandlePacket(_ context.Context, _ SessionContext, packet *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	h.packet = packet
	return nil, nil
}

type capturingRawFrameHandler struct {
	clientID      uint64
	routeMetadata []byte
}

type blockingRawFrameHandler struct {
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

type embeddedBlockingPacketHandler struct {
	*TunPacketHandler
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
}

type panicEncodeCodec struct {
	dataplane.Codec
}

type countingEncodeCodec struct {
	dataplane.Codec
	calls int
}

func (c *countingEncodeCodec) Encode(packet *vpnpacket.VpnPacket) ([]byte, error) {
	c.calls++
	return c.Codec.Encode(packet)
}

func (panicEncodeCodec) Encode(*vpnpacket.VpnPacket) ([]byte, error) {
	panic("oversized payload reached codec")
}

func (*capturingRawFrameHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (h *capturingRawFrameHandler) HandleRawFrame(_ context.Context, _ SessionContext, raw []byte) (bool, []*vpnpacket.VpnPacket, error) {
	h.clientID = vpnpacket.GetFixedV4ClientID(raw)
	h.routeMetadata = append([]byte(nil), raw[13:21]...)
	return true, nil, nil
}

func (*blockingRawFrameHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	return nil, nil
}

func (h *blockingRawFrameHandler) HandleRawFrame(context.Context, SessionContext, []byte) (bool, []*vpnpacket.VpnPacket, error) {
	h.entered <- struct{}{}
	<-h.release
	h.done <- struct{}{}
	return true, nil, nil
}

func (h *embeddedBlockingPacketHandler) HandlePacket(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
	h.entered <- struct{}{}
	<-h.release
	h.done <- struct{}{}
	return nil, nil
}

func (h *embeddedBlockingPacketHandler) HandleRawFrame(context.Context, SessionContext, []byte) (bool, []*vpnpacket.VpnPacket, error) {
	h.entered <- struct{}{}
	<-h.release
	h.done <- struct{}{}
	return true, nil, nil
}
