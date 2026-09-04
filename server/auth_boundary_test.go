// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

var errTestAuthDenied = errors.New("test auth denied")

func TestApplicationAuthenticationAttemptsConsumeRateLimit(t *testing.T) {
	wireCodec := dataplane.WireCodec{}
	encode := func(packet *vpnpacket.VpnPacket) []byte {
		t.Helper()
		raw, err := wireCodec.Encode(packet)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	validAuth := encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "client", Sk: "secret"})
	attempts := []struct {
		name              string
		raw               []byte
		codec             dataplane.Codec
		wantProviderCalls int32
	}{
		{name: "undecodable packet", raw: []byte{0}, codec: wireCodec},
		{name: "wrong command", raw: encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdClientClose}), codec: wireCodec},
		{name: "empty client id", raw: encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Sk: "secret"}), codec: wireCodec},
		{name: "empty secret", raw: encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "client"}), codec: wireCodec},
		{name: "invalid client id utf8", raw: encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: string([]byte{0xff}), Sk: "secret"}), codec: wireCodec},
		{name: "invalid secret utf8", raw: encode(&vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: "client", Sk: string([]byte{0xff})}), codec: wireCodec},
		{
			name:  "oversized custom codec credential",
			raw:   []byte{1},
			codec: fixedAuthPacketCodec{packet: &vpnpacket.VpnPacket{Cmd: vpnpacket.CmdAuthRequest, Id: strings.Repeat("a", maxAuthCredentialBytes+1), Sk: "secret"}},
		},
		{name: "provider rejection", raw: validAuth, codec: wireCodec, wantProviderCalls: 1},
	}
	paths := []struct {
		name     string
		protocol client.Protocol
		control  bool
	}{
		{name: "TalariaUDP", protocol: client.ProtocolTalariaUDP},
		{name: "TalariaTCP", protocol: client.ProtocolTalariaTCP, control: true},
	}
	for _, path := range paths {
		for _, attempt := range attempts {
			t.Run(path.name+"/"+attempt.name, func(t *testing.T) {
				limits, err := normalizeResourceLimits(ResourceLimits{
					MaxAuthAttemptsPerWindow:          2,
					MaxAuthAttemptsPerSourcePerWindow: 1,
					AuthAttemptWindow:                 time.Minute,
				})
				if err != nil {
					t.Fatal(err)
				}
				var providerCalls atomic.Int32
				srv := &Server{
					protocol:  path.protocol,
					codec:     attempt.codec,
					resources: newResourceLimiter(limits),
					auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
						providerCalls.Add(1)
						return AuthResult{}, errTestAuthDenied
					}),
				}
				opt := ServeOptions{
					Protocol:       path.protocol,
					ReadBufferSize: 4096,
					AuthTimeout:    time.Second,
				}
				firstConn := &authAttemptConn{preAuthFuzzConn: newPreAuthFuzzConn(attempt.raw)}
				if path.control {
					_, err = srv.authenticateControlConn(context.Background(), firstConn, opt)
				} else {
					_, err = srv.authenticatePacketConn(context.Background(), firstConn, opt)
				}
				if err == nil {
					t.Fatal("first authentication attempt returned no error")
				}
				if got := providerCalls.Load(); got != attempt.wantProviderCalls {
					t.Fatalf("provider calls = %d, want %d", got, attempt.wantProviderCalls)
				}

				secondConn := &authAttemptConn{preAuthFuzzConn: newPreAuthFuzzConn(validAuth)}
				if path.control {
					_, err = srv.authenticateControlConn(context.Background(), secondConn, opt)
				} else {
					_, err = srv.authenticatePacketConn(context.Background(), secondConn, opt)
				}
				if !errors.Is(err, errAuthenticationRateLimit) {
					t.Fatalf("second authentication error = %v, want rate limit", err)
				}
				if remaining := secondConn.reader.Len(); remaining != len(validAuth) {
					t.Fatalf("rate-limited authentication read %d bytes before rejection", len(validAuth)-remaining)
				}
				if got := providerCalls.Load(); got != attempt.wantProviderCalls {
					t.Fatalf("provider calls after rate limit = %d, want %d", got, attempt.wantProviderCalls)
				}
			})
		}
	}
}

func TestServePacketConnRejectsTrafficBeforeAuthenticationWithoutSideEffects(t *testing.T) {
	tests := []struct {
		name          string
		firstPacket   *vpnpacket.VpnPacket
		wantAuthCalls int32
	}{
		{
			name: "invalid credentials",
			firstPacket: &vpnpacket.VpnPacket{
				Cmd: vpnpacket.CmdAuthRequest,
				Id:  "client",
				Sk:  "wrong-secret",
			},
			wantAuthCalls: 1,
		},
		{
			name: "data before authentication",
			firstPacket: &vpnpacket.VpnPacket{
				Cmd:      vpnpacket.CmdData,
				ClientId: 77,
				Data:     []byte("must-not-forward"),
			},
			wantAuthCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := dataplane.WireCodec{}
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()

			var authCalls atomic.Int32
			var handlerCalls atomic.Int32
			srv := &Server{
				protocol: client.ProtocolTalariaUDP,
				codec:    codec,
				auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
					authCalls.Add(1)
					return AuthResult{}, errTestAuthDenied
				}),
				handler: PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
					handlerCalls.Add(1)
					return nil, nil
				}),
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.ServePacketConn(context.Background(), serverConn, ServeOptions{
					Protocol:    client.ProtocolTalariaUDP,
					AuthTimeout: time.Second,
				})
			}()

			writeTestPacket(t, codec, clientConn, tt.firstPacket)
			response := readTestPacket(t, codec, clientConn)
			if response.Cmd != vpnpacket.CmdErr {
				t.Fatalf("response command = %d, want CmdErr", response.Cmd)
			}

			select {
			case err := <-errCh:
				if err == nil {
					t.Fatal("unauthenticated packet connection returned no error")
				}
			case <-time.After(time.Second):
				t.Fatal("unauthenticated packet connection did not close")
			}

			if got := authCalls.Load(); got != tt.wantAuthCalls {
				t.Fatalf("auth calls = %d, want %d", got, tt.wantAuthCalls)
			}
			if got := handlerCalls.Load(); got != 0 {
				t.Fatalf("packet handler calls = %d, want 0", got)
			}
			if _, ok := srv.CurrentSession(77); ok {
				t.Fatal("unauthenticated packet connection activated a session")
			}
		})
	}
}

func TestServeControlConnRejectsTrafficBeforeAuthenticationWithoutSideEffects(t *testing.T) {
	tests := []struct {
		name          string
		firstPacket   *vpnpacket.VpnPacket
		wantAuthCalls int32
	}{
		{
			name: "invalid credentials",
			firstPacket: &vpnpacket.VpnPacket{
				Cmd: vpnpacket.CmdAuthRequest,
				Id:  "client",
				Sk:  "wrong-secret",
			},
			wantAuthCalls: 1,
		},
		{
			name: "data before authentication",
			firstPacket: &vpnpacket.VpnPacket{
				Cmd:      vpnpacket.CmdData,
				ClientId: 77,
				Data:     []byte("must-not-forward"),
			},
			wantAuthCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := dataplane.WireCodec{}
			serverPipe, clientConn := net.Pipe()
			defer clientConn.Close()
			controlConn := &fakeControlConn{Conn: serverPipe}

			var authCalls atomic.Int32
			var handlerCalls atomic.Int32
			sessions := &countingControlSessionActivator{}
			srv := &Server{
				protocol: client.ProtocolTalariaTCP,
				codec:    codec,
				auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
					authCalls.Add(1)
					return AuthResult{}, errTestAuthDenied
				}),
				handler: PacketHandlerFunc(func(context.Context, SessionContext, *vpnpacket.VpnPacket) ([]*vpnpacket.VpnPacket, error) {
					handlerCalls.Add(1)
					return nil, nil
				}),
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.ServeControlConn(context.Background(), controlConn, ServeOptions{
					Protocol:    client.ProtocolTalariaTCP,
					AuthTimeout: time.Second,
					Sessions:    sessions,
				})
			}()

			writeTestPacket(t, codec, clientConn, tt.firstPacket)
			response := readTestPacket(t, codec, clientConn)
			if response.Cmd != vpnpacket.CmdErr {
				t.Fatalf("response command = %d, want CmdErr", response.Cmd)
			}

			select {
			case err := <-errCh:
				if err == nil {
					t.Fatal("unauthenticated control connection returned no error")
				}
			case <-time.After(time.Second):
				t.Fatal("unauthenticated control connection did not close")
			}

			if got := authCalls.Load(); got != tt.wantAuthCalls {
				t.Fatalf("auth calls = %d, want %d", got, tt.wantAuthCalls)
			}
			if got := handlerCalls.Load(); got != 0 {
				t.Fatalf("packet handler calls = %d, want 0", got)
			}
			if got := sessions.calls.Load(); got != 0 {
				t.Fatalf("session activations = %d, want 0", got)
			}
			if clientID, ok := controlConn.ClientID(); ok || clientID != 0 {
				t.Fatalf("bound client id = %d/%v, want 0/false", clientID, ok)
			}
			if _, ok := srv.CurrentSession(77); ok {
				t.Fatal("unauthenticated control connection activated a session")
			}
		})
	}
}

func TestAuthenticationFailureDoesNotExposeProviderError(t *testing.T) {
	codec := dataplane.WireCodec{}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	const sensitiveProviderError = "database lookup failed for secret sensitive-secret"
	srv := &Server{
		protocol: client.ProtocolTalariaUDP,
		codec:    codec,
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{}, errors.New(sensitiveProviderError)
		}),
		handler: EchoPacketHandler{},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServePacketConn(context.Background(), serverConn, ServeOptions{
			Protocol:    client.ProtocolTalariaUDP,
			AuthTimeout: time.Second,
		})
	}()

	writeTestPacket(t, codec, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "sensitive-secret",
	})
	response := readTestPacket(t, codec, clientConn)
	if response.Cmd != vpnpacket.CmdErr || response.ErrorMessage != "authentication failed" {
		t.Fatalf("response = cmd=%d error=%q, want generic authentication failure", response.Cmd, response.ErrorMessage)
	}
	err := <-errCh
	if err == nil || strings.Contains(err.Error(), "sensitive-secret") || strings.Contains(err.Error(), "database lookup") {
		t.Fatalf("returned auth error leaked provider detail: %v", err)
	}
}

func TestAuthenticationSuccessAfterDeadlineIsNotCommitted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	conn := newPreAuthFuzzConn(nil)
	srv := &Server{
		codec: dataplane.WireCodec{},
		auth: AuthProviderFunc(func(ctx context.Context, _ AuthRequest) (AuthResult, error) {
			<-ctx.Done()
			return AuthResult{ClientID: 42, Version: 1}, nil
		}),
	}
	_, err := srv.authenticatePacket(ctx, conn, client.ProtocolTalariaUDP, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late provider success = %v, want context deadline exceeded", err)
	}
	if conn.writes.Len() != 0 {
		t.Fatal("late provider success wrote AuthSuccess")
	}
}

func TestAuthenticationDeadlineIsRecheckedAfterEncoding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := newPreAuthFuzzConn(nil)
	srv := &Server{
		codec: fixedAuthPacketCodec{onEncode: cancel},
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{ClientID: 42, Version: 1}, nil
		}),
	}
	_, err := srv.authenticatePacket(ctx, conn, client.ProtocolTalariaUDP, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context canceled during encoding = %v, want context canceled", err)
	}
	if conn.writes.Len() != 0 {
		t.Fatal("authentication canceled during encoding wrote AuthSuccess")
	}
}

func TestAuthenticationDeadlineIsRecheckedAfterWriting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	conn := &delayedAuthWriteConn{
		preAuthFuzzConn: newPreAuthFuzzConn(nil),
		delay:           30 * time.Millisecond,
	}
	srv := &Server{
		codec: dataplane.WireCodec{},
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{ClientID: 42, Version: 1}, nil
		}),
	}
	_, err := srv.authenticatePacket(ctx, conn, client.ProtocolTalariaUDP, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("context expired during write = %v, want context deadline exceeded", err)
	}
}

func TestAuthenticationSuccessWriteUsesDeadline(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	srv := &Server{
		codec: dataplane.WireCodec{},
		auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
			return AuthResult{ClientID: 42, Version: 1}, nil
		}),
	}
	result := make(chan error, 1)
	go func() {
		_, err := srv.authenticateControlConn(context.Background(), serverConn, ServeOptions{
			Protocol:       client.ProtocolTalariaTCP,
			ReadBufferSize: 2048,
			AuthTimeout:    20 * time.Millisecond,
		})
		result <- err
	}()
	writeTestPacket(t, dataplane.WireCodec{}, clientConn, &vpnpacket.VpnPacket{
		Cmd: vpnpacket.CmdAuthRequest,
		Id:  "client",
		Sk:  "secret",
	})
	select {
	case err := <-result:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("blocked authentication success write = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication success write ignored its deadline")
	}
}

type countingControlSessionActivator struct {
	calls atomic.Int32
}

func (a *countingControlSessionActivator) ActivateControlSession(
	context.Context,
	net.Conn,
	SessionContext,
	PacketWriter,
	func(),
) (func() error, func() error, func(), error) {
	a.calls.Add(1)
	return func() error { return nil }, func() error { return nil }, func() {}, nil
}

type authAttemptConn struct {
	*preAuthFuzzConn
}

type delayedAuthWriteConn struct {
	*preAuthFuzzConn
	delay time.Duration
}

func (c *delayedAuthWriteConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.preAuthFuzzConn.Write(p)
}

func (*authAttemptConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}

type fixedAuthPacketCodec struct {
	packet   *vpnpacket.VpnPacket
	onEncode func()
}

func (c fixedAuthPacketCodec) Encode(packet *vpnpacket.VpnPacket) ([]byte, error) {
	if c.onEncode != nil {
		c.onEncode()
	}
	return dataplane.WireCodec{}.Encode(packet)
}

func (c fixedAuthPacketCodec) Decode([]byte) (*vpnpacket.VpnPacket, int, error) {
	return c.packet, 0, nil
}
