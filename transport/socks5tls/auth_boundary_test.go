// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func TestSessionAuthenticatorRetainsOnlySessionIdentity(t *testing.T) {
	now := time.Unix(100, 0)
	grant, err := coretransport.NewSessionGrant(42, 7, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registry := coretransport.NewSessionRegistry()
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	server := &Server{registry: registry, now: func() time.Time { return now }}
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(grant.DataToken)))
	base64.RawURLEncoding.Encode(password, grant.DataToken[:])
	requestBytes := statute.NewUserPassRequest(statute.UserPassAuthVersion, []byte("42"), password).Bytes()
	defer clear(password)
	defer clear(requestBytes)
	var response bytes.Buffer
	authContext, err := (sessionAuthenticator{server: server}).Authenticate(bytes.NewReader(requestBytes), &response, "")
	if err != nil {
		t.Fatal(err)
	}
	if authContext.Payload["username"] != "" || authContext.Payload["password"] != "" {
		t.Fatal("authentication context retained SOCKS credential text")
	}
	request := &gosocks5.Request{AuthContext: authContext}
	session, ok := server.authenticateRequest(request)
	if !ok || session != grant.SessionRef {
		t.Fatalf("authenticated session = %+v, %v; want %+v, true", session, ok, grant.SessionRef)
	}
	if request.AuthContext != nil || len(authContext.Payload) != 0 {
		t.Fatal("consumed authentication context retained session metadata")
	}
}

func TestSessionAuthenticatorCompletesShortWrites(t *testing.T) {
	now := time.Unix(100, 0)
	grant, err := coretransport.NewSessionGrant(42, 7, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registry := coretransport.NewSessionRegistry()
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	password := make([]byte, base64.RawURLEncoding.EncodedLen(len(grant.DataToken)))
	base64.RawURLEncoding.Encode(password, grant.DataToken[:])
	request := statute.NewUserPassRequest(statute.UserPassAuthVersion, []byte("42"), password).Bytes()
	defer clear(password)
	defer clear(request)
	response := new(oneByteWriter)
	if _, err := (sessionAuthenticator{server: &Server{registry: registry, now: func() time.Time { return now }}}).Authenticate(bytes.NewReader(request), response, ""); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		statute.VersionSocks5, statute.MethodUserPassAuth,
		statute.UserPassAuthVersion, statute.AuthSuccess,
	}
	if !bytes.Equal(response.Bytes(), want) {
		t.Fatalf("authentication response = %v, want %v", response.Bytes(), want)
	}
}

func TestSessionAuthenticatorUsesOneFailureResponse(t *testing.T) {
	now := time.Unix(100, 0)
	grant, err := coretransport.NewSessionGrant(42, 7, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	registry := coretransport.NewSessionRegistry()
	if err := registry.Activate(grant, now); err != nil {
		t.Fatal(err)
	}
	wrong := grant.DataToken
	wrong[0] ^= 0xff
	want := []byte{
		statute.VersionSocks5, statute.MethodUserPassAuth,
		statute.UserPassAuthVersion, statute.AuthFailure,
	}
	tests := []struct {
		name     string
		clientID uint64
		token    [coretransport.DataTokenSize]byte
		at       time.Time
	}{
		{name: "unknown", clientID: grant.ClientID + 1, token: wrong, at: now},
		{name: "expired", clientID: grant.ClientID, token: grant.DataToken, at: now.Add(time.Second)},
		{name: "wrong token", clientID: grant.ClientID, token: wrong, at: now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := make([]byte, base64.RawURLEncoding.EncodedLen(len(tt.token)))
			base64.RawURLEncoding.Encode(password, tt.token[:])
			defer clear(password)
			request := statute.NewUserPassRequest(statute.UserPassAuthVersion, []byte(strconv.FormatUint(tt.clientID, 10)), password).Bytes()
			defer clear(request)
			var response bytes.Buffer
			server := &Server{registry: registry, now: func() time.Time { return tt.at }}
			if _, err := (sessionAuthenticator{server: server}).Authenticate(bytes.NewReader(request), &response, ""); !errors.Is(err, statute.ErrUserAuthFailed) {
				t.Fatalf("authentication error = %v", err)
			}
			if !bytes.Equal(response.Bytes(), want) {
				t.Fatalf("authentication response = %v, want %v", response.Bytes(), want)
			}
		})
	}
}

type oneByteWriter struct {
	bytes.Buffer
}

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func TestUnauthenticatedDataStreamNeverOpensTarget(t *testing.T) {
	tests := []struct {
		name            string
		activateServer  bool
		mutateClientRef bool
		mutateToken     bool
	}{
		{
			name: "locally forged grant without server session",
		},
		{
			name:           "wrong token for active session",
			activateServer: true,
			mutateToken:    true,
		},
		{
			name:            "wrong client id for active session",
			activateServer:  true,
			mutateClientRef: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			listener := newPipeListener()
			server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
				Listener:  listener,
				TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var openStreamCalls atomic.Int32
			serveErr := make(chan error, 1)
			go func() {
				serveErr <- server.Serve(ctx,
					coretransport.ControlHandlerFunc(func(context.Context, net.Conn) error {
						return errors.New("control handler must not be called")
					}),
					coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
						openStreamCalls.Add(1)
						return nil, errors.New("target must not be opened")
					}),
				)
			}()

			client, err := NewClient(ClientConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret,
				Address:   listener.Addr().String(),
				TLSConfig: clientTLS,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return listener.DialContext(ctx)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			serverGrant, err := coretransport.NewSessionGrant(1001, 1, time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if tt.activateServer {
				if err := server.Activate(ctx, serverGrant); err != nil {
					t.Fatal(err)
				}
			}
			clientGrant := serverGrant
			if tt.mutateClientRef {
				clientGrant.ClientID++
			}
			if tt.mutateToken {
				clientGrant.DataToken[0] ^= 0xff
			}
			if err := client.Activate(ctx, clientGrant); err != nil {
				t.Fatal(err)
			}

			dialCtx, dialCancel := context.WithTimeout(ctx, time.Second)
			stream, err := client.DialStream(dialCtx, testDestination())
			dialCancel()
			if stream != nil {
				_ = stream.Close()
			}
			if err == nil {
				t.Fatal("unauthenticated data stream was accepted")
			}
			if got := openStreamCalls.Load(); got != 0 {
				t.Fatalf("open stream calls = %d, want 0", got)
			}

			cancel()
			_ = server.Close()
			select {
			case err := <-serveErr:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("server did not stop")
			}
		})
	}
}
