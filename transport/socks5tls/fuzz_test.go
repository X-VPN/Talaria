// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"testing"
	"time"

	coretransport "github.com/X-VPN/Talaria/transport"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func FuzzSOCKS5RequestParsing(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	f.Add([]byte{})
	f.Add([]byte{5, 3, 0xff})

	f.Fuzz(func(t *testing.T, request []byte) {
		if len(request) > 4096 {
			t.Skip()
		}
		now := time.Unix(100, 0)
		grant := coretransport.SessionGrant{
			SessionRef: coretransport.SessionRef{ClientID: 1, Generation: 1},
		}
		grant.DataToken[0] = 1
		registry := coretransport.NewSessionRegistry()
		if err := registry.Activate(grant, now); err != nil {
			t.Fatal(err)
		}
		server := &Server{
			now:      func() time.Time { return now },
			registry: registry,
			flows:    make(map[coretransport.SessionRef]map[*streamFlow]struct{}),
			expiry:   make(map[coretransport.SessionRef]*time.Timer),
			closed:   make(chan struct{}),
			streamHandler: coretransport.StreamHandlerFunc(func(context.Context, coretransport.StreamRequest) (net.Conn, error) {
				return nil, net.ErrClosed
			}),
		}
		socksServer := gosocks5.NewServer(
			gosocks5.WithResolver(noResolveResolver{}),
			gosocks5.WithAuthMethods([]gosocks5.Authenticator{
				sessionAuthenticator{server: server},
			}),
			gosocks5.WithConnectHandle(server.handleConnect),
			gosocks5.WithBindHandle(rejectUnsupportedCommand),
			gosocks5.WithAssociateHandle(rejectUnsupportedCommand),
		)

		password := base64.RawURLEncoding.EncodeToString(grant.DataToken[:])
		wire := []byte{5, 1, statute.MethodUserPassAuth}
		wire = append(wire, 1, 1, '1', byte(len(password)))
		wire = append(wire, password...)
		wire = append(wire, request...)
		_ = socksServer.ServeConn(newFuzzMemoryConn(wire))
	})
}

func FuzzDecodeCredentials(f *testing.F) {
	f.Add("1", base64.RawURLEncoding.EncodeToString(make([]byte, coretransport.DataTokenSize)))
	f.Add("", "")
	f.Add(strconv.FormatUint(^uint64(0), 10), "invalid")
	f.Fuzz(func(t *testing.T, user, password string) {
		if len(user) > 1024 || len(password) > 1024 {
			t.Skip()
		}
		var token [coretransport.DataTokenSize]byte
		_, _ = decodeCredentialsBytes([]byte(user), []byte(password), &token)
		clear(token[:])
	})
}

type fuzzMemoryConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func newFuzzMemoryConn(raw []byte) *fuzzMemoryConn {
	return &fuzzMemoryConn{reader: bytes.NewReader(raw)}
}

func (c *fuzzMemoryConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (c *fuzzMemoryConn) Write(p []byte) (int, error)    { return c.writes.Write(p) }
func (*fuzzMemoryConn) Close() error                     { return nil }
func (*fuzzMemoryConn) LocalAddr() net.Addr              { return fuzzSOCKSAddr("local") }
func (*fuzzMemoryConn) RemoteAddr() net.Addr             { return fuzzSOCKSAddr("remote") }
func (*fuzzMemoryConn) SetDeadline(time.Time) error      { return nil }
func (*fuzzMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*fuzzMemoryConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzSOCKSAddr string

func (a fuzzSOCKSAddr) Network() string { return "fuzz" }
func (a fuzzSOCKSAddr) String() string  { return string(a) }
