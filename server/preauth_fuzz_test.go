// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
)

func FuzzControlPreAuthStateMachine(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64*1024 {
			t.Skip()
		}
		srv := &Server{
			protocol: client.ProtocolTalariaTCP,
			codec:    dataplane.WireCodec{},
			auth: AuthProviderFunc(func(context.Context, AuthRequest) (AuthResult, error) {
				return AuthResult{ClientID: 1, Version: 1}, nil
			}),
		}
		conn := newPreAuthFuzzConn(raw)
		_, _ = srv.authenticateControlConn(context.Background(), conn, ServeOptions{
			Protocol:       client.ProtocolTalariaTCP,
			ReadBufferSize: 64 * 1024,
			AuthTimeout:    time.Second,
		})
	})
}

type preAuthFuzzConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func newPreAuthFuzzConn(raw []byte) *preAuthFuzzConn {
	return &preAuthFuzzConn{reader: bytes.NewReader(raw)}
}

func (c *preAuthFuzzConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (c *preAuthFuzzConn) Write(p []byte) (int, error)    { return c.writes.Write(p) }
func (*preAuthFuzzConn) Close() error                     { return nil }
func (*preAuthFuzzConn) LocalAddr() net.Addr              { return preAuthFuzzAddr("local") }
func (*preAuthFuzzConn) RemoteAddr() net.Addr             { return preAuthFuzzAddr("remote") }
func (*preAuthFuzzConn) SetDeadline(time.Time) error      { return nil }
func (*preAuthFuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (*preAuthFuzzConn) SetWriteDeadline(time.Time) error { return nil }

type preAuthFuzzAddr string

func (a preAuthFuzzAddr) Network() string { return "fuzz" }
func (a preAuthFuzzAddr) String() string  { return string(a) }
