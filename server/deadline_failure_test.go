// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAuthenticationRejectsReadDeadlineFailureBeforeReading(t *testing.T) {
	want := errors.New("synthetic read deadline failure")
	for _, tt := range []struct {
		name string
		auth func(*Server, net.Conn, ServeOptions) error
	}{
		{
			name: "packet",
			auth: func(s *Server, conn net.Conn, opt ServeOptions) error {
				_, err := s.authenticatePacketConn(context.Background(), conn, opt)
				return err
			},
		},
		{
			name: "control",
			auth: func(s *Server, conn net.Conn, opt ServeOptions) error {
				_, err := s.authenticateControlConn(context.Background(), conn, opt)
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &failingReadDeadlineConn{err: want}
			err := tt.auth(&Server{}, conn, ServeOptions{AuthTimeout: time.Second, ReadBufferSize: 64})
			if !errors.Is(err, want) {
				t.Fatalf("authentication error = %v, want %v", err, want)
			}
			if conn.readCalled {
				t.Fatal("authentication read after deadline setup failed")
			}
		})
	}
}

func TestAuthenticationRejectsWriteDeadlineFailureBeforeReading(t *testing.T) {
	want := errors.New("synthetic write deadline failure")
	for _, tt := range []struct {
		name string
		auth func(*Server, net.Conn, ServeOptions) error
	}{
		{
			name: "packet",
			auth: func(s *Server, conn net.Conn, opt ServeOptions) error {
				_, err := s.authenticatePacketConn(context.Background(), conn, opt)
				return err
			},
		},
		{
			name: "control",
			auth: func(s *Server, conn net.Conn, opt ServeOptions) error {
				_, err := s.authenticateControlConn(context.Background(), conn, opt)
				return err
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := &failingWriteDeadlineConn{err: want}
			err := tt.auth(&Server{}, conn, ServeOptions{AuthTimeout: time.Second, ReadBufferSize: 64})
			if !errors.Is(err, want) {
				t.Fatalf("authentication error = %v, want %v", err, want)
			}
			if conn.readCalled {
				t.Fatal("authentication read after deadline setup failed")
			}
		})
	}
}

type failingReadDeadlineConn struct {
	err        error
	readCalled bool
}

func (c *failingReadDeadlineConn) Read([]byte) (int, error) {
	c.readCalled = true
	return 0, errors.New("unexpected read")
}
func (*failingReadDeadlineConn) Write(p []byte) (int, error)       { return len(p), nil }
func (*failingReadDeadlineConn) Close() error                      { return nil }
func (*failingReadDeadlineConn) LocalAddr() net.Addr               { return nil }
func (*failingReadDeadlineConn) RemoteAddr() net.Addr              { return nil }
func (*failingReadDeadlineConn) SetDeadline(time.Time) error       { return nil }
func (c *failingReadDeadlineConn) SetReadDeadline(time.Time) error { return c.err }
func (*failingReadDeadlineConn) SetWriteDeadline(time.Time) error  { return nil }

type failingWriteDeadlineConn struct {
	err        error
	readCalled bool
}

func (c *failingWriteDeadlineConn) Read([]byte) (int, error) {
	c.readCalled = true
	return 0, errors.New("unexpected read")
}
func (*failingWriteDeadlineConn) Write(p []byte) (int, error)     { return len(p), nil }
func (*failingWriteDeadlineConn) Close() error                    { return nil }
func (*failingWriteDeadlineConn) LocalAddr() net.Addr             { return nil }
func (*failingWriteDeadlineConn) RemoteAddr() net.Addr            { return nil }
func (*failingWriteDeadlineConn) SetDeadline(time.Time) error     { return nil }
func (*failingWriteDeadlineConn) SetReadDeadline(time.Time) error { return nil }
func (c *failingWriteDeadlineConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		return nil
	}
	return c.err
}
