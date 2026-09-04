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

func TestServerStopsAfterPermanentTalariaUDPAcceptError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	want := errors.New("synthetic permanent accept failure")
	acceptor := &permanentErrorTalariaUDPAcceptor{err: want}
	s := &Server{cancel: cancel}

	s.runTalariaUDPAcceptLoop(ctx, acceptor, Config{})

	if acceptor.calls != 1 {
		t.Fatalf("Accept calls = %d, want 1", acceptor.calls)
	}
	if ctx.Err() == nil {
		t.Fatal("permanent TalariaUDP accept failure did not close the server")
	}
}

func TestServerClosesConnectionReturnedWithTalariaUDPAcceptError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	acceptor := &permanentErrorTalariaUDPAcceptor{
		conn: serverConn,
		err:  errors.New("synthetic permanent accept failure"),
	}
	s := &Server{cancel: cancel}

	s.runTalariaUDPAcceptLoop(ctx, acceptor, Config{})

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := clientConn.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection returned with TalariaUDP accept error remained open")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("timed out waiting for failed TalariaUDP connection to close")
		}
	}
}

func TestServerStopsAfterNilTalariaUDPAcceptResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var conn *net.TCPConn
	acceptor := &permanentErrorTalariaUDPAcceptor{conn: conn}
	s := &Server{cancel: cancel}

	s.runTalariaUDPAcceptLoop(ctx, acceptor, Config{})

	if acceptor.calls != 1 {
		t.Fatalf("Accept calls = %d, want 1", acceptor.calls)
	}
	if ctx.Err() == nil {
		t.Fatal("nil TalariaUDP accept result did not close the server")
	}
}

type permanentErrorTalariaUDPAcceptor struct {
	conn  net.Conn
	err   error
	calls int
}

func (a *permanentErrorTalariaUDPAcceptor) Accept(context.Context) (net.Conn, error) {
	a.calls++
	return a.conn, a.err
}
