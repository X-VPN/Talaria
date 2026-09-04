// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnSetReadDeadlineWakesBlockedRead(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:    1,
		SessionQueue:   2,
		MaxPacket:      4,
		ReadBufferSize: 4,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 30001}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := conn.Read(buf)
		result <- err
	}()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("blocked read error = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not wake blocked read")
	}
}

func TestConnBlockedReadRecomputesExtendedDeadline(t *testing.T) {
	listener := newManualTestListener(t, NewListenerReq{
		AcceptQueue:    1,
		SessionQueue:   2,
		MaxPacket:      4,
		ReadBufferSize: 4,
	})
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 21), Port: 30002}
	if err := listener.ReceivePacket([]byte{1}, addr); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		n   int
		err error
	}
	result := make(chan readResult, 1)
	go func() {
		n, err := conn.Read(buf)
		result <- readResult{n: n, err: err}
	}()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if err := listener.ReceivePacket([]byte{2}, addr); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.err != nil || got.n != 1 || buf[0] != 2 {
			t.Fatalf("read after deadline extension = n=%d data=%v err=%v", got.n, buf, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not continue after deadline extension")
	}
}
