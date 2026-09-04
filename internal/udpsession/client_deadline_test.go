// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func newLoopbackClientConn(t *testing.T, req NewClientConnReq) *clientConn {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	conn, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	client, ok := NewClientConn(conn, req).(*clientConn)
	if !ok {
		t.Fatal("unexpected client connection type")
	}
	return client
}

func TestClientConnDeadlineRefreshIsRaceFree(t *testing.T) {
	client := newLoopbackClientConn(t, NewClientConnReq{IOTimeout: time.Millisecond})

	const iterations = 200
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bufs := [][]byte{make([]byte, client.maxPacket)}
		sizes := make([]int, 1)
		for i := 0; i < iterations; i++ {
			_, _ = client.ReadBatch(ctx, bufs, sizes)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = client.SetReadDeadline(time.Now().Add(time.Hour))
		}
	}()
	wg.Wait()
}

func TestClientConnKeepsCallerReadDeadline(t *testing.T) {
	client := newLoopbackClientConn(t, NewClientConnReq{IOTimeout: 5 * time.Second})

	const callerTimeout = 50 * time.Millisecond
	if err := client.SetReadDeadline(time.Now().Add(callerTimeout)); err != nil {
		t.Fatal(err)
	}

	bufs := [][]byte{make([]byte, client.maxPacket)}
	sizes := make([]int, 1)
	start := time.Now()
	if _, err := client.ReadBatch(context.Background(), bufs, sizes); err == nil {
		t.Fatal("expected the read to fail at the caller's deadline")
	}
	elapsed := time.Since(start)

	if elapsed < callerTimeout/2 {
		t.Fatalf("read returned after %s, before the caller's %s deadline", elapsed, callerTimeout)
	}
	if elapsed > time.Second {
		t.Fatalf("read blocked for %s, so it used the %s ioTimeout deadline instead of the caller's %s",
			elapsed, 5*time.Second, callerTimeout)
	}
}

func TestClientConnDeadlineRefreshFailureDoesNotAdvanceState(t *testing.T) {
	client := newLoopbackClientConn(t, NewClientConnReq{IOTimeout: time.Second})
	if err := client.conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err := client.refreshReadDeadline(time.Now()); err == nil {
		t.Fatal("read deadline refresh succeeded on a closed socket")
	}
	if !client.ioReadDeadline.IsZero() {
		t.Fatalf("read deadline advanced after failure: %v", client.ioReadDeadline)
	}

	client.writeMu.Lock()
	err := client.refreshWriteDeadlineLocked(time.Now())
	client.writeMu.Unlock()
	if err == nil {
		t.Fatal("write deadline refresh succeeded on a closed socket")
	}
	if !client.ioWriteDeadline.IsZero() {
		t.Fatalf("write deadline advanced after failure: %v", client.ioWriteDeadline)
	}
}
