// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestListenerRecoversWindowsReadErrors(t *testing.T) {
	for _, err := range []error{
		windows.WSAEMSGSIZE, windows.WSAECONNRESET, windows.WSAENETRESET,
		windows.WSAECONNREFUSED, windows.WSAEWOULDBLOCK, windows.WSAENOBUFS,
		windows.ERROR_NOT_ENOUGH_MEMORY, windows.WSAENETDOWN, windows.WSAENETUNREACH,
		windows.WSAEHOSTUNREACH, windows.WSAEHOSTDOWN, windows.WSAETIMEDOUT,
	} {
		t.Run(err.Error(), func(t *testing.T) {
			testListenerRecoversReadError(t, err)
		})
	}
}

func TestListenerSurvivesWindowsOversizedDatagrams(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	listener, err := NewListener(NewListenerReq{PacketConn: pc, ReadBufferSize: 4, MaxPacket: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("init")); err != nil {
		t.Fatal(err)
	}
	conn := acceptTestSession(t, listener)
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "init" {
		t.Fatalf("initial packet = %q, error = %v", buf[:n], err)
	}
	// Windows ReadFrom returns WSAEMSGSIZE for each datagram exceeding
	// the four-byte receive buffer; none may close the shared listener.
	oversized := make([]byte, 1024)
	for range 50 {
		if _, err := peer.Write(oversized); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := peer.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "next" {
		t.Fatalf("packet after oversized burst = %q, error = %v", buf[:n], err)
	}
	newPeer, err := net.Dial("udp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer newPeer.Close()
	if err := newPeer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := newPeer.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	newConn := acceptTestSession(t, listener)
	defer newConn.Close()
}
