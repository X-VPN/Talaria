// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestNewClientConnClampsPublicBufferSizes(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client, ok := NewClientConn(conn, NewClientConnReq{
		MaxPacket: defaultMaxPacket + 1,
		BatchSize: maxBatchSize + 1,
	}).(*clientConn)
	if !ok {
		t.Fatal("unexpected client connection type")
	}
	if client.maxPacket != defaultMaxPacket {
		t.Fatalf("max packet = %d, want %d", client.maxPacket, defaultMaxPacket)
	}
	if client.batchSize != maxBatchSize {
		t.Fatalf("batch size = %d, want %d", client.batchSize, maxBatchSize)
	}
}

func TestClientConnSerializesCompleteReadPath(t *testing.T) {
	batch := &blockingClientBatchPacketConn{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}, 2),
	}
	client := &clientConn{
		maxPacket:    4,
		batchSize:    1,
		batchEnabled: true,
		batchV4:      batch,
		readMsgs4:    make([]ipv4.Message, 1),
		readVecs4:    make([][1][]byte, 1),
	}
	results := make(chan error, 2)
	read := func() {
		_, err := client.ReadBatch(context.Background(), [][]byte{make([]byte, 4)}, make([]int, 1))
		results <- err
	}
	go read()
	<-batch.entered
	go read()
	select {
	case <-batch.entered:
		t.Fatal("second ReadBatch entered shared batch state concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	batch.release <- struct{}{}
	select {
	case <-batch.entered:
	case <-time.After(time.Second):
		t.Fatal("second ReadBatch did not run after the first completed")
	}
	batch.release <- struct{}{}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := batch.maxActive.Load(); got != 1 {
		t.Fatalf("concurrent batch readers = %d want 1", got)
	}
}

func TestMaxUDPPayloadForAddrUsesIPFamily(t *testing.T) {
	if got := MaxUDPPayloadForAddr(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}); got != MaxUDPPayloadIPv4 {
		t.Fatalf("IPv4 UDP payload maximum = %d want %d", got, MaxUDPPayloadIPv4)
	}
	if got := MaxUDPPayloadForAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1")}); got != MaxUDPPayloadIPv6 {
		t.Fatalf("IPv6 UDP payload maximum = %d want %d", got, MaxUDPPayloadIPv6)
	}
}

func TestCompactReadBatch(t *testing.T) {
	const maxPacket = 4
	tests := []struct {
		name        string
		packets     [][]byte
		sizes       []int
		n           int
		wantPackets [][]byte
		wantErr     bool
	}{
		{name: "no messages", n: 0},
		{name: "empty datagram", packets: [][]byte{nil}, sizes: []int{0}, n: 1},
		{name: "leading empty", packets: [][]byte{nil, {1}, {2, 3}}, sizes: []int{0, 1, 2}, n: 3, wantPackets: [][]byte{{1}, {2, 3}}},
		{name: "middle empty", packets: [][]byte{{1}, nil, {2, 3}}, sizes: []int{1, 0, 2}, n: 3, wantPackets: [][]byte{{1}, {2, 3}}},
		{name: "trailing empty", packets: [][]byte{{1}, {2, 3}, nil}, sizes: []int{1, 2, 0}, n: 3, wantPackets: [][]byte{{1}, {2, 3}}},
		{name: "multiple empty", packets: [][]byte{nil, {1}, nil, {2, 3}, nil}, sizes: []int{0, 1, 0, 2, 0}, n: 5, wantPackets: [][]byte{{1}, {2, 3}}},
		{name: "negative size", packets: [][]byte{{1}}, sizes: []int{-1}, n: 1, wantErr: true},
		{name: "oversized packet", packets: [][]byte{{1}}, sizes: []int{maxPacket + 1}, n: 1, wantErr: true},
		{name: "invalid count", n: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bufs := make([][]byte, len(tt.sizes))
			for i := range bufs {
				bufs[i] = make([]byte, maxPacket)
				if i < len(tt.packets) {
					copy(bufs[i], tt.packets[i])
				}
			}
			sizes := append([]int(nil), tt.sizes...)
			n, err := compactReadBatch(bufs, sizes, tt.n, maxPacket)
			if tt.wantErr {
				if err == nil {
					t.Fatal("invalid batch metadata was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n != len(tt.wantPackets) {
				t.Fatalf("packet count = %d, want %d", n, len(tt.wantPackets))
			}
			for i, want := range tt.wantPackets {
				if sizes[i] != len(want) {
					t.Fatalf("size[%d] = %d, want %d", i, sizes[i], len(want))
				}
				if !bytes.Equal(bufs[i][:sizes[i]], want) {
					t.Fatalf("packet[%d] = %v, want %v", i, bufs[i][:sizes[i]], want)
				}
			}
			for i := n; i < tt.n; i++ {
				if sizes[i] != 0 {
					t.Fatalf("discarded size[%d] = %d, want 0", i, sizes[i])
				}
			}
		})
	}
}

func TestClientReadBatchSkipsEmptyBatch(t *testing.T) {
	tests := []struct {
		name string
		ipv6 bool
	}{
		{name: "IPv4"},
		{name: "IPv6", ipv6: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := &scriptedClientBatchPacketConn{reads: [][][]byte{{nil, nil}, {{1, 2}}}}
			client := &clientConn{
				maxPacket:    4,
				batchSize:    2,
				batchEnabled: true,
			}
			if tt.ipv6 {
				client.batchIPv6 = true
				client.batchV6 = batch
				client.readMsgs6 = make([]ipv6.Message, client.batchSize)
				client.readVecs6 = make([][1][]byte, client.batchSize)
			} else {
				client.batchV4 = batch
				client.readMsgs4 = make([]ipv4.Message, client.batchSize)
				client.readVecs4 = make([][1][]byte, client.batchSize)
			}
			bufs := [][]byte{make([]byte, client.maxPacket), make([]byte, client.maxPacket)}
			sizes := make([]int, len(bufs))
			n, err := client.ReadBatch(t.Context(), bufs, sizes)
			if err != nil {
				t.Fatal(err)
			}
			if batch.readCalls != 2 {
				t.Fatalf("batch reads = %d, want 2", batch.readCalls)
			}
			if n != 1 || sizes[0] != 2 || !bytes.Equal(bufs[0][:sizes[0]], []byte{1, 2}) {
				t.Fatalf("read = n=%d size=%d packet=%v, want 1/2/[1 2]", n, sizes[0], bufs[0][:sizes[0]])
			}
		})
	}
}

func TestClientWriteBatchSkipsEmptyPackets(t *testing.T) {
	for _, ipv6Batch := range []bool{false, true} {
		name := "IPv4"
		if ipv6Batch {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			batch := &recordingClientBatchPacketConn{}
			client := &clientConn{
				maxPacket:    4,
				batchSize:    3,
				batchEnabled: true,
				batchIPv6:    ipv6Batch,
			}
			if ipv6Batch {
				client.batchV6 = batch
				client.writeMsgs6 = make([]ipv6.Message, client.batchSize)
				client.writeVecs6 = make([][1][]byte, client.batchSize)
			} else {
				client.batchV4 = batch
				client.writeMsgs4 = make([]ipv4.Message, client.batchSize)
				client.writeVecs4 = make([][1][]byte, client.batchSize)
			}
			written, err := client.WriteBatch(context.Background(), [][]byte{{1}, nil, {2}}, []int{1, 0, 1})
			if err != nil {
				t.Fatal(err)
			}
			if written != 2 {
				t.Fatalf("WriteBatch() = %d, want 2", written)
			}
			if got := batch.writeSizes; !bytes.Equal(got, []byte{1, 1}) {
				t.Fatalf("written packet sizes = %v, want [1 1]", got)
			}
		})
	}
}

type scriptedClientBatchPacketConn struct {
	reads     [][][]byte
	readCalls int
}

type blockingClientBatchPacketConn struct {
	entered   chan struct{}
	release   chan struct{}
	active    atomic.Int32
	maxActive atomic.Int32
}

type recordingClientBatchPacketConn struct {
	writeSizes []byte
}

func (c *blockingClientBatchPacketConn) ReadBatch(msgs []ipv4.Message, _ int) (int, error) {
	active := c.active.Add(1)
	for {
		maxActive := c.maxActive.Load()
		if active <= maxActive || c.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	c.entered <- struct{}{}
	<-c.release
	c.active.Add(-1)
	msgs[0].Buffers[0][0] = 1
	msgs[0].N = 1
	return 1, nil
}

func (*blockingClientBatchPacketConn) WriteBatch([]ipv4.Message, int) (int, error) {
	return 0, net.ErrClosed
}

func (*recordingClientBatchPacketConn) ReadBatch([]ipv4.Message, int) (int, error) {
	return 0, net.ErrClosed
}

func (c *recordingClientBatchPacketConn) WriteBatch(msgs []ipv4.Message, _ int) (int, error) {
	for _, msg := range msgs {
		c.writeSizes = append(c.writeSizes, byte(len(msg.Buffers[0])))
	}
	return len(msgs), nil
}

func (c *scriptedClientBatchPacketConn) ReadBatch(msgs []ipv4.Message, _ int) (int, error) {
	c.readCalls++
	if len(c.reads) == 0 {
		return 0, net.ErrClosed
	}
	batch := c.reads[0]
	c.reads = c.reads[1:]
	if len(batch) > len(msgs) {
		return 0, net.ErrClosed
	}
	for i, packet := range batch {
		copy(msgs[i].Buffers[0], packet)
		msgs[i].N = len(packet)
	}
	return len(batch), nil
}

func (*scriptedClientBatchPacketConn) WriteBatch([]ipv4.Message, int) (int, error) {
	return 0, net.ErrClosed
}
