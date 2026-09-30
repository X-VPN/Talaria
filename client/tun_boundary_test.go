// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/X-VPN/Talaria/client/dataplane"
)

func TestDownlinkTunWriterDropsWhenQueueIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tun := &queueBlockingTun{started: make(chan struct{})}
	writer := newDownlinkTunWriter(ctx, tun, defaultDownlinkQueueSize, noopStatsSink{}, nil)
	pool := dataplane.NewPool(256, dataplane.DefaultHeadroom)
	data := testIPv4Packet()
	enqueue := func() error {
		pkt := pool.Get()
		copy(pkt.Raw[pkt.Start:], data)
		pkt.End = pkt.Start + len(data)
		if err := writer.writeBuffer(pkt, pool); err != nil {
			pool.Put(pkt)
			return err
		}
		return nil
	}
	if err := enqueue(); err != nil {
		t.Fatal(err)
	}
	<-tun.started
	for range defaultDownlinkQueueSize {
		if err := enqueue(); err != nil {
			t.Fatal(err)
		}
	}
	if err := enqueue(); err != nil {
		t.Fatalf("drop from full downlink queue: %v", err)
	}
	if got := len(writer.queue); got != defaultDownlinkQueueSize {
		t.Fatalf("downlink queue size after drop = %d, want %d", got, defaultDownlinkQueueSize)
	}
	cancel()
	writer.close()
}

func TestDownlinkTunWriterDoesNotCountDroppedPackets(t *testing.T) {
	valid := testIPv4Packet()
	tun := &invalidProgressTun{writeN: len(valid)}
	stats := &tunWriteStats{}
	var callbackErr error
	writer := newDownlinkTunWriter(context.Background(), tun, 2, stats, func(err error) {
		callbackErr = err
	})
	for _, data := range [][]byte{{0x45, 0, 0}, valid} {
		pkt := &dataplane.PacketBuffer{Raw: data, End: len(data)}
		if err := writer.writeBuffer(pkt, nil); err != nil {
			writer.close()
			t.Fatalf("enqueue packet: %v", err)
		}
	}
	writer.close()
	if err := writer.getErr(); err != nil || callbackErr != nil {
		t.Fatalf("writer error = %v, callback error = %v; want nil", err, callbackErr)
	}
	if tun.writes != 1 {
		t.Fatalf("TUN writes = %d, want 1", tun.writes)
	}
	if stats.downloadBytes != len(valid) || stats.tunBytes != len(valid) || stats.tunCalls != 1 {
		t.Fatalf("download bytes = %d, TUN bytes = %d, TUN callbacks = %d; want %d, %d, 1",
			stats.downloadBytes, stats.tunBytes, stats.tunCalls, len(valid), len(valid))
	}
}

func TestUplinkConnWriterUsesConfiguredQueueSize(t *testing.T) {
	for _, test := range []struct {
		configured int
		want       int
	}{
		{configured: 0, want: defaultUplinkQueueSize},
		{configured: 7, want: 7},
	} {
		writer := newUplinkConnWriter(context.Background(), nil, test.configured, noopStatsSink{}, nil)
		if got := cap(writer.queue); got != test.want {
			t.Errorf("uplink queue capacity = %d, want %d", got, test.want)
		}
		writer.close()
	}
}

func TestTunHelpersRejectInvalidProgress(t *testing.T) {
	validIPv4 := testIPv4Packet()
	t.Run("read overflow", func(t *testing.T) {
		pkt := &dataplane.PacketBuffer{Raw: make([]byte, 16), Start: 4, End: 4}
		tun := &invalidProgressTun{readN: 13}
		if _, err := readTunPacketToBuffer(tun, pkt); err == nil {
			t.Fatal("overflowing TUN read was accepted")
		}
	})

	t.Run("offset read negative", func(t *testing.T) {
		pkt := &dataplane.PacketBuffer{Raw: make([]byte, 16), Start: 4, End: 4}
		tun := &invalidProgressOffsetTun{invalidProgressTun: invalidProgressTun{readN: -1}}
		if _, err := readTunPacketToBuffer(tun, pkt); err == nil {
			t.Fatal("negative offset TUN read was accepted")
		}
	})

	t.Run("payload short write", func(t *testing.T) {
		pkt := &dataplane.PacketBuffer{Raw: validIPv4, Start: 0, End: len(validIPv4)}
		tun := &invalidProgressTun{writeN: 2}
		if n, err := writeTunPacketBuffer(context.Background(), tun, pkt); n != 2 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeTunPacketBuffer() = (%d, %v), want (2, %v)", n, err, io.ErrShortWrite)
		}
	})

	t.Run("offset short write", func(t *testing.T) {
		pkt := &dataplane.PacketBuffer{Raw: append([]byte{0}, validIPv4...), Start: 1, End: 1 + len(validIPv4)}
		tun := &invalidProgressOffsetTun{invalidProgressTun: invalidProgressTun{writeN: 2}}
		if n, err := writeTunPacketBuffer(context.Background(), tun, pkt); n != 2 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeTunPacketBuffer() = (%d, %v), want (2, %v)", n, err, io.ErrShortWrite)
		}
	})

	t.Run("invalid packet bounds", func(t *testing.T) {
		packets := []*dataplane.PacketBuffer{
			{Raw: []byte{0, 1, 2}, Start: -1, End: 1},
			{Raw: []byte{0, 1, 2}, Start: 2, End: 1},
			{Raw: []byte{0, 1, 2}, Start: 1, End: 4},
		}
		for _, pkt := range packets {
			tun := &trackingOffsetTun{}
			if _, err := writeTunPacketBuffer(context.Background(), tun, pkt); !errors.Is(err, errInvalidTunPacket) {
				t.Fatalf("invalid packet bounds error = %v, want %v", err, errInvalidTunPacket)
			}
			if tun.writes != 0 {
				t.Fatalf("offset TUN writes = %d, want 0", tun.writes)
			}
			if err := copyTunPayload(pkt, []byte{1}); !errors.Is(err, errInvalidTunPacket) {
				t.Fatalf("invalid copy bounds error = %v, want %v", err, errInvalidTunPacket)
			}
		}
	})
}

func testIPv4Packet() []byte {
	return []byte{
		0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0x66, 0xdb,
		10, 1, 0, 2, 10, 2, 0, 1,
		8, 0, 0xf7, 0xfd, 0, 1, 0, 1,
	}
}

func TestWriteConnFrameRejectsShortWrite(t *testing.T) {
	if err := writeConnFrame(shortWriteConn{}, []byte{1, 2}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeConnFrame() error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestReadConnFrameRejectsInvalidProgress(t *testing.T) {
	for _, readErr := range []error{nil, errors.New("synthetic read failure")} {
		for _, n := range []int{-1, 2} {
			read, err := readConnFrame(invalidReadProgressConn{n: n, err: readErr}, make([]byte, 1))
			if read != 0 || err == nil {
				t.Fatalf("readConnFrame() with progress %d and error %v = %d, %v; want 0, error", n, readErr, read, err)
			}
		}
	}
}

type shortWriteConn struct{ net.Conn }

func (shortWriteConn) Write([]byte) (int, error) { return 1, nil }

type invalidReadProgressConn struct {
	net.Conn
	n   int
	err error
}

func (c invalidReadProgressConn) Read([]byte) (int, error) {
	return c.n, c.err
}

type invalidProgressTun struct {
	readN  int
	writeN int
	writes int
}

type tunWriteStats struct {
	noopStatsSink
	downloadBytes int
	tunBytes      int
	tunCalls      int
}

func (s *tunWriteStats) OnDownloadBytes(_ context.Context, n int) { s.downloadBytes += n }
func (s *tunWriteStats) OnTunWrite(_ context.Context, n int) {
	s.tunBytes += n
	s.tunCalls++
}

type queueBlockingTun struct {
	started chan struct{}
	once    sync.Once
}

func (*queueBlockingTun) Read([]byte) (int, error)  { return 0, io.EOF }
func (*queueBlockingTun) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (t *queueBlockingTun) WriteContext(ctx context.Context, _ []byte) (int, error) {
	t.once.Do(func() { close(t.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}
func (*queueBlockingTun) Close() error { return nil }

func (t *invalidProgressTun) Read([]byte) (int, error)  { return t.readN, nil }
func (t *invalidProgressTun) Write([]byte) (int, error) { return t.writeN, nil }
func (t *invalidProgressTun) WriteContext(context.Context, []byte) (int, error) {
	t.writes++
	return t.writeN, nil
}
func (*invalidProgressTun) Close() error { return nil }

type invalidProgressOffsetTun struct {
	invalidProgressTun
}

func (t *invalidProgressOffsetTun) ReadPacketOffset([]byte, int) (int, error) {
	return t.readN, nil
}

func (t *invalidProgressOffsetTun) WritePacketOffset(context.Context, []byte, int, int) (int, error) {
	return t.writeN, nil
}

type trackingOffsetTun struct {
	invalidProgressTun
	writes int
}

func (t *trackingOffsetTun) WritePacketOffset(context.Context, []byte, int, int) (int, error) {
	t.writes++
	return 0, nil
}
