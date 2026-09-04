// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestNewTunPacketHandlerRejectsInvalidDeviceBatchSize(t *testing.T) {
	for _, batchSize := range []int{0, -1, 257} {
		t.Run(fmt.Sprintf("batch_%d", batchSize), func(t *testing.T) {
			_, err := NewTunPacketHandler(TunPacketHandlerConfig{
				Device:        newScriptedTunDevice(batchSize),
				VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
			})
			if err == nil {
				t.Fatalf("batch size %d: expected an error", batchSize)
			}
		})
	}
}

func TestNewTunPacketHandlerRejectsInvalidWriteBudgets(t *testing.T) {
	tests := []struct {
		name   string
		update func(*TunPacketHandlerConfig)
	}{
		{
			name: "negative virtual IP reuse delay",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.VirtualIPReuseDelay = -1
			},
		},
		{
			name: "positive virtual IP reuse delay",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.VirtualIPReuseDelay = time.Second
			},
		},
		{
			name: "negative read buffer",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.ReadBufferSize = -1
			},
		},
		{
			name: "read buffer above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.ReadBufferSize = maxServerTunReadBufferSize + 1
			},
		},
		{
			name: "read buffer below MTU",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.ReadBufferSize = 1499
			},
		},
		{
			name: "negative global bytes",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueBytes = -1
			},
		},
		{
			name: "negative global packets",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueSize = -1
			},
		},
		{
			name: "global bytes above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueBytes = maxServerTunWriteQueueBytes + 1
			},
		},
		{
			name: "derived global write bytes above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.Device = &headroomTunDevice{
					scriptedTunDevice: newScriptedTunDevice(1),
					headroom:          maxServerTunWriteHeadroom,
				}
				cfg.WriteQueueSize = 1 << 16
			},
		},
		{
			name: "negative session packets",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.SessionWritePackets = -1
			},
		},
		{
			name: "session packets above global",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueSize = 2
				cfg.SessionWritePackets = 3
			},
		},
		{
			name: "negative session bytes",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.SessionWriteBytes = -1
			},
		},
		{
			name: "session bytes above global",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueBytes = 1024
				cfg.SessionWriteBytes = 1025
			},
		},
		{
			name: "derived session write bytes above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.WriteQueueSize = 1 << 16
				cfg.SessionWritePackets = 1 << 16
			},
		},
		{
			name: "negative device write headroom",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.Device = &headroomTunDevice{
					scriptedTunDevice: newScriptedTunDevice(1),
					headroom:          -1,
				}
			},
		},
		{
			name: "negative global downlink packets",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.GlobalDownlinkPackets = -1
			},
		},
		{
			name: "session downlink packets above global",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.DownlinkPackets = 2
				cfg.GlobalDownlinkPackets = 1
			},
		},
		{
			name: "negative global downlink bytes",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.GlobalDownlinkBytes = -1
			},
		},
		{
			name: "derived session downlink bytes above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.DownlinkPackets = 1 << 16
			},
		},
		{
			name: "derived global downlink bytes above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.GlobalDownlinkPackets = 1 << 18
			},
		},
		{
			name: "session downlink bytes above global",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.DownlinkBytes = 2
				cfg.GlobalDownlinkBytes = 1
			},
		},
		{
			name: "device write headroom above maximum",
			update: func(cfg *TunPacketHandlerConfig) {
				cfg.Device = &headroomTunDevice{
					scriptedTunDevice: newScriptedTunDevice(1),
					headroom:          maxServerTunWriteHeadroom + 1,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TunPacketHandlerConfig{
				Device:        newScriptedTunDevice(1),
				VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
			}
			tt.update(&cfg)
			if _, err := NewTunPacketHandler(cfg); err == nil {
				t.Fatal("expected an invalid write budget error")
			}
		})
	}
}

func TestTunReadAllocationUsesMTUAndBoundedPrefetch(t *testing.T) {
	dev := newScriptedTunDevice(256)
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	if want := 1500 + defaultServerTunReadBufferExtra; handler.readBufferSize != want {
		t.Fatalf("read buffer size = %d, want %d", handler.readBufferSize, want)
	}

	tests := []struct {
		batchSize int
		want      int
	}{
		{batchSize: 1, want: 64},
		{batchSize: 8, want: 64},
		{batchSize: 16, want: 32},
		{batchSize: 128, want: 4},
		{batchSize: 256, want: 2},
	}
	for _, tt := range tests {
		if got := serverTunReadPrefetchBatches(tt.batchSize); got != tt.want {
			t.Errorf("batch size %d: prefetch batches = %d, want %d", tt.batchSize, got, tt.want)
		}
	}

}

func TestTunQueueBytesDeriveFromPacketLimitsAndDevice(t *testing.T) {
	const (
		writePackets          = 7
		sessionWritePackets   = 3
		downlinkPackets       = 2
		globalDownlinkPackets = 5
		writeHeadroom         = 64
	)
	device := &headroomTunDevice{
		scriptedTunDevice: newScriptedTunDevice(1),
		headroom:          writeHeadroom,
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:                device,
		VirtualIPBase:         netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:        writePackets,
		SessionWritePackets:   sessionWritePackets,
		DownlinkPackets:       downlinkPackets,
		GlobalDownlinkPackets: globalDownlinkPackets,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	writePacketBytes := handler.device.MTU() + writeHeadroom
	if want := writePackets * writePacketBytes; handler.writeBytesMax != want {
		t.Errorf("write queue bytes = %d, want %d", handler.writeBytesMax, want)
	}
	if want := sessionWritePackets * writePacketBytes; handler.sessionBytes != want {
		t.Errorf("session write bytes = %d, want %d", handler.sessionBytes, want)
	}
	if want := downlinkPackets * handler.device.MTU(); handler.downlinkBytes != want {
		t.Errorf("session downlink bytes = %d, want %d", handler.downlinkBytes, want)
	}
	if want := globalDownlinkPackets * handler.device.MTU(); handler.globalDownlinkBytes != want {
		t.Fatalf("global downlink bytes = %d, want %d", handler.globalDownlinkBytes, want)
	}
}

func TestTunWriteBudgetBackpressuresUntilCapacityIsReleased(t *testing.T) {
	firstWriteStarted := make(chan struct{})
	releaseFirstWrite := make(chan struct{})
	dev := newScriptedTunDevice(1)
	dev.writeFn = func(ctx context.Context, call int, bufs [][]byte, _ []int, _ int) (int, error) {
		if call == 0 {
			close(firstWriteStarted)
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-releaseFirstWrite:
			}
		}
		return len(bufs), nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:              dev,
		VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:      2,
		WriteQueueBytes:     8,
		SessionWritePackets: 1,
		SessionWriteBytes:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	var releaseOnce sync.Once
	releaseWrite := func() {
		releaseOnce.Do(func() {
			close(releaseFirstWrite)
		})
	}
	defer releaseWrite()

	owner := attachTunWriterTestSession(t, handler, 71)
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstWriteStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN write did not start")
	}

	enqueueDone := make(chan error, 1)
	go func() {
		enqueueDone <- handler.enqueuePayloadWrite(context.Background(), owner, []byte{4})
	}()
	select {
	case err := <-enqueueDone:
		t.Fatalf("saturated session write did not backpressure: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	handler.writeBudgetMu.Lock()
	packets, bytes := handler.writePackets, handler.writeBytes
	sessionPackets, sessionBytes := owner.tunWritePackets, owner.tunWriteBytes
	handler.writeBudgetMu.Unlock()
	if packets != 1 || bytes != 3 || sessionPackets != 1 || sessionBytes != 3 {
		t.Fatalf(
			"write budget while backpressured = global %d/%d session %d/%d, want 1/3 and 1/3",
			packets,
			bytes,
			sessionPackets,
			sessionBytes,
		)
	}
	releaseWrite()
	select {
	case err := <-enqueueDone:
		if err != nil {
			t.Fatalf("backpressured enqueue failed after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backpressured enqueue did not resume")
	}
}

func TestTunWriteBudgetWaitHonorsContext(t *testing.T) {
	dev := newBlockingWriteTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:              dev,
		VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:      1,
		WriteQueueBytes:     4,
		SessionWritePackets: 1,
		SessionWriteBytes:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	first := attachTunWriterTestSession(t, handler, 72)
	second := attachTunWriterTestSession(t, handler, 73)
	if err := handler.enqueuePayloadWrite(context.Background(), first, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dev.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN write did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = handler.enqueuePayloadWrite(ctx, second, []byte{3})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("backpressured enqueue error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestTunWriteBudgetMakesProgressForConcurrentWaiters(t *testing.T) {
	firstWriteStarted := make(chan struct{})
	releaseFirstWrite := make(chan struct{})
	dev := newScriptedTunDevice(1)
	dev.writeFn = func(ctx context.Context, call int, bufs [][]byte, _ []int, _ int) (int, error) {
		if call == 0 {
			close(firstWriteStarted)
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-releaseFirstWrite:
			}
		}
		return len(bufs), nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:              dev,
		VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:      1,
		WriteQueueBytes:     1,
		SessionWritePackets: 1,
		SessionWriteBytes:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	releaseWrite := func() {
		releaseOnce.Do(func() {
			close(releaseFirstWrite)
		})
	}
	defer releaseWrite()
	defer handler.Close()

	owner := attachTunWriterTestSession(t, handler, 76)
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstWriteStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN write did not start")
	}

	const waiters = 32
	errs := make(chan error, waiters)
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(value byte) {
			defer wg.Done()
			errs <- handler.enqueuePayloadWrite(context.Background(), owner, []byte{value})
		}(byte(i + 2))
	}
	releaseWrite()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent budget waiters did not make progress")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("backpressured enqueue failed: %v", err)
		}
	}
}

func TestTunWriteBudgetRejectsRequestThatCanNeverFit(t *testing.T) {
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:              newScriptedTunDevice(1),
		VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:      2,
		WriteQueueBytes:     8,
		SessionWritePackets: 1,
		SessionWriteBytes:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	owner := attachTunWriterTestSession(t, handler, 74)
	if err := handler.enqueuePayloadWrite(context.Background(), owner, make([]byte, 5)); !errors.Is(err, ErrTunWriteQueueFull) {
		t.Fatalf("oversized write error = %v, want %v", err, ErrTunWriteQueueFull)
	}
}

func TestTunCopiedWriteUsesDeviceHeadroom(t *testing.T) {
	writeDone := make(chan struct{})
	dev := &headroomTunDevice{
		scriptedTunDevice: newScriptedTunDevice(1),
		headroom:          10,
	}
	dev.writeFn = func(_ context.Context, _ int, bufs [][]byte, sizes []int, offset int) (int, error) {
		if offset != dev.headroom {
			t.Fatalf("write offset = %d, want %d", offset, dev.headroom)
		}
		if len(bufs) != 1 || len(sizes) != 1 || sizes[0] != 3 {
			t.Fatalf("write batch = %d buffers/%v sizes, want 1/[3]", len(bufs), sizes)
		}
		if got := bufs[0][offset : offset+sizes[0]]; !reflect.DeepEqual(got, []byte{1, 2, 3}) {
			t.Fatalf("write payload = %v, want [1 2 3]", got)
		}
		close(writeDone)
		return 1, nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	owner := attachTunWriterTestSession(t, handler, 75)
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN write did not complete")
	}
}

func TestTunCopiedIngressChargesPayloadAndHeadroomCapacity(t *testing.T) {
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	dev := &headroomTunDevice{
		scriptedTunDevice: newScriptedTunDevice(1),
		headroom:          32,
	}
	dev.writeFn = func(ctx context.Context, _ int, bufs [][]byte, _ []int, _ int) (int, error) {
		close(writeStarted)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-releaseWrite:
			return len(bufs), nil
		}
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:              dev,
		VirtualIPBase:       netip.MustParseAddr("172.21.100.1"),
		WriteQueueBytes:     128,
		SessionWriteBytes:   64,
		WriteQueueSize:      1,
		SessionWritePackets: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(releaseWrite)
	defer handler.Close()
	owner := attachTunWriterTestSession(t, handler, 76)
	payload := make([]byte, 20)
	if err := handler.enqueuePayloadWrite(context.Background(), owner, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("copied TUN write did not start")
	}
	handler.writeBudgetMu.Lock()
	globalBytes := handler.writeBytes
	sessionBytes := owner.tunWriteBytes
	handler.writeBudgetMu.Unlock()
	want := dev.headroom + len(payload)
	if globalBytes != want || sessionBytes != want {
		t.Fatalf("copied write budget = global %d session %d, want %d", globalBytes, sessionBytes, want)
	}
}

func TestValidTunPacketRangeRejectsIntegerOverflow(t *testing.T) {
	if validTunPacketRange([]byte{1}, int(^uint(0)>>1), 1) {
		t.Fatal("overflowing packet range was accepted")
	}
}

func attachTunWriterTestSession(t *testing.T, handler *TunPacketHandler, id uint64) *tunHandlerSession {
	t.Helper()
	session := SessionContext{ClientID: id, Generation: 1}
	if _, err := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	}); err != nil {
		t.Fatal(err)
	}
	owner := handler.getSession(session)
	if owner == nil {
		t.Fatal("session was not attached")
	}
	return owner
}

func TestTunWritePendingGroupHonorsBatchSizeAndPartialWrites(t *testing.T) {
	dev := newScriptedTunDevice(4)
	dev.writeFn = func(_ context.Context, _ int, bufs [][]byte, _ []int, _ int) (int, error) {
		if len(bufs) > 2 {
			return 2, nil
		}
		return len(bufs), nil
	}
	handler := newTunWriteUnitHandler(dev)
	defer handler.cancel()

	owner := &tunHandlerSession{tunWriteActive: true}
	pending := make([]*serverTunWriteReq, 10)
	for i := range pending {
		pending[i] = &serverTunWriteReq{
			owner: owner,
			bufs:  [][]byte{{byte(i)}},
			sizes: []int{1},
		}
	}

	if err := handler.writePendingGroup(handler.ctx, pending, 0, make([][]byte, 4), make([]int, 4)); err != nil {
		t.Fatal(err)
	}

	dev.mu.Lock()
	gotCalls := append([]int(nil), dev.calls...)
	gotPackets := append([]byte(nil), dev.packets...)
	dev.mu.Unlock()
	if want := []int{4, 2, 4, 2, 2}; !reflect.DeepEqual(gotCalls, want) {
		t.Fatalf("write batch sizes = %v, want %v", gotCalls, want)
	}
	if want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}; !reflect.DeepEqual(gotPackets, want) {
		t.Fatalf("written packet order = %v, want %v", gotPackets, want)
	}
}

func TestTunWriteBatchRejectsInvalidProgress(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{name: "zero", n: 0},
		{name: "overflow", n: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := newScriptedTunDevice(2)
			dev.writeFn = func(_ context.Context, _ int, _ [][]byte, _ []int, _ int) (int, error) {
				return tt.n, nil
			}
			handler := newTunWriteUnitHandler(dev)
			defer handler.cancel()

			err := handler.writeTunBatch(
				handler.ctx,
				[][]byte{{1}, {2}},
				[]int{1, 1},
				0,
			)
			if err == nil {
				t.Fatal("expected invalid progress error")
			}
		})
	}
}

func TestTunWritePendingDropsReplacedSession(t *testing.T) {
	dev := newScriptedTunDevice(4)
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	firstSession := SessionContext{ClientID: 41, Generation: 1}
	detachFirst, err := handler.AttachSessionWriters(context.Background(), firstSession, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachFirst()
	old := handler.getSession(firstSession)
	if old == nil {
		t.Fatal("first session was not attached")
	}

	detachSecond, err := handler.AttachSessionWriters(context.Background(), SessionContext{
		ClientID:   41,
		Generation: 2,
	}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachSecond()
	detachFirst()

	req := &serverTunWriteReq{
		owner: old,
		bufs:  [][]byte{{1, 2, 3}},
		sizes: []int{3},
	}
	if err := handler.flushWritePending(
		[]*serverTunWriteReq{req},
		make([][]byte, dev.BatchSize()),
		make([]int, dev.BatchSize()),
	); err != nil {
		t.Fatal(err)
	}

	dev.mu.Lock()
	calls := len(dev.calls)
	dev.mu.Unlock()
	if calls != 0 {
		t.Fatalf("replaced session wrote %d TUN batches, want 0", calls)
	}
}

func TestTunSessionReplacementCancelsBlockedOldWrite(t *testing.T) {
	firstWriteStarted := make(chan struct{})
	secondWriteDone := make(chan struct{})
	var firstOnce sync.Once
	var secondOnce sync.Once
	dev := newScriptedTunDevice(1)
	dev.writeFn = func(ctx context.Context, call int, bufs [][]byte, _ []int, _ int) (int, error) {
		if call == 0 {
			firstOnce.Do(func() {
				close(firstWriteStarted)
			})
			<-ctx.Done()
			return 0, ctx.Err()
		}
		secondOnce.Do(func() {
			close(secondWriteDone)
		})
		return len(bufs), nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	firstSession := SessionContext{ClientID: 45, Generation: 1}
	detachFirst, err := handler.AttachSessionWriters(context.Background(), firstSession, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detachFirst()
	old := handler.getSession(firstSession)
	if old == nil {
		t.Fatal("first session was not attached")
	}
	if err := handler.enqueuePayloadWrite(context.Background(), old, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstWriteStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old session TUN write did not start")
	}

	secondSession := SessionContext{ClientID: 45, Generation: 2}
	attachDone := make(chan error, 1)
	go func() {
		_, attachErr := handler.AttachSessionWriters(context.Background(), secondSession, SessionWriters{
			Packet: func(*vpnpacket.VpnPacket) error { return nil },
			Close:  func() {},
		})
		attachDone <- attachErr
	}()
	select {
	case err := <-attachDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session replacement was blocked by the old TUN write")
	}
	detachFirst()
	if err := handler.Err(); err != nil {
		t.Fatalf("old session cancellation poisoned the handler: %v", err)
	}
	select {
	case <-handler.ctx.Done():
		t.Fatal("old session cancellation stopped the handler")
	default:
	}

	current := handler.getSession(secondSession)
	if current == nil {
		t.Fatal("replacement session was not attached")
	}
	if err := handler.enqueuePayloadWrite(context.Background(), current, []byte{2}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondWriteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("replacement session did not write to TUN")
	}
}

func TestTunWriteFailureCancelsHandler(t *testing.T) {
	wantErr := errors.New("injected TUN write failure")
	dev := newScriptedTunDevice(1)
	dev.writeFn = func(_ context.Context, _ int, _ [][]byte, _ []int, _ int) (int, error) {
		return 0, wantErr
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	session := SessionContext{ClientID: 52, Generation: 1}
	detach, err := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer detach()
	owner := handler.getSession(session)
	if owner == nil {
		t.Fatal("session was not attached")
	}

	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not canceled after TUN write failure")
	}
	if got := handler.Err(); !errors.Is(got, wantErr) {
		t.Fatalf("write error = %v, want %v", got, wantErr)
	}
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{2}); !errors.Is(err, wantErr) {
		t.Fatalf("enqueue after write failure = %v, want %v", err, wantErr)
	}
}

func TestTunReadFailureCancelsHandler(t *testing.T) {
	wantErr := errors.New("injected TUN read failure")
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	var readOnce sync.Once
	dev := newScriptedTunDevice(1)
	dev.readFn = func(ctx context.Context, _ [][]byte, _ []int, _ int) (int, error) {
		readOnce.Do(func() {
			close(readStarted)
		})
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-releaseRead:
			return 0, wantErr
		}
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	_, err = handler.AttachSessionWriters(context.Background(), SessionContext{
		ClientID:   56,
		Generation: 1,
	}, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN read did not start")
	}
	close(releaseRead)
	select {
	case <-handler.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not canceled after TUN read failure")
	}
	if got := handler.Err(); !errors.Is(got, wantErr) {
		t.Fatalf("handler error = %v, want %v", got, wantErr)
	}
}

func TestTunWriteCloseUnblocksConcurrentEnqueue(t *testing.T) {
	dev := newBlockingWriteTunDevice()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          dev,
		VirtualIPBase:   netip.MustParseAddr("172.21.100.1"),
		WriteQueueSize:  1,
		DownlinkPackets: 1,
		DownlinkBytes:   64,
	})
	if err != nil {
		t.Fatal(err)
	}

	session := SessionContext{ClientID: 63, Generation: 1}
	_, err = handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := handler.getSession(session)
	if owner == nil {
		t.Fatal("session was not attached")
	}
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dev.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("TUN write did not start")
	}

	const writers = 64
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(v byte) {
			defer wg.Done()
			errs <- handler.enqueuePayloadWrite(context.Background(), owner, []byte{v})
		}(byte(i + 2))
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- handler.Close()
	}()
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent enqueue did not unblock during close")
	}
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler close deadlocked")
	}
	close(errs)
	for err := range errs {
		if err != nil &&
			!errors.Is(err, ErrTunWriteQueueFull) &&
			!errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected enqueue error: %v", err)
		}
	}
}

func TestTunDeviceWriteMayCloseHandler(t *testing.T) {
	dev := newScriptedTunDevice(1)
	writeReturned := make(chan struct{})
	closeDone := make(chan error, 1)
	cleanupDone := make(chan struct{})
	var handler *TunPacketHandler
	dev.writeFn = func(_ context.Context, _ int, bufs [][]byte, _ []int, _ int) (int, error) {
		closeDone <- handler.Close()
		close(writeReturned)
		return len(bufs), nil
	}
	var err error
	handler, err = NewTunPacketHandler(TunPacketHandlerConfig{
		Device: dev,
		Cleanup: func() error {
			<-writeReturned
			close(cleanupDone)
			return nil
		},
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	session := SessionContext{ClientID: 64, Generation: 1}
	if _, err := handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TunDevice.WritePackets deadlocked while closing its handler")
	}
	select {
	case <-handler.writeDone:
	case <-time.After(time.Second):
		t.Fatal("shared TUN write loop did not stop after reentrant close")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after TunDevice.WritePackets returned")
	}
}

func TestTunDeviceWriteMayDetachSession(t *testing.T) {
	dev := newScriptedTunDevice(1)
	detachDone := make(chan struct{})
	var detach func()
	dev.writeFn = func(_ context.Context, _ int, bufs [][]byte, _ []int, _ int) (int, error) {
		detach()
		close(detachDone)
		return len(bufs), nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:        dev,
		VirtualIPBase: netip.MustParseAddr("172.21.100.1"),
		TargetPolicy:  allowPrivateTargetPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	session := SessionContext{ClientID: 65, Generation: 1}
	detach, err = handler.AttachSessionWriters(context.Background(), session, SessionWriters{
		Packet: func(*vpnpacket.VpnPacket) error { return nil },
		Close:  func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandlePacket(context.Background(), session, &vpnpacket.VpnPacket{
		Cmd:  vpnpacket.CmdData,
		Data: makeIPv4TCPPacket([4]byte{10, 80, 0, 2}, [4]byte{10, 15, 20, 66}),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-detachDone:
	case <-time.After(time.Second):
		t.Fatal("TunDevice.WritePackets deadlocked while detaching its session")
	}
}

func BenchmarkTunWritePendingGroup(b *testing.B) {
	dev := discardTunDevice{batchSize: 32}
	handler := newTunWriteUnitHandler(dev)
	defer handler.cancel()

	owner := &tunHandlerSession{tunWriteActive: true}
	pending := make([]*serverTunWriteReq, 256)
	for i := range pending {
		pending[i] = &serverTunWriteReq{
			owner: owner,
			bufs:  [][]byte{make([]byte, 1500)},
			sizes: []int{1500},
		}
	}
	writeBufs := make([][]byte, dev.BatchSize())
	writeSizes := make([]int, dev.BatchSize())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := handler.writePendingGroup(handler.ctx, pending, 0, writeBufs, writeSizes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTunWriteBudget(b *testing.B) {
	handler := &TunPacketHandler{
		ctx:             context.Background(),
		writeBudgetWake: make(chan struct{}, 1),
		writePacketsMax: 1024,
		writeBytesMax:   16 << 20,
		sessionPackets:  256,
		sessionBytes:    4 << 20,
	}
	owner := &tunHandlerSession{tunWriteWake: make(chan struct{}, 1)}
	req := &serverTunWriteReq{
		owner:    owner,
		budgeted: true,
		packets:  1,
		bytes:    1500,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := handler.reserveWriteBudget(context.Background(), owner, req.packets, req.bytes); err != nil {
			b.Fatal(err)
		}
		handler.releaseWriteBudget(req)
	}
}

type scriptedTunDevice struct {
	batchSize int
	readFn    func(context.Context, [][]byte, []int, int) (int, error)
	writeFn   func(context.Context, int, [][]byte, []int, int) (int, error)
	releaseFn func(context.Context, netip.Addr) error

	mu      sync.Mutex
	calls   []int
	packets []byte

	closed   chan struct{}
	closeOne sync.Once
}

type headroomTunDevice struct {
	*scriptedTunDevice
	headroom int
}

func (d *headroomTunDevice) WriteHeadroom() int {
	return d.headroom
}

func newScriptedTunDevice(batchSize int) *scriptedTunDevice {
	return &scriptedTunDevice{
		batchSize: batchSize,
		closed:    make(chan struct{}),
	}
}

func (d *scriptedTunDevice) ReadPackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.readFn != nil {
		return d.readFn(ctx, bufs, sizes, offset)
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *scriptedTunDevice) WritePackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	d.mu.Lock()
	call := len(d.calls)
	d.calls = append(d.calls, len(bufs))
	writeFn := d.writeFn
	d.mu.Unlock()

	n := len(bufs)
	var err error
	if writeFn != nil {
		n, err = writeFn(ctx, call, bufs, sizes, offset)
	}
	if n >= 0 && n <= len(bufs) {
		d.mu.Lock()
		for i := 0; i < n; i++ {
			if i >= len(sizes) || sizes[i] <= 0 || offset < 0 || offset+sizes[i] > len(bufs[i]) {
				continue
			}
			d.packets = append(d.packets, bufs[i][offset])
		}
		d.mu.Unlock()
	}
	return n, err
}

func (d *scriptedTunDevice) ReleaseVirtualIP(ctx context.Context, vip netip.Addr) error {
	if d.releaseFn != nil {
		return d.releaseFn(ctx, vip)
	}
	return nil
}

func (d *scriptedTunDevice) BatchSize() int   { return d.batchSize }
func (*scriptedTunDevice) MTU() int           { return 1500 }
func (*scriptedTunDevice) WriteHeadroom() int { return 0 }
func (d *scriptedTunDevice) Close() error {
	d.closeOne.Do(func() {
		close(d.closed)
	})
	return nil
}

type discardTunDevice struct {
	batchSize int
}

func (d discardTunDevice) ReadPackets(ctx context.Context, _ [][]byte, _ []int, _ int) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (d discardTunDevice) WritePackets(_ context.Context, bufs [][]byte, _ []int, _ int) (int, error) {
	return len(bufs), nil
}

func (discardTunDevice) ReleaseVirtualIP(context.Context, netip.Addr) error { return nil }
func (d discardTunDevice) BatchSize() int                                   { return d.batchSize }
func (discardTunDevice) MTU() int                                           { return 1500 }
func (discardTunDevice) WriteHeadroom() int                                 { return 0 }
func (discardTunDevice) Close() error                                       { return nil }

func newTunWriteUnitHandler(device TunDevice) *TunPacketHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &TunPacketHandler{
		device: device,
		ctx:    ctx,
		cancel: cancel,
	}
}
