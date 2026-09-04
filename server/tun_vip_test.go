// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

func TestVirtualIPMaxOffset(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		prefix string
		want   uint32
	}{
		// Reference deployment: base .2 inside a /24 leaves .3 through .254.
		{name: "reference /24", base: "172.21.100.2", prefix: "172.21.100.0/24", want: 252},
		{name: "base at network+1", base: "10.0.0.1", prefix: "10.0.0.0/24", want: 253},
		{name: "wider /16", base: "10.0.0.2", prefix: "10.0.0.0/16", want: 65532},
		{name: "small /30", base: "10.0.0.1", prefix: "10.0.0.0/30", want: 1},
		{name: "base is last assignable", base: "10.0.0.254", prefix: "10.0.0.0/24", want: 0},
		{name: "no room in /31", base: "10.0.0.0", prefix: "10.0.0.0/31", want: 0},
		{name: "no room in /32", base: "10.0.0.1", prefix: "10.0.0.1/32", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := virtualIPMaxOffset(netip.MustParseAddr(tt.base), netip.MustParsePrefix(tt.prefix))
			if got != tt.want {
				t.Fatalf("virtualIPMaxOffset(%s, %s) = %d, want %d", tt.base, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestAllocateVIPStaysInsidePrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("172.21.100.0/24")
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("172.21.100.2"),
		VirtualIPPrefix: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	seen := make(map[netip.Addr]bool, handler.virtualIPMax)
	for i := uint32(0); i < handler.virtualIPMax; i++ {
		vip, err := handler.allocateVIPLocked(uint64(i + 1))
		if err != nil {
			t.Fatalf("allocation %d failed early: %v", i+1, err)
		}
		if !prefix.Contains(vip) {
			t.Fatalf("allocation %d returned %s, outside %s", i+1, vip, prefix)
		}
		if vip == prefix.Masked().Addr() {
			t.Fatalf("allocation %d returned the network address %s", i+1, vip)
		}
		if vip.As4() == [4]byte{172, 21, 100, 255} {
			t.Fatalf("allocation %d returned the broadcast address %s", i+1, vip)
		}
		if seen[vip] {
			t.Fatalf("allocation %d reused %s", i+1, vip)
		}
		seen[vip] = true
		// Mark it live so the allocator must skip it, as AttachSessionWriters does.
		handler.byVIP[vip] = &tunHandlerSession{vip: vip}
	}

	if _, err := handler.allocateVIPLocked(1000); err == nil {
		t.Fatal("allocation succeeded after the pool was exhausted")
	}
}

func TestTunVirtualIPReusedBySameClientAfterRelease(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	defer handler.Close()
	var firstVIP netip.Addr
	for generation := uint64(1); generation <= 512; generation++ {
		session := SessionContext{ClientID: 1, Generation: generation}
		owner, detach := attachVIPTestSession(t, handler, session)
		if generation == 1 {
			firstVIP = owner.vip
		} else if owner.vip != firstVIP {
			t.Fatalf("generation %d received VIP %s, want recycled %s", generation, owner.vip, firstVIP)
		}
		detach()
		if err := handler.Err(); err != nil {
			t.Fatalf("generation %d release failed: %v", generation, err)
		}
		if len(handler.releasedVIP) != 1 {
			t.Fatalf("generation %d left %d VIP reservations", generation, len(handler.releasedVIP))
		}
	}
}

func TestTunVirtualIPRemainsBoundToClientForHandlerLifetime(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	t.Cleanup(func() { _ = handler.Close() })

	owner, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 1})
	vip := owner.vip
	detach()
	if otherDetach, err := handler.AttachSessionWriters(
		context.Background(),
		SessionContext{ClientID: 10002, Generation: 1},
		vipTestWriters(),
	); err == nil {
		otherDetach()
		t.Fatal("released VIP crossed authenticated clients")
	}
	replacement, detachReplacement := attachVIPTestSession(
		t, handler, SessionContext{ClientID: 10001, Generation: 2},
	)
	if replacement.vip != vip {
		t.Fatalf("same client received VIP %s, want %s", replacement.vip, vip)
	}
	detachReplacement()
	handler.mu.RLock()
	boundClient := handler.vipBindings[vip]
	boundVIP := handler.vipByClient[10001]
	bindings := len(handler.vipBindings)
	clients := len(handler.vipByClient)
	handler.mu.RUnlock()
	if boundClient != 10001 || boundVIP != vip || bindings != 1 || clients != 1 {
		t.Fatalf("VIP binding client=%d vip=%s bindings=%d clients=%d", boundClient, boundVIP, bindings, clients)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	handler.waitWorkers()
	handler.mu.RLock()
	bindings = len(handler.vipBindings)
	clients = len(handler.vipByClient)
	released := len(handler.releasedVIP)
	cleanups := len(handler.vipCleanups)
	handler.mu.RUnlock()
	if bindings != 0 || clients != 0 || released != 0 || cleanups != 0 {
		t.Fatalf("closed VIP accounting bindings=%d clients=%d released=%d cleanups=%d", bindings, clients, released, cleanups)
	}
}

func TestTunVirtualIPPoolCapacityCountsDistinctClients(t *testing.T) {
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/29"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	vips := make(map[uint64]netip.Addr, handler.virtualIPMax)
	for clientID := uint64(1); clientID <= uint64(handler.virtualIPMax); clientID++ {
		owner, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: clientID, Generation: 1})
		vips[clientID] = owner.vip
		detach()
	}
	if detach, attachErr := handler.AttachSessionWriters(
		context.Background(),
		SessionContext{ClientID: uint64(handler.virtualIPMax) + 1, Generation: 1},
		vipTestWriters(),
	); attachErr == nil {
		detach()
		t.Fatal("distinct client exceeded the virtual IP pool")
	}
	for clientID, vip := range vips {
		owner, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: clientID, Generation: 2})
		if owner.vip != vip {
			detach()
			t.Fatalf("client %d received VIP %s, want %s", clientID, owner.vip, vip)
		}
		detach()
	}
}

func TestTunOverlappingGenerationsUseOneVirtualIP(t *testing.T) {
	device := newScriptedTunDevice(1)
	released := make(chan netip.Addr, 2)
	device.releaseFn = func(_ context.Context, vip netip.Addr) error {
		released <- vip
		return nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/29"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	const generations = 16
	owners := make([]*tunHandlerSession, 0, generations)
	detaches := make([]func(), 0, generations)
	for generation := uint64(1); generation <= generations; generation++ {
		owner, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: generation})
		if len(owners) != 0 && owner.vip != owners[0].vip {
			detach()
			t.Fatalf("generation %d received VIP %s, want %s", generation, owner.vip, owners[0].vip)
		}
		owners = append(owners, owner)
		detaches = append(detaches, detach)
	}
	other, detachOther := attachVIPTestSession(t, handler, SessionContext{ClientID: 10002, Generation: 1})
	if other.vip == owners[0].vip {
		detachOther()
		t.Fatal("different clients shared one virtual IP")
	}
	handler.mu.RLock()
	bindings := len(handler.vipBindings)
	clients := len(handler.vipByClient)
	current := handler.byVIP[owners[0].vip]
	handler.mu.RUnlock()
	if bindings != 2 || clients != 2 || current != owners[0] {
		t.Fatalf("overlap accounting bindings=%d clients=%d current=%p want=%p", bindings, clients, current, owners[0])
	}
	if current, attached := handler.getDataSession(SessionContext{ClientID: 10001, Generation: generations}); current != nil || !attached {
		t.Fatal("pending generation could send before virtual IP handoff")
	}

	detaches[0]()
	select {
	case vip := <-released:
		if vip != owners[0].vip {
			t.Fatalf("handoff released VIP = %s, want %s", vip, owners[0].vip)
		}
	default:
		t.Fatal("virtual IP handoff bypassed device cleanup")
	}
	if current := handler.getSessionByVIP(owners[0].vip); current != owners[len(owners)-1] {
		t.Fatalf("current generation = %p, want %p", current, owners[len(owners)-1])
	}
	if current, attached := handler.getDataSession(SessionContext{ClientID: 10001, Generation: generations}); current != owners[len(owners)-1] || !attached {
		t.Fatal("replacement generation could not send after virtual IP handoff")
	}
	for i := 1; i < len(detaches)-1; i++ {
		detaches[i]()
		select {
		case vip := <-released:
			t.Fatalf("non-owner generation released active shared VIP %s at generation %d", vip, i+1)
		default:
		}
	}
	detaches[len(detaches)-1]()
	select {
	case vip := <-released:
		if vip != owners[0].vip {
			t.Fatalf("released VIP = %s, want %s", vip, owners[0].vip)
		}
	default:
		t.Fatal("last generation did not release its virtual IP")
	}
	detachOther()
}

func TestTunReadBatchCannotCrossVIPRelease(t *testing.T) {
	device := &blockingVIPReleaseTunDevice{
		discardTunDevice: discardTunDevice{batchSize: 1},
		started:          make(chan netip.Addr, 1),
		unblock:          make(chan struct{}),
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	oldSession := SessionContext{ClientID: 10001, Generation: 1}
	old, detachOld := attachVIPTestSession(t, handler, oldSession)
	old.bindClientIP(netip.MustParseAddr("10.80.0.2"))
	batch := uncapturedVIPTestBatch(old)
	readEpoch := handler.vipEpoch.Load()
	replacementSession := SessionContext{ClientID: 10001, Generation: 2}
	replacement, detachReplacement := attachVIPTestSession(t, handler, replacementSession)
	defer detachReplacement()
	replacement.bindClientIP(netip.MustParseAddr("10.80.0.3"))
	if replacement.vip != old.vip {
		t.Fatalf("replacement VIP = %s, want %s", replacement.vip, old.vip)
	}
	detached := make(chan struct{})
	go func() {
		detachOld()
		close(detached)
	}()

	select {
	case vip := <-device.started:
		if vip != old.vip {
			t.Fatalf("released VIP = %s, want %s", vip, old.vip)
		}
	case <-time.After(time.Second):
		t.Fatal("virtual IP release did not start")
	}

	if owner := handler.getSessionByVIP(old.vip); owner != nil {
		t.Fatal("replacement took ownership before device cleanup completed")
	}
	if current, attached := handler.getDataSession(replacementSession); current != nil || !attached {
		t.Fatal("replacement could send before device cleanup completed")
	}
	pendingPacket := makeIPv4TCPPacket([4]byte{10, 80, 0, 3}, [4]byte{8, 8, 8, 8})
	if err := handler.handleDataPayload(context.Background(), replacementSession, pendingPacket); err != nil {
		t.Fatalf("pending replacement data closed the session: %v", err)
	}
	if detach, err := handler.AttachSessionWriters(
		context.Background(),
		SessionContext{ClientID: 10001, Generation: 3},
		vipTestWriters(),
	); err == nil {
		detach()
		t.Fatal("VIP was reassigned before device cleanup completed")
	}
	close(device.unblock)
	select {
	case <-detached:
	case <-time.After(time.Second):
		t.Fatal("virtual IP release did not finish")
	}
	if owner := handler.getSessionByVIP(old.vip); owner != replacement {
		t.Fatal("replacement did not take ownership after device cleanup")
	}
	if current, attached := handler.getDataSession(replacementSession); current != replacement || !attached {
		t.Fatal("replacement could not send after device cleanup")
	}
	handler.captureTunBatchOwnersAtEpoch(batch, readEpoch)
	if batch.owners[0] != nil {
		t.Fatal("packet read by the old ownership epoch acquired the new owner")
	}
	if _, _, _, ok := handler.prepareTunPacketFrameForOwner(
		batch.bufs[0], batch.headroom, batch.sizes[0], batch.owners[0], true,
	); ok {
		t.Fatal("packet captured during release was accepted by the new owner")
	}
}

func TestServerDetachesBuiltinTunStateBeforePhysicalCleanup(t *testing.T) {
	device := &blockingVIPReleaseTunDevice{
		discardTunDevice: discardTunDevice{batchSize: 1},
		started:          make(chan netip.Addr, 1),
		unblock:          make(chan struct{}),
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{handler: handler}
	releaseWorkers := make(chan struct{})
	workersStarted := make(chan struct{}, defaultSessionReclaimWorkers)
	var releaseWorkersOnce sync.Once
	var unblockOnce sync.Once
	t.Cleanup(func() {
		releaseWorkersOnce.Do(func() { close(releaseWorkers) })
		unblockOnce.Do(func() { close(device.unblock) })
		srv.stopSessionReclaimer()
		_ = handler.Close()
	})
	for range defaultSessionReclaimWorkers {
		srv.reclaimSession(func() {
			workersStarted <- struct{}{}
			<-releaseWorkers
		})
	}
	for range defaultSessionReclaimWorkers {
		select {
		case <-workersStarted:
		case <-time.After(time.Second):
			t.Fatal("session reclaimer did not enter physical cleanup")
		}
	}

	session := SessionContext{ClientID: 10001, Generation: 1}
	binding, err := srv.prepareSession(activeServerSessionConfig{Ref: session.Ref()})
	if err != nil {
		t.Fatal(err)
	}
	detach, err := srv.attachPacketSession(context.Background(), context.Background(), session, vipTestWriters())
	if err != nil {
		srv.releaseSession(binding)
		t.Fatal(err)
	}
	owner := handler.getSession(session)
	if owner == nil {
		srv.releaseSession(binding)
		t.Fatal("attached TUN session is missing")
	}
	detach()
	srv.releaseSession(binding)
	if handler.getSession(session) != nil || handler.getSessionByVIP(owner.vip) != nil {
		t.Fatal("logical TUN detach waited for physical cleanup")
	}
	select {
	case <-device.started:
		t.Fatal("physical TUN cleanup bypassed the bounded reclaimer")
	default:
	}
	owner.tunWriteMu.RLock()
	active := owner.tunWriteActive
	owner.tunWriteMu.RUnlock()
	owner.sendMu.Lock()
	sendStopped := owner.sendStopped
	owner.sendMu.Unlock()
	if active || !sendStopped {
		t.Fatalf("logical TUN detach active=%v senderStopped=%v", active, sendStopped)
	}

	releaseWorkersOnce.Do(func() { close(releaseWorkers) })
	select {
	case vip := <-device.started:
		if vip != owner.vip {
			t.Fatalf("physical cleanup VIP = %s, want %s", vip, owner.vip)
		}
	case <-time.After(time.Second):
		t.Fatal("queued physical TUN cleanup did not start")
	}
	unblockOnce.Do(func() { close(device.unblock) })
	deadline := time.Now().Add(time.Second)
	for {
		handler.mu.RLock()
		released := handler.releasedVIP[owner.vip]
		handler.mu.RUnlock()
		if released.reusable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("physical TUN cleanup did not complete")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTunReadBatchSurvivesUnrelatedVIPAssignment(t *testing.T) {
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/29"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	owner, detachOwner := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 1})
	defer detachOwner()
	batch := uncapturedVIPTestBatch(owner)
	readEpoch := handler.vipEpoch.Load()
	_, detachOther := attachVIPTestSession(t, handler, SessionContext{ClientID: 10002, Generation: 1})
	defer detachOther()

	handler.captureTunBatchOwnersAtEpoch(batch, readEpoch)
	if batch.owners[0] != owner {
		t.Fatal("unrelated VIP assignment invalidated the current owner")
	}
}

func TestTunReadEpochDoesNotObservePartialVIPAssignment(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	defer handler.Close()

	handler.mu.Lock()
	want := handler.vipEpoch.Add(1)
	started := make(chan struct{})
	snapshot := make(chan uint64, 1)
	go func() {
		close(started)
		snapshot <- handler.snapshotVIPEpoch()
	}()
	<-started
	select {
	case got := <-snapshot:
		handler.mu.Unlock()
		t.Fatalf("read epoch observed partial VIP assignment: %d", got)
	case <-time.After(20 * time.Millisecond):
	}
	handler.mu.Unlock()

	select {
	case got := <-snapshot:
		if got != want {
			t.Fatalf("read epoch = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("read epoch remained blocked after VIP assignment")
	}
}

func TestTunVirtualIPReleaseWaitsForActiveWrite(t *testing.T) {
	device := newScriptedTunDevice(1)
	writeStarted := make(chan struct{})
	writeCanceled := make(chan struct{})
	finishWrite := make(chan struct{})
	releaseStarted := make(chan struct{})
	device.writeFn = func(ctx context.Context, _ int, _ [][]byte, _ []int, _ int) (int, error) {
		close(writeStarted)
		<-ctx.Done()
		close(writeCanceled)
		<-finishWrite
		return 0, ctx.Err()
	}
	device.releaseFn = func(context.Context, netip.Addr) error {
		close(releaseStarted)
		return nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	owner, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 1})
	if err := handler.enqueuePayloadWrite(context.Background(), owner, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("TUN write did not start")
	}

	detached := make(chan struct{})
	go func() {
		detach()
		close(detached)
	}()
	select {
	case <-writeCanceled:
	case <-time.After(time.Second):
		t.Fatal("session detach did not cancel the active TUN write")
	}
	select {
	case <-releaseStarted:
		t.Fatal("VIP release started before the active TUN write stopped")
	default:
	}
	close(finishWrite)
	select {
	case <-releaseStarted:
	case <-time.After(time.Second):
		t.Fatal("VIP release did not start after the TUN write stopped")
	}
	select {
	case <-detached:
	case <-time.After(time.Second):
		t.Fatal("session detach did not finish")
	}
}

func TestTunSharedVirtualIPReleaseWaitsForOlderGenerationWrite(t *testing.T) {
	device := newScriptedTunDevice(1)
	writeStarted := make(chan struct{})
	writeCanceled := make(chan struct{})
	finishWrite := make(chan struct{})
	releaseStarted := make(chan struct{})
	device.writeFn = func(ctx context.Context, _ int, _ [][]byte, _ []int, _ int) (int, error) {
		close(writeStarted)
		<-ctx.Done()
		close(writeCanceled)
		<-finishWrite
		return 0, ctx.Err()
	}
	device.releaseFn = func(context.Context, netip.Addr) error {
		close(releaseStarted)
		return nil
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	old, detachOld := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 1})
	if err := handler.enqueuePayloadWrite(context.Background(), old, []byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("old generation TUN write did not start")
	}
	replacement, detachReplacement := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 2})
	if replacement.vip != old.vip {
		t.Fatalf("replacement VIP = %s, want %s", replacement.vip, old.vip)
	}
	detachOld()
	select {
	case <-writeCanceled:
	case <-time.After(time.Second):
		t.Fatal("old generation TUN write was not canceled")
	}
	detachReplacement()
	select {
	case <-releaseStarted:
		t.Fatal("shared VIP released before the old generation write stopped")
	default:
	}
	close(finishWrite)
	select {
	case <-releaseStarted:
	case <-time.After(time.Second):
		t.Fatal("shared VIP was not released after all generation writes stopped")
	}
}

func TestTunVirtualIPReleaseFailureStopsHandler(t *testing.T) {
	device := newScriptedTunDevice(1)
	releaseErr := errors.New("flush failed")
	device.releaseFn = func(context.Context, netip.Addr) error {
		return releaseErr
	}
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	_, detach := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 1})
	detach()
	if err := handler.Err(); !errors.Is(err, releaseErr) {
		t.Fatalf("handler error = %v, want virtual IP release failure", err)
	}
	select {
	case <-handler.Done():
	default:
		t.Fatal("handler remained active after virtual IP release failed")
	}
}

func TestTunReadBatchDropsCapturedOwnerAfterVIPReuse(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	defer handler.Close()

	oldSession := SessionContext{ClientID: 10001, Generation: 1}
	old, detachOld := attachVIPTestSession(t, handler, oldSession)
	old.bindClientIP(netip.MustParseAddr("10.80.0.2"))
	batch := capturedVIPTestBatch(t, handler, old)
	replacementSession := SessionContext{ClientID: oldSession.ClientID, Generation: 2}
	replacement, detachReplacement := attachVIPTestSession(t, handler, replacementSession)
	defer detachReplacement()
	replacement.bindClientIP(netip.MustParseAddr("10.80.0.3"))
	if replacement.vip != old.vip {
		t.Fatalf("replacement VIP = %s, want reused %s", replacement.vip, old.vip)
	}
	if owner := handler.getSessionByVIP(old.vip); owner != old {
		t.Fatal("pending replacement took downlink ownership before handoff")
	}
	detachOld()
	if owner := handler.getSessionByVIP(old.vip); owner != replacement {
		t.Fatal("replacement did not take downlink ownership after handoff")
	}

	if _, _, _, ok := handler.prepareTunPacketFrameForOwner(
		batch.bufs[0], batch.headroom, batch.sizes[0], batch.owners[0], true,
	); ok {
		t.Fatal("batch captured for detached owner was accepted after VIP reuse")
	}
	handler.handleTunBatchWithScratch(
		batch.bufs, batch.sizes, batch.owners, batch.n, batch.headroom, nil, nil,
	)
}

func TestTunDemuxedBatchCannotEnqueueAfterVIPReuse(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	defer handler.Close()

	oldSession := SessionContext{ClientID: 10001, Generation: 1}
	old, detachOld := attachVIPTestSession(t, handler, oldSession)
	old.bindClientIP(netip.MustParseAddr("10.80.0.2"))
	batch := capturedVIPTestBatch(t, handler, old)
	ts, frame, frameSize, ok := handler.prepareTunPacketFrameForOwner(
		batch.bufs[0], batch.headroom, batch.sizes[0], batch.owners[0], true,
	)
	if !ok || ts != old {
		t.Fatal("active captured owner did not demux")
	}

	detachOld()
	replacement, detachReplacement := attachVIPTestSession(t, handler, SessionContext{ClientID: 10001, Generation: 2})
	defer detachReplacement()
	replacement.bindClientIP(netip.MustParseAddr("10.80.0.3"))
	if err := handler.enqueueSessionDownlink(ts, [][]byte{frame}, []int{frameSize}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("enqueue after owner detach = %v, want net.ErrClosed", err)
	}
}

func TestTunCapturedOwnerSurvivesRapidVIPChurn(t *testing.T) {
	handler := newSingleVIPTunHandler(t)
	defer handler.Close()

	session := SessionContext{ClientID: 10001, Generation: 1}
	owner, detach := attachVIPTestSession(t, handler, session)
	owner.bindClientIP(netip.MustParseAddr("10.80.0.2"))
	for generation := uint64(2); generation <= 65; generation++ {
		batch := capturedVIPTestBatch(t, handler, owner)
		detach()
		session.Generation = generation
		var nextDetach func()
		owner, nextDetach = attachVIPTestSession(t, handler, session)
		detach = nextDetach
		owner.bindClientIP(netip.MustParseAddr("10.80.0.2"))
		if _, _, _, ok := handler.prepareTunPacketFrameForOwner(
			batch.bufs[0], batch.headroom, batch.sizes[0], batch.owners[0], true,
		); ok {
			t.Fatalf("captured owner survived VIP reuse at generation %d", generation)
		}
	}
	detach()
}

func newSingleVIPTunHandler(t *testing.T) *TunPacketHandler {
	t.Helper()
	handler, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("10.0.0.1"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func attachVIPTestSession(t *testing.T, handler *TunPacketHandler, session SessionContext) (*tunHandlerSession, func()) {
	t.Helper()
	detach, err := handler.AttachSessionWriters(context.Background(), session, vipTestWriters())
	if err != nil {
		t.Fatal(err)
	}
	ts := handler.getSession(session)
	if ts == nil {
		detach()
		t.Fatal("attached session is missing")
	}
	return ts, detach
}

func vipTestWriters() SessionWriters {
	return SessionWriters{
		Raw:   func([]byte) error { return nil },
		Close: func() {},
	}
}

func capturedVIPTestBatch(t *testing.T, handler *TunPacketHandler, owner *tunHandlerSession) *serverTunReadBatch {
	t.Helper()
	packet := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, owner.vip.As4())
	headroom := vpnpacket.RawCmdDataHeaderLen()
	batch := newServerTunReadBatch(1, headroom, len(packet))
	copy(batch.bufs[0][headroom:], packet)
	batch.sizes[0] = len(packet)
	batch.n = 1
	handler.captureTunBatchOwners(batch)
	if batch.owners[0] != owner {
		t.Fatal("TUN read batch did not capture its current VIP owner")
	}
	return batch
}

func uncapturedVIPTestBatch(owner *tunHandlerSession) *serverTunReadBatch {
	packet := makeIPv4TCPPacket([4]byte{10, 15, 20, 66}, owner.vip.As4())
	headroom := vpnpacket.RawCmdDataHeaderLen()
	batch := newServerTunReadBatch(1, headroom, len(packet))
	copy(batch.bufs[0][headroom:], packet)
	batch.sizes[0] = len(packet)
	batch.n = 1
	return batch
}

type blockingVIPReleaseTunDevice struct {
	discardTunDevice
	started chan netip.Addr
	unblock chan struct{}
}

func (d *blockingVIPReleaseTunDevice) ReleaseVirtualIP(ctx context.Context, vip netip.Addr) error {
	d.started <- vip
	select {
	case <-d.unblock:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestNewTunPacketHandlerRejectsUnusablePrefix(t *testing.T) {
	if _, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("10.0.0.254"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/24"),
	}); err == nil {
		t.Fatal("accepted a base with no assignable address above it")
	}

	if _, err := NewTunPacketHandler(TunPacketHandlerConfig{
		Device:          discardTunDevice{batchSize: 1},
		VirtualIPBase:   netip.MustParseAddr("192.168.5.2"),
		VirtualIPPrefix: netip.MustParsePrefix("10.0.0.0/24"),
	}); err == nil {
		t.Fatal("accepted a base outside the configured prefix")
	}
}
