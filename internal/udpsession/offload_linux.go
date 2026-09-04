// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package udpsession

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func udpControlSize() int {
	return unix.CmsgSpace(2)
}

func enableUDPGSO(conn *net.UDPConn) bool {
	return withUDPConnFD(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_SEGMENT, 0)
	}) == nil
}

// enableUDPGRO reports whether UDP generic receive offload was enabled.
//
// GRO is deliberately off. Turning it on is a single setsockopt, but the
// coalesced receive path it feeds has no test coverage and the listener never
// sets its own udpGRO flag, so enabling it here would change the client read
// path while leaving the server on the uncoalesced one. Re-enabling must come
// with coverage for segment parsing and for a short final segment.
//
// The unreachable setsockopt call that used to sit below this return is kept
// out of the tree because `go vet` reports it on every Linux build.
func enableUDPGRO(_ *net.UDPConn) bool {
	return false
}

func withUDPConnFD(conn *net.UDPConn, fn func(fd int) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var callErr error
	if err := raw.Control(func(fd uintptr) {
		callErr = fn(int(fd))
	}); err != nil {
		return err
	}
	return callErr
}

func buildUDPSegmentOOB(segSize int, oob []byte) []byte {
	if segSize <= 0 || segSize > 0xffff {
		return nil
	}
	need := unix.CmsgSpace(2)
	if cap(oob) < need {
		oob = make([]byte, need)
	}
	oob = oob[:need]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	dataOffset := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(oob[dataOffset:dataOffset+2], uint16(segSize))
	return oob
}

func parseUDPGROSegmentSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range msgs {
		m := msgs[i]
		if m.Header.Level != unix.SOL_UDP || m.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(m.Data) < 2 {
			continue
		}
		return int(binary.NativeEndian.Uint16(m.Data[:2]))
	}
	return 0
}

func isUDPSegmentUnsupported(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == unix.ENOPROTOOPT || errno == unix.EOPNOTSUPP || errno == unix.EINVAL
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return isUDPSegmentUnsupported(opErr.Err)
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return isUDPSegmentUnsupported(sysErr.Err)
	}
	return false
}
