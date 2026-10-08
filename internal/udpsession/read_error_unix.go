// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package udpsession

import (
	"errors"
	"syscall"
)

func classifyReadError(err error) readErrorAction {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return readErrorUnknown
	}
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		return readErrorRetry
	}
	switch errno {
	case syscall.EMSGSIZE, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET:
		// These errors concern a datagram, not the shared UDP socket.
		return readErrorDrop
	case syscall.EINTR, syscall.ETIMEDOUT, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EHOSTDOWN,
		syscall.EPROTO, syscall.EACCES, syscall.ENOPROTOOPT, syscall.EOPNOTSUPP:
		// ICMP feedback can also report protocol, permission or option errors.
		return readErrorRetry
	case syscall.EBADF, syscall.ENOTSOCK, syscall.ESHUTDOWN, syscall.EINVAL, syscall.EFAULT:
		return readErrorFatal
	default:
		return readErrorUnknown
	}
}
