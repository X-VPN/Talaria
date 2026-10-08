// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udpsession

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func classifyReadError(err error) readErrorAction {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return readErrorUnknown
	}
	switch errno {
	case windows.WSAEMSGSIZE, windows.WSAECONNRESET, windows.WSAENETRESET, windows.WSAECONNREFUSED:
		// UDP truncation and ICMP feedback do not invalidate the shared socket.
		return readErrorDrop
	case windows.WSAEWOULDBLOCK, windows.WSAENOBUFS, windows.ERROR_NOT_ENOUGH_MEMORY,
		windows.WSAENETDOWN, windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH,
		windows.WSAEHOSTDOWN, windows.WSAETIMEDOUT:
		return readErrorRetry
	case windows.ERROR_INVALID_HANDLE, windows.ERROR_INVALID_PARAMETER,
		windows.WSAEBADF, windows.WSAENOTSOCK, windows.WSAESHUTDOWN,
		windows.WSAEINVAL, windows.WSAEFAULT, windows.WSAEOPNOTSUPP, windows.WSANOTINITIALISED:
		return readErrorFatal
	default:
		return readErrorUnknown
	}
}
