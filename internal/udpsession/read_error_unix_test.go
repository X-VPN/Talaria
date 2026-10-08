// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package udpsession

import (
	"syscall"
	"testing"
)

func TestListenerRecoversUnixReadErrors(t *testing.T) {
	for _, err := range []error{
		syscall.EMSGSIZE, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET,
		syscall.EINTR, syscall.EAGAIN, syscall.EWOULDBLOCK, syscall.ETIMEDOUT,
		syscall.ENOBUFS, syscall.ENOMEM, syscall.ENETDOWN, syscall.ENETUNREACH,
		syscall.EHOSTUNREACH, syscall.EHOSTDOWN, syscall.EPROTO, syscall.EACCES,
		syscall.ENOPROTOOPT, syscall.EOPNOTSUPP,
	} {
		t.Run(err.Error(), func(t *testing.T) { testListenerRecoversReadError(t, err) })
	}
}
