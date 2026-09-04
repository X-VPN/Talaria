// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/X-VPN/Talaria/internal/extension"
)

type closeWriter interface {
	CloseWrite() error
}

type relayResult struct {
	err error
}

func Relay(ctx context.Context, left, right net.Conn) error {
	if extension.IsNil(left) || extension.IsNil(right) {
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeRelayConnections(left, right)
		case <-done:
		}
	}()

	results := make(chan relayResult, 2)
	copyOneWay := func(dst, src net.Conn) {
		err := extension.Do("transport relay connection", func() error {
			_, copyErr := io.Copy(dst, src)
			copyErr = normalizeRelayError(copyErr)
			if closeWrite, ok := dst.(closeWriter); ok {
				copyErr = errors.Join(copyErr, normalizeRelayError(closeWrite.CloseWrite()))
			}
			return copyErr
		})
		results <- relayResult{err: normalizeRelayError(err)}
	}
	go copyOneWay(left, right)
	go copyOneWay(right, left)

	first := <-results
	if first.err != nil {
		closeRelayConnections(left, right)
	}
	second := <-results
	if first.err != nil {
		return first.err
	}
	return second.err
}

func closeRelayConnections(left, right net.Conn) {
	_ = extension.Do("transport relay left connection close", left.Close)
	_ = extension.Do("transport relay right connection close", right.Close)
}

func normalizeRelayError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}
