// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package netdial applies a dial timeout consistently across transports, so a
// caller cannot accidentally get an unbounded connect.
package netdial

import (
	"errors"
	"net"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/lifecycle"
)

type Dialer = func(network, address string) (net.Conn, error)

const maxConcurrentLegacyDials = 64

type WrapTimeoutReq struct {
	Dial    Dialer
	Timeout time.Duration
	Closer  lifecycle.Closer
	// DoNotRegisterResult leaves a successful connection with the caller while
	// still using Closer to abort the in-flight dial. The caller must establish
	// its own close registration before exposing the connection.
	DoNotRegisterResult bool
}

func WrapTimeout(req WrapTimeoutReq) Dialer {
	dialSlots := make(chan struct{}, maxConcurrentLegacyDials)
	return func(network, address string) (net.Conn, error) {
		closer := req.Closer
		if extension.IsNil(closer) {
			closer = lifecycle.NewCloser()
		}
		timeout := req.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		closed, err := legacyCloserIsClosed(closer)
		if err != nil {
			return nil, err
		}
		if closed {
			return nil, errors.New("lifecycle closer was already closed before dial")
		}
		if req.Dial == nil {
			return nil, errors.New("nil parent dialer")
		}
		closeCh, err := legacyCloserDone(closer)
		if err != nil {
			return nil, err
		}
		select {
		case dialSlots <- struct{}{}:
		case <-closeCh:
			return nil, errors.New("lifecycle closer fired while waiting for a dial slot")
		default:
			return nil, errors.New("too many concurrent legacy dials")
		}

		type dialResult struct {
			conn net.Conn
			err  error
		}
		resultCh := make(chan dialResult)
		abandoned := make(chan struct{})
		go func() {
			defer func() { <-dialSlots }()
			var conn net.Conn
			err := extension.Do("legacy parent dialer", func() error {
				var dialErr error
				conn, dialErr = req.Dial(network, address)
				return dialErr
			})
			select {
			case resultCh <- dialResult{conn: conn, err: err}:
			case <-abandoned:
				if !extension.IsNil(conn) {
					_ = extension.Do("abandoned legacy dial connection close", conn.Close)
				}
			}
		}()
		defer close(abandoned)

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-closeCh:
			return nil, errors.New("lifecycle closer fired during dial")
		case <-timer.C:
			return nil, errors.New("dial timed out")
		case result := <-resultCh:
			if result.err != nil {
				if !extension.IsNil(result.conn) {
					_ = extension.Do("failed legacy dial connection close", result.conn.Close)
				}
				return nil, result.err
			}
			if extension.IsNil(result.conn) {
				return nil, errors.New("legacy dialer returned a nil connection")
			}
			if req.DoNotRegisterResult {
				closed, err := legacyCloserIsClosed(closer)
				if err != nil {
					_ = extension.Do("legacy dial connection close", result.conn.Close)
					return nil, err
				}
				if closed {
					_ = extension.Do("legacy dial connection close", result.conn.Close)
					return nil, errors.New("lifecycle closer fired after the dial completed")
				}
				return result.conn, nil
			}
			var unregister func()
			if err := extension.Run("legacy dial lifecycle registration", func() {
				unregister = closer.AddOnClose(func() {
					_ = extension.Do("registered legacy dial connection close", result.conn.Close)
				})
			}); err != nil {
				_ = extension.Do("legacy dial connection close", result.conn.Close)
				return nil, err
			}
			closed, err := legacyCloserIsClosed(closer)
			if err != nil {
				if unregister != nil {
					_ = extension.Run("legacy dial lifecycle unregister", unregister)
				}
				_ = extension.Do("legacy dial connection close", result.conn.Close)
				return nil, err
			}
			if unregister == nil || closed {
				if unregister != nil {
					_ = extension.Run("legacy dial lifecycle unregister", unregister)
				}
				_ = extension.Do("legacy dial connection close", result.conn.Close)
				// The two causes are reported separately: a missing unregister
				// means the closer never accepted the registration, so nothing
				// would have closed this connection, which is a different fault
				// from the closer having fired in the meantime.
				if unregister == nil {
					return nil, errors.New("lifecycle closer did not return an unregister function")
				}
				return nil, errors.New("lifecycle closer fired after the dial completed")
			}
			return result.conn, nil
		}
	}
}

func legacyCloserIsClosed(closer lifecycle.Closer) (closed bool, err error) {
	err = extension.Run("legacy dial lifecycle closed check", func() {
		closed = closer.IsClose()
	})
	return closed, err
}

func legacyCloserDone(closer lifecycle.Closer) (done <-chan struct{}, err error) {
	err = extension.Run("legacy dial lifecycle close channel", func() {
		done = closer.GetCloseChan()
	})
	return done, err
}
