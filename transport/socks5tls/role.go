// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"errors"
	"io"
	"net"
)

type connectionRole byte

const (
	connectionRoleControl connectionRole = 1
	connectionRoleStream  connectionRole = 2
)

func writeConnectionRole(conn net.Conn, role connectionRole) error {
	if role != connectionRoleControl && role != connectionRoleStream {
		return errors.New("invalid TLS connection role")
	}
	_, err := writeAllCount(conn, []byte{byte(role)})
	return err
}

func readConnectionRole(conn net.Conn) (connectionRole, error) {
	var raw [1]byte
	if _, err := io.ReadFull(conn, raw[:]); err != nil {
		return 0, err
	}
	role := connectionRole(raw[0])
	if role != connectionRoleControl && role != connectionRoleStream {
		return 0, errors.New("invalid TLS connection role")
	}
	return role, nil
}
