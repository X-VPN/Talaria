// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"unicode"
	"unicode/utf8"
)

func randomIntBetween(min, max int) int {
	if max <= min {
		return min
	}
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err != nil {
		return min
	}
	n := binary.LittleEndian.Uint64(buf[:])
	return min + int(n%uint64(max-min+1))
}

func readString255(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errors.New("vpnpacket: missing string length")
	}
	n := int(b[0])
	if len(b) < 1+n {
		return "", errors.New("vpnpacket: string length exceeds buffer")
	}
	return string(b[1 : 1+n]), nil
}

// readDisplayString255 decodes one single-line message and rejects terminal controls.
func readDisplayString255(b []byte) (string, error) {
	s, err := readString255(b)
	if err != nil {
		return "", err
	}
	if err := validateDisplayString(s); err != nil {
		return "", err
	}
	return s, nil
}

// validateDisplayString permits UTF-8 graphic runes but excludes controls, format characters, and line separators.
func validateDisplayString(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("vpnpacket: display string is not valid UTF-8")
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return errors.New("vpnpacket: display string contains a non-graphic character")
		}
	}
	return nil
}

func readBool(b byte) bool {
	return b != 0
}

func validUTF8String(s string) bool {
	return utf8.ValidString(s)
}
