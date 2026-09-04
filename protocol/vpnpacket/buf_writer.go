// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpacket

import (
	"encoding/binary"
	"fmt"
)

type BufWriter struct {
	b []byte
}

func (w *BufWriter) Reset() {
	w.b = w.b[:0]
}

func (w *BufWriter) Write_(p []byte) {
	w.b = append(w.b, p...)
}

func (w *BufWriter) WriteByte_(b byte) {
	w.b = append(w.b, b)
}

func (w *BufWriter) WriteBool(v bool) {
	if v {
		w.WriteByte_(1)
		return
	}
	w.WriteByte_(0)
}

func (w *BufWriter) WriteLittleEndUint16(v uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	w.Write_(buf[:])
}

func (w *BufWriter) WriteLittleEndUint32(v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	w.Write_(buf[:])
}

func (w *BufWriter) WriteLittleEndUint64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	w.Write_(buf[:])
}

func (w *BufWriter) WriteString255(s string) error {
	if len(s) > 255 {
		return fmt.Errorf("vpnpacket: string length %d exceeds 255 bytes", len(s))
	}
	w.WriteByte_(byte(len(s)))
	w.Write_([]byte(s))
	return nil
}

func (w *BufWriter) GetBytes() []byte {
	return w.b
}
