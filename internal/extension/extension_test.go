// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package extension

import (
	"errors"
	"testing"
)

type nilTarget struct{}

func TestIsNilRecognizesTypedNil(t *testing.T) {
	var target *nilTarget
	var value any = target
	if !IsNil(value) {
		t.Fatal("typed nil was not recognized")
	}
	if IsNil(&nilTarget{}) || IsNil(1) {
		t.Fatal("non-nil value was reported nil")
	}
}

func TestDoConvertsPanicToError(t *testing.T) {
	err := Do("test callback", func() error { panic("boom") })
	if !errors.Is(err, ErrPanic) {
		t.Fatalf("error = %v, want ErrPanic", err)
	}
}
