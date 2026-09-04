// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package extension contains helpers for calling application code safely.
package extension

import (
	"errors"
	"fmt"
	"reflect"
)

var ErrPanic = errors.New("extension panicked")

// IsNil recognizes typed nil values stored in an interface.
func IsNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func PanicError(scope string, recovered any) error {
	return fmt.Errorf("%s: %w: %v", scope, ErrPanic, recovered)
}

func Recover(scope string, err *error) {
	if recovered := recover(); recovered != nil {
		*err = PanicError(scope, recovered)
	}
}

func Run(scope string, fn func()) (err error) {
	defer Recover(scope, &err)
	fn()
	return nil
}

func Do(scope string, fn func() error) (err error) {
	defer Recover(scope, &err)
	return fn()
}
