// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"crypto/tls"
	"testing"
)

func TestNewListenerRejectsDynamicCertificateCallback(t *testing.T) {
	called := false
	listener, err := NewListener(NewListenerReq{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			called = true
			return nil, nil
		},
	})
	if listener != nil || err == nil {
		t.Fatalf("listener result = %v, %v", listener, err)
	}
	if called {
		t.Fatal("certificate callback was called")
	}
}

func TestNewListenerRejectsDynamicCertificateOptions(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*NewListenerReq)
	}{
		{name: "fallback certificate", configure: func(req *NewListenerReq) { req.FallbackCertificate = &tls.Certificate{} }},
		{name: "cache", configure: func(req *NewListenerReq) { req.CacheGetCertificate = true }},
		{name: "pure cache", configure: func(req *NewListenerReq) { req.CachePureGetCertificate = true }},
		{name: "cache scope", configure: func(req *NewListenerReq) { req.CertificateCacheScope = []byte("scope") }},
		{name: "fallback", configure: func(req *NewListenerReq) { req.AllowCertificateFallback = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req NewListenerReq
			tt.configure(&req)
			listener, err := NewListener(req)
			if listener != nil || err == nil {
				t.Fatalf("listener result = %v, %v", listener, err)
			}
		})
	}
}
