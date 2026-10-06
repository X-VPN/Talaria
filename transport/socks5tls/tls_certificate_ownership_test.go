// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestNewServerOwnsTLSCertificate(t *testing.T) {
	for _, kind := range []string{"ECDSA", "RSA", "RSA without primes", "Ed25519"} {
		t.Run(kind, func(t *testing.T) {
			config, _ := testTLSConfigs(t)
			certificate := &config.Certificates[0]
			caKey := certificate.PrivateKey.(crypto.Signer)
			var key crypto.Signer = caKey
			var err error
			switch kind {
			case "RSA", "RSA without primes":
				key, err = rsa.GenerateKey(rand.Reader, 2048)
				if kind == "RSA without primes" && err == nil {
					key.(*rsa.PrivateKey).Primes = nil
					key.(*rsa.PrivateKey).Precomputed = rsa.PrecomputedValues{}
				}
			case "Ed25519":
				_, key, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Reissue the existing fixture with the selected leaf key.
			ca, err := x509.ParseCertificate(certificate.Certificate[1])
			if err != nil {
				t.Fatal(err)
			}
			ca.PublicKey = caKey.Public()
			certificate.Certificate[1], err = x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			certificate.Certificate[0], err = x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
			if err != nil {
				t.Fatal(err)
			}
			certificate.PrivateKey = key
			certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			certificate.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519}
			certificate.OCSPStaple = []byte{1, 2, 3}
			certificate.SignedCertificateTimestamps = [][]byte{{4, 5}, {6, 7}}
			// The client's trust store must not share the caller's certificate bytes.
			root, err := x509.ParseCertificate(bytes.Clone(certificate.Certificate[1]))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(root)
			clientConfig := &tls.Config{ServerName: "vpn.test", RootCAs: roots}
			listener := newPipeListener()
			t.Cleanup(func() { _ = listener.Close() })
			server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: config})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			owned := &server.tlsConfig.Certificates[0]
			wantChain := [][]byte{bytes.Clone(certificate.Certificate[0]), bytes.Clone(certificate.Certificate[1])}
			var wantKey []byte
			if kind != "RSA without primes" {
				wantKey, err = x509.MarshalPKCS8PrivateKey(owned.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
			}
			handshake := func() {
				t.Helper()
				serverConn, clientConn := net.Pipe()
				defer serverConn.Close()
				defer clientConn.Close()
				_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
				serverDone := make(chan error, 1)
				go func() { serverDone <- tls.Server(serverConn, server.tlsConfig).Handshake() }()
				client := tls.Client(clientConn, clientConfig)
				if err := client.Handshake(); err != nil {
					t.Fatal(err)
				}
				if err := <-serverDone; err != nil {
					t.Fatal(err)
				}
				state := client.ConnectionState()
				if !bytes.Equal(state.PeerCertificates[0].Raw, wantChain[0]) ||
					!bytes.Equal(state.OCSPResponse, []byte{1, 2, 3}) ||
					!reflect.DeepEqual(state.SignedCertificateTimestamps, [][]byte{{4, 5}, {6, 7}}) {
					t.Fatal("handshake did not retain the original certificate metadata")
				}
			}
			handshake()
			derBuffers := append([][]byte(nil), certificate.Certificate...)
			sctBuffers := append([][]byte(nil), certificate.SignedCertificateTimestamps...)
			mutate := func() {
				for i, der := range derBuffers {
					clear(der)
					certificate.Certificate[i] = []byte{0}
				}
				clear(certificate.Leaf.Raw)
				certificate.Leaf.DNSNames[0] = "changed.test"
				certificate.SupportedSignatureAlgorithms[0] = 0
				clear(certificate.OCSPStaple)
				for i, sct := range sctBuffers {
					clear(sct)
					certificate.SignedCertificateTimestamps[i] = []byte{0}
				}
				switch key := key.(type) {
				case *rsa.PrivateKey:
					key.N.SetInt64(0)
					key.D.SetInt64(0)
					for _, prime := range key.Primes {
						prime.SetInt64(0)
					}
					if key.Precomputed.Dp != nil {
						key.Precomputed.Dp.SetInt64(0)
						key.Precomputed.Dq.SetInt64(0)
						key.Precomputed.Qinv.SetInt64(0)
					}
				case *ecdsa.PrivateKey:
					key.X.SetInt64(0)
					key.Y.SetInt64(0)
					key.D.SetInt64(0)
				case ed25519.PrivateKey:
					clear(key)
				}
			}
			mutate()
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
						mutate()
					}
				}
			}()
			defer func() { close(stop); <-done }()
			handshake()
			if !reflect.DeepEqual(owned.Certificate, wantChain) || !bytes.Equal(owned.Leaf.Raw, wantChain[0]) || owned.Leaf.DNSNames[0] != "vpn.test" {
				t.Fatal("caller mutation changed server certificate data")
			}
			if !reflect.DeepEqual(owned.SupportedSignatureAlgorithms, []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519}) {
				t.Fatal("caller mutation changed server signature algorithms")
			}
			if wantKey != nil {
				gotKey, err := x509.MarshalPKCS8PrivateKey(owned.PrivateKey)
				if err != nil || !bytes.Equal(gotKey, wantKey) {
					t.Fatalf("caller mutation changed server private key: %v", err)
				}
			}
		})
	}
}

func TestNormalizeServerTLSConfigPreservesSignatureAlgorithmPolicy(t *testing.T) {
	for _, algorithms := range [][]tls.SignatureScheme{nil, {}} {
		config, _ := testTLSConfigs(t)
		config.Certificates[0].SupportedSignatureAlgorithms = algorithms
		owned, err := normalizeServerTLSConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(owned.Certificates[0].SupportedSignatureAlgorithms, algorithms) {
			t.Fatalf("signature policy changed: want %#v, got %#v", algorithms, owned.Certificates[0].SupportedSignatureAlgorithms)
		}
	}
}
