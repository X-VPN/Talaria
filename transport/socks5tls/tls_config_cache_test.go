// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"
)

type rejectedTLSReader struct{}

func (rejectedTLSReader) Read([]byte) (int, error) {
	panic("unexpected TLS reader call")
}

type rejectedTLSWriter struct{}

func (rejectedTLSWriter) Write([]byte) (int, error) {
	panic("unexpected TLS writer call")
}

type rejectedTLSSigner struct{}

func (rejectedTLSSigner) Public() crypto.PublicKey {
	panic("unexpected TLS signer public key call")
}

func (rejectedTLSSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("unexpected TLS signer call")
}

func TestNewServerRejectsDynamicTLSCallbacks(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*tls.Config)
	}{
		{
			name: "GetCertificate",
			configure: func(config *tls.Config) {
				config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					panic("unexpected certificate callback")
				}
			},
		},
		{
			name: "GetConfigForClient",
			configure: func(config *tls.Config) {
				config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
					panic("unexpected config callback")
				}
			},
		},
		{
			name: "GetClientCertificate",
			configure: func(config *tls.Config) {
				config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					panic("unexpected client certificate callback")
				}
			},
		},
		{
			name: "VerifyPeerCertificate",
			configure: func(config *tls.Config) {
				config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
					panic("unexpected peer certificate callback")
				}
			},
		},
		{
			name: "VerifyConnection",
			configure: func(config *tls.Config) {
				config.VerifyConnection = func(tls.ConnectionState) error {
					panic("unexpected connection callback")
				}
			},
		},
		{
			name: "UnwrapSession",
			configure: func(config *tls.Config) {
				config.UnwrapSession = func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
					panic("unexpected session unwrap callback")
				}
			},
		},
		{
			name: "WrapSession",
			configure: func(config *tls.Config) {
				config.WrapSession = func(tls.ConnectionState, *tls.SessionState) ([]byte, error) {
					panic("unexpected session wrap callback")
				}
			},
		},
		{
			name: "Time",
			configure: func(config *tls.Config) {
				config.Time = func() time.Time {
					panic("unexpected TLS clock callback")
				}
			},
		},
		{
			name: "Rand",
			configure: func(config *tls.Config) {
				config.Rand = rejectedTLSReader{}
			},
		},
		{
			name: "KeyLogWriter",
			configure: func(config *tls.Config) {
				config.KeyLogWriter = rejectedTLSWriter{}
			},
		},
		{
			name: "EncryptedClientHelloRejectionVerify",
			configure: func(config *tls.Config) {
				config.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error {
					panic("unexpected ECH rejection callback")
				}
			},
		},
		{
			name: "GetEncryptedClientHelloKeys",
			configure: func(config *tls.Config) {
				config.GetEncryptedClientHelloKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
					panic("unexpected ECH key callback")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, _ := testTLSConfigs(t)
			tt.configure(config)
			listener := newPipeListener()
			server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: config})
			if server != nil || err == nil {
				t.Fatalf("server result = %v, %v", server, err)
			}
			_ = listener.Close()
		})
	}
}

func TestNewServerRejectsCustomTLSPrivateKey(t *testing.T) {
	config, _ := testTLSConfigs(t)
	config.Certificates[0].PrivateKey = rejectedTLSSigner{}
	listener := newPipeListener()
	server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: config})
	if server != nil || err == nil {
		t.Fatalf("server result = %v, %v", server, err)
	}
	_ = listener.Close()
}

func TestNormalizeServerTLSConfigRSAKeySize(t *testing.T) {
	for _, tt := range []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{name: "1024 bits", bits: 1024, wantErr: true},
		{name: "2047 bits", bits: 2047, wantErr: true},
		{name: "2048 bits", bits: 2048},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, tt.bits)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				SignatureAlgorithm: x509.SHA256WithRSA,
				NotBefore:          time.Now().Add(-time.Minute),
				NotAfter:           time.Now().Add(time.Hour),
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = normalizeServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{{
				Certificate: [][]byte{der},
				PrivateKey:  key,
			}}})
			if tt.wantErr {
				if err == nil || err.Error() != "server tls RSA key must be at least 2048 bits" {
					t.Fatalf("expected RSA key size error, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNormalizeServerTLSConfigCAKeySize(t *testing.T) {
	config, _ := testTLSConfigs(t)
	serverKey := config.Certificates[0].PrivateKey.(crypto.Signer)
	rsaKeys := make(map[int]crypto.Signer)
	for _, bits := range []int{1024, 2047, 2048} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		rsaKeys[bits] = key
	}
	const weakRSA = "server tls CA RSA key must be at least 2048 bits"
	for _, tt := range []struct {
		name         string
		intermediate crypto.Signer
		root         crypto.Signer
		malformed    bool
		wantErr      string
	}{
		{name: "1024-bit intermediate", intermediate: rsaKeys[1024], root: rsaKeys[2048], wantErr: weakRSA},
		{name: "1024-bit root", intermediate: rsaKeys[2048], root: rsaKeys[1024], wantErr: weakRSA},
		{name: "2047-bit intermediate", intermediate: rsaKeys[2047], root: rsaKeys[2048], wantErr: weakRSA},
		{name: "2048-bit CAs", intermediate: rsaKeys[2048], root: rsaKeys[2048]},
		{name: "ECDSA CAs", intermediate: serverKey, root: serverKey},
		{name: "malformed intermediate", intermediate: rsaKeys[2048], root: rsaKeys[2048], malformed: true, wantErr: "server tls CA certificate is invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keys := []crypto.Signer{serverKey, tt.intermediate, tt.root}
			names := []string{"vpn.test", "intermediate", "root"}
			chain := make([][]byte, len(keys))
			var parent *x509.Certificate
			var signer crypto.Signer
			for i := len(keys) - 1; i >= 0; i-- {
				template := &x509.Certificate{
					SerialNumber:          big.NewInt(int64(i + 1)),
					Subject:               pkix.Name{CommonName: names[i]},
					NotBefore:             time.Now().Add(-time.Minute),
					NotAfter:              time.Now().Add(time.Hour),
					BasicConstraintsValid: true,
					IsCA:                  i > 0,
					KeyUsage:              x509.KeyUsageDigitalSignature,
				}
				if i > 0 {
					template.KeyUsage |= x509.KeyUsageCertSign
				}
				if parent == nil {
					parent, signer = template, keys[i]
				}
				der, err := x509.CreateCertificate(rand.Reader, template, parent, keys[i].Public(), signer)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if i < len(keys)-1 {
					if err := parsed.CheckSignatureFrom(parent); err != nil {
						t.Fatal(err)
					}
				}
				chain[i], parent, signer = der, parsed, keys[i]
			}
			if tt.malformed {
				chain[1] = []byte("invalid certificate")
			}
			_, err := normalizeServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{{
				Certificate: chain,
				PrivateKey:  serverKey,
			}}})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("expected %q, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewServerRejectsTLSClientAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*tls.Config)
	}{
		{
			name: "client auth",
			configure: func(config *tls.Config) {
				config.ClientAuth = tls.RequestClientCert
			},
		},
		{
			name: "client CA pool",
			configure: func(config *tls.Config) {
				config.ClientCAs = x509.NewCertPool()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, _ := testTLSConfigs(t)
			tt.configure(config)
			listener := newPipeListener()
			server, err := NewServer(ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: config})
			if server != nil || err == nil {
				t.Fatalf("server result = %v, %v", server, err)
			}
			_ = listener.Close()
		})
	}
}

func TestNewServerRejectsDynamicTLSOptions(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*ServerConfig)
	}{
		{name: "cache", configure: func(config *ServerConfig) { config.CacheTLSConfig = true }},
		{name: "pure cache", configure: func(config *ServerConfig) { config.CachePureTLSConfig = true }},
		{name: "cache scope", configure: func(config *ServerConfig) { config.TLSConfigCacheScope = []byte("scope") }},
		{name: "fallback", configure: func(config *ServerConfig) { config.AllowTLSConfigFallback = true }},
		{name: "clock", configure: func(config *ServerConfig) { config.Now = time.Now }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, _ := testTLSConfigs(t)
			listener := newPipeListener()
			config := ServerConfig{WireIdentity: "vpn.test", WireSecret: testTalariaTCPWireSecret, Listener: listener, TLSConfig: tlsConfig}
			tt.configure(&config)
			server, err := NewServer(config)
			if server != nil || err == nil {
				t.Fatalf("server result = %v, %v", server, err)
			}
			_ = listener.Close()
		})
	}
}
