// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package socks5tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"reflect"
	"time"
)

const (
	defaultClientEstablishmentTimeout = 10 * time.Second
	maxClientEstablishmentTimeout     = 5 * time.Minute
	maxConcurrentClientDials          = 64
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type ClientConfig struct {
	Address              string
	TLSConfig            *tls.Config
	DialContext          DialContextFunc
	EstablishmentTimeout time.Duration
	// WireIdentity must uniquely identify this TalariaTCP endpoint.
	WireIdentity string
	// WireSecret must contain at least 32 bytes. It is used only for the outer
	// TalariaTCP stream transform.
	WireSecret []byte
}

type ServerConfig struct {
	Listen                 string
	Listener               net.Listener
	TLSConfig              *tls.Config
	CacheTLSConfig         bool
	CachePureTLSConfig     bool
	TLSConfigCacheScope    []byte
	AllowTLSConfigFallback bool
	// WireIdentity must uniquely identify this TalariaTCP endpoint and match the client.
	WireIdentity     string
	HandshakeTimeout time.Duration
	AdmissionLimits  AdmissionLimits
	Now              func() time.Time
	now              func() time.Time
	WireSecret       []byte
}

// AdmissionLimits bounds unauthenticated work and open transport connections.
// Zero values select finite production defaults.
type AdmissionLimits struct {
	MaxConnections            int
	MaxConnectionsPerSourceIP int
	MaxPendingHandshakes      int
	MaxPendingPerSourceIP     int
	IPv6SourcePrefixBits      int
}

func validateNegotiatedProtocol(negotiated string) error {
	if negotiated != "" {
		return errors.New("TalariaTCP negotiated an unexpected TLS ALPN")
	}
	return nil
}

func validateNegotiatedCipherSuite(cipherSuite uint16) error {
	if cipherSuite == tls.TLS_AES_128_GCM_SHA256 {
		return errors.New("TLS AES-128-GCM is disabled")
	}
	return nil
}

func disableAES128GCM(hello *tls.ClientHelloInfo) {
	for i, suite := range hello.CipherSuites {
		if suite == tls.TLS_AES_128_GCM_SHA256 {
			hello.CipherSuites[i] = 0xffff
		}
	}
}

func normalizeClientTLSConfig(cfg *tls.Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("client tls config is required")
	}
	if cfg.Rand != nil || cfg.Time != nil || cfg.KeyLogWriter != nil {
		return nil, errors.New("client tls Rand, Time, and KeyLogWriter hooks are not supported")
	}
	if cfg.InsecureSkipVerify {
		return nil, errors.New("client tls certificate verification cannot be disabled")
	}
	if cfg.ServerName == "" {
		return nil, errors.New("client tls server name is required")
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("client tls max version must allow TLS 1.3")
	}
	if cfg.MinVersion > tls.VersionTLS13 {
		return nil, errors.New("client tls min version must allow TLS 1.3")
	}
	clone := cfg.Clone()
	if cfg.RootCAs != nil {
		clone.RootCAs = cfg.RootCAs.Clone()
	}
	clone.MinVersion = tls.VersionTLS13
	clone.MaxVersion = tls.VersionTLS13
	clone.DynamicRecordSizingDisabled = true
	clone.SessionTicketsDisabled = true
	return clone, nil
}

func normalizeServerTLSConfig(cfg *tls.Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("server tls config is required")
	}
	if cfg.Rand != nil || cfg.Time != nil || cfg.GetCertificate != nil ||
		cfg.GetClientCertificate != nil || cfg.GetConfigForClient != nil ||
		cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil ||
		cfg.UnwrapSession != nil || cfg.WrapSession != nil ||
		cfg.KeyLogWriter != nil || cfg.EncryptedClientHelloRejectionVerify != nil ||
		cfg.GetEncryptedClientHelloKeys != nil {
		return nil, errors.New("server tls callback and I/O hooks are not supported")
	}
	if cfg.ClientAuth != tls.NoClientCert || cfg.ClientCAs != nil {
		return nil, errors.New("server tls client authentication is not supported")
	}
	if len(cfg.Certificates) == 0 {
		return nil, errors.New("server tls certificate is required")
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("server tls max version must allow TLS 1.3")
	}
	if cfg.MinVersion > tls.VersionTLS13 {
		return nil, errors.New("server tls min version must allow TLS 1.3")
	}
	clone := cfg.Clone()
	clone.Certificates = append([]tls.Certificate(nil), cfg.Certificates...)
	for i := range clone.Certificates {
		leaf, err := validateStaticServerCertificate(clone.Certificates[i])
		if err != nil {
			return nil, err
		}
		clone.Certificates[i].Leaf = leaf
	}
	clone.NameToCertificate = nil
	clone.MinVersion = tls.VersionTLS13
	clone.MaxVersion = tls.VersionTLS13
	clone.DynamicRecordSizingDisabled = true
	return clone, nil
}

func validateStaticServerCertificate(certificate tls.Certificate) (*x509.Certificate, error) {
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("server tls certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("server tls certificate is invalid")
	}
	switch key := certificate.PrivateKey.(type) {
	case *rsa.PrivateKey:
		publicKey, ok := leaf.PublicKey.(*rsa.PublicKey)
		if key == nil || key.N == nil || key.E <= 0 || !ok || !key.PublicKey.Equal(publicKey) {
			return nil, errors.New("server tls certificate private key is invalid")
		}
		if key.N.BitLen() < 2048 {
			return nil, errors.New("server tls RSA key must be at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if key == nil || key.D == nil || key.X == nil || key.Y == nil ||
			!standardECDSACurve(key.Curve) || !ok || !key.PublicKey.Equal(publicKey) {
			return nil, errors.New("server tls certificate private key is invalid")
		}
	case ed25519.PrivateKey:
		publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
		if len(key) != ed25519.PrivateKeySize || !ok || !key.Public().(ed25519.PublicKey).Equal(publicKey) {
			return nil, errors.New("server tls certificate private key is invalid")
		}
	default:
		return nil, errors.New("server tls custom private keys are not supported")
	}
	return leaf, nil
}

func standardECDSACurve(curve elliptic.Curve) bool {
	curveType := reflect.TypeOf(curve)
	return curveType == reflect.TypeOf(elliptic.P256()) ||
		curveType == reflect.TypeOf(elliptic.P384()) ||
		curveType == reflect.TypeOf(elliptic.P521())
}
