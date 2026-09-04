// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/transport/socks5tls"
)

func newSelfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "talaria.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"talaria.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func certificatePEM(t *testing.T, certificate tls.Certificate) (string, string) {
	t.Helper()
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
}

func TestStaticCertificateDrivesTalariaTCPHandshake(t *testing.T) {
	certificate := newSelfSignedCertificate(t)
	certPEM, keyPEM := certificatePEM(t, certificate)
	srv, err := Start(context.Background(), Config{
		Protocol:               client.ProtocolTalariaTCP,
		Host:                   "127.0.0.1",
		Port:                   0,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		TalariaTCPWireSecret:   "0123456789abcdef0123456789abcdef",
		TalariaTCPWireIdentity: "talaria.test",
		Auth: StaticAuthProvider{
			ClientID:         "client",
			SecretKey:        "secret",
			AssignedClientID: 42,
			Version:          1,
		},
		PacketHandler: EchoPacketHandler{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	transportClient, err := socks5tls.NewClient(socks5tls.ClientConfig{
		Address:      srv.Addr(),
		TLSConfig:    &tls.Config{ServerName: "talaria.test", RootCAs: roots, MinVersion: tls.VersionTLS13},
		WireIdentity: "talaria.test",
		WireSecret:   []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transportClient.Close()
	conn, err := transportClient.DialControl(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

func TestStaticCertificateStartsTalariaUDPListener(t *testing.T) {
	certificate := newSelfSignedCertificate(t)
	certPEM, keyPEM := certificatePEM(t, certificate)
	srv, err := Start(context.Background(), Config{
		Protocol:               client.ProtocolTalariaUDP,
		Host:                   "127.0.0.1",
		Port:                   0,
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		TalariaUDPWireSecret:   "0123456789abcdef0123456789abcdef",
		TalariaUDPWireIdentity: "vpn.test",
		Auth:                   StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
		PacketHandler:          EchoPacketHandler{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, _, err := net.SplitHostPort(srv.Addr()); err != nil {
		t.Fatalf("listener address = %q: %v", srv.Addr(), err)
	}
}

func TestStartRejectsDynamicCertificateCallback(t *testing.T) {
	for _, protocol := range []client.Protocol{client.ProtocolTalariaUDP, client.ProtocolTalariaTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			called := false
			server, err := Start(context.Background(), Config{
				Protocol: protocol,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					called = true
					return nil, nil
				},
			})
			if server != nil || err == nil {
				t.Fatalf("server result = %v, %v", server, err)
			}
			if called {
				t.Fatal("certificate callback was called")
			}
		})
	}
}

func TestStartRejectsDynamicCertificateOptions(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
	}{
		{name: "cache", configure: func(config *Config) { config.CacheGetCertificate = true }},
		{name: "pure cache", configure: func(config *Config) { config.CachePureGetCertificate = true }},
		{name: "cache scope", configure: func(config *Config) { config.CertificateCacheScope = []byte("scope") }},
		{name: "fallback", configure: func(config *Config) { config.AllowCertificateFallback = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{Protocol: client.ProtocolTalariaTCP}
			tt.configure(&config)
			server, err := Start(context.Background(), config)
			if server != nil || err == nil {
				t.Fatalf("server result = %v, %v", server, err)
			}
		})
	}
}

func TestCancelingParentContextClosesTalariaUDPListenerBeforeDone(t *testing.T) {
	certificate := newSelfSignedCertificate(t)
	certPEM, keyPEM := certificatePEM(t, certificate)
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := Start(ctx, Config{
		Protocol:               client.ProtocolTalariaUDP,
		Host:                   "127.0.0.1",
		Port:                   0,
		TalariaUDPWireSecret:   "0123456789abcdef0123456789abcdef",
		TalariaUDPWireIdentity: "vpn.test",
		CertPEM:                certPEM,
		KeyPEM:                 keyPEM,
		Auth:                   StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
		PacketHandler:          EchoPacketHandler{},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()
	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := srv.Wait(waitCtx); err != nil {
		t.Fatalf("wait after parent cancellation: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("TalariaUDP socket remains bound after Done: %v", err)
	}
	_ = packetConn.Close()
}

func TestStartRequiresStaticCertificate(t *testing.T) {
	for _, protocol := range []client.Protocol{client.ProtocolTalariaUDP, client.ProtocolTalariaTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			_, err := Start(context.Background(), Config{
				Protocol:      protocol,
				Auth:          StaticAuthProvider{ClientID: "client", SecretKey: "secret", AssignedClientID: 42},
				PacketHandler: EchoPacketHandler{},
			})
			if err == nil {
				t.Fatal("server started with no certificate")
			}
		})
	}
}
