// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/udpsession"
	"github.com/X-VPN/Talaria/lifecycle"
)

func TestValidateRetryMaxPacket(t *testing.T) {
	tests := []struct {
		name      string
		maxPacket int
		wantErr   bool
	}{
		{name: "123 bytes cannot carry request and challenge", maxPacket: 123, wantErr: true},
		{name: "124 bytes is the minimum", maxPacket: 124},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRetryMaxPacket(tt.maxPacket); (err != nil) != tt.wantErr {
				t.Fatalf("validate max packet %d: err=%v wantErr=%v", tt.maxPacket, err, tt.wantErr)
			}
		})
	}
}

func TestMaxPlainPacketReservesTalariaUDPWireOverhead(t *testing.T) {
	if got := udptlsWirePacketSize(defaultMaxPlainPacket) + wireEnvelopeOverhead; got != udpsession.MaxUDPPayloadIPv4 {
		t.Fatalf("default TalariaUDP wire packet = %d want %d", got, udpsession.MaxUDPPayloadIPv4)
	}
	if got := udptlsWirePacketSize(maxPlainPacket) + wireEnvelopeOverhead; got != udpsession.MaxUDPPayloadIPv6 {
		t.Fatalf("maximum TalariaUDP wire packet = %d want %d", got, udpsession.MaxUDPPayloadIPv6)
	}
	if _, err := NewListener(NewListenerReq{MaxPacket: maxPlainPacket + 1}); err == nil {
		t.Fatal("TalariaUDP listener accepted plaintext size that overflows the UDP wire limit")
	}
}

func TestSecureWireProfileRequiresSecretAndNeverDowngrades(t *testing.T) {
	if listener, err := NewListener(NewListenerReq{}); listener != nil || err == nil || !strings.Contains(err.Error(), "wire secret") {
		t.Fatalf("default listener = %v, %v; want missing wire secret", listener, err)
	}
	secret := bytes.Repeat([]byte{0x31}, minimumWireSecretSize)
	if listener, err := NewListener(NewListenerReq{WireSecret: secret}); listener != nil || err == nil || !strings.Contains(err.Error(), "wire identity") {
		t.Fatalf("unidentified listener = %v, %v; want missing wire identity", listener, err)
	}
	called := false
	dialer := NewDialer(NewDialerReq{
		ParentDial: func(string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("unexpected dial")
		},
		ParentDialAlreadyHasTimeout: true,
		TLSConfig:                   &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()},
	})
	if conn, err := dialer("udp", "127.0.0.1:443"); conn != nil || err == nil || !strings.Contains(err.Error(), "wire secret") {
		t.Fatalf("default dialer = %v, %v; want missing wire secret", conn, err)
	}
	if called {
		t.Fatal("missing wire secret reached the network path")
	}
	dialer = NewDialer(NewDialerReq{
		ParentDial: func(string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("unexpected dial")
		},
		ParentDialAlreadyHasTimeout: true,
		TLSConfig:                   &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()},
		WireSecret:                  secret,
	})
	if conn, err := dialer("udp", "127.0.0.1:443"); conn != nil || err == nil || !strings.Contains(err.Error(), "wire identity") {
		t.Fatalf("unidentified dialer = %v, %v; want missing wire identity", conn, err)
	}
	if called {
		t.Fatal("missing wire identity reached the network path")
	}
	if wire, err := newWireCodec(wireProfileReserved1, nil, testWireIdentity, nil); err == nil || wire != nil {
		t.Fatalf("reserved profile = %v, %v", wire, err)
	}
	if listener, err := NewListener(NewListenerReq{WireProfile: wireProfileReserved1}); listener != nil || err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("reserved-profile listener = %v, %v", listener, err)
	}
	dialer = NewDialer(NewDialerReq{
		ParentDial: func(string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("unexpected dial")
		},
		ParentDialAlreadyHasTimeout: true,
		TLSConfig:                   &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()},
		WireSecret:                  secret,
		WireIdentity:                testWireIdentity,
		WireProfile:                 wireProfileReserved1,
	})
	if conn, err := dialer("udp", "127.0.0.1:443"); conn != nil || err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("reserved-profile dialer = %v, %v", conn, err)
	}
	if called {
		t.Fatal("reserved-profile dialer reached the network path")
	}
}

func TestRegisterDialedConnRejectsClosedGroup(t *testing.T) {
	group := lifecycle.NewCloser()
	group.Close()
	conn := &scriptedBatchConn{}
	if err := registerDialedConn(group, conn); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("registerDialedConn() error = %v want net.ErrClosed", err)
	}
	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()
	if !closed {
		t.Fatal("failed registration did not close candidate connection")
	}
}

func TestNewDialerContainsParentDialPanic(t *testing.T) {
	dialer := NewDialer(NewDialerReq{
		ParentDial:                  func(string, string) (net.Conn, error) { panic("dial panic") },
		ParentDialAlreadyHasTimeout: true,
		TLSConfig:                   &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()},
		WireSecret:                  bytes.Repeat([]byte{0x32}, minimumWireSecretSize),
		WireIdentity:                testWireIdentity,
	})
	if conn, err := dialer("udp", "127.0.0.1:443"); conn != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("dial result = %v, %v; want extension panic", conn, err)
	}
}

func TestNewDialerClosesConnectionReturnedWithError(t *testing.T) {
	control, peer := net.Pipe()
	defer peer.Close()
	want := errors.New("parent dial failed")
	dialer := NewDialer(NewDialerReq{
		ParentDial:                  func(string, string) (net.Conn, error) { return control, want },
		ParentDialAlreadyHasTimeout: true,
		TLSConfig:                   &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()},
		WireSecret:                  bytes.Repeat([]byte{0x33}, minimumWireSecretSize),
		WireIdentity:                testWireIdentity,
	})
	if conn, err := dialer("udp", "127.0.0.1:443"); conn != nil || !errors.Is(err, want) {
		t.Fatalf("dial result = %v, %v; want nil, %v", conn, err, want)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := peer.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("connection returned with parent dial error was not closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed parent dial connection to close")
	}
}

func TestNewListenerRejectsTypedNilPacketConn(t *testing.T) {
	var pc *net.UDPConn
	if listener, err := NewListener(NewListenerReq{PacketConn: pc}); listener != nil || err == nil || !strings.Contains(err.Error(), "typed nil") {
		t.Fatalf("listener result = %v, %v; want typed-nil error", listener, err)
	}
}

func TestNewListenerContainsListenPacketPanic(t *testing.T) {
	certPEM, keyPEM := newHandshakeTestCertificatePEM(t)
	listener, err := NewListener(NewListenerReq{
		ListenPacket: func(string, string) (net.PacketConn, error) { panic("listen panic") },
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		WireSecret:   bytes.Repeat([]byte{0x34}, minimumWireSecretSize),
		WireIdentity: testWireIdentity,
	})
	if listener != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("listener result = %v, %v; want extension panic", listener, err)
	}
}

func TestNewListenerRejectsInvalidCertificateBeforeListen(t *testing.T) {
	called := false
	listener, err := NewListener(NewListenerReq{
		ListenPacket: func(string, string) (net.PacketConn, error) {
			called = true
			return nil, errors.New("unexpected listen")
		},
		CertPEM:      "invalid",
		KeyPEM:       "invalid",
		WireProfile:  WireProfileSecure,
		WireSecret:   bytes.Repeat([]byte{0x24}, minimumWireSecretSize),
		WireIdentity: testWireIdentity,
	})
	if listener != nil || err == nil || !strings.Contains(err.Error(), "TalariaUDP certificate") {
		t.Fatalf("listener result = %v, %v; want certificate error", listener, err)
	}
	if called {
		t.Fatal("listener opened a packet connection before validating its certificate")
	}
}

func TestNewListenerRSAKeyStrength(t *testing.T) {
	for _, bits := range []int{1024, 2047, 2048} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber:       big.NewInt(1),
				NotBefore:          time.Now().Add(-time.Hour),
				NotAfter:           time.Now().Add(time.Hour),
				SignatureAlgorithm: x509.SHA256WithRSA,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			listenErr := errors.New("stop before listen")
			called := false
			_, err = NewListener(NewListenerReq{
				CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
				KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
				ListenPacket: func(string, string) (net.PacketConn, error) {
					called = true
					return nil, listenErr
				},
				WireSecret:   bytes.Repeat([]byte{0x24}, minimumWireSecretSize),
				WireIdentity: testWireIdentity,
			})
			if bits < 2048 {
				if called || err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
					t.Fatalf("weak RSA certificate: listen called=%v, err=%v", called, err)
				}
			} else if !called || !errors.Is(err, listenErr) {
				t.Fatalf("RSA-2048 certificate rejected: listen called=%v, err=%v", called, err)
			}
		})
	}
}

func TestNewListenerCAKeyStrength(t *testing.T) {
	certificate, _ := newHandshakeTestCertificate(t)
	serverKey := certificate.PrivateKey.(crypto.Signer)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	rsaKeys := make(map[int]crypto.Signer)
	for _, bits := range []int{1024, 2047, 2048} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		rsaKeys[bits] = key
	}
	const weakRSA = "TalariaUDP CA RSA key must be at least 2048 bits"
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
		{name: "malformed intermediate", intermediate: rsaKeys[2048], root: rsaKeys[2048], malformed: true, wantErr: "TalariaUDP CA certificate is invalid"},
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
			var certPEM bytes.Buffer
			for _, der := range chain {
				certPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			}
			listenErr := errors.New("stop before listen")
			called := false
			_, err := NewListener(NewListenerReq{
				CertPEM: certPEM.String(),
				KeyPEM:  keyPEM,
				ListenPacket: func(string, string) (net.PacketConn, error) {
					called = true
					return nil, listenErr
				},
				WireSecret:   bytes.Repeat([]byte{0x24}, minimumWireSecretSize),
				WireIdentity: testWireIdentity,
			})
			if tt.wantErr != "" {
				if called || err == nil || err.Error() != tt.wantErr {
					t.Fatalf("listen called=%v, err=%v; want %q before listen", called, err, tt.wantErr)
				}
			} else if !called || !errors.Is(err, listenErr) {
				t.Fatalf("valid CA chain rejected: listen called=%v, err=%v", called, err)
			}
		})
	}
}

func TestServerCertificateCallbackContainsPanic(t *testing.T) {
	cfg := serverTLSConfigWithCertificate(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		panic("certificate panic")
	})
	if cert, err := cfg.GetCertificate(nil); cert != nil || !errors.Is(err, extension.ErrPanic) {
		t.Fatalf("certificate result = %v, %v; want extension panic", cert, err)
	}
}

func TestServerTLSConfigDisablesAES128GCM(t *testing.T) {
	certificate, _ := newHandshakeTestCertificate(t)
	cfg := serverTLSConfigWithCertificate(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate, nil })
	hello := &tls.ClientHelloInfo{CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
	}}
	if _, err := cfg.GetConfigForClient(hello); err != nil {
		t.Fatal(err)
	}
	if hello.CipherSuites[0] == tls.TLS_AES_128_GCM_SHA256 || hello.CipherSuites[1] != tls.TLS_AES_256_GCM_SHA384 {
		t.Fatalf("server TLS cipher suites = %x", hello.CipherSuites)
	}
}

func TestListenerCloseDrainsUnacceptedConnections(t *testing.T) {
	first := &scriptedBatchConn{}
	second := &scriptedBatchConn{}
	l := &Listener{acceptResults: make(chan udptlsAcceptResult, 3)}
	l.acceptResults <- udptlsAcceptResult{conn: first}
	l.acceptResults <- udptlsAcceptResult{err: errors.New("synthetic accept failure")}
	l.acceptResults <- udptlsAcceptResult{conn: second}

	l.closePendingAcceptResults()

	if len(l.acceptResults) != 0 {
		t.Fatalf("pending accept results = %d, want 0", len(l.acceptResults))
	}
	for i, conn := range []*scriptedBatchConn{first, second} {
		conn.mu.Lock()
		closed := conn.closed
		conn.mu.Unlock()
		if !closed {
			t.Fatalf("unaccepted connection %d was not closed", i)
		}
	}
}

func TestPostHandshakeDeadlineResetFailureReleasesPendingPackets(t *testing.T) {
	want := errors.New("synthetic post-handshake deadline reset failure")
	inner := &deadlineResetFailureBatchConn{err: want}
	pending := []udptlsEncryptedPacket{{buf: make([]byte, 32), n: 32, reserved: 32}}

	err := resetPostHandshakeDeadline(inner, pending)
	if !errors.Is(err, want) {
		t.Fatalf("deadline reset error = %v, want %v", err, want)
	}
	if inner.released != 32 {
		t.Fatalf("released bytes = %d, want 32", inner.released)
	}
	if pending[0].buf != nil || pending[0].reserved != 0 {
		t.Fatal("pending packet retained after deadline reset failed")
	}
}

type deadlineResetFailureBatchConn struct {
	scriptedBatchConn
	err      error
	released int64
}

func (c *deadlineResetFailureBatchConn) SetDeadline(time.Time) error { return c.err }
func (*deadlineResetFailureBatchConn) ReserveQueuedBytes(int64) bool { return true }
func (c *deadlineResetFailureBatchConn) ReleaseQueuedBytes(n int64)  { c.released += n }

func TestClientTLSConfigRejectsUnsafeOrIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *tls.Config
	}{
		{name: "missing config"},
		{name: "missing server name", cfg: &tls.Config{RootCAs: x509.NewCertPool()}},
		{name: "missing trust roots", cfg: &tls.Config{ServerName: "vpn.example"}},
		{name: "disabled verification", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}},
		{name: "Rand", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), Rand: strings.NewReader("")}},
		{name: "Time", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), Time: time.Now}},
		{name: "KeyLogWriter", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), KeyLogWriter: &bytes.Buffer{}}},
		{name: "maximum version below TLS 1.3", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), MaxVersion: tls.VersionTLS12}},
		{name: "minimum version above TLS 1.3", cfg: &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13 + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newClientTLSConfig(NewDialerReq{TLSConfig: tt.cfg}); err == nil {
				t.Fatal("client TLS config was accepted")
			}
		})
	}
}

func TestClientTLSConfigPreservesVerificationAndPinsTLS13(t *testing.T) {
	roots := x509.NewCertPool()
	errPeerRejected := errors.New("synthetic peer rejection")
	errMutatedPeerRejected := errors.New("mutated peer rejection")
	errConnectionRejected := errors.New("synthetic connection rejection")
	input := &tls.Config{
		ServerName: " vpn.example ",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"caller-protocol"},
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			return errPeerRejected
		},
		VerifyConnection: func(tls.ConnectionState) error {
			return errConnectionRejected
		},
	}
	cfg, err := newClientTLSConfig(NewDialerReq{TLSConfig: input})
	if err != nil {
		t.Fatal(err)
	}
	if cfg == input {
		t.Fatal("caller TLS config was not cloned")
	}
	if cfg.ServerName != "vpn.example" || cfg.RootCAs == roots {
		t.Fatalf("unexpected identity snapshot: server=%q roots_cloned=%v", cfg.ServerName, cfg.RootCAs != roots)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("client TLS verification is disabled")
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS versions = %x..%x", cfg.MinVersion, cfg.MaxVersion)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("TLS session tickets are enabled")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != TunnelTLSALPN {
		t.Fatalf("TalariaUDP ALPN = %v", cfg.NextProtos)
	}
	roots.AddCert(&x509.Certificate{Raw: []byte{1}, RawSubject: []byte("late root")})
	if len(cfg.RootCAs.Subjects()) != 0 {
		t.Fatal("caller trust-pool mutation reached TLS snapshot")
	}
	input.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
		return errMutatedPeerRejected
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); !errors.Is(err, errPeerRejected) {
		t.Fatalf("VerifyPeerCertificate error = %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, errConnectionRejected) {
		t.Fatalf("VerifyConnection error = %v", err)
	}
	if input.ServerName != " vpn.example " || input.MinVersion != tls.VersionTLS12 || input.NextProtos[0] != "caller-protocol" {
		t.Fatal("caller TLS config was mutated")
	}
}

func TestValidateNegotiatedProtocol(t *testing.T) {
	if err := validateNegotiatedProtocol(tls.ConnectionState{NegotiatedProtocol: TunnelTLSALPN}); err != nil {
		t.Fatalf("expected TalariaUDP ALPN was rejected: %v", err)
	}
	for _, negotiated := range []string{"", "h2", "acme-tls/1", "example.invalid/1"} {
		if err := validateNegotiatedProtocol(tls.ConnectionState{NegotiatedProtocol: negotiated}); err == nil {
			t.Fatalf("unexpected ALPN %q was accepted", negotiated)
		}
	}
}

func TestNewDialerSnapshotsTLSConfigBeforeHandshake(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	tests := []struct {
		name          string
		mutate        func(*tls.Config)
		unexpectedErr string
	}{
		{name: "server name", mutate: func(cfg *tls.Config) { cfg.ServerName = "" }, unexpectedErr: "server_name"},
		{name: "trust roots", mutate: func(cfg *tls.Config) { cfg.RootCAs = nil }, unexpectedErr: "root_ca_pool"},
		{name: "verification", mutate: func(cfg *tls.Config) { cfg.InsecureSkipVerify = true }, unexpectedErr: "verification cannot be disabled"},
		{name: "TLS version", mutate: func(cfg *tls.Config) { cfg.MaxVersion = tls.VersionTLS12 }, unexpectedErr: "max TLS version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &tls.Config{ServerName: "vpn.example", RootCAs: x509.NewCertPool()}
			dialer := NewDialer(NewDialerReq{
				ParentDial: func(string, string) (net.Conn, error) {
					return net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
				},
				ParentDialTimeout:           25 * time.Millisecond,
				ParentDialAlreadyHasTimeout: true,
				TLSConfig:                   cfg,
				WireSecret:                  bytes.Repeat([]byte{0x35}, minimumWireSecretSize),
				WireIdentity:                testWireIdentity,
			})
			tt.mutate(cfg)
			conn, err := dialer("udp", serverConn.LocalAddr().String())
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("dial unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), tt.unexpectedErr) {
				t.Fatalf("dial used mutated TLS config: %v", err)
			}
		})
	}
}

func TestSecureWireProfileTransfersMaximumPacket(t *testing.T) {
	certificate, roots := newHandshakeTestCertificate(t)
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	secret := []byte("0123456789abcdef0123456789abcdef")
	listener, err := NewListener(NewListenerReq{
		ListenAddr:   "127.0.0.1:0",
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		WireSecret:   secret,
		WireIdentity: testWireIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		accepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()
	dialer := NewDialer(NewDialerReq{
		ParentDial: func(string, string) (net.Conn, error) {
			return net.Dial("udp", listener.Addr().String())
		},
		ParentDialTimeout:           5 * time.Second,
		ParentDialAlreadyHasTimeout: true,
		Closer:                      lifecycle.NewCloser(),
		TLSConfig: &tls.Config{
			ServerName: "example.com",
			RootCAs:    roots,
		},
		WireSecret:   secret,
		WireIdentity: testWireIdentity,
	})
	clientConn, err := dialer("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.conn.Close()

	want := bytes.Repeat([]byte{0x5a}, defaultMaxPlainPacket)
	if _, err := clientConn.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := result.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	n, err := result.conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("secure payload = %q, want %q", got[:n], want)
	}
}
