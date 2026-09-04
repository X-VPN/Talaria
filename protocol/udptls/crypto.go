// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// udptlsExporterLabel is the TLS 1.3 exporter label (RFC 8446 section 7.5)
	// used to derive the UDP data-channel master secret from the completed
	// handshake. The EXPORTER- prefix follows the RFC 5705 convention that keeps
	// labels from colliding with other users of the same connection.
	//
	// udptlsExporterInfo is not passed to TLS. It is the HKDF info prefix that
	// splits the exported master into per-direction keys, nonce salts, and each
	// key-update generation.
	//
	// Both values are inputs to the key schedule, so they are protocol
	// identifiers: two peers that disagree on either will complete the TLS
	// handshake and then fail to authenticate each other's datagrams.
	udptlsExporterLabel = "EXPORTER-talaria-udp"
	udptlsExporterInfo  = "talaria/udp/data"
	udptlsNonceSaltSize = 4
)

type udptlsCipherSpec struct {
	keyLen  int
	hashNew func() hash.Hash
	newAEAD func([]byte) (cipher.AEAD, error)
	// confidentialityLimit and integrityLimit are the RFC 9001 section 6.6 AEAD
	// usage bounds for this suite: the number of packets that may be encrypted
	// under one key, and the number of forged packets that may fail
	// authentication before the key must be retired.
	confidentialityLimit uint64
	integrityLimit       uint64
}

type udptlsSessionMaterial struct {
	sendKey  []byte
	recvKey  []byte
	sendSalt [udptlsNonceSaltSize]byte
	recvSalt [udptlsNonceSaltSize]byte
}

type udptlsConnectionState struct {
	version              uint16
	handshakeComplete    bool
	cipherSuite          uint16
	exportKeyingMaterial func(label string, context []byte, length int) ([]byte, error)
}

func deriveSessionMaterial(state udptlsConnectionState, mode udptlsMode) (udptlsSessionMaterial, error) {
	if !state.handshakeComplete {
		return udptlsSessionMaterial{}, fmt.Errorf("TalariaUDP tls handshake incomplete")
	}
	if state.version != 0x0304 {
		return udptlsSessionMaterial{}, fmt.Errorf("TalariaUDP requires tls 1.3, got %x", state.version)
	}
	spec, err := cipherSpecFromSuite(state.cipherSuite)
	if err != nil {
		return udptlsSessionMaterial{}, err
	}

	masterLen := spec.hashNew().Size()
	context := []byte{
		byte(handshakePacketVersion),
		byte(state.cipherSuite >> 8),
		byte(state.cipherSuite),
	}
	master, err := state.exportKeyingMaterial(udptlsExporterLabel, context, masterLen)
	if err != nil {
		return udptlsSessionMaterial{}, fmt.Errorf("TalariaUDP exporter: %w", err)
	}
	defer clear(master)

	c2sKey, err := hkdfExpand(spec.hashNew, master, udptlsExporterInfo+"/c2s-key", spec.keyLen)
	if err != nil {
		return udptlsSessionMaterial{}, err
	}
	defer clear(c2sKey)
	s2cKey, err := hkdfExpand(spec.hashNew, master, udptlsExporterInfo+"/s2c-key", spec.keyLen)
	if err != nil {
		return udptlsSessionMaterial{}, err
	}
	defer clear(s2cKey)
	c2sSalt, err := hkdfExpand(spec.hashNew, master, udptlsExporterInfo+"/c2s-salt", udptlsNonceSaltSize)
	if err != nil {
		return udptlsSessionMaterial{}, err
	}
	defer clear(c2sSalt)
	s2cSalt, err := hkdfExpand(spec.hashNew, master, udptlsExporterInfo+"/s2c-salt", udptlsNonceSaltSize)
	if err != nil {
		return udptlsSessionMaterial{}, err
	}
	defer clear(s2cSalt)

	m := udptlsSessionMaterial{}
	switch mode {
	case udptlsModeServer:
		m.sendKey = append([]byte(nil), s2cKey...)
		m.recvKey = append([]byte(nil), c2sKey...)
		copy(m.sendSalt[:], s2cSalt)
		copy(m.recvSalt[:], c2sSalt)
	default:
		m.sendKey = append([]byte(nil), c2sKey...)
		m.recvKey = append([]byte(nil), s2cKey...)
		copy(m.sendSalt[:], c2sSalt)
		copy(m.recvSalt[:], s2cSalt)
	}
	return m, nil
}

func (m udptlsSessionMaterial) newAEADPair(cipherSuite uint16) (cipher.AEAD, cipher.AEAD, error) {
	spec, err := cipherSpecFromSuite(cipherSuite)
	if err != nil {
		return nil, nil, err
	}
	sendAEAD, err := spec.newAEAD(m.sendKey)
	if err != nil {
		return nil, nil, fmt.Errorf("TalariaUDP new send aead: %w", err)
	}
	recvAEAD, err := spec.newAEAD(m.recvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("TalariaUDP new recv aead: %w", err)
	}
	return sendAEAD, recvAEAD, nil
}

func cipherSpecFromSuite(suite uint16) (udptlsCipherSpec, error) {
	switch suite {
	case tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256:
		// The TLS handshake rejects AES-128 before reaching the data plane. Keep
		// its selector fail-safe here too: it always constructs AES-256.
		return udptlsCipherSpec{
			keyLen:  32,
			hashNew: sha512.New384,
			newAEAD: func(key []byte) (cipher.AEAD, error) {
				block, err := aes.NewCipher(key)
				if err != nil {
					return nil, err
				}
				return cipher.NewGCM(block)
			},
			confidentialityLimit: 1 << 23,
			integrityLimit:       1 << 52,
		}, nil
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return udptlsCipherSpec{
			keyLen:  32,
			hashNew: sha256.New,
			newAEAD: chacha20poly1305.New,
			// RFC 9001 puts the ChaCha20-Poly1305 confidentiality limit beyond
			// the 62-bit packet number space; the shared rekey threshold applies
			// long before it.
			confidentialityLimit: 1 << 62,
			integrityLimit:       1 << 36,
		}, nil
	default:
		return udptlsCipherSpec{}, fmt.Errorf("TalariaUDP tls cipher suite unsupported: %x", suite)
	}
}

// ratchetKey derives the next epoch of a directional data key from the current
// one.
//
// Deriving each epoch from its predecessor rather than from a retained exporter
// root is deliberate. The current key is uniformly random secret material, so
// HKDF-Expand over it is a one-way PRF step: an attacker holding epoch n+1
// cannot recover epoch n, and the exporter root is discarded once epoch 0 exists,
// so there is no long-lived secret whose disclosure would expose the whole
// connection. Root-derived epochs would be cheaper to look up in any order but
// would give up that property. It is also why a receiver only ever derives one
// epoch ahead: a chain cannot be skipped forward cheaply, which is exactly the
// bound that stops a spoofed epoch from forcing work.
//
// Both directions ratchet independently and no key is ever reused, so nonce
// uniqueness holds within every epoch.
func ratchetKey(hashNew func() hash.Hash, key []byte, keyLen int) ([]byte, error) {
	return hkdfExpand(hashNew, key, udptlsExporterInfo+"/epoch", keyLen)
}

func hkdfExpand(hashNew func() hash.Hash, secret []byte, info string, size int) ([]byte, error) {
	out := make([]byte, size)
	reader := hkdf.New(hashNew, secret, nil, []byte(info))
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, fmt.Errorf("TalariaUDP hkdf expand %s: %w", info, err)
	}
	return out, nil
}
