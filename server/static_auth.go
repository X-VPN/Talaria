// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/X-VPN/Talaria/protocol/vpnpacket"
)

const maxStaticAuthCredentials = 1 << 16
const staticAuthSecretDomain = "talaria-static-auth-secret-v1"

type StaticCredential struct {
	ClientID         string
	SecretKey        string
	AssignedClientID uint64
	Version          byte
}

type StaticAuthProvider struct {
	ClientID         string
	SecretKey        string
	AssignedClientID uint64
	Version          byte
	Credentials      []StaticCredential
}

type compiledStaticCredential struct {
	secret   [sha256.Size]byte
	clientID uint64
	version  byte
}

type compiledStaticAuthProvider struct {
	credentials map[string]compiledStaticCredential
	dummySecret [sha256.Size]byte
}

type boundedAuthProvider interface {
	AuthProvider
	boundedAuthProvider()
}

func (p StaticAuthProvider) Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error) {
	compiled, err := compileStaticAuthProvider(p)
	if err != nil {
		return AuthResult{}, err
	}
	return compiled.Authenticate(ctx, req)
}

func (p *compiledStaticAuthProvider) Authenticate(_ context.Context, req AuthRequest) (AuthResult, error) {
	if p == nil || req.Packet == nil || req.Packet.Cmd != vpnpacket.CmdAuthRequest {
		return AuthResult{}, errors.New("expected auth request")
	}
	credential, ok := p.credentials[req.ClientID]
	expected := credential.secret
	if !ok {
		expected = p.dummySecret
	}
	candidate := staticAuthSecretDigest(req.SecretKey)
	matched := subtle.ConstantTimeCompare(candidate[:], expected[:])
	clear(candidate[:])
	if !ok {
		matched = 0
	}
	if matched != 1 {
		return AuthResult{}, errors.New("auth failed")
	}
	return AuthResult{ClientID: credential.clientID, Version: credential.version}, nil
}

func (*compiledStaticAuthProvider) boundedAuthProvider() {}

func normalizeBoundedAuthProvider(provider AuthProvider) (AuthProvider, error) {
	switch value := provider.(type) {
	case StaticAuthProvider:
		return compileStaticAuthProvider(value)
	case *StaticAuthProvider:
		if value == nil {
			return nil, errors.New("Talaria server: missing auth provider")
		}
		return compileStaticAuthProvider(*value)
	default:
		return nil, errors.New("Talaria server: Auth must use StaticAuthProvider")
	}
}

func compileStaticAuthProvider(provider StaticAuthProvider) (*compiledStaticAuthProvider, error) {
	legacy := provider.ClientID != "" || provider.SecretKey != "" || provider.AssignedClientID != 0 || provider.Version != 0
	if legacy && len(provider.Credentials) != 0 {
		return nil, errors.New("Talaria server: static auth cannot mix one credential with Credentials")
	}
	credentials := provider.Credentials
	if len(credentials) == 0 {
		credentials = []StaticCredential{{
			ClientID:         provider.ClientID,
			SecretKey:        provider.SecretKey,
			AssignedClientID: provider.AssignedClientID,
			Version:          provider.Version,
		}}
	}
	if len(credentials) > maxStaticAuthCredentials {
		return nil, fmt.Errorf("Talaria server: static auth credential count exceeds %d", maxStaticAuthCredentials)
	}
	compiled := &compiledStaticAuthProvider{
		credentials: make(map[string]compiledStaticCredential, len(credentials)),
		dummySecret: staticAuthSecretDigest(""),
	}
	assigned := make(map[uint64]int, len(credentials))
	for i, credential := range credentials {
		if !validAuthCredential(credential.ClientID) || !validAuthCredential(credential.SecretKey) {
			return nil, fmt.Errorf("Talaria server: invalid static auth credential %d", i)
		}
		if _, exists := compiled.credentials[credential.ClientID]; exists {
			return nil, fmt.Errorf("Talaria server: duplicate static auth client id %q", credential.ClientID)
		}
		clientID := credential.AssignedClientID
		if clientID == 0 {
			if len(credentials) != 1 {
				return nil, fmt.Errorf("Talaria server: static auth credential %d is missing assigned client id", i)
			}
			clientID = 1
		}
		if previous, exists := assigned[clientID]; exists {
			return nil, fmt.Errorf("Talaria server: static auth credentials %d and %d have duplicate assigned client id %d", previous, i, clientID)
		}
		assigned[clientID] = i
		version := credential.Version
		if version == 0 {
			version = DefaultAuthVersion
		}
		compiled.credentials[credential.ClientID] = compiledStaticCredential{
			secret:   staticAuthSecretDigest(credential.SecretKey),
			clientID: clientID,
			version:  version,
		}
	}
	return compiled, nil
}

func staticAuthSecretDigest(secret string) [sha256.Size]byte {
	var input [len(staticAuthSecretDomain) + 8 + maxAuthCredentialBytes]byte
	copy(input[:], staticAuthSecretDomain)
	binary.BigEndian.PutUint64(input[len(staticAuthSecretDomain):], uint64(len(secret)))
	copy(input[len(staticAuthSecretDomain)+8:], secret)
	digest := sha256.Sum256(input[:])
	clear(input[:])
	return digest
}
