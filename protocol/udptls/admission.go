// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package udptls

import (
	"errors"

	"github.com/X-VPN/Talaria/internal/sourceip"
)

const (
	defaultAcceptQueue                           = 256
	defaultSessionQueue                          = 4096
	sessionQueueMemoryBaseline                   = 256
	defaultMaxSessions                           = 4096
	defaultMaxSessionsPerSourceIP                = 512
	defaultMaxPendingHandshakes                  = 128
	defaultMaxPendingHandshakesPerSourceIP       = 64
	defaultMaxQueuedBytes                  int64 = 512 << 20
	baseMaxQueuedBytesPerSession           int64 = 16 << 20
	queuedBytesPerAdditionalSessionPacket  int64 = 10 << 10
	defaultMaxQueuedBytesPerSession              = baseMaxQueuedBytesPerSession + int64(defaultSessionQueue-sessionQueueMemoryBaseline)*queuedBytesPerAdditionalSessionPacket
	maxAdmissionQueue                            = 1 << 16
	maxAdmissionSessions                         = 1 << 20
	maxAdmissionHandshakes                       = 1 << 16
	maxAdmissionQueuedBytes                int64 = 8 << 30
)

// AdmissionLimits bounds unauthenticated UDP sessions, TLS handshakes, and
// retained receive buffers. Zero values select finite production defaults.
type AdmissionLimits struct {
	AcceptQueue                     int
	SessionQueue                    int
	MaxSessions                     int
	MaxSessionsPerSourceIP          int
	MaxPendingHandshakes            int
	MaxPendingHandshakesPerSourceIP int
	MaxQueuedBytes                  int64
	MaxQueuedBytesPerSourceIP       int64
	MaxQueuedBytesPerSession        int64
	IPv6SourcePrefixBits            int
}

func normalizeAdmissionLimits(limits AdmissionLimits, legacyQueue int) (AdmissionLimits, error) {
	if legacyQueue < 0 || limits.AcceptQueue < 0 || limits.SessionQueue < 0 {
		return AdmissionLimits{}, errors.New("TalariaUDP: queue limits cannot be negative")
	}
	if limits.MaxSessions < 0 || limits.MaxSessionsPerSourceIP < 0 || limits.MaxPendingHandshakes < 0 ||
		limits.MaxPendingHandshakesPerSourceIP < 0 {
		return AdmissionLimits{}, errors.New("TalariaUDP: admission limits cannot be negative")
	}
	if limits.MaxQueuedBytes < 0 || limits.MaxQueuedBytesPerSourceIP < 0 || limits.MaxQueuedBytesPerSession < 0 {
		return AdmissionLimits{}, errors.New("TalariaUDP: queued byte limits cannot be negative")
	}
	var err error
	limits.IPv6SourcePrefixBits, err = sourceip.NormalizePrefixBits(limits.IPv6SourcePrefixBits)
	if err != nil {
		return AdmissionLimits{}, err
	}
	if limits.AcceptQueue > maxAdmissionQueue || limits.SessionQueue > maxAdmissionQueue {
		return AdmissionLimits{}, errors.New("TalariaUDP: queue limit is too large")
	}
	if limits.MaxSessions > maxAdmissionSessions || limits.MaxSessionsPerSourceIP > maxAdmissionSessions {
		return AdmissionLimits{}, errors.New("TalariaUDP: session limit is too large")
	}
	if limits.MaxPendingHandshakes > maxAdmissionHandshakes ||
		limits.MaxPendingHandshakesPerSourceIP > maxAdmissionHandshakes {
		return AdmissionLimits{}, errors.New("TalariaUDP: pending handshake limit is too large")
	}
	if limits.MaxQueuedBytes > maxAdmissionQueuedBytes || limits.MaxQueuedBytesPerSourceIP > maxAdmissionQueuedBytes || limits.MaxQueuedBytesPerSession > maxAdmissionQueuedBytes {
		return AdmissionLimits{}, errors.New("TalariaUDP: queued byte limit is too large")
	}
	if limits.AcceptQueue == 0 {
		limits.AcceptQueue = legacyQueue
		if limits.AcceptQueue == 0 {
			limits.AcceptQueue = defaultAcceptQueue
		}
	}
	if limits.SessionQueue == 0 {
		limits.SessionQueue = legacyQueue
		if limits.SessionQueue == 0 {
			limits.SessionQueue = defaultSessionQueue
		}
	}
	if limits.MaxSessions == 0 {
		limits.MaxSessions = defaultMaxSessions
	}
	if limits.MaxSessionsPerSourceIP == 0 {
		limits.MaxSessionsPerSourceIP = min(defaultMaxSessionsPerSourceIP, limits.MaxSessions/2)
	}
	if limits.MaxSessionsPerSourceIP == 0 || limits.MaxSessionsPerSourceIP >= limits.MaxSessions {
		return AdmissionLimits{}, errors.New("TalariaUDP: source session limit must be less than global limit")
	}
	if limits.MaxPendingHandshakes == 0 {
		limits.MaxPendingHandshakes = min(defaultMaxPendingHandshakes, limits.MaxSessions)
	}
	if limits.MaxPendingHandshakesPerSourceIP == 0 {
		limits.MaxPendingHandshakesPerSourceIP = min(
			defaultMaxPendingHandshakesPerSourceIP,
			limits.MaxPendingHandshakes/2,
			limits.MaxSessionsPerSourceIP,
		)
	}
	if limits.MaxPendingHandshakesPerSourceIP == 0 ||
		limits.MaxPendingHandshakesPerSourceIP >= limits.MaxPendingHandshakes {
		return AdmissionLimits{}, errors.New("TalariaUDP: source pending handshake limit must be less than global limit")
	}
	if limits.MaxPendingHandshakes > limits.MaxSessions {
		return AdmissionLimits{}, errors.New("TalariaUDP: pending handshake limit cannot exceed session limit")
	}
	if limits.MaxPendingHandshakesPerSourceIP > limits.MaxSessionsPerSourceIP {
		return AdmissionLimits{}, errors.New("TalariaUDP: source pending handshake limit cannot exceed source session limit")
	}
	if limits.MaxQueuedBytes == 0 {
		limits.MaxQueuedBytes = defaultMaxQueuedBytes
	}
	if limits.MaxQueuedBytesPerSourceIP == 0 {
		limits.MaxQueuedBytesPerSourceIP = limits.MaxQueuedBytes / 2
	}
	if limits.MaxQueuedBytesPerSourceIP == 0 || limits.MaxQueuedBytesPerSourceIP >= limits.MaxQueuedBytes {
		return AdmissionLimits{}, errors.New("TalariaUDP: source queued byte limit must be less than global limit")
	}
	if limits.MaxQueuedBytesPerSession == 0 {
		limits.MaxQueuedBytesPerSession = min(baseMaxQueuedBytesPerSession, limits.MaxQueuedBytes/2)
		if extra := limits.SessionQueue - sessionQueueMemoryBaseline; extra > 0 {
			limits.MaxQueuedBytesPerSession = baseMaxQueuedBytesPerSession + int64(extra)*queuedBytesPerAdditionalSessionPacket
			if limits.MaxQueuedBytesPerSession > limits.MaxQueuedBytesPerSourceIP || limits.MaxQueuedBytesPerSession >= limits.MaxQueuedBytes {
				return AdmissionLimits{}, errors.New("TalariaUDP: session queue exceeds queued byte budgets")
			}
		}
	}
	if limits.MaxQueuedBytesPerSession == 0 || limits.MaxQueuedBytesPerSession >= limits.MaxQueuedBytes {
		return AdmissionLimits{}, errors.New("TalariaUDP: session queued byte limit must be less than global limit")
	}
	return limits, nil
}
