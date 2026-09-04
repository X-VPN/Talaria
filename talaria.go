// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package talaria provides high-level client and server entry points for the
// Talaria VPN library.
package talaria

import (
	"context"

	"github.com/X-VPN/Talaria/client"
	"github.com/X-VPN/Talaria/client/dataplane"
	clientdefaults "github.com/X-VPN/Talaria/client/defaults"
	talariaserver "github.com/X-VPN/Talaria/server"
	coretransport "github.com/X-VPN/Talaria/transport"
)

type Config = client.Config
type Protocol = client.Protocol
type Session = client.Session
type TunProvider = client.TunProvider

type ClientOptions = clientdefaults.ClientOptions
type ServerConfig = talariaserver.Config
type Server = talariaserver.Server
type SessionRef = coretransport.SessionRef
type SessionController = talariaserver.SessionController
type ResourceLimits = talariaserver.ResourceLimits
type TalariaTCPAdmissionLimits = talariaserver.TalariaTCPAdmissionLimits
type TalariaUDPAdmissionLimits = talariaserver.TalariaUDPAdmissionLimits

const (
	ProtocolTalariaUDP = client.ProtocolTalariaUDP
	ProtocolTalariaTCP = client.ProtocolTalariaTCP

	DefaultMTU = dataplane.DefaultMTU
)

// ParseProtocol returns the exact supported protocol, with an empty value selecting TalariaUDP.
func ParseProtocol(value string) (Protocol, error) {
	return client.ParseProtocol(value)
}

func NewClient(cfg Config, tun TunProvider, opt ClientOptions) (Session, error) {
	return clientdefaults.NewSession(cfg, tun, opt)
}

func Run(ctx context.Context, cfg Config, tun TunProvider, opt ClientOptions) (Session, error) {
	sess, err := NewClient(cfg, tun, opt)
	if err != nil {
		return nil, err
	}
	if err := sess.Start(ctx); err != nil {
		_ = sess.Close()
		return nil, err
	}
	return sess, nil
}

func StartServer(ctx context.Context, cfg ServerConfig) (*Server, error) {
	return talariaserver.Start(ctx, cfg)
}
