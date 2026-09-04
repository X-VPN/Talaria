// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/X-VPN/Talaria/internal/extension"
	"github.com/X-VPN/Talaria/internal/ippacket"
	coretransport "github.com/X-VPN/Talaria/transport"
)

var errTargetBlocked = errors.New("Talaria server: target is blocked by policy")

// referenceMetadataPrefixes are cloud instance-metadata endpoints. They are the
// classic server-side request forgery target: a VPN exit reaches them from
// inside the host's network, and they hand out instance credentials, IAM or RAM
// role tokens, and user-data to anything that can send them an HTTP request. A
// tunnel that forwarded a client packet to one of these would let that client
// read the server's own cloud credentials.
//
// They are listed explicitly rather than left to the generic rules because the
// generic rules do not reliably cover them:
//
//   - 169.254.169.254 is the de-facto standard used by AWS, GCP, Azure, Oracle
//     and OpenStack. It is link-local, so IsLinkLocalUnicast already catches it;
//     it is repeated here so the intent survives a change to those checks.
//   - 100.100.100.200 is Alibaba Cloud ECS. It sits in RFC 6598 shared address
//     space, not in link-local or RFC 1918, so it is only covered by the private
//     address rule - and that rule is switched off whenever a deployment sets
//     AllowPrivateTargets to reach its own LAN. This entry is what keeps it
//     blocked in that configuration.
//   - 168.63.129.16 is the Azure host agent endpoint. It is inside a
//     Microsoft-owned public range, so no generic rule reaches it at all and
//     only this entry blocks it.
//   - fd00:ec2::254 is the AWS IPv6 metadata endpoint. It is inside the ULA
//     range, so like the Alibaba entry it is only otherwise covered while
//     private targets are denied.
var referenceMetadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

var referenceNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// referenceSharedAddressPrefixes are private-use ranges that netip.Addr.IsPrivate
// does not report. IsPrivate already covers RFC 1918 and the fc00::/7 ULA range.
var referenceSharedAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // RFC 6598 carrier-grade NAT space
}

// referenceNonPublicPrefixes follows the IANA IPv4 and IPv6 special-purpose
// registries. Private ranges are handled separately so AllowPrivateTargets can
// opt into them without also allowing documentation, benchmarking, reserved,
// transition, or discard-only space.
var referenceNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

// These globally reachable assignments sit inside broader IANA protocol
// blocks which are otherwise not globally reachable.
var referencePublicSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.9/32"),
	netip.MustParsePrefix("192.0.0.10/32"),
	netip.MustParsePrefix("2001:1::1/128"),
	netip.MustParsePrefix("2001:1::2/128"),
	netip.MustParsePrefix("2001:1::3/128"),
	netip.MustParsePrefix("2001:3::/32"),
	netip.MustParsePrefix("2001:4:112::/48"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:30::/28"),
}

// This list includes the NAT64 well-known prefix. Inside 2000::/3, IANA
// reserves every unlisted prefix for future allocation.
var referenceAllocatedIPv6Prefixes = []netip.Prefix{
	referenceNAT64Prefix,
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:200::/23"),
	netip.MustParsePrefix("2001:400::/23"),
	netip.MustParsePrefix("2001:600::/23"),
	netip.MustParsePrefix("2001:800::/22"),
	netip.MustParsePrefix("2001:c00::/23"),
	netip.MustParsePrefix("2001:e00::/23"),
	netip.MustParsePrefix("2001:1200::/23"),
	netip.MustParsePrefix("2001:1400::/22"),
	netip.MustParsePrefix("2001:1800::/23"),
	netip.MustParsePrefix("2001:1a00::/23"),
	netip.MustParsePrefix("2001:1c00::/22"),
	netip.MustParsePrefix("2001:2000::/19"),
	netip.MustParsePrefix("2001:4000::/23"),
	netip.MustParsePrefix("2001:4200::/23"),
	netip.MustParsePrefix("2001:4400::/23"),
	netip.MustParsePrefix("2001:4600::/23"),
	netip.MustParsePrefix("2001:4800::/23"),
	netip.MustParsePrefix("2001:4a00::/23"),
	netip.MustParsePrefix("2001:4c00::/23"),
	netip.MustParsePrefix("2001:5000::/20"),
	netip.MustParsePrefix("2001:8000::/19"),
	netip.MustParsePrefix("2001:a000::/20"),
	netip.MustParsePrefix("2001:b000::/20"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2003::/18"),
	netip.MustParsePrefix("2400::/12"),
	netip.MustParsePrefix("2410::/12"),
	netip.MustParsePrefix("2600::/12"),
	netip.MustParsePrefix("2610::/23"),
	netip.MustParsePrefix("2620::/23"),
	netip.MustParsePrefix("2630::/12"),
	netip.MustParsePrefix("2800::/12"),
	netip.MustParsePrefix("2a00::/12"),
	netip.MustParsePrefix("2a10::/12"),
	netip.MustParsePrefix("2c00::/12"),
}

type ReferenceTargetPolicyConfig struct {
	// ProtectedPrefixes identifies deployment-specific control planes,
	// management networks, and other destinations the VPN must not reach.
	ProtectedPrefixes []netip.Prefix
	NAT64Prefixes     []netip.Prefix
	// AllowLocalInterfaceTargets permits access to addresses assigned directly
	// to the Talaria server. It is false by default.
	AllowLocalInterfaceTargets bool
	AllowNativeIPv6            bool
	// AllowPrivateTargets permits RFC 1918, RFC 6598 and IPv6 ULA destinations.
	// It is false by default, so an authenticated client cannot reach the
	// server's own LAN or VPC through the tunnel. Deployments that intentionally
	// offer private-network access must opt in.
	AllowPrivateTargets bool
}

type referenceTargetPolicy struct {
	protected       []netip.Prefix
	nat64           []netip.Prefix
	nat64Configured bool
	allowLocal      bool
	allowPrivate    bool
	allowNativeIPv6 bool

	discoverLocalAddresses func() (map[netip.Addr]struct{}, error)
}

// ReferenceTargetPolicy allows public unicast destinations while rejecting
// addresses that should not be reachable through a general VPN exit, including
// the server's own private networks. Set
// ReferenceTargetPolicyConfig.AllowPrivateTargets to permit private
// destinations.
func ReferenceTargetPolicy() TargetPolicy {
	policy, _ := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{})
	return policy
}

func NewReferenceTargetPolicy(cfg ReferenceTargetPolicyConfig) (TargetPolicy, error) {
	if cfg.AllowNativeIPv6 && cfg.NAT64Prefixes == nil {
		return nil, errors.New("Talaria server: native IPv6 requires an explicit NAT64 prefix declaration")
	}
	protected := make([]netip.Prefix, 0, len(referenceMetadataPrefixes)+len(cfg.ProtectedPrefixes))
	for _, prefix := range append(referenceMetadataPrefixes, cfg.ProtectedPrefixes...) {
		if normalized, ok := normalizeTargetPrefix(prefix); ok {
			protected = append(protected, normalized)
		} else {
			return nil, fmt.Errorf("Talaria server: invalid protected target prefix %v", prefix)
		}
	}
	nat64 := []netip.Prefix{referenceNAT64Prefix}
	for _, prefix := range cfg.NAT64Prefixes {
		normalized, ok := normalizeNAT64Prefix(prefix)
		if !ok {
			return nil, fmt.Errorf("Talaria server: invalid NAT64 prefix %v", prefix)
		}
		duplicate := false
		for _, existing := range nat64 {
			if existing == normalized {
				duplicate = true
				break
			}
			if existing.Contains(normalized.Addr()) || normalized.Contains(existing.Addr()) {
				return nil, fmt.Errorf("Talaria server: overlapping NAT64 prefixes %v and %v", existing, normalized)
			}
		}
		if !duplicate {
			nat64 = append(nat64, normalized)
		}
	}
	return &referenceTargetPolicy{
		protected:              protected,
		nat64:                  nat64,
		nat64Configured:        cfg.NAT64Prefixes != nil,
		discoverLocalAddresses: localInterfaceAddresses,
		allowLocal:             cfg.AllowLocalInterfaceTargets,
		allowPrivate:           cfg.AllowPrivateTargets,
		allowNativeIPv6:        cfg.AllowNativeIPv6,
	}, nil
}

func (p *referenceTargetPolicy) ValidateTarget(_ context.Context, req TargetPolicyRequest) error {
	if req.IP.Zone() != "" {
		return errTargetBlocked
	}
	ip := req.IP.Unmap()
	targets := [2]netip.Addr{ip}
	targetCount := 1
	translated := false
	if ip.Is6() {
		if !p.nat64Configured {
			return fmt.Errorf("%w: IPv6 target semantics are not configured", errTargetBlocked)
		}
		for _, prefix := range p.nat64 {
			if !prefix.Contains(ip) {
				continue
			}
			embedded, ok := nat64EmbeddedIPv4(ip, prefix)
			if !ok {
				return fmt.Errorf("%w: malformed NAT64 destination %s", errTargetBlocked, ip)
			}
			targets[targetCount] = embedded
			targetCount++
			translated = true
			break
		}
		if !translated && !p.allowNativeIPv6 {
			return fmt.Errorf("%w: native IPv6 targets are not allowed", errTargetBlocked)
		}
	}
	for i, target := range targets[:targetCount] {
		if !target.IsValid() || target.IsUnspecified() || target.IsLoopback() ||
			target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast() || target.IsMulticast() ||
			target == netip.MustParseAddr("255.255.255.255") {
			return errTargetBlocked
		}
		for _, prefix := range p.protected {
			if prefix.Contains(target) {
				return errTargetBlocked
			}
		}
		if !translated || i != 0 {
			if !p.allowPrivate && isSharedAddressSpace(target) {
				return fmt.Errorf("%w: private destination %s is not allowed", errTargetBlocked, target)
			}
			if isNonPublicSpecialAddress(target) {
				return fmt.Errorf("%w: special-purpose destination %s is not allowed", errTargetBlocked, target)
			}
			if target.Is6() && !target.IsPrivate() && !isAllocatedIPv6Address(target) {
				return fmt.Errorf("%w: unallocated destination %s is not allowed", errTargetBlocked, target)
			}
		}
	}
	if !p.allowLocal {
		localAddresses, err := p.discoverLocalAddresses()
		if err != nil {
			return fmt.Errorf("%w: discover local interface addresses: %v", errTargetBlocked, err)
		}
		for _, target := range targets[:targetCount] {
			if _, local := localAddresses[target]; local {
				return errTargetBlocked
			}
		}
	}
	return nil
}

func isReferenceTargetPolicy(policy TargetPolicy) bool {
	value, ok := policy.(*referenceTargetPolicy)
	return ok && value != nil
}

func nat64EmbeddedIPv4(ip netip.Addr, prefix netip.Prefix) (netip.Addr, bool) {
	if !ip.Is6() || !prefix.Contains(ip) {
		return netip.Addr{}, false
	}
	switch prefix.Bits() {
	case 32, 40, 48, 56, 64:
	case 96:
		raw := ip.As16()
		return netip.AddrFrom4([4]byte(raw[12:])), true
	default:
		return netip.Addr{}, false
	}
	raw := ip.As16()
	prefixBytes := prefix.Bits() / 8
	beforeU := 8 - prefixBytes
	if raw[8] != 0 {
		return netip.Addr{}, false
	}
	var embedded [4]byte
	copy(embedded[:beforeU], raw[prefixBytes:8])
	afterU := 4 - beforeU
	copy(embedded[beforeU:], raw[9:9+afterU])
	for _, value := range raw[9+afterU:] {
		if value != 0 {
			return netip.Addr{}, false
		}
	}
	return netip.AddrFrom4(embedded), true
}

func isAllocatedIPv6Address(ip netip.Addr) bool {
	for _, prefix := range referenceAllocatedIPv6Prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func isNonPublicSpecialAddress(ip netip.Addr) bool {
	for _, prefix := range referencePublicSpecialPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	for _, prefix := range referenceNonPublicPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// isSharedAddressSpace reports whether ip belongs to a private-use or
// carrier-shared range that a general VPN exit should not reach by default.
func isSharedAddressSpace(ip netip.Addr) bool {
	if ip.IsPrivate() {
		return true
	}
	for _, prefix := range referenceSharedAddressPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeTargetPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, false
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), true
}

func normalizeNAT64Prefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return netip.Prefix{}, false
	}
	prefix = prefix.Masked()
	if !prefix.Addr().IsGlobalUnicast() {
		return netip.Prefix{}, false
	}
	switch prefix.Bits() {
	case 32, 40, 48, 56, 64, 96:
		return prefix, true
	default:
		return netip.Prefix{}, false
	}
}

func localInterfaceAddresses() (map[netip.Addr]struct{}, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			host, _, splitErr := net.SplitHostPort(address.String())
			if splitErr == nil {
				ip = net.ParseIP(host)
			}
		}
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			local[addr.Unmap()] = struct{}{}
		}
	}
	return local, nil
}

func (s *Server) resolveStreamTarget(ctx context.Context, session SessionContext, target coretransport.Destination, local net.Addr) ([]netip.Addr, error) {
	host := strings.TrimSuffix(strings.TrimSpace(target.Host), ".")
	if host == "" {
		return nil, errors.New("Talaria server: target host is empty")
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip.Unmap()}
	} else {
		var resolved []netip.Addr
		var err error
		if s.boundedOutbound {
			resolved, err = s.lookupIP(ctx, "ip", host)
			if err == nil {
				err = ctx.Err()
			}
		} else {
			resolved, err = callBoundedExtension(ctx, s.outboundSlots, s.resources, session.ClientID, "Talaria target resolver", func() ([]netip.Addr, error) {
				return s.lookupIP(ctx, "ip", host)
			}, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("Talaria server: resolve target: %w", err)
		}
		addresses = uniqueResolvedIPs(resolved)
	}
	if len(addresses) == 0 {
		return nil, errors.New("Talaria server: target resolved to no addresses")
	}
	for _, ip := range addresses {
		request := TargetPolicyRequest{
			Session: session,
			Network: target.Network,
			Host:    target.Host,
			Port:    target.Port,
			IP:      ip,
		}
		var err error
		if s.boundedOutbound {
			err = s.policy.ValidateTarget(ctx, request)
			if err == nil {
				err = ctx.Err()
			}
		} else {
			_, err = callBoundedExtension(ctx, s.outboundSlots, s.resources, session.ClientID, "Talaria target policy", func() (struct{}, error) {
				return struct{}{}, s.policy.ValidateTarget(ctx, request)
			}, nil)
		}
		if err != nil {
			return nil, err
		}
		if s.isOwnTransportIP(ip, target.Port, local) {
			return nil, errors.New("stream target resolves to the Talaria transport listener")
		}
	}
	return addresses, nil
}

func (s *Server) validateBuiltinRawIPTarget(ctx context.Context, session SessionContext, raw []byte) error {
	if s == nil {
		return errTargetBlocked
	}
	if _, ok := s.handler.(*TunPacketHandler); !ok {
		return nil
	}
	if extension.IsNil(s.policy) {
		return errTargetBlocked
	}
	packet, err := ippacket.ParseIPPacket(raw)
	if err != nil || !packet.IsIPv4() {
		return nil
	}
	network := coretransport.NetworkIP
	port := uint16(0)
	if packet.IsTCP() {
		network = coretransport.NetworkTCP
		port = packet.DstPort()
	} else if packet.IsUDP() {
		network = coretransport.NetworkUDP
		port = packet.DstPort()
	}
	request := TargetPolicyRequest{
		Session: session,
		Network: network,
		Host:    packet.DstAddr().String(),
		Port:    port,
		IP:      packet.DstAddr(),
	}
	if s.boundedOutbound {
		err = s.policy.ValidateTarget(ctx, request)
		if err == nil {
			err = ctx.Err()
		}
	} else {
		_, err = callBoundedExtension(ctx, s.outboundSlots, s.resources, session.ClientID, "Talaria raw target policy", func() (struct{}, error) {
			return struct{}{}, s.policy.ValidateTarget(ctx, request)
		}, nil)
	}
	if err != nil {
		return err
	}
	if !s.getActiveSessions().isCurrent(session.Ref()) {
		return net.ErrClosed
	}
	return nil
}

func uniqueResolvedIPs(addresses []netip.Addr) []netip.Addr {
	unique := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	return unique
}

func (s *Server) dialResolvedTarget(ctx context.Context, clientID uint64, target coretransport.Destination, addresses []netip.Addr) (net.Conn, error) {
	var dialErr error
	for _, ip := range addresses {
		address := net.JoinHostPort(ip.String(), strconv.Itoa(int(target.Port)))
		var conn net.Conn
		var err error
		if s.boundedOutbound {
			conn, err = s.dial(ctx, string(target.Network), address)
			if ctxErr := ctx.Err(); ctxErr != nil {
				if !extension.IsNil(conn) {
					_ = extension.Do("Talaria server expired outbound connection close", conn.Close)
				}
				return nil, ctxErr
			}
			if err != nil && !extension.IsNil(conn) {
				_ = extension.Do("Talaria server failed outbound connection close", conn.Close)
				conn = nil
			}
		} else {
			conn, err = callBoundedExtension(ctx, s.outboundSlots, s.resources, clientID, "Talaria server outbound dialer", func() (net.Conn, error) {
				return s.dial(ctx, string(target.Network), address)
			}, func(conn net.Conn) {
				if !extension.IsNil(conn) {
					_ = conn.Close()
				}
			})
		}
		if err == nil {
			if !extension.IsNil(conn) {
				return conn, nil
			}
			err = errors.New("Talaria server: outbound dial returned a nil connection")
		}
		dialErr = errors.Join(dialErr, err)
		if ctx.Err() != nil {
			break
		}
	}
	if dialErr == nil {
		dialErr = errors.New("Talaria server: target has no dialable address")
	}
	return nil, dialErr
}

func (s *Server) isOwnTransportIP(targetIP netip.Addr, targetPort uint16, local net.Addr) bool {
	if int(targetPort) != addrPortString(s.addr) {
		return false
	}
	targetIP = targetIP.Unmap()
	if localIP, ok := addrIP(local); ok && targetIP == localIP {
		return true
	}
	listenerHost, _, err := net.SplitHostPort(s.addr)
	if err != nil {
		return false
	}
	listenerIP, err := netip.ParseAddr(strings.TrimSpace(listenerHost))
	if err != nil {
		return false
	}
	listenerIP = listenerIP.Unmap()
	if !listenerIP.IsUnspecified() {
		return targetIP == listenerIP
	}
	if targetIP.IsLoopback() {
		return true
	}
	discoverInterfaces := net.InterfaceAddrs
	if s.interfaceAddrs != nil {
		discoverInterfaces = s.interfaceAddrs
	}
	interfaces, err := discoverInterfaces()
	if err != nil || len(interfaces) == 0 {
		return true
	}
	for _, address := range interfaces {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && targetIP == prefix.Addr().Unmap() {
			return true
		}
	}
	return false
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(addrString(addr))
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
