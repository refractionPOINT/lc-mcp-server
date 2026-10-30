package cimd

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// blockedPrefixes lists address ranges that are never fetched from, on top of
// what the netip classification helpers already cover (loopback, RFC 1918 and
// RFC 4193 private, link-local, multicast, unspecified). The IPv4 entries are
// matched after IPv4-mapped IPv6 addresses are unmapped, so ::ffff:10.0.0.1 is
// judged exactly like 10.0.0.1.
//
// Every IPv6 range that embeds an IPv4 address (NAT64, IPv4-translated, 6to4,
// Teredo, IPv4-compatible) is refused as a whole rather than by inspecting the
// embedded address: a client document has no reason to live behind one, and a
// translator on the path would otherwise reach internal IPv4 space.
//
// The list follows the IANA IPv4 and IPv6 Special-Purpose Address Registries
// for everything that is not globally reachable. isGlobalIPv6Unicast is the
// positive gate that catches space the registries have not assigned yet.
var blockedPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // carrier-grade NAT (RFC 6598)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes the broadcast address
	// IPv6
	"::/96",           // unspecified, loopback and deprecated IPv4-compatible
	"::ffff:0:0:0/96", // IPv4-translated (SIIT, RFC 2765/7915): embeds an IPv4 address
	"64:ff9b::/96",    // NAT64: embeds an arbitrary IPv4 address
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001::/23",       // IETF protocol assignments, includes Teredo
	"2001:10::/28",    // deprecated ORCHID
	"2001:20::/28",    // ORCHIDv2
	"2001:30::/28",    // drone remote ID entity tags
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4: embeds an arbitrary IPv4 address
	"3fff::/20",       // documentation (RFC 9637)
	"5f00::/16",       // SRv6 SIDs
	"fc00::/7",        // unique local addresses (RFC 4193)
	"fe80::/10",       // link-local
	"fec0::/10",       // deprecated site-local
	"ff00::/8",        // multicast
)

// globalIPv6Unicast is the only IPv6 space allocated for global unicast use
// today (2000::/3). Anything outside it is refused whatever the deny-list says.
var globalIPv6Unicast = netip.MustParsePrefix("2000::/3")

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// IsForbiddenIP reports whether the metadata fetcher must refuse to connect to
// ip. The policy is a deny-list of every non-public-unicast range we know of;
// an address that is not clearly global unicast is refused.
func IsForbiddenIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	// Drop any IPv6 zone and turn ::ffff:a.b.c.d into a.b.c.d so a mapped
	// form can't dodge the IPv4 rules.
	ip = ip.WithZone("").Unmap()

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return true
	}
	if !ip.Is4() && !globalIPv6Unicast.Contains(ip) {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ssrfDialControl is a net.Dialer.Control hook. It runs after DNS resolution,
// immediately before the socket connects, on the exact address that will be
// used, so a hostname that resolves to a public address at check time and a
// private one at connect time (DNS rebinding) is still refused.
func ssrfDialControl(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp4", "tcp6":
	default:
		return fmt.Errorf("cimd: network %q not allowed", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("cimd: bad dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("cimd: dial address %q is not an IP", address)
	}
	if IsForbiddenIP(ip) {
		return fmt.Errorf("cimd: destination address %s is not allowed", ip)
	}
	return nil
}
