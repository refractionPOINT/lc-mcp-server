package http

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// DefaultTrustedProxyHops is how many entries at the END of X-Forwarded-For
// were written by infrastructure we operate, which is also how far from the end
// the real client address sits.
//
// Production serves mcp.limacharlie.io as a Cloud Run domain mapping, so the
// only hop in front of the container is Google's front end. It APPENDS the
// address it accepted the connection from, so a caller sending
// `X-Forwarded-For: 1.2.3.4` arrives as `1.2.3.4, <real client>`. Reading the
// first entry (the old behaviour) let any caller pick a fresh rate-limit key per
// request. Reading the last one is unforgeable. Behind a Google external
// Application Load Balancer the LB would append its own address after the
// client's, and the value would have to be 2: set TRUSTED_PROXY_HOPS in the same
// change that puts one in front.
const DefaultTrustedProxyHops = 1

// maxTrustedProxyHops bounds the configured value; anything larger is a typo.
const maxTrustedProxyHops = 8

// trustedProxyHops is process-wide because the access-log and panic middleware
// resolve client addresses without a Server.
var trustedProxyHops atomic.Int32

func init() { trustedProxyHops.Store(DefaultTrustedProxyHops) }

// SetTrustedProxyHops sets how many trailing X-Forwarded-For entries are ours.
// Values outside [1, maxTrustedProxyHops] are ignored.
func SetTrustedProxyHops(n int) bool {
	if n < 1 || n > maxTrustedProxyHops {
		return false
	}
	trustedProxyHops.Store(int32(n))
	return true
}

// configureTrustedProxyHops applies TRUSTED_PROXY_HOPS, if set and valid.
func configureTrustedProxyHops() (int, error) {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HOPS"))
	if raw == "" {
		return int(trustedProxyHops.Load()), nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || !SetTrustedProxyHops(n) {
		return int(trustedProxyHops.Load()), fmt.Errorf("invalid TRUSTED_PROXY_HOPS %q: want an integer from 1 to %d", raw, maxTrustedProxyHops)
	}
	return n, nil
}

// ipv6KeyBits is the prefix an IPv6 client is keyed on. A single customer is
// normally routed a /64, so keying on the full address would hand one host 2^64
// rate-limit buckets.
const ipv6KeyBits = 64

// getClientIP returns the address used to key rate limits and to log the caller.
func getClientIP(r *http.Request) string {
	return clientIP(r, int(trustedProxyHops.Load()))
}

// clientIP resolves the client address from the END of X-Forwarded-For, hops
// entries from the right, counted across every header line (a caller can send
// its own lines; the trusted hop's entry is always last). X-Real-IP is ignored:
// nothing in front of this service sets it, so it is caller-controlled.
//
// When the header is absent, shorter than hops, or the selected entry is not an
// IP address, it falls back to the transport peer (RemoteAddr), never to a
// caller-supplied string. It does not allocate: it runs before the limiter
// charges the request, and the header can be most of the header budget.
func clientIP(r *http.Request, hops int) string {
	if hops < 1 {
		hops = 1
	}
	remaining := hops
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		v := values[i]
		for end := len(v); end > 0; {
			start := strings.LastIndexByte(v[:end], ',') + 1
			entry := strings.TrimSpace(v[start:end])
			end = start - 1
			if entry == "" {
				continue
			}
			remaining--
			if remaining > 0 {
				continue
			}
			if ip := normalizeIP(entry); ip != "" {
				return ip
			}
			return peerIP(r)
		}
	}
	return peerIP(r)
}

// peerIP is the address of the transport peer, or "unknown".
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := normalizeIP(host); ip != "" {
		return ip
	}
	return "unknown"
}

// normalizeIP returns the canonical key for an address ("" if s is not one):
// IPv4-mapped IPv6 is unmapped, IPv6 is narrowed to its /64, a port suffix and
// zone are tolerated.
func normalizeIP(s string) string {
	if s == "" {
		return ""
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(s)
		if splitErr != nil {
			return ""
		}
		if addr, err = netip.ParseAddr(host); err != nil {
			return ""
		}
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is6() {
		p, err := addr.Prefix(ipv6KeyBits)
		if err != nil {
			return ""
		}
		return p.String()
	}
	return addr.String()
}
