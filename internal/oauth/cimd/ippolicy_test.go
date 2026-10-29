package cimd

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsForbiddenIP(t *testing.T) {
	forbidden := []string{
		// loopback
		"127.0.0.1", "127.255.255.254", "::1",
		// RFC 1918
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		// RFC 4193 ULA
		"fc00::1", "fd12:3456:789a::1",
		// link-local, including the cloud metadata address
		"169.254.169.254", "169.254.0.1", "fe80::1", "fe80::a00:27ff:fe4e:66a1",
		// CGNAT
		"100.64.0.1", "100.127.255.254",
		// unspecified / this-network / broadcast / reserved
		"0.0.0.0", "0.1.2.3", "::", "255.255.255.255", "240.0.0.1",
		// multicast
		"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2",
		// documentation, benchmarking, protocol assignments
		"192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "192.0.0.8", "2001:db8::1",
		// IPv6 transition mechanisms that embed IPv4
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
		// IPv4-mapped forms of forbidden addresses
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.0.1", "::ffff:169.254.169.254",
		"::ffff:100.64.0.1", "::ffff:0.0.0.0",
		// IPv4-compatible loopback-ish
		"::7f00:1",
		// zone must not matter
		"fe80::1%eth0",
	}
	forbidden = append(forbidden, rangeSamples...)
	for _, s := range forbidden {
		t.Run("forbidden/"+s, func(t *testing.T) {
			ip, err := netip.ParseAddr(s)
			require.NoError(t, err)
			assert.True(t, IsForbiddenIP(ip), "%s must be forbidden", s)
		})
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
		"2606:4700:4700::1111", "2a00:1450:4001:81b::200e",
		"::ffff:8.8.8.8",
		// neighbours of blocked space that are globally reachable unicast
		"2001:4860:4860::8888", "2001:200::1", "2620:fe::fe", "2a02:26f0::1", "3ffe::1", "2fff:ffff::1",
		"192.88.98.1", "192.88.100.1", "192.0.1.1", "198.20.0.1", "223.255.255.254",
	}
	for _, s := range allowed {
		t.Run("allowed/"+s, func(t *testing.T) {
			ip, err := netip.ParseAddr(s)
			require.NoError(t, err)
			assert.False(t, IsForbiddenIP(ip), "%s must be allowed", s)
		})
	}

	assert.True(t, IsForbiddenIP(netip.Addr{}), "the zero Addr is forbidden")
}

// rangeSamples has the first, a middle and the last address of every range in
// blockedPrefixes and of the other special-purpose space (IANA IPv4 and IPv6
// Special-Purpose Address Registries), including ranges that embed IPv4.
var rangeSamples = []string{
	// IPv4-translated (the review repro: loopback, metadata and RFC 1918 behind a translator)
	"::ffff:0:0:0", "::ffff:0:7f00:1", "::ffff:0:a9fe:a9fe", "::ffff:0:10.0.0.1", "::ffff:0:ffff:ffff",
	// documentation, RFC 9637
	"3fff::", "3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
	// SRv6 SIDs
	"5f00::", "5f00::1", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	// NAT64 (well-known and local-use) embedding internal IPv4
	"64:ff9b::", "64:ff9b::a9fe:a9fe", "64:ff9b::ffff:ffff",
	"64:ff9b:1::", "64:ff9b:1::a00:1", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
	// discard-only
	"100::", "100::1", "100::ffff:ffff:ffff:ffff",
	// IETF protocol assignments incl. Teredo, and the ORCHID / drone ID ranges
	"2001::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:10::", "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:20::", "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:30::", "2001:3f:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
	// 6to4 embedding private and public IPv4: the whole /16 is refused
	"2002::", "2002:a00:1::1", "2002:7f00:1::", "2002:a9fe:a9fe::1", "2002:808:808::1", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	// ULA, link-local, site-local, multicast
	"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	// IPv6 space outside 2000::/3 that is not (yet) global unicast
	"4000::1", "8000::1", "a000::1", "e000::1", "1fff:ffff::1",
	// IPv4 special-purpose ranges, first and last
	"0.0.0.0", "0.255.255.255", "100.64.0.0", "100.127.255.255", "192.0.0.0", "192.0.0.255",
	"192.0.2.0", "192.0.2.255", "192.88.99.0", "192.88.99.255", "198.18.0.0", "198.19.255.255",
	"198.51.100.0", "198.51.100.255", "203.0.113.0", "203.0.113.255", "240.0.0.0", "255.255.255.255",
	// and their IPv4-mapped forms
	"::ffff:192.88.99.1", "::ffff:198.19.0.1", "::ffff:240.0.0.1", "::ffff:255.255.255.255",
}

func TestSpecialPurposeRangesRefusedAtBothLayers(t *testing.T) {
	for _, s := range rangeSamples {
		t.Run(s, func(t *testing.T) {
			ip, err := netip.ParseAddr(s)
			require.NoError(t, err)
			assert.True(t, IsForbiddenIP(ip), "IsForbiddenIP(%s)", s)

			network, address := "tcp6", net.JoinHostPort(s, "443")
			if ip.Is4() {
				network = "tcp4"
			}
			assert.Error(t, ssrfDialControl(network, address, nil), "ssrfDialControl(%s)", address)
			// a v4-mapped address may be dialled on either network type
			if ip.Is4In6() {
				assert.Error(t, ssrfDialControl("tcp4", address, nil))
			}
		})
	}
}

func TestPublicNeighboursAllowedAtBothLayers(t *testing.T) {
	for _, s := range []string{"2001:4860:4860::8888", "2620:fe::fe", "2a02:26f0::1", "192.88.98.1", "192.88.100.1", "8.8.8.8"} {
		ip := netip.MustParseAddr(s)
		assert.False(t, IsForbiddenIP(ip), s)
		network := "tcp6"
		if ip.Is4() {
			network = "tcp4"
		}
		assert.NoError(t, ssrfDialControl(network, net.JoinHostPort(s, "443"), nil), s)
	}
}

func TestSSRFDialControl(t *testing.T) {
	assert.Error(t, ssrfDialControl("tcp4", "127.0.0.1:443", nil))
	assert.Error(t, ssrfDialControl("tcp6", "[::1]:443", nil))
	assert.Error(t, ssrfDialControl("tcp4", "169.254.169.254:80", nil))
	assert.Error(t, ssrfDialControl("tcp6", "[::ffff:10.1.2.3]:443", nil))
	assert.Error(t, ssrfDialControl("tcp4", "not-an-ip:443", nil), "unresolved names are refused")
	assert.Error(t, ssrfDialControl("tcp4", "garbage", nil))
	assert.Error(t, ssrfDialControl("udp4", "8.8.8.8:443", nil), "only TCP")
	assert.Error(t, ssrfDialControl("unix", "/tmp/x", nil))
	assert.NoError(t, ssrfDialControl("tcp4", "8.8.8.8:443", nil))
	assert.NoError(t, ssrfDialControl("tcp6", "[2606:4700:4700::1111]:443", nil))
}

// A real dial through the production dialer configuration must be refused at
// connect time, whether the target is given as an IP or resolved from a name.
func TestSafeClientRefusesLoopbackAtDialTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	client := newSafeClient()
	for _, host := range []string{"127.0.0.1", "localhost"} {
		_, err := client.Get("https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/client.json")
		require.Error(t, err, host)
		assert.Contains(t, err.Error(), "not allowed", host)
	}
	select {
	case <-accepted:
		t.Fatal("the safe client completed a TCP connection to loopback")
	default:
	}
}

func TestSafeClientConfiguration(t *testing.T) {
	client := newSafeClient()
	assert.Nil(t, client.Jar, "no cookie jar")
	assert.NotNil(t, client.CheckRedirect, "redirects must be handled explicitly")
	assert.NotZero(t, client.Timeout)

	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, tr.Proxy, "proxy environment variables must not be honoured")
	assert.True(t, tr.DisableKeepAlives)
	assert.NotZero(t, tr.MaxResponseHeaderBytes)
}
