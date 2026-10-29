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
