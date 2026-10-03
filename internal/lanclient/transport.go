package lanclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

const RequestTimeout = 15 * time.Second

var errDestination = errors.New("configured agent destination could not be verified")

// The destination comes only from protected operator-supplied local config.
// Every DNS answer is vetted and the chosen literal address is dialed directly;
// environment proxies, redirects and second DNS lookups cannot change it.
func permittedAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, raw := range []string{"169.254.0.0/16", "100.100.100.200/32", "fd00:ec2::254/128", "168.63.129.16/32", "0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	if ip.Is6() && !ip.IsLoopback() && !ip.IsPrivate() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	return ip.IsLoopback() || ip.IsGlobalUnicast()
}
func newHTTPClient(tlsConfig *tls.Config, httpTest bool) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errDestination
		}
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errDestination
		}
		var ips []netip.Addr
		if ip, e := netip.ParseAddr(host); e == nil {
			ips = []netip.Addr{ip}
		} else {
			ips, e = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if e != nil {
				return nil, errDestination
			}
		}
		if !vettedAddresses(ips, httpTest) {
			return nil, errDestination
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		for _, ip := range ips {
			conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errDestination
	}
	return &http.Client{Transport: transport, Timeout: RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func vettedAddresses(ips []netip.Addr, httpTest bool) bool {
	if len(ips) == 0 || len(ips) > 16 {
		return false
	}
	for _, ip := range ips {
		if !permittedAddress(ip) || (httpTest && !ip.Unmap().IsLoopback() && !ip.Unmap().IsPrivate()) {
			return false
		}
	}
	return true
}
