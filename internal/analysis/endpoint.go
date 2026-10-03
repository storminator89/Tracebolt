package analysis

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var ErrInvalidConfig = errors.New("invalid model provider configuration")

type endpointPolicy struct {
	url      string
	origin   string
	host     string
	port     string
	loopback bool
}

func parseEndpoint(base string, allowed []string) (endpointPolicy, error) {
	bad := func() (endpointPolicy, error) { return endpointPolicy{}, ErrInvalidConfig }
	if base == "" || len(base) > 512 || strings.TrimSpace(base) != base || strings.ContainsAny(base, "\\%\r\n\t") || len(allowed) > 16 {
		return bad()
	}
	u, err := url.Parse(base)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(base, "#") || u.RawPath != "" {
		return bad()
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return bad()
	}
	if u.Host != strings.ToLower(u.Host) || !validHost(u.Hostname()) {
		return bad()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return bad()
		}
	} else {
		if strings.HasSuffix(u.Host, ":") {
			return bad()
		}
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	origin := u.Scheme + "://" + u.Host
	local := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if !local {
		if u.Scheme != "https" {
			return bad()
		}
		found := false
		for _, originAllowed := range allowed {
			// The trusted allowlist contains exact HTTPS origins, never wildcards,
			// arbitrary paths or values supplied by the model/request body.
			a, err := url.Parse(originAllowed)
			if err != nil || len(originAllowed) > 512 || a.Scheme != "https" || a.User != nil || a.Host == "" || a.Path != "" || a.RawQuery != "" || a.ForceQuery || a.Fragment != "" || a.Opaque != "" || originAllowed != "https://"+a.Host {
				return bad()
			}
			if originAllowed == origin {
				found = true
			}
		}
		if !found {
			return bad()
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicAddress(ip) {
			return bad()
		}
	}
	path := strings.TrimSuffix(u.Path, "/")
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			return bad()
		}
		for _, component := range strings.Split(path[1:], "/") {
			if component == "" {
				return bad()
			}
			for _, r := range component {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
					return bad()
				}
			}
		}
	}
	u.Path = path + "/chat/completions"
	return endpointPolicy{url: u.String(), origin: origin, host: u.Hostname(), port: port, loopback: local}, nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	// DNS names only; localhost-like names are not a local-mode shortcut.
	if !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

var forbiddenNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}

// publicAddress is intentionally conservative. In addition to private and
// link-local ranges it blocks shared/transition/documentation ranges and Azure's
// special platform address. LAN support requires a separate reviewed policy.
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("168.63.129.16") {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range forbiddenNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type lookupIPs func(context.Context, string, string) ([]netip.Addr, error)

// resolveTarget vets every answer and returns a literal dial address. DNS is not
// consulted again by the dialer, preventing resolve/check/dial rebinding gaps.
func (p endpointPolicy) resolveTarget(ctx context.Context, lookup lookupIPs) (string, error) {
	if p.loopback {
		return net.JoinHostPort(p.host, p.port), nil
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(p.host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		var err error
		ips, err = lookup(ctx, "ip", p.host)
		if err != nil {
			return "", ErrUnavailable
		}
	}
	if len(ips) == 0 || len(ips) > 32 {
		return "", ErrUnavailable
	}
	for _, ip := range ips {
		if !publicAddress(ip) {
			return "", ErrUnavailable
		}
	}
	return net.JoinHostPort(ips[0].Unmap().String(), p.port), nil
}
