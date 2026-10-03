package analysis

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestEndpointDefaultBoundaryAndAllowlist(t *testing.T) {
	cases := []struct {
		base     string
		allow    []string
		endpoint string
		local    bool
	}{
		{"http://127.0.0.1:11434/v1", nil, "http://127.0.0.1:11434/v1/chat/completions", true},
		{"http://[::1]:11434/v1/", nil, "http://[::1]:11434/v1/chat/completions", true},
		{"https://models.example.com/custom/v1", []string{"https://models.example.com"}, "https://models.example.com/custom/v1/chat/completions", false},
		{"https://8.8.8.8:443/v1", []string{"https://8.8.8.8:443"}, "https://8.8.8.8:443/v1/chat/completions", false},
	}
	for _, tt := range cases {
		t.Run(tt.base, func(t *testing.T) {
			p, err := parseEndpoint(tt.base, tt.allow)
			if err != nil || p.url != tt.endpoint || p.loopback != tt.local {
				t.Fatalf("unexpected endpoint %#v %v", p, err)
			}
		})
	}
}

func TestEndpointRejectsURLTricksAndUnsafeDestinations(t *testing.T) {
	bases := []string{
		"http://models.example.com/v1", "https://models.example.com/v1", "file:///etc/passwd", "http://localhost:11434/v1", "http://127.0.0.2:11434/v1", "http://2130706433/v1", "http://0177.0.0.1/v1",
		"http://127.0.0.1:11434/v1?key=secret", "http://127.0.0.1:11434/v1?", "http://127.0.0.1:11434/v1#", "http://127.0.0.1:11434/v1#fragment", "http://user:secret@127.0.0.1/v1",
		"http://127.0.0.1:11434/v1/%2e%2e/metadata", "http://127.0.0.1:11434/v1/../metadata", "http://127.0.0.1:11434//v1", "http://127.0.0.1:11434/v1\\test", "http://127.0.0.1:11434/v1 ",
		"http://127.0.0.1:0/v1", "http://127.0.0.1:99999/v1", "http://127.0.0.1:080/v1", "http://127.0.0.1:/v1", "https://MODELS.example.com/v1", "https://models.example.com./v1",
		"http://[::ffff:127.0.0.1]:11434/v1", "http://[fe80::1%25eth0]/v1", " https://models.example.com/v1", "https:models.example.com",
	}
	for _, base := range bases {
		t.Run(base, func(t *testing.T) {
			if _, err := parseEndpoint(base, nil); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("accepted %q: %v", base, err)
			}
		})
	}
	for _, host := range []string{"169.254.169.254", "168.63.129.16", "100.100.100.200", "10.0.0.1", "172.16.0.1", "192.168.1.10", "0.0.0.0", "[::ffff:169.254.169.254]", "[fd00::1]", "[64:ff9b::a00:1]"} {
		origin := "https://" + host
		if _, err := parseEndpoint(origin+"/v1", []string{origin}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted forbidden allowlisted origin %s: %v", origin, err)
		}
	}
	for _, allow := range []string{"https://models.example.com/", "https://user@models.example.com", "https://models.example.com#x", "https://*.example.com", "http://models.example.com"} {
		if _, err := parseEndpoint("https://models.example.com/v1", []string{allow}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("accepted unsafe allowlist %s", allow)
		}
	}
}

func TestPublicAddressExcludesMappedAndMetadataNetworks(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.2.3.4", "172.31.1.2", "192.168.1.2", "169.254.169.254", "168.63.129.16", "100.100.100.200", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1", "198.18.1.2", "203.0.113.1", "::", "::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::1", "2001:db8::1", "2001::1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Fatalf("unsafe address accepted: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !publicAddress(netip.MustParseAddr(ip)) {
			t.Fatalf("ordinary public address rejected: %s", ip)
		}
	}
}

func TestResolveVetsAllAnswersAndPinsIP(t *testing.T) {
	p, err := parseEndpoint("https://models.example.com/v1", []string{"https://models.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	lookups := 0
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups++
		if network != "ip" || host != "models.example.com" {
			t.Fatal("unexpected lookup")
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	target, err := p.resolveTarget(context.Background(), lookup)
	if err != nil || target != "8.8.8.8:443" || lookups != 1 {
		t.Fatalf("DNS target not pinned: %q %v", target, err)
	}
	for _, ips := range [][]netip.Addr{
		nil,
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::ffff:169.254.169.254")},
		{netip.MustParseAddr("192.168.1.1")},
	} {
		_, err := p.resolveTarget(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) { return ips, nil })
		if err == nil {
			t.Fatalf("unsafe DNS answers accepted: %v", ips)
		}
	}
	local, _ := parseEndpoint("http://127.0.0.1:11434/v1", nil)
	target, err = local.resolveTarget(context.Background(), func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("loopback triggered DNS")
		return nil, nil
	})
	if err != nil || target != "127.0.0.1:11434" {
		t.Fatal("loopback target changed")
	}
}
