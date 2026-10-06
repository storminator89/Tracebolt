package applicationcheck

import (
	"context"
	"net/netip"
	"sort"
)

// resolveAllowed is the existing all-answer policy, shared without expanding it.
// The returned list is a private sorted copy. A subsequent numeric dial cannot
// trigger a second hostname lookup. No lookup here is an authoritative DNS claim.
func (p *probe) resolveAllowed(ctx context.Context, host string, t target) ([]netip.Addr, string) {
	var addresses []netip.Addr
	if literal, e := netip.ParseAddr(host); e == nil {
		addresses = []netip.Addr{literal}
	} else {
		var e error
		addresses, e = p.resolve(ctx, host)
		if e != nil || len(addresses) == 0 {
			if ctx.Err() != nil {
				return nil, "timeout"
			}
			return nil, "dns_failed"
		}
	}
	allowed := map[netip.Addr]bool{}
	for _, s := range t.AllowedAddresses {
		ip, e := netip.ParseAddr(s)
		if e != nil {
			return nil, "invalid_configuration"
		}
		allowed[ip] = true
	}
	if len(addresses) > MaxAddresses {
		return nil, "destination_blocked"
	}
	for _, ip := range addresses {
		if !allowedAddress(ip, t.AllowPrivateLAN) || !allowed[ip.Unmap()] {
			return nil, "destination_blocked"
		}
	}
	addresses = append([]netip.Addr(nil), addresses...)
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return addresses, ""
}
