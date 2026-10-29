package lanclient

import (
	"net/netip"
	"time"

	"localrmm/internal/lantrust"
)

// ValidateBootstrapTrustAt validates public TLS destination policy at a supplied
// instant without constructing a client, resolving DNS or making a request.
// It must not be used as authority for an active transport or enrollment.
func ValidateBootstrapTrustAt(origin string, serverCAPEM []byte, at time.Time) error {
	u, err := canonicalOrigin(origin, "https")
	if err != nil {
		return ErrConfiguration
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !vettedAddresses([]netip.Addr{ip}, false) {
		return ErrConfiguration
	}
	if lantrust.ValidateServerTrustAt(serverCAPEM, u.Hostname(), at) != nil {
		return ErrConfiguration
	}
	return nil
}
