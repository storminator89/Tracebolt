package lanclient

import (
	"context"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/lanconfig"
	"path/filepath"
	"time"
)

const endpointConsentName = "endpoint-identity-consent.json"

type endpointSource func(context.Context, string, time.Time, endpointidentity.LocalConsent, string) (endpointidentity.Snapshot, error)

func endpointConsentPath(m Material) string {
	return filepath.Join(m.config.StateDirectory, endpointConsentName)
}

// Invalid, absent or foreign consent disables only this extension. No manager
// configuration, profile label or previously pending frame can imply consent.
func readEndpointConsent(m Material) (endpointidentity.LocalConsent, bool) {
	if !m.valid() || !m.config.complete() {
		return endpointidentity.LocalConsent{}, false
	}
	raw, e := lanconfig.ReadProtected(endpointConsentPath(m), true, endpointidentity.MaxConsentBytes)
	if e != nil {
		return endpointidentity.LocalConsent{}, false
	}
	c, e := endpointidentity.DecodeLocalConsent(raw, m.binding)
	return c, e == nil
}
