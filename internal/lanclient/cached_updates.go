package lanclient

import (
	"context"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/lanconfig"
	"path/filepath"
	"time"
)

const cachedUpdatesConsentName = "cached-updates-consent.json"

type cachedUpdatesSource func(context.Context, string, time.Time, cachedupdates.LocalConsent, string) (cachedupdates.Snapshot, error)

func cachedUpdatesConsentPath(m Material) string {
	return filepath.Join(m.config.StateDirectory, cachedUpdatesConsentName)
}

// Invalid, absent or foreign consent disables only this extension. No manager
// configuration, profile label or previously pending frame can imply consent.
func readCachedUpdatesConsent(m Material) (cachedupdates.LocalConsent, bool) {
	if !m.valid() || !m.config.complete() {
		return cachedupdates.LocalConsent{}, false
	}
	raw, e := lanconfig.ReadProtected(cachedUpdatesConsentPath(m), true, cachedupdates.MaxConsentBytes)
	if e != nil {
		return cachedupdates.LocalConsent{}, false
	}
	c, e := cachedupdates.DecodeLocalConsent(raw, m.binding)
	return c, e == nil
}
