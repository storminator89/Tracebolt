//go:build !linux

package lanclient

func writeCachedUpdatesConsent(Material, []byte) error { return ErrConfiguration }
func removeCachedUpdatesConsent(Material) error        { return ErrConfiguration }
