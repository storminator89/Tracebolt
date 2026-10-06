//go:build !linux

package linuxcveprogress

// Never silently downgrade to unprotected persistence on another platform.
func openStorage(string) (storage, error) { return nil, ErrUnsupported }
