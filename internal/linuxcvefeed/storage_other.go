//go:build !linux

package linuxcvefeed

// Native protected persistence is intentionally unavailable until its platform
// permissions and crash semantics are implemented and tested. Never silently
// downgrade to an unprotected cache on another manager platform.
func openStorage(string) (storage, error) { return nil, ErrUnsupported }
