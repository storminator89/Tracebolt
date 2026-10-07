//go:build !windows

package windowsstate

func openNative(string, Options) (backend, error) { return nil, ErrUnsupported }

// ReadProtected is a non-mutating, bounded native protected-file read. The
// private flag is retained for config callers; public files use the same strict
// owner/DACL policy and are never allowed a weaker reader/writer set.
func ReadProtected(path, runtimeSID string, private bool, maxBytes int64) ([]byte, error) {
	return nil, ErrUnsupported
}

// ReadProtectedInstaller is unavailable outside Windows.
func ReadProtectedInstaller(path string, private bool, maxBytes int64) ([]byte, error) {
	return nil, ErrUnsupported
}
