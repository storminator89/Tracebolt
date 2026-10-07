//go:build !linux

package packageupdatestore

// Protected SQLite operation is supported only on Linux. Cross-builds are not
// native acceptance and never turn this stub into a permissive implementation.
type protectedFile struct{ path string }

func openProtected(string, bool) (*protectedFile, error) { return nil, ErrStorage }
func (*protectedFile) check() error                      { return ErrStorage }
func (*protectedFile) sync() error                       { return ErrStorage }
func (*protectedFile) close() error                      { return nil }
