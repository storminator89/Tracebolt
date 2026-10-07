//go:build !linux && !windows

package lanconfig

func ReadProtected(string, bool, int64) ([]byte, error) { return nil, ErrConfiguration }
