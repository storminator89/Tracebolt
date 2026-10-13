//go:build !linux && !windows && !darwin

package lanconfig

func ReadProtected(string, bool, int64) ([]byte, error) { return nil, ErrConfiguration }
