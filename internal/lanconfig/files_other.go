//go:build !linux

package lanconfig

func ReadProtected(string, bool, int64) ([]byte, error) { return nil, ErrConfiguration }
