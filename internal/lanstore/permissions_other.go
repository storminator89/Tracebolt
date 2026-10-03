//go:build !linux

package lanstore

func privateStateDirectory(string) error { return ErrStorage }
func privateStateFile(string) error      { return ErrStorage }
