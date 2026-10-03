//go:build !linux

package enrollmentstore

func privateStateDirectory(string) error { return ErrStorage }
func privateStateFile(string) error      { return ErrStorage }
