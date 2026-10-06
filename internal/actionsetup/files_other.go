//go:build !linux

package actionsetup

func createProtected(string, []byte) error { return ErrSetup }
func createDirectory(string) error         { return ErrSetup }
