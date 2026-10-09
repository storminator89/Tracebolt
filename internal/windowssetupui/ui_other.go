//go:build !windows

package windowssetupui

import "os"

// Run is deliberately inert on every non-Windows platform, including tests.
func Run(Config, Hooks) error { return ErrUnsupported }

func openPublicFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrConfiguration
	}
	return f, nil
}

func validPublicPath(path string) bool { return path != "" }
