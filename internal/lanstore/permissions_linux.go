//go:build linux

package lanstore

import (
	"os"
	"path/filepath"
	"syscall"
)

// A private direct directory and trusted, nonreplaceable ancestor chain remove
// the cross-account Lstat/open substitution path. Same-UID or root compromise
// remains outside this process-level boundary.
func privateStateDirectory(dir string) error {
	current := dir
	direct := true
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrStorage
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrStorage
		}
		uid := uint32(os.Geteuid())
		if stat.Uid != uid && stat.Uid != 0 {
			return ErrStorage
		}
		if direct && (stat.Uid != uid || info.Mode().Perm()&0077 != 0) {
			return ErrStorage
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrStorage
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
		direct = false
	}
	return nil
}
func privateStateFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ErrStorage
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ErrStorage
	}
	return nil
}
