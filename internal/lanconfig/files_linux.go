//go:build linux

package lanconfig

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ReadProtected rejects replaceable path components, symlinks and shared private
// files. Same-UID/root compromise remains outside this process boundary.
func ReadProtected(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrConfiguration
	}
	original, e := os.Lstat(path)
	if e != nil || !original.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	stat, ok := original.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	if !ok || stat.Nlink != 1 || (stat.Uid != uid && stat.Uid != 0) || original.Mode().Perm()&0022 != 0 {
		return nil, ErrConfiguration
	}
	if private && (stat.Uid != uid || original.Mode().Perm()&0077 != 0) {
		return nil, ErrConfiguration
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrConfiguration
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uid && st.Uid != 0) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return nil, ErrConfiguration
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(original, opened) {
		return nil, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, ErrConfiguration
	}
	return raw, nil
}
