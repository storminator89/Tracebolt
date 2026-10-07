//go:build linux

package packagehelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
)

// root is immutable and always / with owner 0 in production. Alternate roots
// exist only through private same-package fixture constructors, never IPC/env/CLI.
type protectedFS struct {
	root  string
	owner uint32
}

func hostFS() protectedFS { return protectedFS{"/", 0} }
func rootIdentity() error {
	r, e, s := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	if runtime.GOARCH != "amd64" || r != 0 || e != 0 || s != 0 || rg != 0 || eg != 0 || sg != 0 {
		return ErrRejected
	}
	return nil
}
func safePath(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && len(p) <= 2048 && !strings.ContainsAny(p, "\x00\r\n\t ")
}
func (fs protectedFS) dir(p string) (*os.File, error) {
	if !safePath(p) {
		return nil, ErrRejected
	}
	fd, e := unix.Open(fs.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := []string{}
	if p != "/" {
		parts = strings.Split(p[1:], "/")
	}
	for i := 0; ; i++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != fs.owner || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
			unix.Close(fd)
			return nil, ErrRejected
		}
		if i == len(parts) {
			return os.NewFile(uintptr(fd), "protected-directory"), nil
		}
		n, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = n
	}
}
func safeFile(st unix.Stat_t, owner uint32, max int64) bool {
	return st.Uid == owner && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Mode&0022 == 0 && st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0 && st.Size >= 0 && st.Size <= max
}
func sameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (fs protectedFS) open(p string, max int64) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	d, e := fs.dir(path.Dir(p))
	if e != nil {
		return nil, st, e
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), path.Base(p), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, st, e
	}
	f := os.NewFile(uintptr(fd), "protected-input")
	if unix.Fstat(fd, &st) != nil || !safeFile(st, fs.owner, max) {
		f.Close()
		return nil, st, ErrRejected
	}
	return f, st, nil
}
func (fs protectedFS) unchanged(p string, f *os.File, st unix.Stat_t) bool {
	var current unix.Stat_t
	if unix.Fstat(int(f.Fd()), &current) != nil || !sameFile(st, current) {
		return false
	}
	other, n, e := fs.open(p, st.Size)
	if e != nil {
		return false
	}
	other.Close()
	return sameFile(st, n)
}
func (fs protectedFS) read(p string, max int) ([]byte, error) {
	d, e := fs.dir(path.Dir(p))
	if e != nil {
		return nil, e
	}
	var marker unix.Stat_t
	ie := unix.Fstatat(int(d.Fd()), path.Base(p)+".intent", &marker, unix.AT_SYMLINK_NOFOLLOW)
	d.Close()
	if ie == nil {
		return nil, ErrUncertain
	}
	if ie != unix.ENOENT {
		return nil, ie
	}
	f, st, e := fs.open(p, int64(max))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max || int64(len(b)) != st.Size || !fs.unchanged(p, f, st) {
		return nil, ErrRejected
	}
	return b, nil
}
func (fs protectedFS) hash(p string, max int64) (string, uint64, error) {
	f, st, e := fs.open(p, max)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, max+1))
	if e != nil || n != st.Size || n > max || !fs.unchanged(p, f, st) {
		return "", 0, ErrRejected
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), uint64(n), nil
}
func (fs protectedFS) create(p string, b []byte) error {
	if !safePath(p) {
		return ErrRejected
	}
	d, e := fs.dir(path.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	name := path.Base(p)
	intent := name + ".intent"
	// An interrupted/uncertain append permanently blocks reads/adoption of this
	// record. Normal runtime never removes an old intent or repairs partial data.
	var st unix.Stat_t
	if e = unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		return os.ErrExist
	} else if e != unix.ENOENT {
		return e
	}
	write := func(n string, raw []byte) error {
		fd, e := unix.Openat(int(d.Fd()), n, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(fd), "protected-output")
		if _, e = f.Write(raw); e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		return e
	}
	digest := sha256.Sum256(b)
	if e = write(intent, []byte(hex.EncodeToString(digest[:]))); e != nil {
		return ErrUncertain
	}
	if e = d.Sync(); e != nil {
		return ErrUncertain
	}
	if e = write(name, b); e != nil {
		return ErrUncertain
	}
	if e = d.Sync(); e != nil {
		return ErrUncertain
	}
	if e = unix.Unlinkat(int(d.Fd()), intent, 0); e != nil {
		return ErrUncertain
	}
	if e = d.Sync(); e != nil {
		// Best effort retain a visible refusal if directory fsync itself failed.
		_ = write(intent, []byte("uncertain"))
		_ = d.Sync()
		return ErrUncertain
	}
	return nil
}
func (fs protectedFS) createJSON(p string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return fs.create(p, b)
}
func (fs protectedFS) json(p string, max int, v any) error {
	b, e := fs.read(p, max)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, v) != nil || !canonical(b, v) {
		return ErrRejected
	}
	return nil
}
func (fs protectedFS) mkdir(p string) error {
	d, e := fs.dir(path.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	if e = unix.Mkdirat(int(d.Fd()), path.Base(p), 0700); e != nil {
		return e
	}
	return d.Sync()
}
func (fs protectedFS) names(p string) ([]string, error) {
	d, e := fs.dir(p)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	names, e := d.Readdirnames(4097)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > 4096 {
		return nil, ErrRejected
	}
	return names, nil
}
func (fs protectedFS) exists(p string) (bool, error) {
	f, _, e := fs.open(p, 8<<20)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	f.Close()
	return true, nil
}
func (fs protectedFS) lock(p string) (func(), error) {
	d, e := fs.dir(path.Dir(p))
	if e != nil {
		return nil, e
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), path.Base(p), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "protected-lock")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !safeFile(st, fs.owner, 4096) {
		f.Close()
		return nil, ErrRejected
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); f.Close() }, nil
}
func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }
