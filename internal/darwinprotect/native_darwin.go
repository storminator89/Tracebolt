//go:build darwin

package darwinprotect

import (
	"errors"
	"golang.org/x/sys/unix"
	"runtime"
	"syscall"
	"unsafe"
)

var ErrUnsafe = errors.New("macOS protected file policy rejected")

// fgetattrlist is an official descriptor-based Darwin API. x/sys v0.48.0
// supplies its ABI constants but no wrapper. Keep this single bounded syscall
// seam explicit; never replace it with pathname tools, xattrs or ACL mutation.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2
func attributes(fd int, common, volume uint32, raw []byte) error {
	if fd < 0 || len(raw) < 12 || len(raw) > maxSecurityBytes {
		return ErrUnsafe
	}
	attr := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: common, Volattr: volume}
	_, _, errno := syscall.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&attr)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), unix.FSOPT_REPORT_FULLSIZE, 0)
	runtime.KeepAlive(&attr)
	runtime.KeepAlive(raw)
	if errno != 0 {
		return ErrUnsafe
	}
	return nil
}

func safeACL(fd int) bool {
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Flags&unix.MNT_LOCAL == 0 {
		return false
	}
	// XNU getvolattrlist substitutes the exact vnode mount root for a
	// non-root descriptor, so capability lookup does not resolve another path.
	// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_attrlist.c
	var volume [36]byte
	if attributes(fd, 0, unix.ATTR_VOL_INFO|unix.ATTR_VOL_CAPABILITIES, volume[:]) != nil || !supportsSecurityAttribute(volume[:]) {
		return false
	}
	var security [maxSecurityBytes]byte
	return attributes(fd, unix.ATTR_CMN_EXTENDED_SECURITY, 0, security[:]) == nil && safeSecurityAttribute(security[:])
}

// Fstat preserves the ordinary stat result only after verifying conservative
// ACL protection and unchanged inode/owner/mode/metadata around that read.
// Callers additionally enforce their own regular-file, link and mode policy.
func Fstat(fd int, out *unix.Stat_t) error {
	if out == nil {
		return ErrUnsafe
	}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !safeACL(fd) || unix.Fstat(fd, &after) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Flags != after.Flags {
		return ErrUnsafe
	}
	*out = after
	return nil
}

// Sync flushes regular files through the drive cache. Publishing stores call it
// before rename, on the containing directory after rename, and again on a
// retained same-volume regular descriptor to flush the namespace publication.
// Unsupported full flush fails closed.
func Sync(fd int) error {
	var st unix.Stat_t
	if Fstat(fd, &st) != nil || unix.Fsync(fd) != nil {
		return ErrUnsafe
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0); err != nil {
			return ErrUnsafe
		}
	}
	return nil
}
