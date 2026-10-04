//go:build linux

package lanclient

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const overviewConsentTemp = ".complete-overview-consent.tmp"

func overviewConsentFileSafe(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size >= 0 && st.Size <= maxOverviewConsentBytes
}
func overviewConsentDirectory(m Material) (*os.File, error) {
	fd, e := unix.Open(m.config.StateDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), "overview-consent-directory")
	if verifyOverviewConsentDirectory(m, fd) != nil {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}
func verifyOverviewConsentDirectory(m Material, fd int) error {
	var held, current unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Lstat(m.config.StateDirectory, &current) != nil || held.Dev != current.Dev || held.Ino != current.Ino || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Mode&07777 != 0700 || held.Uid != uint32(os.Geteuid()) {
		return ErrState
	}
	return nil
}
func checkOverviewConsentEntry(fd int) (bool, error) {
	var st unix.Stat_t
	e := unix.Fstatat(fd, overviewConsentName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	if e != nil || !overviewConsentFileSafe(st) {
		return false, ErrState
	}
	return true, nil
}
func writeOverviewConsent(m Material, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxOverviewConsentBytes {
		return ErrConfiguration
	}
	dir, e := overviewConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if _, e = checkOverviewConsentEntry(fd); e != nil {
		return e
	}
	// A leftover temporary is not implicitly adopted or removed. A failed
	// operation is uncertain; retain its bounded private bytes for inspection.
	temp, e := unix.Openat(fd, overviewConsentTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(temp), "overview-consent-temporary")
	defer f.Close()
	var original unix.Stat_t
	if unix.Fstat(temp, &original) != nil || !overviewConsentFileSafe(original) {
		return ErrState
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrState
	}
	if unix.Fsync(temp) != nil || verifyOverviewConsentDirectory(m, fd) != nil {
		return ErrState
	}
	var current, entry unix.Stat_t
	if unix.Fstat(temp, &current) != nil || unix.Fstatat(fd, overviewConsentTemp, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !overviewConsentFileSafe(current) || !overviewConsentFileSafe(entry) || original.Dev != current.Dev || original.Ino != current.Ino || current.Dev != entry.Dev || current.Ino != entry.Ino || current.Size != int64(len(raw)) {
		return ErrState
	}
	if _, e = checkOverviewConsentEntry(fd); e != nil {
		return e
	}
	if unix.Renameat(fd, overviewConsentTemp, fd, overviewConsentName) != nil || unix.Fsync(fd) != nil || verifyOverviewConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
func removeOverviewConsent(m Material) error {
	dir, e := overviewConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	exists, e := checkOverviewConsentEntry(fd)
	if e != nil || !exists {
		return e
	}
	if unix.Unlinkat(fd, overviewConsentName, 0) != nil || unix.Fsync(fd) != nil || verifyOverviewConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}

// Keep imports deliberately narrow: no network, process execution or mutation
// outside the fixed sidecar and its create-exclusive temporary are possible.

// overviewInitializationState is read-only. A surviving marker is uncertain,
// never an invitation to initialize or reset either consumed sequence domain.
func overviewInitializationState(m Material) error {
	dir, e := overviewConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	for _, name := range []string{overviewInitName, overviewConsentTemp} {
		var st unix.Stat_t
		e = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(e, unix.ENOENT) {
			return ErrState
		}
	}
	return nil
}
func beginOverviewInitialization(m Material) error {
	dir, e := overviewConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	temp, e := unix.Openat(fd, overviewInitName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(temp), "overview-initialization")
	defer f.Close()
	if unix.Fsync(temp) != nil || unix.Fsync(fd) != nil || verifyOverviewConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
func finishOverviewInitialization(m Material) error {
	dir, e := overviewConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	var st unix.Stat_t
	if unix.Fstatat(fd, overviewInitName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !overviewConsentFileSafe(st) || st.Size != 0 {
		return ErrState
	}
	if unix.Unlinkat(fd, overviewInitName, 0) != nil || unix.Fsync(fd) != nil || verifyOverviewConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
