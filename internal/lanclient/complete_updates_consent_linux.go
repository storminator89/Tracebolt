//go:build linux

package lanclient

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const completeUpdatesConsentTemp = ".complete-cached-updates-consent.tmp"

func completeUpdatesConsentFileSafe(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size >= 0 && st.Size <= maxCompleteUpdatesConsentBytes
}
func completeUpdatesConsentDirectory(m Material) (*os.File, error) {
	fd, e := unix.Open(m.config.StateDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), "completeUpdates-consent-directory")
	if verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}
func verifyCompleteUpdatesConsentDirectory(m Material, fd int) error {
	var held, current unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Lstat(m.config.StateDirectory, &current) != nil || held.Dev != current.Dev || held.Ino != current.Ino || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Mode&07777 != 0700 || held.Uid != uint32(os.Geteuid()) {
		return ErrState
	}
	return nil
}
func checkCompleteUpdatesConsentEntry(fd int) (bool, error) {
	var st unix.Stat_t
	e := unix.Fstatat(fd, completeUpdatesConsentName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	if e != nil || !completeUpdatesConsentFileSafe(st) {
		return false, ErrState
	}
	return true, nil
}
func writeCompleteUpdatesConsent(m Material, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxCompleteUpdatesConsentBytes {
		return ErrConfiguration
	}
	dir, e := completeUpdatesConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if _, e = checkCompleteUpdatesConsentEntry(fd); e != nil {
		return e
	}
	// A leftover temporary is not implicitly adopted or removed. A failed
	// operation is uncertain; retain its bounded private bytes for inspection.
	temp, e := unix.Openat(fd, completeUpdatesConsentTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(temp), "completeUpdates-consent-temporary")
	defer f.Close()
	var original unix.Stat_t
	if unix.Fstat(temp, &original) != nil || !completeUpdatesConsentFileSafe(original) {
		return ErrState
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrState
	}
	if unix.Fsync(temp) != nil || verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		return ErrState
	}
	var current, entry unix.Stat_t
	if unix.Fstat(temp, &current) != nil || unix.Fstatat(fd, completeUpdatesConsentTemp, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !completeUpdatesConsentFileSafe(current) || !completeUpdatesConsentFileSafe(entry) || original.Dev != current.Dev || original.Ino != current.Ino || current.Dev != entry.Dev || current.Ino != entry.Ino || current.Size != int64(len(raw)) {
		return ErrState
	}
	if _, e = checkCompleteUpdatesConsentEntry(fd); e != nil {
		return e
	}
	if unix.Renameat(fd, completeUpdatesConsentTemp, fd, completeUpdatesConsentName) != nil || unix.Fsync(fd) != nil || verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
func removeCompleteUpdatesConsent(m Material) error {
	dir, e := completeUpdatesConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	exists, e := checkCompleteUpdatesConsentEntry(fd)
	if e != nil || !exists {
		return e
	}
	if unix.Unlinkat(fd, completeUpdatesConsentName, 0) != nil || unix.Fsync(fd) != nil || verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}

// Keep imports deliberately narrow: no network, process execution or mutation
// outside the fixed sidecar and its create-exclusive temporary are possible.

// completeUpdatesInitializationState is read-only. A surviving marker is uncertain,
// never an invitation to initialize or reset either consumed sequence domain.
func completeUpdatesInitializationState(m Material) error {
	dir, e := completeUpdatesConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	for _, name := range []string{completeUpdatesInitName, completeUpdatesConsentTemp} {
		var st unix.Stat_t
		e = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(e, unix.ENOENT) {
			return ErrState
		}
	}
	return nil
}
func beginCompleteUpdatesInitialization(m Material) error {
	dir, e := completeUpdatesConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	temp, e := unix.Openat(fd, completeUpdatesInitName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(temp), "completeUpdates-initialization")
	defer f.Close()
	if unix.Fsync(temp) != nil || unix.Fsync(fd) != nil || verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
func finishCompleteUpdatesInitialization(m Material) error {
	dir, e := completeUpdatesConsentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	var st unix.Stat_t
	if unix.Fstatat(fd, completeUpdatesInitName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !completeUpdatesConsentFileSafe(st) || st.Size != 0 {
		return ErrState
	}
	if unix.Unlinkat(fd, completeUpdatesInitName, 0) != nil || unix.Fsync(fd) != nil || verifyCompleteUpdatesConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
