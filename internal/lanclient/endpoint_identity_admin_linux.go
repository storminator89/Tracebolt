//go:build linux

package lanclient

import (
	"errors"
	"localrmm/internal/endpointidentity"
	"os"

	"golang.org/x/sys/unix"
)

const endpointConsentTemp = ".endpoint-identity-consent.tmp"

func consentFileSafe(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size >= 0 && st.Size <= endpointidentity.MaxConsentBytes
}
func consentDirectory(m Material) (*os.File, error) {
	fd, e := unix.Open(m.config.StateDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrState
	}
	f := os.NewFile(uintptr(fd), "endpoint-consent-directory")
	if verifyConsentDirectory(m, fd) != nil {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}
func verifyConsentDirectory(m Material, fd int) error {
	var held, current unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Lstat(m.config.StateDirectory, &current) != nil || held.Dev != current.Dev || held.Ino != current.Ino || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Mode&07777 != 0700 || held.Uid != uint32(os.Geteuid()) {
		return ErrState
	}
	return nil
}
func checkConsentEntry(fd int) (bool, error) {
	var st unix.Stat_t
	e := unix.Fstatat(fd, endpointConsentName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return false, nil
	}
	if e != nil || !consentFileSafe(st) {
		return false, ErrState
	}
	return true, nil
}
func writeEndpointConsent(m Material, raw []byte) error {
	if len(raw) == 0 || len(raw) > endpointidentity.MaxConsentBytes {
		return ErrConfiguration
	}
	dir, e := consentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if _, e = checkConsentEntry(fd); e != nil {
		return e
	}
	// A leftover temporary is not implicitly adopted or removed. A failed
	// operation is uncertain; retain its bounded private bytes for inspection.
	temp, e := unix.Openat(fd, endpointConsentTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrState
	}
	f := os.NewFile(uintptr(temp), "endpoint-consent-temporary")
	defer f.Close()
	var original unix.Stat_t
	if unix.Fstat(temp, &original) != nil || !consentFileSafe(original) {
		return ErrState
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrState
	}
	if unix.Fsync(temp) != nil || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	var current, entry unix.Stat_t
	if unix.Fstat(temp, &current) != nil || unix.Fstatat(fd, endpointConsentTemp, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !consentFileSafe(current) || !consentFileSafe(entry) || original.Dev != current.Dev || original.Ino != current.Ino || current.Dev != entry.Dev || current.Ino != entry.Ino || current.Size != int64(len(raw)) {
		return ErrState
	}
	if _, e = checkConsentEntry(fd); e != nil {
		return e
	}
	if unix.Renameat(fd, endpointConsentTemp, fd, endpointConsentName) != nil || unix.Fsync(fd) != nil || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}
func removeEndpointConsent(m Material) error {
	dir, e := consentDirectory(m)
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	exists, e := checkConsentEntry(fd)
	if e != nil || !exists {
		return e
	}
	if unix.Unlinkat(fd, endpointConsentName, 0) != nil || unix.Fsync(fd) != nil || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	return nil
}

// Keep imports deliberately narrow: no network, process execution or mutation
// outside the fixed sidecar and its create-exclusive temporary are possible.
