//go:build linux

package lanclientstate

import (
	"crypto/sha256"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// InspectExisting validates one protected stable ledger snapshot without taking
// the sender's lock. It never creates, writes, cleans or recovers state and may
// reject a concurrent write. This is setup metadata only, never sender admission.
func InspectExisting(dir, binding string) error {
	if !validDigest(binding) {
		return ErrBinding
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return ErrUnsafe
	}
	s := &linuxStorage{}
	defer s.close()
	if err := s.openDirectoryMode(dir, false); err != nil {
		return err
	}
	fd, err := unix.Openat(s.dirFD(), lockName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return safeOpenError(err)
	}
	s.lock = os.NewFile(uintptr(fd), "read-only-sender-lock-inspection")
	if unix.Fstat(fd, &s.lockID) != nil || !privateFile(s.lockID) || s.lockID.Size != 0 {
		return ErrUnsafe
	}
	if err := s.verifyPaths(); err != nil {
		return err
	}
	raw, id, err := s.readState()
	if err != nil {
		return err
	}
	record, err := decodeRecord(raw)
	if err != nil {
		return err
	}
	if record.Binding != binding {
		return ErrBinding
	}
	s.stateID, s.hash = &id, sha256.Sum256(raw)
	return s.verify()
}
