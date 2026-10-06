//go:build linux

package lanclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/systemstate"
	"os"

	"golang.org/x/sys/unix"
)

const socketSetupTemp = ".socket-owner-consent.tmp"

// Every temporary is an incomplete operation, never an invitation to repair or
// adopt files. No cleanup/unlink route exists in this lifecycle.
func socketSetupAbsent(fd int, name string) error {
	var st unix.Stat_t
	if !errors.Is(unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
		return ErrState
	}
	return nil
}
func socketSetupSafe(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) &&
		st.Nlink == 1 && st.Size >= 0 && st.Size <= socketOwnerMaxConsentBytes
}
func socketSetupSameFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func socketSetupReadAt(fd int, name string) ([]byte, unix.Stat_t, error) {
	var original unix.Stat_t
	handle, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, original, nil
	}
	if err != nil {
		return nil, original, ErrState
	}
	file := os.NewFile(uintptr(handle), "socket-owner-consent-read")
	defer file.Close()
	if unix.Fstat(handle, &original) != nil || !socketSetupSafe(original) || original.Size == 0 {
		return nil, original, ErrState
	}
	raw, err := io.ReadAll(io.LimitReader(file, socketOwnerMaxConsentBytes+1))
	if err != nil || int64(len(raw)) != original.Size || len(raw) > socketOwnerMaxConsentBytes {
		return nil, original, ErrState
	}
	var held, entry unix.Stat_t
	if unix.Fstat(handle, &held) != nil || unix.Fstatat(fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!socketSetupSameFile(original, held) || !socketSetupSameFile(held, entry) {
		return nil, original, ErrState
	}
	return raw, held, nil
}
func socketSetupDecode(raw []byte) (*SocketOwnerConsent, error) {
	if raw == nil {
		return nil, nil
	}
	var c SocketOwnerConsent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		return nil, ErrState
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrState
	}
	return &c, nil
}
func inspectSocketSetupConsent(m Material) (*SocketOwnerConsent, error) {
	dir, err := consentDirectory(m)
	if err != nil {
		return nil, ErrState
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if socketSetupAbsent(fd, socketSetupTemp) != nil {
		return nil, ErrState
	}
	raw, _, err := socketSetupReadAt(fd, socketOwnerConsentName)
	if err != nil || verifyConsentDirectory(m, fd) != nil {
		return nil, ErrState
	}
	return socketSetupDecode(raw)
}

func openSocketSetupState(m Material) (socketSetupState, error) {
	state, err := systemstate.OpenExistingNoRecovery(systemStateDirectory(m.config), systemStateBinding(m))
	if err != nil {
		return nil, ErrState
	}
	// Check after taking the lock. The no-recovery open never deletes a leftover,
	// including one appearing between the identity read and lock acquisition.
	systemMaterial := m
	systemMaterial.config.StateDirectory = systemStateDirectory(m.config)
	dir, err := consentDirectory(systemMaterial)
	if err != nil {
		state.Close()
		return nil, ErrState
	}
	defer dir.Close()
	if socketSetupAbsent(int(dir.Fd()), ".system-state.tmp") != nil || verifyConsentDirectory(systemMaterial, int(dir.Fd())) != nil {
		state.Close()
		return nil, ErrState
	}
	return socketSetupNativeState{state}, nil
}

type socketSetupFileOps struct {
	write  func(*os.File, []byte) (int, error)
	sync   func(int) error
	rename func(int, string, int, string, bool) error
}

func socketSetupDefaultFileOps() socketSetupFileOps {
	return socketSetupFileOps{write: func(f *os.File, raw []byte) (int, error) { return f.Write(raw) }, sync: unix.Fsync,
		rename: func(oldfd int, old string, newfd int, name string, create bool) error {
			if create {
				return unix.Renameat2(oldfd, old, newfd, name, unix.RENAME_NOREPLACE)
			}
			return unix.Renameat(oldfd, old, newfd, name)
		}}
}
func writeSocketSetupConsent(m Material, old *SocketOwnerConsent, next SocketOwnerConsent, current func() error) error {
	return writeSocketSetupConsentUsing(m, old, next, current, socketSetupDefaultFileOps())
}
func writeSocketSetupConsentUsing(m Material, old *SocketOwnerConsent, next SocketOwnerConsent, current func() error, ops socketSetupFileOps) error {
	raw, err := json.Marshal(next)
	if err != nil || len(raw) == 0 || len(raw) > socketOwnerMaxConsentBytes || current == nil {
		return ErrState
	}
	var expected []byte
	if old != nil {
		expected, err = json.Marshal(old)
		if err != nil {
			return ErrState
		}
	}
	dir, err := consentDirectory(m)
	if err != nil {
		return ErrState
	}
	defer dir.Close()
	fd := int(dir.Fd())
	before, original, err := socketSetupReadAt(fd, socketOwnerConsentName)
	if err != nil || !bytes.Equal(before, expected) || socketSetupAbsent(fd, socketSetupTemp) != nil || current() != nil {
		return ErrState
	}
	temp, err := unix.Openat(fd, socketSetupTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrState
	}
	file := os.NewFile(uintptr(temp), "socket-owner-consent-temporary")
	defer file.Close()
	var temporary unix.Stat_t
	if unix.Fstat(temp, &temporary) != nil || !socketSetupSafe(temporary) || temporary.Size != 0 {
		return ErrState
	}
	if n, err := ops.write(file, raw); err != nil || n != len(raw) {
		return ErrState
	}
	if ops.sync(temp) != nil || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	written, writtenID, err := socketSetupReadAt(fd, socketSetupTemp)
	if err != nil || !bytes.Equal(written, raw) || writtenID.Dev != temporary.Dev || writtenID.Ino != temporary.Ino {
		return ErrState
	}
	// Recheck activated identity and locked ledger after writing the private
	// temporary but before committing any declaration.
	if current() != nil {
		return ErrState
	}
	before, existingID, err := socketSetupReadAt(fd, socketOwnerConsentName)
	if err != nil || !bytes.Equal(before, expected) || old != nil && !socketSetupSameFile(original, existingID) {
		return ErrState
	}
	var held, entry unix.Stat_t
	if unix.Fstat(temp, &held) != nil || unix.Fstatat(fd, socketSetupTemp, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!socketSetupSameFile(writtenID, held) || !socketSetupSameFile(held, entry) || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	// Initial install is no-replace. Disable replaces only the exact validated
	// existing consent under both sender locks; it never removes the tombstone.
	if ops.rename(fd, socketSetupTemp, fd, socketOwnerConsentName, old == nil) != nil || ops.sync(fd) != nil || verifyConsentDirectory(m, fd) != nil {
		return ErrState
	}
	after, committed, err := socketSetupReadAt(fd, socketOwnerConsentName)
	if err != nil || !bytes.Equal(after, raw) || committed.Dev != writtenID.Dev || committed.Ino != writtenID.Ino || socketSetupAbsent(fd, socketSetupTemp) != nil {
		return ErrState
	}
	return nil
}
