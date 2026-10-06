//go:build linux

package inventorystate

import (
	"context"
	"crypto/sha256"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// InspectExisting checks a protected stable ledger and pack snapshot without
// acquiring the live sender lock or performing any write/recovery. A concurrent
// write may reject the snapshot; it never produces a new sender state handle.
func InspectExisting(dir, binding, agentID string) error {
	if !validDigest(binding) {
		return ErrBinding
	}
	if _, err := packageTransfer.generationID(agentID, 1); err != nil {
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
	s.lock = os.NewFile(uintptr(fd), "read-only-inventory-lock-inspection")
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
	record, err := decodeRecordKind(packageTransfer, raw)
	if err != nil {
		return err
	}
	if record.Binding != binding || record.AgentID != agentID {
		return ErrBinding
	}
	s.stateID, s.hash = &id, sha256.Sum256(raw)
	if err := s.inspect(); err != nil {
		return err
	}
	pack, err := s.loadPack(record.Phase == "retiring")
	if err != nil {
		return err
	}
	wantPack := record.Phase == "ready" || record.Phase == "abort" || record.Phase == "retiring"
	if !wantPack && len(pack) != 0 {
		return ErrUncertain
	}
	if wantPack && len(pack) == 0 && record.Phase != "retiring" {
		return ErrCorrupt
	}
	if len(pack) > 0 {
		if int64(len(pack)) != record.PackBytes || digest(pack) != record.PackSHA256 {
			return ErrCorrupt
		}
		if _, err := decodePack(context.Background(), pack, record); err != nil {
			return err
		}
	}
	if err := s.verify(); err != nil {
		return err
	}
	if err := s.verifyPack(wantPack); err != nil {
		return err
	}
	return s.inspect()
}
