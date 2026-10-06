//go:build linux

package agentinstall

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const readAdminUpgradeIntent = controlDirectory + "/read-admin-upgrade-transaction.json"
const readAdminIntent = controlDirectory + "/read-admin-intent.json"

// This root-owned intent is written by the verified, same-scope coordinator
// only after every participant has drained. It is not a grant or an enrollment
// record. Original consent, helper receipts and identity remain immutable.
type readAdminUpgradeIntentRecord struct {
	Version             string `json:"version"`
	Phase               string `json:"phase"`
	AgentSHA256         string `json:"agentSHA256"`
	EnrollSHA256        string `json:"enrollSHA256"`
	SourceSHA256        string `json:"sourceSHA256"`
	PreviousOwnerSHA256 string `json:"previousOwnerSHA256"`
	HistorySHA256       string `json:"historySHA256"`
}

func (h *linuxHost) readAdminUpgradeGuard(r Request) error {
	marker := h.path(readAdminUpgradeIntent)
	_, intentErr := os.Lstat(marker)
	_, parentErr := os.Lstat(h.path(readAdminIntent))
	if r.UpgradeCoordinatorFD == 0 {
		// Unresolved coordinated work cannot be resumed by ordinary restart/upgrade.
		if !os.IsNotExist(intentErr) || r.Action == Upgrade && !os.IsNotExist(parentErr) {
			return ErrState
		}
		return nil
	}
	if r.Action != Upgrade || !r.Apply || r.UpgradeCoordinatorFD < 3 || intentErr != nil || parentErr != nil {
		return ErrContract
	}
	if h.secureFile(marker, true, 4096) != nil || h.secureFile(h.path(readAdminIntent), true, 16384) != nil {
		return ErrState
	}
	raw, err := os.ReadFile(marker)
	var intent readAdminUpgradeIntentRecord
	if err != nil || decodeCanonical(raw, &intent) != nil || intent.Version != "tracebolt.read-admin-upgrade-transaction.v1" || intent.Phase != "native-ready" || intent.AgentSHA256 != r.AgentSHA256 || intent.EnrollSHA256 != r.EnrollSHA256 || intent.SourceSHA256 != r.SourceSHA256 || !validDigest(intent.PreviousOwnerSHA256) || !validDigest(intent.HistorySHA256) {
		return ErrState
	}
	ownerPath := h.path(filepath.Join(controlDirectory, "installation-owner.json"))
	if h.secureFile(ownerPath, true, 16384) != nil {
		return ErrState
	}
	owner, err := os.ReadFile(ownerPath)
	if err != nil || sum(owner) != intent.PreviousOwnerSHA256 {
		return ErrState
	}
	lockPath := h.path(filepath.Join(controlDirectory, "install.lock"))
	if h.secureFile(lockPath, true, 4096) != nil {
		return ErrState
	}
	var borrowed, named unix.Stat_t
	if unix.Fstat(r.UpgradeCoordinatorFD, &borrowed) != nil || unix.Lstat(lockPath, &named) != nil || borrowed.Dev != named.Dev || borrowed.Ino != named.Ino || borrowed.Mode != named.Mode || borrowed.Uid != uint32(h.owner) || borrowed.Gid != named.Gid || borrowed.Nlink != 1 || borrowed.Mode&07777 != 0600 {
		return ErrState
	}
	// A shared open-file description retains the coordinator's flock across the
	// child. Neither the child nor its duplicate may call LOCK_UN on this lock.
	if unix.Flock(r.UpgradeCoordinatorFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrState
	}
	// Python pass_fds clears CLOEXEC on this inherited descriptor. Restore it
	// before any validation/systemctl child is started, preserving other flags.
	// Do not close or unlock the shared description held by the coordinator.
	flags, err := unix.FcntlInt(uintptr(r.UpgradeCoordinatorFD), unix.F_GETFD, 0)
	if err != nil {
		return ErrState
	}
	if _, err = unix.FcntlInt(uintptr(r.UpgradeCoordinatorFD), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return ErrState
	}
	return nil
}
