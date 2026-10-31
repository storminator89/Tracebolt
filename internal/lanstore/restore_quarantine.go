package lanstore

import (
	"errors"
	"os"
	"path/filepath"
)

// RestoreQuarantineFile is a fixed, nonsecret, deny-only marker. Its contents,
// age and integrity never establish the freshness of restored authority.
const RestoreQuarantineFile = "restore-quarantine"

var ErrRestoreQuarantined = errors.New("manager state is in restore quarantine; keep writers stopped and reconcile current authority independently; no release command is available")

// CheckRestoreQuarantine is read-only. Any object at the marker path, including
// an empty/partial file, directory or dangling symlink, denies startup. Failure
// to inspect the protected path also fails closed. A missing marker is NOT proof
// against rollback: an unannounced replacement of the whole state directory
// cannot be detected using that same directory alone.
func CheckRestoreQuarantine(dir string) error {
	absolute, err := restoreQuarantineDirectory(dir)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(absolute, RestoreQuarantineFile)); err == nil {
		return ErrRestoreQuarantined
	}
	if !os.IsNotExist(err) {
		return ErrStorage
	}
	return nil
}

// MarkRestoreQuarantine exclusively creates and syncs a deny-only marker in an
// existing private directory. The caller must have stopped every manager writer;
// all concurrent/automatic starts must remain disabled through establishment.
// This function does not stop a live manager or fence work already admitted.
// Nothing is removed or overwritten. On any write/sync error, retain the marker
// and treat the outcome as uncertain; even partial marker bytes deny startup.
// There is deliberately no clear, release, reset or reauthorization operation.
func MarkRestoreQuarantine(dir string) error {
	absolute, err := restoreQuarantineDirectory(dir)
	if err != nil || privateStateDirectory(absolute) != nil {
		return ErrStorage
	}
	path := filepath.Join(absolute, RestoreQuarantineFile)
	if err = CheckRestoreQuarantine(absolute); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		// A concurrent creator can only make the decision more restrictive.
		if _, statErr := os.Lstat(path); statErr == nil {
			return ErrRestoreQuarantined
		}
		return ErrStorage
	}
	_, writeErr := file.WriteString("tracebolt.restore-quarantine.v1\nindependent-current-authority-reconciliation-required\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrStorage
	}
	directory, err := os.Open(absolute)
	if err != nil {
		return ErrStorage
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStorage
	}
	return nil
}

func restoreQuarantineDirectory(dir string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", ErrStorage
	}
	absolute, err := safePath(dir)
	if err != nil {
		return "", ErrStorage
	}
	if _, err = os.Lstat(absolute); os.IsNotExist(err) {
		// Ordinary fresh startup may create its private directory later. Mark
		// never creates it: it separately requires privateStateDirectory.
		return absolute, nil
	}
	if err != nil || privateStateDirectory(absolute) != nil {
		return "", ErrStorage
	}
	return absolute, nil
}
