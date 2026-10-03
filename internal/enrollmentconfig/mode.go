package enrollmentconfig

import (
	"bytes"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"os"
	"path/filepath"
)

const ModeFile = "identity-mode-v2.json"
const DatabaseFile = "enrollment-v2.db"

// RejectEnrollmentMode prevents an existing v2 ledger from silently returning
// to manual-v1 operation, including an interrupted mode-marker initialization.
func RejectEnrollmentMode(dir string) error {
	for _, name := range []string{ModeFile, DatabaseFile, DatabaseFile + "-wal", DatabaseFile + "-shm", DatabaseFile + "-journal"} {
		if _, e := os.Lstat(filepath.Join(dir, name)); e == nil || !os.IsNotExist(e) {
			return ErrConfiguration
		}
	}
	return nil
}

// PrepareMode persists the exact identity/profile/trust binding after all
// material and existing registry checks. Tombstones count as legacy entries.
// It never rewrites or adopts an existing mismatched marker.
func (m Material) PrepareMode(dir string, legacyEntries int) error {
	if m.value == nil || dir != m.value.lan.StateDirectory || legacyEntries != 0 {
		return ErrConfiguration
	}
	path := filepath.Join(dir, ModeFile)
	if lanstore.ValidateStateFile(path) != nil {
		return ErrConfiguration
	}
	expected := m.marker()
	if _, e := os.Lstat(path); e == nil {
		raw, e := lanconfig.ReadProtected(path, true, 8192)
		if e != nil || !bytes.Equal(raw, expected) {
			return ErrConfiguration
		}
		return nil
	} else if !os.IsNotExist(e) {
		return ErrConfiguration
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(filepath.Join(dir, DatabaseFile+suffix)); e == nil || !os.IsNotExist(e) {
			return ErrConfiguration
		}
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrConfiguration
	}
	_, e = f.Write(expected)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrConfiguration
	}
	d, e := os.Open(dir)
	if e != nil {
		return ErrConfiguration
	}
	e = d.Sync()
	ce = d.Close()
	if e != nil || ce != nil {
		return ErrConfiguration
	}
	return nil
}
