//go:build windows && tracebolt_setup_native

package windowsstate

import (
	"strings"

	"golang.org/x/sys/windows"
)

// ReadSetupReceiptSnapshot is available only to the separately gated packaged
// Setup acceptance driver. It reads a provisional admin-only receipt snapshot
// while the real worker holds its journal lease at the hidden-input prompt.
// It never opens the journal lock, changes storage, or verifies the manifest.
// The controller must perform a full Store read after worker quiescence and
// bind that authoritative outcome to the same original service and consent.
func ReadSetupReceiptSnapshot(path string, maxBytes int64) (raw []byte, err error) {
	parts, err := splitPath(path)
	if err != nil || len(parts) < 2 || maxBytes != 64<<10 {
		return nil, ErrPolicy
	}
	at := strings.LastIndex(path, `\`)
	parent, name := path[:at], path[at+1:]
	if name != "receipt.json" || !strings.HasSuffix(parent, "-installer") {
		return nil, ErrPolicy
	}
	o := Options{InstallerOnly: true}
	pins, err := pinPath(parent, o, false)
	if err != nil {
		return nil, err
	}
	b := &nativeStore{path: parent, options: o, pins: pins}
	defer func() {
		if closeErr := b.close(); closeErr != nil {
			err = closeErr
		}
		if err != nil {
			clear(raw)
			raw = nil
		}
	}()
	// The snapshot owns its receipt handle so its Close error is checked too.
	// Production Store.read and journal ownership remain untouched.
	h, err := ntOpen(b.root(), name, readAccess, 0, windows.FILE_OPEN, false, nil)
	if err != nil {
		return nil, err
	}
	var original fileID
	raw, err = readSetupSnapshotLeaf(func() ([]byte, error) {
		return readHandle(h, maxBytes)
	}, func() error {
		id, e := validateHandle(h, false, o, true)
		if e != nil || original != (fileID{}) && id != original {
			return ErrIntegrity
		}
		if e = validateFinalPath(h, path); e != nil {
			return ErrIntegrity
		}
		original = id
		return nil
	}, func() error { return windows.CloseHandle(h) })
	if err != nil {
		return raw, err
	}
	if err = b.verify(); err != nil {
		return raw, err
	}
	return raw, nil
}
