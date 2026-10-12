//go:build tracebolt_setup_native

package windowsstate

import "bytes"

// readSetupSnapshotLeaf owns exactly one read-only acceptance handle. Production
// Store reads do not use this helper. Even a final Close failure must discard
// provisional bytes before the controller can submit hidden invitation input.
func readSetupSnapshotLeaf(read func() ([]byte, error), verify func() error, close func() error) (raw []byte, err error) {
	if close == nil {
		return nil, ErrPolicy
	}
	defer func() {
		if closeErr := close(); closeErr != nil {
			err = closeErr
		}
		if err != nil {
			clear(raw)
			raw = nil
		}
	}()
	if read == nil || verify == nil {
		return nil, ErrPolicy
	}
	if err = verify(); err != nil {
		return nil, err
	}
	raw, err = read()
	if err != nil {
		return raw, err
	}
	if len(raw) == 0 || len(raw) > 64<<10 {
		return raw, ErrIntegrity
	}
	again, readErr := read()
	defer clear(again)
	if readErr != nil {
		return raw, readErr
	}
	if !bytes.Equal(raw, again) {
		return raw, ErrIntegrity
	}
	if err = verify(); err != nil {
		return raw, err
	}
	return raw, nil
}
