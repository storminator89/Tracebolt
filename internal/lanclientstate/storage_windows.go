//go:build windows

package lanclientstate

import (
	"errors"
	"os"

	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

type windowsStorage struct{ store *windowsstate.Store }

func newStorage(path string) (storage, []byte, bool, error) { return newStorageMode(path, true) }
func newStorageMode(path string, allowFresh bool) (storage, []byte, bool, error) {
	sid, err := windowsservice.LookupServiceSID()
	if err != nil {
		return nil, nil, false, ErrUnsafe
	}
	// The enrollment coordinator alone prepares a new protected child store.
	// The sender never creates a directory or repairs absent used state.
	st, err := windowsstate.Open(path, windowsagentconfig.Sender(sid, false))
	if err != nil {
		return nil, nil, false, ErrUnsafe
	}
	raw, err := st.Read("state.json")
	if errors.Is(err, os.ErrNotExist) && allowFresh {
		return &windowsStorage{st}, nil, true, nil
	}
	if err != nil {
		_ = st.Close()
		return nil, nil, false, ErrCorrupt
	}
	return &windowsStorage{st}, raw, false, nil
}
func (s *windowsStorage) verify() error {
	if s.store.Verify() != nil {
		return ErrUnsafe
	}
	return nil
}

// Windowsstate fails closed on interrupted writes. It never deletes or adopts
// temporaries automatically; cleanup is therefore a read-only verification.
func (s *windowsStorage) cleanup() error { return s.verify() }
func (s *windowsStorage) replace(raw []byte) error {
	if s.store.Write("state.json", raw) != nil {
		return ErrIO
	}
	return nil
}
func (s *windowsStorage) close() error {
	if s == nil || s.store == nil {
		return nil
	}
	if s.store.Close() != nil {
		return ErrIO
	}
	return nil
}
