//go:build windows

package enrollmentclient

import (
	"errors"
	"os"
	"slices"

	"localrmm/internal/windowsagentconfig"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// The installer prepares this fixed-schema store with the service SID before
// interactive enrollment. No Windows endpoint state is adopted or created here.
// Missing previously initialized files are rejected inside windowsstate.Open.
type localStore struct {
	storeRedaction
	store *windowsstate.Store
	sid   string
}

func openStore(path string) (*localStore, error)         { return openWindowsStore(path, false) }
func openExistingStore(path string) (*localStore, error) { return openWindowsStore(path, true) }
func openWindowsStore(path string, requireLedger bool) (*localStore, error) {
	sid, err := windowsservice.LookupServiceSID()
	if err != nil {
		return nil, ErrState
	}
	st, err := windowsstate.Open(path, windowsagentconfig.Enrollment(sid, false))
	if err != nil {
		return nil, ErrState
	}
	fail := func() (*localStore, error) { _ = st.Close(); return nil, ErrState }
	entries, err := st.Entries()
	if err != nil {
		return fail()
	}
	raw, err := st.Read("ledger.json")
	clear(raw)
	if err != nil {
		// Only an explicitly prepared, manifest-proven never-used empty store may
		// generate its first key. Resume never creates a missing identity.
		if !errors.Is(err, os.ErrNotExist) || requireLedger || len(entries) != 0 {
			return fail()
		}
	}
	return &localStore{store: st, sid: sid}, nil
}
func (s *localStore) Read(name string) ([]byte, error) {
	raw, err := s.store.Read(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrState
	}
	return raw, nil
}
func (s *localStore) Write(name string, raw []byte) error {
	if s.store.Write(name, raw) != nil {
		return ErrState
	}
	return nil
}
func (s *localStore) TelemetryExists() (bool, error) {
	names, err := s.store.Entries()
	if err != nil {
		return false, ErrState
	}
	return slices.Contains(names, "telemetry"), nil
}
func (s *localStore) EnsureTelemetry() error {
	exists, err := s.TelemetryExists()
	if err != nil || exists {
		return ErrState
	}
	child, err := s.store.CreateDirectoryStore("telemetry", windowsagentconfig.Sender(s.sid, true))
	if err != nil {
		return ErrState
	}
	if child.Close() != nil {
		return ErrState
	}
	return nil
}
func (s *localStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	if s.store.Close() != nil {
		return ErrState
	}
	return nil
}
