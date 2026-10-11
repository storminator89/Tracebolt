package lanclientstate

// WindowsFullSoftwareUsed is an immutable used-state fence in the mandatory
// primary sender record. No sequence, pending byte, digest or binding changes.
// A missing extension root after this fence is fatal, never default-off.
func (s *State) WindowsFullSoftwareUsed() (bool, error) {
	v, e := s.locked()
	if e != nil {
		return false, e
	}
	defer v.mu.Unlock()
	return v.record.WindowsFullSoftwareUsed, nil
}

// WindowsFullSoftwareInitializationLease is deliberately distinct from the
// read-only inspection lease. Only the separately acknowledged local Windows
// scope initializer may set its irreversible fence. The existing primary lock
// remains held through marker, sidecar creation and consent publication.
type WindowsFullSoftwareInitializationLease struct{ state *State }

func AcquireWindowsFullSoftwareInitialization(dir, binding string) (*WindowsFullSoftwareInitializationLease, error) {
	s, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &WindowsFullSoftwareInitializationLease{state: s}, nil
}
func (l *WindowsFullSoftwareInitializationLease) Used() (bool, error) {
	if l == nil {
		return false, ErrClosed
	}
	return l.state.WindowsFullSoftwareUsed()
}
func (l *WindowsFullSoftwareInitializationLease) Mark() error {
	if l == nil {
		return ErrClosed
	}
	v, e := l.state.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.WindowsFullSoftwareUsed {
		return nil
	}
	next := v.record
	next.Version = 3
	if next.WindowsFullProcessesUsed {
		next.Version = 4
	}
	if next.WindowsNetworkContextUsed {
		next.Version = 5
	}
	next.WindowsFullSoftwareUsed = true
	if next.WindowsUserSoftwareUsed {
		next.Version = 6
	}
	return v.commit(next)
}
func (l *WindowsFullSoftwareInitializationLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
