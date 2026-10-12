package lanclientstate

// WindowsUserSoftwareUsed is an immutable used-state fence in the mandatory
// primary sender record. No sequence, pending byte, digest or binding changes.
// A missing extension root after this fence is fatal, never default-off.
func (s *State) WindowsUserSoftwareUsed() (bool, error) {
	v, e := s.locked()
	if e != nil {
		return false, e
	}
	defer v.mu.Unlock()
	return v.record.WindowsUserSoftwareUsed, nil
}

// WindowsUserSoftwareInitializationLease is deliberately distinct from the
// read-only inspection lease. Only the separately acknowledged local Windows
// scope initializer may set its irreversible fence. The existing primary lock
// remains held through marker, sidecar creation and consent publication.
type WindowsUserSoftwareInitializationLease struct{ state *State }

func AcquireWindowsUserSoftwareInitialization(dir, binding string) (*WindowsUserSoftwareInitializationLease, error) {
	s, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &WindowsUserSoftwareInitializationLease{state: s}, nil
}
func (l *WindowsUserSoftwareInitializationLease) Used() (bool, error) {
	if l == nil {
		return false, ErrClosed
	}
	return l.state.WindowsUserSoftwareUsed()
}
func (l *WindowsUserSoftwareInitializationLease) Mark() error {
	if l == nil {
		return ErrClosed
	}
	v, e := l.state.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.WindowsUserSoftwareUsed {
		return nil
	}
	next := v.record
	next.Version = 6
	next.WindowsUserSoftwareUsed = true
	return v.commit(next)
}
func (l *WindowsUserSoftwareInitializationLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
