package lanclientstate

// WindowsFullServicesUsed is an immutable used-state fence in the mandatory
// primary sender record. No sequence, pending byte, digest or binding changes.
// A missing extension root after this fence is fatal, never default-off.
func (s *State) WindowsFullServicesUsed() (bool, error) {
	v, e := s.locked()
	if e != nil {
		return false, e
	}
	defer v.mu.Unlock()
	return v.record.WindowsFullServicesUsed, nil
}

// WindowsFullServicesInitializationLease is deliberately distinct from the
// read-only inspection lease. Only the separately acknowledged local Windows
// scope initializer may set its irreversible fence. The existing primary lock
// remains held through marker, sidecar creation and consent publication.
type WindowsFullServicesInitializationLease struct{ state *State }

func AcquireWindowsFullServicesInitialization(dir, binding string) (*WindowsFullServicesInitializationLease, error) {
	s, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &WindowsFullServicesInitializationLease{state: s}, nil
}
func (l *WindowsFullServicesInitializationLease) Used() (bool, error) {
	if l == nil {
		return false, ErrClosed
	}
	return l.state.WindowsFullServicesUsed()
}
func (l *WindowsFullServicesInitializationLease) Mark() error {
	if l == nil {
		return ErrClosed
	}
	v, e := l.state.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.WindowsFullServicesUsed {
		return nil
	}
	next := v.record
	next.Version = 2
	if next.WindowsFullSoftwareUsed {
		next.Version = 3
	}
	next.WindowsFullServicesUsed = true
	return v.commit(next)
}
func (l *WindowsFullServicesInitializationLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
