package lanclientstate

// WindowsFullProcessesUsed is an immutable used-state fence in the mandatory
// primary sender record. No sequence, pending byte, digest or binding changes.
// A missing extension root after this fence is fatal, never default-off.
func (s *State) WindowsFullProcessesUsed() (bool, error) {
	v, e := s.locked()
	if e != nil {
		return false, e
	}
	defer v.mu.Unlock()
	return v.record.WindowsFullProcessesUsed, nil
}

// WindowsFullProcessesInitializationLease is deliberately distinct from the
// read-only inspection lease. Only the separately acknowledged local Windows
// scope initializer may set its irreversible fence. The existing primary lock
// remains held through marker, sidecar creation and consent publication.
type WindowsFullProcessesInitializationLease struct{ state *State }

func AcquireWindowsFullProcessesInitialization(dir, binding string) (*WindowsFullProcessesInitializationLease, error) {
	s, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &WindowsFullProcessesInitializationLease{state: s}, nil
}
func (l *WindowsFullProcessesInitializationLease) Used() (bool, error) {
	if l == nil {
		return false, ErrClosed
	}
	return l.state.WindowsFullProcessesUsed()
}
func (l *WindowsFullProcessesInitializationLease) Mark() error {
	if l == nil {
		return ErrClosed
	}
	v, e := l.state.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.WindowsFullProcessesUsed {
		return nil
	}
	next := v.record
	next.Version = 4
	if next.WindowsNetworkContextUsed {
		next.Version = 5
	}
	next.WindowsFullProcessesUsed = true
	if next.WindowsUserSoftwareUsed {
		next.Version = 6
	}
	return v.commit(next)
}
func (l *WindowsFullProcessesInitializationLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
