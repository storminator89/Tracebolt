package lanclientstate

// WindowsNetworkContextUsed is an immutable used-state fence in the mandatory
// primary sender record. No sequence, pending byte, digest or binding changes.
// A missing extension root after this fence is fatal, never default-off.
func (s *State) WindowsNetworkContextUsed() (bool, error) {
	v, e := s.locked()
	if e != nil {
		return false, e
	}
	defer v.mu.Unlock()
	return v.record.WindowsNetworkContextUsed, nil
}

// WindowsNetworkContextInitializationLease is deliberately distinct from the
// read-only inspection lease. Only the separately acknowledged local Windows
// scope initializer may set its irreversible fence. The existing primary lock
// remains held through marker, sidecar creation and consent publication.
type WindowsNetworkContextInitializationLease struct{ state *State }

func AcquireWindowsNetworkContextInitialization(dir, binding string) (*WindowsNetworkContextInitializationLease, error) {
	s, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &WindowsNetworkContextInitializationLease{state: s}, nil
}
func (l *WindowsNetworkContextInitializationLease) Used() (bool, error) {
	if l == nil {
		return false, ErrClosed
	}
	return l.state.WindowsNetworkContextUsed()
}
func (l *WindowsNetworkContextInitializationLease) Mark() error {
	if l == nil {
		return ErrClosed
	}
	v, e := l.state.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.WindowsNetworkContextUsed {
		return nil
	}
	next := v.record
	next.Version = 5
	next.WindowsNetworkContextUsed = true
	return v.commit(next)
}
func (l *WindowsNetworkContextInitializationLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
