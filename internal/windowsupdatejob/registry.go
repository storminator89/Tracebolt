package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"localrmm/internal/enrollmentstate"
)

// MaxDevices bounds the explicit registry independently of the enrollment
// record limit. Membership grants nothing: each operation uses its Manager's
// exact original identity, local consent, current leaf and transaction fences.
const MaxDevices = 25

type Registry struct {
	managers map[string]*Manager
	ordered  []*Manager
}

func NewRegistry(managers []*Manager) (*Registry, error) {
	if len(managers) == 0 || len(managers) > MaxDevices {
		return nil, ErrInvalid
	}
	r := &Registry{managers: map[string]*Manager{}}
	keys, executors, grants := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var key ed25519.PublicKey
	var binding enrollmentstate.Binding
	for _, m := range managers {
		if !m.EnrollmentOwned() || !ValidBinding(m.Binding()) {
			return nil, ErrAuthority
		}
		b := m.Binding()
		if key == nil {
			key = m.PublicKey()
			binding = m.transactionStore.WindowsUpdateEnrollmentBinding()
		}
		if len(key) != ed25519.PublicKeySize || !bytes.Equal(key, m.PublicKey()) || !m.MatchesBinding(binding) || r.managers[b.DeviceID] != nil || keys[b.ExecutorKeyID] || executors[b.ExecutorID] || grants[b.GrantID] {
			return nil, ErrAuthority
		}
		keys[b.ExecutorKeyID], executors[b.ExecutorID], grants[b.GrantID] = true, true, true
		r.managers[b.DeviceID] = m
		r.ordered = append(r.ordered, m)
	}
	return r, nil
}
func (r *Registry) Manager(device string) *Manager {
	if r == nil {
		return nil
	}
	return r.managers[device]
}
func (r *Registry) Managers() []*Manager {
	if r == nil {
		return nil
	}
	return append([]*Manager(nil), r.ordered...)
}
func (r *Registry) Close() {
	for _, m := range r.Managers() {
		m.Close()
	}
}
func (r *Registry) ConfigureOperatorPolicy(allowed func(string) bool) error {
	if r == nil {
		return ErrInvalid
	}
	for _, m := range r.ordered {
		if e := m.ConfigureOperatorPolicy(allowed); e != nil {
			return e
		}
	}
	return nil
}
func (r *Registry) PublicKeys() []ed25519.PublicKey {
	if r == nil {
		return nil
	}
	out := []ed25519.PublicKey{r.ordered[0].PublicKey()}
	for _, m := range r.ordered {
		out = append(out, m.ExecutorPublicKey())
	}
	return out
}
func (r *Registry) MatchesBinding(b enrollmentstate.Binding) bool {
	if r == nil || len(r.ordered) == 0 {
		return false
	}
	for _, m := range r.ordered {
		if !m.MatchesBinding(b) || !m.OperatorPolicyConfigured() {
			return false
		}
	}
	return true
}
