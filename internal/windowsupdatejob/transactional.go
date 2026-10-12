package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"time"

	"localrmm/internal/actionpermit"
)

// TransactionStore owns enrollment credentials and job state in ONE durable
// transaction. It checks current activated-leaf validity, revocation, original
// scope and both observation/rejection floors again at the final commit. A
// separate file store wrapped in an enrollment lease cannot implement this.
// On rejection it commits only a monotonically advancing rejection-time floor;
// no changed job/envelope leaves the transaction. Uncertain commits fail closed.
type TransactionStore interface {
	WindowsUpdateEnrollmentBinding() enrollmentstate.Binding
	WindowsUpdateJobTransaction(context.Context, Binding, ed25519.PublicKey, time.Time, func(*Record, Current, time.Time) error) (Record, time.Time, error)
}

// OpenTransactional is the manager integration constructor. It creates no
// scope, key, tables, endpoint identity, executor grant or persistent access.
// A nil source selects the durable signed readiness-request/report workflow.
func OpenTransactional(ctx context.Context, store TransactionStore, b Binding, key ed25519.PrivateKey, now func() time.Time, checks ...func() error) (*Manager, error) {
	if len(checks) > 1 || store == nil || !ValidBinding(b) || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || actionpermit.Digest(key.Public().(ed25519.PublicKey)) != b.KeyID || now == nil {
		return nil, ErrInvalid
	}
	enrollment := store.WindowsUpdateEnrollmentBinding()
	if enrollment.InstanceID != b.ManagerID || enrollment.Profile != "tls" || enrollment.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil, ErrAuthority
	}
	m := &Manager{transactionStore: store, binding: b, key: bytes.Clone(key), now: now}
	if len(checks) == 1 {
		if checks[0] == nil {
			return nil, ErrInvalid
		}
		m.configurationCheck = checks[0]
	}
	e := m.transaction(ctx, func(Current, int64) error { return nil })
	if e != nil {
		clear(m.key)
		return nil, e
	}
	return m, nil
}
func (m *Manager) enrollmentTransaction(ctx context.Context, fn func(Current, int64) error) error {
	if m.failed {
		return ErrUncertain
	}
	var original Record
	ctx = WithFinalCheck(ctx, func() error {
		if m.configurationCheck != nil {
			if err := m.configurationCheck(); err != nil {
				return err
			}
		}
		old := map[string]int64{}
		priorJobs := map[string]Job{}
		for _, j := range original.Jobs {
			old[j.ID] = j.ClaimedAt
			priorJobs[j.ID] = j
		}
		for _, j := range m.record.Jobs {
			prior := priorJobs[j.ID]
			if j.Schedule != nil && (prior.Schedule == nil || j.Schedule.TriggeredAt != prior.Schedule.TriggeredAt || len(j.Envelope) > 0 && len(prior.Envelope) == 0 || j.ReadinessClaimedAt != prior.ReadinessClaimedAt || j.ClaimedAt != prior.ClaimedAt) && !m.scheduleAuthorized(&j) {
				return ErrAuthority
			}
			if j.ClaimedAt != 0 && old[j.ID] == 0 && (m.operatorAllowed == nil || !m.operatorAllowed(j.ActorID)) {
				return ErrAuthority
			}
		}
		return nil
	})
	record, _, e := m.transactionStore.WindowsUpdateJobTransaction(ctx, m.binding, m.key.Public().(ed25519.PublicKey), m.now().UTC(), func(r *Record, c Current, at time.Time) error {
		if r.Validate() != nil || r.Consent.Binding != m.binding || !bytes.Equal(r.PublicKey, m.key.Public().(ed25519.PublicKey)) {
			return ErrIntegrity
		}
		raw, err := EncodeRecord(*r)
		if err != nil {
			return err
		}
		m.record, err = DecodeRecord(raw)
		if err != nil {
			return err
		}
		m.raw = raw
		original, _ = DecodeRecord(raw)
		if err = m.current(c, at.Unix()); err != nil {
			return err
		}
		if err = fn(c, at.Unix()); err != nil {
			return err
		}
		if m.configurationCheck != nil {
			if err = m.configurationCheck(); err != nil {
				return err
			}
		}
		*r = m.record
		return nil
	})
	if e != nil {
		if e == ErrUncertain || e == ErrIntegrity {
			m.failed = true
		}
		return e
	}
	if record.Validate() != nil || record.Consent.Binding != m.binding {
		m.failed = true
		return ErrIntegrity
	}
	raw, err := EncodeRecord(record)
	if err != nil {
		m.failed = true
		return ErrIntegrity
	}
	m.record, err = DecodeRecord(raw)
	m.raw = bytes.Clone(raw)
	return err
}

// EnrollmentOwned rejects accidental production wiring of the file-backed
// source fixture seam. The public API config accepts only this constructor.
func (m *Manager) EnrollmentOwned() bool { return m != nil && m.transactionStore != nil }

func (m *Manager) MatchesStore(s TransactionStore) bool {
	return m != nil && m.transactionStore != nil && s != nil && reflect.ValueOf(m.transactionStore).Comparable() && reflect.ValueOf(s).Comparable() && m.transactionStore == s
}
func (m *Manager) MatchesBinding(b enrollmentstate.Binding) bool {
	return m != nil && m.transactionStore != nil && m.transactionStore.WindowsUpdateEnrollmentBinding() == b
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
	clear(m.key)
}
func (m *Manager) PublicKey() ed25519.PublicKey {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return nil
	}
	return bytes.Clone(m.key.Public().(ed25519.PublicKey))
}
func (m *Manager) ExecutorPublicKey() ed25519.PublicKey {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return nil
	}
	return bytes.Clone(m.record.ExecutorPublicKey)
}

// ConfigureOperatorPolicy is called once during trusted startup, never by HTTP.
// Durable approval does not revive a removed operator or permission on restart.
func (m *Manager) ConfigureOperatorPolicy(allowed func(string) bool) error {
	if m == nil || allowed == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.operatorAllowed != nil || m.failed {
		return ErrInvalid
	}
	m.operatorAllowed = allowed
	return nil
}
func (m *Manager) OperatorPolicyConfigured() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.failed && m.operatorAllowed != nil
}

type finalCheckKey struct{}

// WithFinalCheck carries trusted manager checks to the enrollment commit fence.
// Network input cannot populate this private context key.
func WithFinalCheck(ctx context.Context, check func() error) context.Context {
	previous, _ := ctx.Value(finalCheckKey{}).(func() error)
	return context.WithValue(ctx, finalCheckKey{}, func() error {
		// Inner manager configuration reads may block. Run them before the
		// outer API's live session/capability fence, never after that fence.
		if check == nil {
			return ErrAuthority
		}
		if err := check(); err != nil {
			return err
		}
		if previous != nil {
			return previous()
		}
		return nil
	})
}
func CheckFinal(ctx context.Context) error {
	check, ok := ctx.Value(finalCheckKey{}).(func() error)
	if !ok || check == nil {
		return nil
	}
	return check()
}

// RegisteredStore adds a validated, authority-free startup read. This separate
// constructor is used only by the explicitly activated multi-device registry.
// Expired/revoked members remain routable to a denied live transaction rather
// than disabling unrelated devices or being silently removed from history.
type RegisteredStore interface {
	TransactionStore
	ReadRegisteredWindowsUpdateJob(context.Context, Binding, ed25519.PublicKey) (Record, error)
}

func OpenRegisteredTransactional(ctx context.Context, store RegisteredStore, b Binding, key ed25519.PrivateKey, now func() time.Time, check func() error) (*Manager, error) {
	if ctx == nil || store == nil || !ValidBinding(b) || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || actionpermit.Digest(key.Public().(ed25519.PublicKey)) != b.KeyID || now == nil || check == nil {
		return nil, ErrInvalid
	}
	enrollment := store.WindowsUpdateEnrollmentBinding()
	if enrollment.InstanceID != b.ManagerID || enrollment.Profile != "tls" || enrollment.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil, ErrAuthority
	}
	if e := check(); e != nil {
		return nil, e
	}
	record, e := store.ReadRegisteredWindowsUpdateJob(WithFinalCheck(ctx, check), b, key.Public().(ed25519.PublicKey))
	if e != nil {
		return nil, e
	}
	if record.Validate() != nil || record.Consent.Binding != b || !bytes.Equal(record.PublicKey, key.Public().(ed25519.PublicKey)) {
		return nil, ErrIntegrity
	}
	raw, e := EncodeRecord(record)
	if e != nil {
		return nil, e
	}
	return &Manager{transactionStore: store, binding: b, key: bytes.Clone(key), now: now, configurationCheck: check, record: record, raw: raw}, nil
}
