package operatorauth

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"math"
	"sort"
	"sync"
	"sync/atomic"
)

const AccountVersion = "tracebolt.operator-accounts.v1"

var (
	ErrAccountConflict    = errors.New("operator account revision conflict")
	ErrAuthorityUncertain = errors.New("operator account authority is uncertain")
)

// AccountRecord is protected store input, never a public account view. Stable
// IDs/usernames cannot be reassigned. Revision also identifies credential and
// approval authority; every change retires all preceding revisions permanently.
type AccountRecord struct {
	Operator        Operator
	Revision        uint64
	RevocationFloor uint64
	Disabled        bool
}
type AccountSnapshot struct {
	AuthorityID string
	Profile     string
	Version     string
	Revision    uint64
	Accounts    []AccountRecord
}

func (AccountRecord) String() string     { return "operatorauth.AccountRecord{redacted}" }
func (AccountRecord) GoString() string   { return "operatorauth.AccountRecord{redacted}" }
func (AccountSnapshot) String() string   { return "operatorauth.AccountSnapshot{redacted}" }
func (AccountSnapshot) GoString() string { return "operatorauth.AccountSnapshot{redacted}" }

// AccountAudit deliberately contains no username, verifier, token or request text.
type AccountAudit struct {
	Revision  uint64 `json:"revision"`
	ActorID   string `json:"actorId"`
	TargetID  string `json:"targetId"`
	Previous  uint64 `json:"previous"`
	Current   uint64 `json:"current"`
	At        int64  `json:"at"`
	Operation string `json:"operation"`
}
type AccountTransition struct {
	PreviousRevision uint64
	Next             AccountSnapshot
	Audit            AccountAudit
}

func (AccountTransition) String() string   { return "operatorauth.AccountTransition{redacted}" }
func (AccountTransition) GoString() string { return "operatorauth.AccountTransition{redacted}" }

// AccountStore commits the revision AND its audit atomically and durably. It
// must never seed missing used state, silently repair a partial write, or return
// nil before durability. Any commit error freezes the affected live account;
// callers do not retry a potentially committed transition. Reload is startup-only.
type AccountStore interface {
	Load(context.Context) (AccountSnapshot, error)
	Commit(context.Context, AccountTransition) error
}

type accountVersion struct {
	record    AccountRecord
	principal principal
}
type accountEntry struct {
	lease   sync.RWMutex
	pending atomic.Bool
	current atomic.Pointer[accountVersion]
}
type liveAccounts struct {
	updates  sync.Mutex
	store    AccountStore
	snapshot AccountSnapshot          // accessed only under updates
	byID     map[string]*accountEntry // immutable map and entry identities
	byName   map[string]*accountEntry
}

func copySnapshot(s AccountSnapshot) AccountSnapshot {
	s.Accounts = append([]AccountRecord(nil), s.Accounts...)
	for i := range s.Accounts {
		s.Accounts[i].Operator.Capabilities = append([]Capability(nil), s.Accounts[i].Operator.Capabilities...)
	}
	return s
}
func validateAccounts(s AccountSnapshot) (map[string]principal, error) {
	if !enrollmentcrypto.ValidID(s.AuthorityID, "authority_") || s.Profile != "tls" || s.Version != AccountVersion || s.Revision == 0 || len(s.Accounts) == 0 || len(s.Accounts) > MaxOperators {
		return nil, ErrConfiguration
	}
	ops := make([]Operator, len(s.Accounts))
	admin := false
	for i, a := range s.Accounts {
		if a.Revision == 0 || a.Revision > s.Revision || a.RevocationFloor != a.Revision-1 {
			return nil, ErrConfiguration
		}
		ops[i] = a.Operator
		for _, c := range a.Operator.Capabilities {
			if !a.Disabled && c == ManageAccounts {
				admin = true
			}
		}
	}
	if !admin {
		return nil, ErrConfiguration
	}
	return namedPrincipals(ops)
}
func loadAccounts(ctx context.Context, store AccountStore) (*liveAccounts, []Operator, error) {
	s, err := store.Load(ctx)
	if err != nil {
		return nil, nil, ErrAuthorityUncertain
	}
	principals, err := validateAccounts(s)
	if err != nil {
		return nil, nil, err
	}
	s = copySnapshot(s)
	live := &liveAccounts{store: store, snapshot: s, byID: map[string]*accountEntry{}, byName: map[string]*accountEntry{}}
	ops := make([]Operator, len(s.Accounts))
	for i, a := range s.Accounts {
		e := &accountEntry{}
		e.current.Store(&accountVersion{a, principals[a.Operator.Username]})
		live.byID[a.Operator.ID] = e
		live.byName[a.Operator.Username] = e
		ops[i] = a.Operator
	}
	return live, ops, nil
}
func (m *Manager) LiveAccounts() bool { return m != nil && m.live != nil }
func (e *accountEntry) permits(epoch uint64, cap Capability) bool {
	if e == nil || e.pending.Load() {
		return false
	}
	v := e.current.Load()
	return v != nil && !v.record.Disabled && epoch == v.record.Revision && epoch > v.record.RevocationFloor && capabilityBit(cap) != 0 && v.principal.grants&capabilityBit(cap) != 0
}
func (s Session) accountActive() bool {
	return s.account == nil || s.account.permits(s.accountRevision, Read)
}

// ApprovalEpoch is persisted with the exact domain/job/approval digest in its
// own durable approval transaction. Zero means historical, unbound authority;
// live mode never adopts it. It is not a standalone authentication credential.
func (s Session) ApprovalEpoch() uint64 { return s.accountRevision }

// BeginActorAdmission must be acquired OUTSIDE controller/store locks and held
// through the final short commit/handoff. Do not recursively acquire it: a queued
// writer makes recursive RWMutex readers deadlock. Bool checks do not lease.
// The receipt epoch is mandatory in live mode, including after regrant/restart.
func (m *Manager) BeginActorAdmission(ctx context.Context, actor string, epoch uint64, caps ...Capability) (func(), error) {
	if m == nil || ctx == nil || ctx.Err() != nil || len(caps) == 0 {
		return nil, ErrForbidden
	}
	if m.live == nil {
		if epoch != 0 {
			return nil, ErrForbidden
		}
		for _, c := range caps {
			if !m.ActorHasCapability(actor, c) {
				return nil, ErrForbidden
			}
		}
		return func() {}, nil
	}
	e := m.live.byID[actor]
	if e == nil || e.pending.Load() {
		return nil, ErrForbidden
	}
	e.lease.RLock()
	for _, c := range caps {
		if ctx.Err() != nil || !e.permits(epoch, c) {
			e.lease.RUnlock()
			return nil, ErrForbidden
		}
	}
	var once sync.Once
	return func() { once.Do(e.lease.RUnlock) }, nil
}

type AccountChange struct {
	TargetID         string
	ExpectedRevision uint64
	Disabled         bool
	Capabilities     []Capability
	PasswordHash     string `json:"-"` // empty retains existing verifier
	ResetCredentials bool   // invalidates sessions/approvals, not an MFA implementation
}

func (AccountChange) String() string   { return "operatorauth.AccountChange{redacted}" }
func (AccountChange) GoString() string { return "operatorauth.AccountChange{redacted}" }

type AccountView struct {
	ID              string       `json:"id"`
	Revision        uint64       `json:"revision"`
	RevocationFloor uint64       `json:"revocationFloor"`
	Disabled        bool         `json:"disabled"`
	Uncertain       bool         `json:"uncertain"`
	Capabilities    []Capability `json:"capabilities"`
}

func (m *Manager) AccountViews(ctx context.Context, requester Session) ([]AccountView, error) {
	if !m.LiveAccounts() {
		return nil, ErrForbidden
	}
	release, err := requester.BeginCapability(ctx, ManageAccounts)
	if err != nil {
		return nil, err
	}
	defer release()
	m.mu.Lock()
	owned := m.requesterLocked(requester)
	m.mu.Unlock()
	if !owned {
		return nil, ErrUnauthenticated
	}
	out := make([]AccountView, 0, len(m.live.byID))
	// Startup operator order is irrelevant to authority; avoid exposing credentials.
	for id, e := range m.live.byID {
		v := e.current.Load()
		out = append(out, AccountView{id, v.record.Revision, v.record.RevocationFloor, v.record.Disabled, e.pending.Load(), append([]Capability(nil), v.record.Operator.Capabilities...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ChangeAccount linearizes durable account changes with actor dispatch leases
// and session admissions. Call without already owning a session or actor lease.
// Serializing updates BEFORE requester admission avoids crossed-admin drain
// deadlocks. Storage never calls back into this Manager.
func (m *Manager) ChangeAccount(ctx context.Context, requester Session, change AccountChange) error {
	if !m.LiveAccounts() || ctx == nil {
		return ErrForbidden
	}
	live := m.live
	live.updates.Lock()
	defer live.updates.Unlock()
	release, err := requester.BeginCapability(ctx, ManageAccounts)
	if err != nil {
		return err
	}
	defer release()
	m.mu.Lock()
	owned := m.requesterLocked(requester)
	m.mu.Unlock()
	if !owned {
		return ErrUnauthenticated
	}
	e := live.byID[change.TargetID]
	if e == nil {
		return ErrAccountConflict
	}
	old := e.current.Load()
	if e.pending.Load() {
		return ErrAuthorityUncertain
	}
	if old.record.Revision != change.ExpectedRevision {
		return ErrAccountConflict
	}
	if old.record.Revision == math.MaxUint64 || live.snapshot.Revision == math.MaxUint64 {
		return ErrAuthorityUncertain
	}
	next := copySnapshot(live.snapshot)
	next.Revision++
	operation := "permissions"
	for i := range next.Accounts {
		a := &next.Accounts[i]
		if a.Operator.ID != change.TargetID {
			continue
		}
		a.RevocationFloor = a.Revision
		a.Revision++
		a.Disabled = change.Disabled
		a.Operator.Capabilities = append([]Capability(nil), change.Capabilities...)
		if change.PasswordHash != "" {
			a.Operator.PasswordHash = change.PasswordHash
			operation = "credential_reset"
		} else if change.ResetCredentials {
			operation = "session_reset"
		} else if a.Disabled {
			operation = "disable"
		}
	}
	principals, err := validateAccounts(next)
	if err != nil {
		return err
	}
	// The unknown-user dummy verifier is immutable startup policy. Preserve its
	// work factors even for a single-account roster, before fencing any session.
	for _, principal := range principals {
		if !sameWorkFactors(principal.verifier, m.verifier) {
			return ErrConfiguration
		}
	}
	// Publish the deny fence before waiting. No fresh login, session admission or
	// actor lease can enter while an older admitted operation drains.
	m.mu.Lock()
	if ctx.Err() != nil || !m.requesterLocked(requester) || !requester.accountActive() || !m.now().Before(requester.gate.expires) {
		m.mu.Unlock()
		return ErrUnauthenticated
	}
	e.pending.Store(true)
	var targets []Session
	for _, s := range m.sessions {
		if s.actor.id == change.TargetID {
			s.markRevoked()
			targets = append(targets, s)
		}
	}
	selfSerial := requester.gate.revocationSerial.Load()
	m.mu.Unlock()
	e.lease.Lock()
	var updated AccountRecord
	for _, a := range next.Accounts {
		if a.Operator.ID == change.TargetID {
			updated = a
			break
		}
	}
	audit := AccountAudit{next.Revision, requester.ActorID(), change.TargetID, old.record.Revision, updated.Revision, m.now().UTC().Unix(), operation}
	requesterValid := ctx.Err() == nil && m.now().Before(requester.gate.expires)
	if requester.account == e {
		requesterValid = requesterValid && requester.accountRevision == old.record.Revision && requester.gate.revocationSerial.Load() == selfSerial
	} else {
		requesterValid = requesterValid && !requester.gate.revoked.Load() && requester.accountActive()
	}
	if audit.At <= 0 || !requesterValid {
		err = ErrUnauthenticated
	} else {
		err = live.store.Commit(ctx, AccountTransition{live.snapshot.Revision, next, audit})
	}
	if err == nil {
		live.snapshot = copySnapshot(next)
		e.current.Store(&accountVersion{updated, principals[updated.Operator.Username]})
		// pending remains until old sessions have drained, including self-revoke.
	}
	e.lease.Unlock()
	release()
	for _, s := range targets {
		s.gate.mu.Lock()
		s.gate.mu.Unlock()
	}
	m.mu.Lock()
	for key, s := range m.sessions {
		if s.account == e && s.gate.revoked.Load() {
			delete(m.sessions, key)
		}
	}
	m.mu.Unlock()
	if err != nil {
		return ErrAuthorityUncertain
	}
	e.pending.Store(false)
	return nil
}

// CredentialProposalStore reads one preprovisioned protected verifier proposal.
// A request can select only the existing actor/revision, never a path or verifier.
type CredentialProposalStore interface {
	ReadCredentialProposal(context.Context, string, uint64) (string, error)
}

func (m *Manager) ChangeAccountWithCredentialProposal(ctx context.Context, requester Session, change AccountChange) error {
	if !m.LiveAccounts() {
		return ErrForbidden
	}
	release, err := requester.BeginCapability(ctx, ManageAccounts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	owned := m.requesterLocked(requester)
	m.mu.Unlock()
	if !owned {
		release()
		return ErrUnauthenticated
	}
	store, ok := m.live.store.(CredentialProposalStore)
	if !ok {
		release()
		return ErrConfiguration
	}
	verifier, err := store.ReadCredentialProposal(ctx, change.TargetID, change.ExpectedRevision)
	release()
	if errors.Is(err, ErrAccountConflict) {
		return ErrAccountConflict
	}
	if errors.Is(err, ErrAuthorityUncertain) {
		return ErrAuthorityUncertain
	}
	if err != nil {
		return ErrConfiguration
	}
	// An empty verifier means "retain" to ChangeAccount, but cannot satisfy an
	// explicit credential reset. Validate even when a custom store is used.
	if _, err := parseHash(verifier); err != nil {
		return ErrConfiguration
	}
	change.PasswordHash = verifier
	return m.ChangeAccount(ctx, requester, change)
}
