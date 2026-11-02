package operatorauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/argon2"
)

// Reserve room for the accepted adjacent step and its proof deadline.
const maxFactorStep = uint64(math.MaxInt64/30 - 2)

const FactorVersion = "tracebolt.operator-factor.totp-sha256.v1"
const FactorActive = "active"
const FactorEnrollmentRequired = "enrollment_required"

// AccountFactor is protected credential material, never an API response.
// SHA-256, eight digits and a thirty-second step are fixed by this version.
type AccountFactor struct {
	Version       string   `json:"version"`
	Generation    uint64   `json:"generation"`
	State         string   `json:"state"`
	Secret        string   `json:"-"`
	LastStep      uint64   `json:"lastStep"`
	RetiredHashes []string `json:"retiredHashes,omitempty"`
}

func (AccountFactor) String() string   { return "operatorauth.AccountFactor{redacted}" }
func (AccountFactor) GoString() string { return "operatorauth.AccountFactor{redacted}" }

type FactorProposalStore interface {
	ReadFactorProposal(context.Context, string, uint64) (string, error)
}

func factorSecret(secret string) ([]byte, bool) {
	if len(secret) != 52 {
		return nil, false
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(raw) != 32 || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw) != secret {
		clear(raw)
		return nil, false
	}
	return raw, true
}
func factorSecretDigest(secret string) (string, bool) {
	raw, ok := factorSecret(secret)
	if !ok {
		return "", false
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), true
}
func validAccountFactor(f *AccountFactor) bool {
	if f == nil {
		return true
	}
	if f.Version != FactorVersion || f.LastStep > maxFactorStep || len(f.RetiredHashes) > 16 || f.Generation != uint64(len(f.RetiredHashes))+1 {
		return false
	}
	seen := map[string]bool{}
	for _, h := range f.RetiredHashes {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != h || seen[h] {
			return false
		}
		seen[h] = true
	}
	switch f.State {
	case FactorEnrollmentRequired:
		return f.Secret == "" && f.LastStep == 0
	case FactorActive:
		digest, ok := factorSecretDigest(f.Secret)
		return ok && !seen[digest]
	}
	return false
}
func factorUsable(f *AccountFactor) bool { return f == nil || f.State == FactorActive }
func factorCode(secret string, step uint64) (string, bool) {
	key, ok := factorSecret(secret)
	if !ok {
		return "", false
	}
	defer clear(key)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	defer clear(sum)
	offset := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[int(offset):int(offset)+4]) & 0x7fffffff
	return fmt.Sprintf("%08d", n%100000000), true
}

// Match all three bounded candidates; consume the greatest match in case of
// a numerical collision. LastStep is monotonic across process restarts.
func matchFactor(f *AccountFactor, otp string, unix int64) (uint64, bool) {
	if f == nil || !validAccountFactor(f) || f.State != FactorActive || len(otp) != 8 || unix < 30 {
		return 0, false
	}
	for _, c := range []byte(otp) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := uint64(unix / 30)
	if step >= maxFactorStep {
		return 0, false
	}
	var matched uint64
	ok := false
	for _, candidate := range []uint64{step - 1, step, step + 1} {
		code, valid := factorCode(f.Secret, candidate)
		if valid && subtle.ConstantTimeCompare([]byte(code), []byte(otp)) == 1 && candidate > f.LastStep {
			matched = candidate
			ok = true
		}
	}
	return matched, ok
}

// A fresh factor proof cannot outlive its accepted time window while an older
// actor operation drains. This context key is private and not caller supplied.
type factorProofKey struct{}
type factorProofWindow struct{ start, end int64 }

func (m *Manager) factorProofContext(ctx context.Context, step uint64) (context.Context, context.CancelFunc) {
	now := m.now().Unix()
	if step > maxFactorStep || now < 30 || uint64(now/30) >= maxFactorStep {
		stopped, cancel := context.WithCancel(ctx)
		cancel()
		return stopped, cancel
	}
	end := int64(step)*30 + 60
	if end <= now || end-now > 90 {
		stopped, cancel := context.WithCancel(ctx)
		cancel()
		return stopped, cancel
	}
	ctx = context.WithValue(ctx, factorProofKey{}, factorProofWindow{now, end})
	return context.WithTimeout(ctx, time.Duration(end-now)*time.Second)
}
func (m *Manager) factorProofCurrent(ctx context.Context) bool {
	proof, ok := ctx.Value(factorProofKey{}).(factorProofWindow)
	if !ok {
		return true
	}
	now := m.now().Unix()
	return now >= proof.start && now < proof.end
}

func (m *Manager) LoginNamedMFA(ctx context.Context, peer, username, password, otp string) (Session, error) {
	return m.loginWithOTP(ctx, peer, username, password, otp, true)
}

// Caller holds live.updates. Failed durability never leaves a password-only path.
func (m *Manager) fenceFactorAccount(e *accountEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.pending.Store(true)
	for _, s := range m.sessions {
		if s.account == e {
			s.markRevoked()
		}
	}
}
func (m *Manager) consumeLoginFactorLocked(ctx context.Context, e *accountEntry, revision uint64, otp string) error {
	if ctx.Err() != nil || !e.permits(revision, Read) {
		// Password verification began with a valid account snapshot. Losing
		// that authority while hashing/waiting is session admission failure,
		// not a claim that the supplied password or OTP was incorrect.
		return ErrUnauthenticated
	}
	old := e.current.Load()
	if old.record.Factor == nil {
		if otp != "" {
			return ErrCredentials
		}
		return nil
	}
	step, ok := matchFactor(old.record.Factor, otp, m.now().Unix())
	if !ok {
		return ErrCredentials
	}
	if m.live.snapshot.Revision == math.MaxUint64 {
		return ErrAuthorityUncertain
	}
	next := copySnapshot(m.live.snapshot)
	next.Revision++
	var updated AccountRecord
	for i := range next.Accounts {
		if next.Accounts[i].Operator.ID == old.record.Operator.ID {
			next.Accounts[i].Factor.LastStep = step
			updated = next.Accounts[i]
		}
	}
	audit := AccountAudit{Revision: next.Revision, ActorID: old.record.Operator.ID, TargetID: old.record.Operator.ID, Previous: revision, Current: revision, At: m.now().UTC().Unix(), Operation: "factor_use"}
	if audit.At <= 0 {
		return ErrCredentials
	}
	if err := m.live.store.Commit(ctx, AccountTransition{m.live.snapshot.Revision, next, audit}); err != nil {
		m.fenceFactorAccount(e)
		return ErrAuthorityUncertain
	}
	m.live.snapshot = copySnapshot(next)
	e.current.Store(&accountVersion{updated, old.principal})
	return nil
}

func (m *Manager) verifyFactorPassword(ctx context.Context, peer, password string, v verifier) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.attempt(peer); err != nil {
		return err
	}
	if !validPassword(password) {
		return ErrCredentials
	}
	select {
	case m.hashing <- struct{}{}:
		defer func() { <-m.hashing }()
	default:
		return ErrBusy
	}
	secret := []byte(password)
	derived := argon2.IDKey(secret, v.salt, v.iterations, v.memory, v.parallelism, 32)
	clear(secret)
	valid := subtle.ConstantTimeCompare(derived, v.hash) == 1
	clear(derived)
	if !valid {
		return ErrCredentials
	}
	return ctx.Err()
}

// Enrollment never creates a session. A successful proof is already consumed;
// logging in requires a later unused OTP and the current account revision.
func (m *Manager) EnrollFactor(ctx context.Context, peer, username, password, otp string, expectedRevision uint64) error {
	if !m.LiveAccounts() || ctx == nil {
		return ErrForbidden
	}
	m.live.updates.Lock()
	defer m.live.updates.Unlock()
	e := m.live.byName[username]
	v := m.verifier
	if e != nil {
		v = e.current.Load().principal.verifier
	}
	if err := m.verifyFactorPassword(ctx, peer, password, v); err != nil {
		return err
	}
	if e == nil || e.pending.Load() {
		return ErrCredentials
	}
	old := e.current.Load().record
	if old.Disabled || old.Revision != expectedRevision || old.Factor != nil && old.Factor.State != FactorEnrollmentRequired {
		return ErrCredentials
	}
	if old.Revision == math.MaxUint64 || m.live.snapshot.Revision == math.MaxUint64 {
		return ErrAuthorityUncertain
	}
	store, ok := m.live.store.(FactorProposalStore)
	if !ok {
		return ErrConfiguration
	}
	secret, err := store.ReadFactorProposal(ctx, old.Operator.ID, expectedRevision)
	if err != nil {
		return err
	}
	generation := uint64(1)
	if old.Factor != nil {
		generation = old.Factor.Generation
	}
	factor := &AccountFactor{Version: FactorVersion, Generation: generation, State: FactorActive, Secret: secret}
	if old.Factor != nil {
		factor.RetiredHashes = append([]string(nil), old.Factor.RetiredHashes...)
	}
	step, ok := matchFactor(factor, otp, m.now().Unix())
	if !ok {
		return ErrCredentials
	}
	factor.LastStep = step
	ctx, cancel := m.factorProofContext(ctx, step)
	defer cancel()
	next := copySnapshot(m.live.snapshot)
	next.Revision++
	for i := range next.Accounts {
		a := &next.Accounts[i]
		if a.Operator.ID == old.Operator.ID {
			a.Factor = factor
			a.RevocationFloor = a.Revision
			a.Revision++
		}
	}
	return m.commitAccountChangeLocked(ctx, e, next, old.Operator.ID, "factor_enroll", nil, func() {})
}

// Reset requires a fresh password AND unused OTP of the authenticated requester.
// Both proof consumption and the exact target transition share updates ordering.
func (m *Manager) ResetFactor(ctx context.Context, requester Session, peer, target string, expectedRevision uint64, password, otp string) error {
	if !m.LiveAccounts() || ctx == nil {
		return ErrForbidden
	}
	m.live.updates.Lock()
	defer m.live.updates.Unlock()
	release, err := requester.BeginCapability(ctx, ManageAccounts)
	if err != nil {
		return err
	}
	defer release()
	m.mu.Lock()
	owned := m.requesterLocked(requester)
	m.mu.Unlock()
	if !owned || requester.account == nil {
		return ErrUnauthenticated
	}
	source := requester.account.current.Load()
	if source.record.Factor == nil || source.record.Factor.State != FactorActive {
		return ErrForbidden
	}
	if err := m.verifyFactorPassword(ctx, peer, password, source.principal.verifier); err != nil {
		return err
	}
	if err := m.consumeLoginFactorLocked(ctx, requester.account, requester.accountRevision, otp); err != nil {
		return err
	}
	ctx, cancel := m.factorProofContext(ctx, requester.account.current.Load().record.Factor.LastStep)
	defer cancel()
	e := m.live.byID[target]
	if e == nil {
		return ErrAccountConflict
	}
	old := e.current.Load().record
	if e.pending.Load() {
		return ErrAuthorityUncertain
	}
	if old.Revision != expectedRevision {
		return ErrAccountConflict
	}
	if old.Factor == nil || old.Factor.State != FactorActive {
		return ErrConfiguration
	}
	if len(old.Factor.RetiredHashes) >= 16 {
		return ErrConfiguration
	}
	if old.Revision == math.MaxUint64 || old.Factor.Generation == math.MaxUint64 || m.live.snapshot.Revision == math.MaxUint64 {
		return ErrAuthorityUncertain
	}
	next := copySnapshot(m.live.snapshot)
	next.Revision++
	for i := range next.Accounts {
		a := &next.Accounts[i]
		if a.Operator.ID == target {
			digest, ok := factorSecretDigest(old.Factor.Secret)
			if !ok {
				return ErrConfiguration
			}
			a.Factor = &AccountFactor{Version: FactorVersion, Generation: old.Factor.Generation + 1, State: FactorEnrollmentRequired, RetiredHashes: append(append([]string(nil), old.Factor.RetiredHashes...), digest)}
			a.RevocationFloor = a.Revision
			a.Revision++
		}
	}
	return m.commitAccountChangeLocked(ctx, e, next, requester.ActorID(), "factor_reset", &requester, release)
}
