//go:build linux

package operatorauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
)

const maxAccountJournal = 32 << 20
const maxAccountFrame = 128 << 10

// AccountJournal is an append-only, fsynced authority/audit chain. A partial tail,
// missing file, chain conflict or write uncertainty is never repaired or reseeded.
// Protection assumes the manager UID/root are trusted; an attacker able to roll
// back the entire protected filesystem is outside this local monotonicity claim.
type AccountJournal struct {
	mu       sync.Mutex
	file     *os.File
	snapshot AccountSnapshot
	previous string
	size     int64
	at       int64
	failed   bool
	syncFile func() error // nil in production; deterministic failure seam in tests
}

func (*AccountJournal) String() string   { return "operatorauth.AccountJournal{redacted}" }
func (*AccountJournal) GoString() string { return "operatorauth.AccountJournal{redacted}" }

type storedAccount struct {
	ID              string        `json:"id"`
	Username        string        `json:"username"`
	PasswordHash    string        `json:"passwordHash"`
	Capabilities    []Capability  `json:"capabilities"`
	Revision        uint64        `json:"revision"`
	RevocationFloor uint64        `json:"revocationFloor"`
	Disabled        bool          `json:"disabled"`
	Factor          *storedFactor `json:"factor,omitempty"`
}

// Only this private wire type marshals factor secrets. Public AccountFactor,
// AccountRecord and AccountSnapshot values never expose them through JSON.
type storedFactor struct {
	Version       string   `json:"version"`
	Generation    uint64   `json:"generation"`
	State         string   `json:"state"`
	Secret        string   `json:"secret,omitempty"`
	LastStep      uint64   `json:"lastStep"`
	RetiredHashes []string `json:"retiredHashes,omitempty"`
}

func (storedFactor) String() string   { return "operatorauth.storedFactor{redacted}" }
func (storedFactor) GoString() string { return "operatorauth.storedFactor{redacted}" }
func storedFactorFor(f *AccountFactor) *storedFactor {
	if f == nil {
		return nil
	}
	return &storedFactor{Version: f.Version, Generation: f.Generation, State: f.State, Secret: f.Secret, LastStep: f.LastStep, RetiredHashes: append([]string(nil), f.RetiredHashes...)}
}
func (f *storedFactor) accountFactor() *AccountFactor {
	if f == nil {
		return nil
	}
	return &AccountFactor{Version: f.Version, Generation: f.Generation, State: f.State, Secret: f.Secret, LastStep: f.LastStep, RetiredHashes: append([]string(nil), f.RetiredHashes...)}
}

type accountFrame struct {
	AuthorityID string           `json:"authorityId"`
	Profile     string           `json:"profile"`
	Version     string           `json:"version"`
	Revision    uint64           `json:"revision"`
	Previous    string           `json:"previous"`
	Accounts    []storedAccount  `json:"accounts,omitempty"`
	Audit       *AccountAudit    `json:"audit"`
	FactorUse   *storedFactorUse `json:"factorUse,omitempty"`
}

// A use record carries no credential or account roster. Replay derives exactly
// one counter advance from the pinned previous snapshot, then validates the full
// reconstructed transition with the same rules as an in-memory writer.
type storedFactorUse struct {
	Generation uint64 `json:"generation"`
	LastStep   uint64 `json:"lastStep"`
}

func frameFor(s AccountSnapshot, previous string, audit *AccountAudit) accountFrame {
	f := accountFrame{AuthorityID: s.AuthorityID, Profile: s.Profile, Version: s.Version, Revision: s.Revision, Previous: previous, Audit: audit, Accounts: make([]storedAccount, len(s.Accounts))}
	if audit != nil && audit.Operation == "factor_use" {
		f.Accounts = nil
		for _, a := range s.Accounts {
			if a.Operator.ID == audit.TargetID && a.Factor != nil {
				f.FactorUse = &storedFactorUse{Generation: a.Factor.Generation, LastStep: a.Factor.LastStep}
				break
			}
		}
		return f
	}
	for i, a := range s.Accounts {
		f.Accounts[i] = storedAccount{ID: a.Operator.ID, Username: a.Operator.Username, PasswordHash: a.Operator.PasswordHash, Capabilities: append([]Capability(nil), a.Operator.Capabilities...), Revision: a.Revision, RevocationFloor: a.RevocationFloor, Disabled: a.Disabled, Factor: storedFactorFor(a.Factor)}
	}
	return f
}
func (f accountFrame) snapshot() AccountSnapshot {
	s := AccountSnapshot{AuthorityID: f.AuthorityID, Profile: f.Profile, Version: f.Version, Revision: f.Revision, Accounts: make([]AccountRecord, len(f.Accounts))}
	for i, a := range f.Accounts {
		s.Accounts[i] = AccountRecord{Operator: Operator{a.ID, a.Username, a.PasswordHash, append([]Capability(nil), a.Capabilities...)}, Revision: a.Revision, RevocationFloor: a.RevocationFloor, Disabled: a.Disabled, Factor: a.Factor.accountFactor()}
	}
	return s
}
func frameDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Factor values are immutable snapshot input. Never share their pointers with a
// frame or with a caller; neither marshaling nor replay may mutate live authority.
func journalFactorCopy(f *AccountFactor) *AccountFactor {
	if f == nil {
		return nil
	}
	copy := *f
	copy.RetiredHashes = append([]string(nil), f.RetiredHashes...)
	return &copy
}

func validTransition(before AccountSnapshot, t AccountTransition) bool {
	if _, err := validateAccounts(t.Next); err != nil || before.AuthorityID != t.Next.AuthorityID || before.Profile != t.Next.Profile || before.Version != t.Next.Version || before.Revision != t.PreviousRevision || t.Next.Revision != before.Revision+1 || t.Next.Revision == 0 || len(before.Accounts) != len(t.Next.Accounts) {
		return false
	}
	a := t.Audit
	if a.Revision != t.Next.Revision || a.At <= 0 || a.Current == 0 {
		return false
	}
	use := a.Operation == "factor_use"
	selfEnrollment := a.Operation == "factor_enroll"
	factorReset := a.Operation == "factor_reset"
	if use {
		if a.Current != a.Previous || a.ActorID != a.TargetID {
			return false
		}
	} else if a.Current != a.Previous+1 {
		return false
	}
	if a.Operation != "permissions" && a.Operation != "disable" && a.Operation != "credential_reset" && a.Operation != "session_reset" && !use && !selfEnrollment && !factorReset {
		return false
	}
	if selfEnrollment && a.ActorID != a.TargetID {
		return false
	}
	target, admin, factorAdmin := false, false, false
	for i, old := range before.Accounts {
		next := t.Next.Accounts[i]
		if old.Operator.ID == a.ActorID && !old.Disabled && (old.Factor == nil || old.Factor.State == "active") {
			for _, c := range old.Operator.Capabilities {
				if c == ManageAccounts {
					admin = true
					factorAdmin = old.Factor != nil && old.Factor.State == "active"
				}
			}
		}
		if old.Operator.ID != a.TargetID {
			if !reflect.DeepEqual(old, next) {
				return false
			}
			continue
		}
		target = true
		if next.Operator.ID != old.Operator.ID || next.Operator.Username != old.Operator.Username || a.Previous != old.Revision || a.Current != next.Revision {
			return false
		}
		if use {
			if old.Disabled || old.Factor == nil || next.Factor == nil || old.Factor.State != "active" || next.Factor.LastStep <= old.Factor.LastStep {
				return false
			}
			comparison := next
			comparison.Factor = journalFactorCopy(next.Factor)
			comparison.Factor.LastStep = old.Factor.LastStep
			if !reflect.DeepEqual(old, comparison) {
				return false
			}
			continue
		}
		if next.RevocationFloor != old.Revision {
			return false
		}
		previousVerifier, previousErr := parseHash(old.Operator.PasswordHash)
		nextVerifier, nextErr := parseHash(next.Operator.PasswordHash)
		if previousErr != nil || nextErr != nil || !sameWorkFactors(previousVerifier, nextVerifier) {
			return false
		}
		if next.Operator.PasswordHash != old.Operator.PasswordHash && a.Operation != "credential_reset" {
			return false
		}
		if selfEnrollment || factorReset {
			// These transitions change only factor authority and the account epoch.
			comparison := next
			comparison.Factor = old.Factor
			comparison.Revision, comparison.RevocationFloor = old.Revision, old.RevocationFloor
			if !reflect.DeepEqual(old, comparison) || next.Factor == nil {
				return false
			}
			if selfEnrollment {
				if old.Disabled || next.Factor.State != "active" || next.Factor.LastStep == 0 {
					return false
				}
				generation := uint64(1)
				if old.Factor != nil {
					if old.Factor.State != "enrollment_required" {
						return false
					}
					generation = old.Factor.Generation
				}
				if next.Factor.Generation != generation || old.Factor != nil && !reflect.DeepEqual(next.Factor.RetiredHashes, old.Factor.RetiredHashes) || old.Factor == nil && len(next.Factor.RetiredHashes) != 0 {
					return false
				}
			} else {
				if old.Factor == nil || old.Factor.State != "active" || next.Factor.State != "enrollment_required" || next.Factor.Generation == 0 || next.Factor.Generation != old.Factor.Generation+1 || next.Factor.Secret != "" || next.Factor.LastStep != 0 {
					return false
				}
				key, ok := factorSecret(old.Factor.Secret)
				if !ok {
					return false
				}
				digest := sha256.Sum256(key)
				clear(key)
				history := append(append([]string(nil), old.Factor.RetiredHashes...), hex.EncodeToString(digest[:]))
				if !reflect.DeepEqual(next.Factor.RetiredHashes, history) {
					return false
				}

			}
		} else if !reflect.DeepEqual(old.Factor, next.Factor) {
			return false
		}
	}
	return target && (use || selfEnrollment || admin && (!factorReset || factorAdmin))
}

// The public path constructors enforce the existing Linux ancestor ownership
// boundary. They do not chmod/chown/create directories or accept symlinks.
func accountJournalParent(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return false
		}
		if dir == filepath.Dir(path) && (st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0) {
			return false
		}
		if filepath.Dir(dir) == dir {
			return true
		}
	}
}
func accountJournalFile(f *os.File) bool {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func CreateAccountJournal(path string, initial AccountSnapshot) (*AccountJournal, error) {
	if !accountJournalParent(path) {
		return nil, ErrConfiguration
	}
	if initial.Revision != 1 {
		return nil, ErrConfiguration
	}
	for _, a := range initial.Accounts {
		if a.Revision != 1 || a.RevocationFloor != 0 {
			return nil, ErrConfiguration
		}
	}
	if _, err := validateAccounts(initial); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrAuthorityUncertain
	}
	j, err := createAccountJournalFile(f, initial)
	if err != nil {
		f.Close()
		return nil, err
	}
	d, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = d.Sync()
		closeErr := d.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		j.Close()
		return nil, ErrAuthorityUncertain
	}
	return j, nil
}

// Descriptor fixture seam: callers of the public constructors cannot bypass
// path checks. Tests use a real private file to exercise append/fsync/reopen even
// in containers whose root ownership fails the production ancestor policy.
func createAccountJournalFile(f *os.File, initial AccountSnapshot) (*AccountJournal, error) {
	if !accountJournalFile(f) || initial.Revision != 1 {
		return nil, ErrConfiguration
	}
	if _, err := validateAccounts(initial); err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	if info.Size() != 0 {
		return nil, ErrAccountConflict
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrAuthorityUncertain
	}
	j := &AccountJournal{file: f}
	if err := j.append(frameFor(initial, "", nil)); err != nil {
		return nil, err
	}
	j.snapshot = copySnapshot(initial)
	return j, nil
}
func OpenAccountJournal(path string) (*AccountJournal, error) {
	if !accountJournalParent(path) {
		return nil, ErrConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrAuthorityUncertain
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrAuthorityUncertain
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrAuthorityUncertain
	}
	j, err := openAccountJournalFile(f)
	if err != nil {
		f.Close()
	}
	return j, err
}
func openAccountJournalFile(f *os.File) (*AccountJournal, error) {
	if !accountJournalFile(f) {
		return nil, ErrConfiguration
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrAuthorityUncertain
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxAccountJournal+1))
	defer clear(raw)
	if err != nil || len(raw) == 0 || len(raw) > maxAccountJournal || raw[len(raw)-1] != '\n' {
		return nil, ErrAuthorityUncertain
	}
	j := &AccountJournal{file: f, size: int64(len(raw))}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	for i, line := range lines {
		if len(line) == 0 || len(line) > maxAccountFrame {
			return nil, ErrAuthorityUncertain
		}
		var frame accountFrame
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&frame) != nil {
			return nil, ErrAuthorityUncertain
		}
		exact, err := json.Marshal(frame)
		same := err == nil && bytes.Equal(exact, line)
		clear(exact)
		if !same || frame.Previous != j.previous {
			return nil, ErrAuthorityUncertain
		}
		var s AccountSnapshot
		if frame.FactorUse != nil {
			if i == 0 || frame.Audit == nil || frame.Audit.Operation != "factor_use" || frame.Accounts != nil {
				return nil, ErrAuthorityUncertain
			}
			s = copySnapshot(j.snapshot)
			s.AuthorityID, s.Profile, s.Version, s.Revision = frame.AuthorityID, frame.Profile, frame.Version, frame.Revision
			found := false
			for n := range s.Accounts {
				a := &s.Accounts[n]
				if a.Operator.ID == frame.Audit.TargetID {
					if a.Factor == nil || a.Factor.Generation != frame.FactorUse.Generation {
						return nil, ErrAuthorityUncertain
					}
					a.Factor.LastStep = frame.FactorUse.LastStep
					found = true
					break
				}
			}
			if !found {
				return nil, ErrAuthorityUncertain
			}
		} else {
			// factor_use has exactly one encoding. It cannot smuggle a complete
			// account mutation or silently omit its consumed-counter evidence.
			if frame.Audit != nil && frame.Audit.Operation == "factor_use" {
				return nil, ErrAuthorityUncertain
			}
			s = frame.snapshot()
		}
		if _, err := validateAccounts(s); err != nil {
			return nil, ErrAuthorityUncertain
		}
		if i == 0 {
			if s.Revision != 1 || frame.Audit != nil {
				return nil, ErrAuthorityUncertain
			}
			for _, a := range s.Accounts {
				if a.Revision != 1 {
					return nil, ErrAuthorityUncertain
				}
			}
		} else {
			if frame.Audit == nil || frame.Audit.At < j.at || !validTransition(j.snapshot, AccountTransition{j.snapshot.Revision, s, *frame.Audit}) {
				return nil, ErrAuthorityUncertain
			}
			j.at = frame.Audit.At
		}
		j.snapshot = s
		j.previous = frameDigest(line)
	}
	return j, nil
}
func (j *AccountJournal) append(frame accountFrame) error {
	raw, err := json.Marshal(frame)
	defer clear(raw)
	if err != nil || len(raw) > maxAccountFrame || j.size+int64(len(raw))+1 > maxAccountJournal {
		return ErrAuthorityUncertain
	}
	info, err := j.file.Stat()
	if err != nil || info.Size() != j.size {
		j.failed = true
		return ErrAuthorityUncertain
	}
	data := append(raw, '\n')
	defer clear(data)
	n, err := j.file.WriteAt(data, j.size)
	if err == nil && n == len(data) {
		if j.syncFile != nil {
			err = j.syncFile()
		} else {
			err = j.file.Sync()
		}
	}
	if err != nil || n != len(data) {
		j.failed = true
		return ErrAuthorityUncertain
	}
	j.size += int64(len(data))
	j.previous = frameDigest(raw)
	return nil
}
func (j *AccountJournal) Load(ctx context.Context) (AccountSnapshot, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || ctx.Err() != nil {
		return AccountSnapshot{}, ErrAuthorityUncertain
	}
	return copySnapshot(j.snapshot), nil
}
func (j *AccountJournal) Commit(ctx context.Context, t AccountTransition) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || ctx.Err() != nil {
		return ErrAuthorityUncertain
	}
	if t.Audit.At < j.at || !validTransition(j.snapshot, t) {
		return ErrAccountConflict
	}
	if err := j.append(frameFor(t.Next, j.previous, &t.Audit)); err != nil {
		j.failed = true
		return err
	}
	j.snapshot = copySnapshot(t.Next)
	j.at = t.Audit.At
	return nil
}
func (j *AccountJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.failed = true
	return j.file.Close()
}

// ReadCredentialProposal never accepts request-supplied paths. The custodian
// provides one private adjacent file, bound to the authority/actor/revision.
// Successful transition leaves it in place; stale proposals cannot be reused.
func (j *AccountJournal) ReadCredentialProposal(ctx context.Context, id string, revision uint64) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || ctx.Err() != nil {
		return "", ErrAuthorityUncertain
	}
	found := false
	for _, a := range j.snapshot.Accounts {
		if a.Operator.ID == id && a.Revision == revision {
			found = true
		}
	}
	if !found {
		return "", ErrAccountConflict
	}
	path := j.file.Name() + ".credential-" + id + ".json"
	if !accountJournalParent(path) {
		return "", ErrConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return "", ErrConfiguration
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", ErrConfiguration
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !accountJournalFile(f) {
		return "", ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 {
		return "", ErrConfiguration
	}
	return parseCredentialProposal(raw, j.snapshot.AuthorityID, id, revision)
}

// parseCredentialProposal validates bytes only. Production invokes it only after
// the protected descriptor and bounded read checks in ReadCredentialProposal.
func parseCredentialProposal(raw []byte, authorityID, id string, revision uint64) (string, error) {
	if len(raw) > 4096 {
		return "", ErrConfiguration
	}
	var proposal struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		PasswordHash     string `json:"passwordHash"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&proposal) != nil {
		return "", ErrConfiguration
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return "", ErrConfiguration
	}
	canonical, err := json.Marshal(proposal)
	defer clear(canonical)
	if err != nil || !bytes.Equal(compact.Bytes(), canonical) || proposal.Version != "tracebolt.operator-credential-proposal.v1" || proposal.AuthorityID != authorityID || proposal.ActorID != id || proposal.ExpectedRevision != revision {
		return "", ErrConfiguration
	}
	if _, err := parseHash(proposal.PasswordHash); err != nil {
		return "", err
	}
	return proposal.PasswordHash, nil
}
