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
	ID              string       `json:"id"`
	Username        string       `json:"username"`
	PasswordHash    string       `json:"passwordHash"`
	Capabilities    []Capability `json:"capabilities"`
	Revision        uint64       `json:"revision"`
	RevocationFloor uint64       `json:"revocationFloor"`
	Disabled        bool         `json:"disabled"`
}
type accountFrame struct {
	AuthorityID string          `json:"authorityId"`
	Profile     string          `json:"profile"`
	Version     string          `json:"version"`
	Revision    uint64          `json:"revision"`
	Previous    string          `json:"previous"`
	Accounts    []storedAccount `json:"accounts"`
	Audit       *AccountAudit   `json:"audit"`
}

func frameFor(s AccountSnapshot, previous string, audit *AccountAudit) accountFrame {
	f := accountFrame{AuthorityID: s.AuthorityID, Profile: s.Profile, Version: s.Version, Revision: s.Revision, Previous: previous, Audit: audit, Accounts: make([]storedAccount, len(s.Accounts))}
	for i, a := range s.Accounts {
		f.Accounts[i] = storedAccount{a.Operator.ID, a.Operator.Username, a.Operator.PasswordHash, a.Operator.Capabilities, a.Revision, a.RevocationFloor, a.Disabled}
	}
	return f
}
func (f accountFrame) snapshot() AccountSnapshot {
	s := AccountSnapshot{AuthorityID: f.AuthorityID, Profile: f.Profile, Version: f.Version, Revision: f.Revision, Accounts: make([]AccountRecord, len(f.Accounts))}
	for i, a := range f.Accounts {
		s.Accounts[i] = AccountRecord{Operator: Operator{a.ID, a.Username, a.PasswordHash, a.Capabilities}, Revision: a.Revision, RevocationFloor: a.RevocationFloor, Disabled: a.Disabled}
	}
	return s
}
func frameDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func validTransition(before AccountSnapshot, t AccountTransition) bool {
	if _, err := validateAccounts(t.Next); err != nil || before.AuthorityID != t.Next.AuthorityID || before.Profile != t.Next.Profile || before.Revision != t.PreviousRevision || t.Next.Revision != before.Revision+1 || t.Next.Revision == 0 || len(before.Accounts) != len(t.Next.Accounts) {
		return false
	}
	a := t.Audit
	if a.Revision != t.Next.Revision || a.At <= 0 || a.Current != a.Previous+1 || a.Current == 0 {
		return false
	}
	if a.Operation != "permissions" && a.Operation != "disable" && a.Operation != "credential_reset" && a.Operation != "session_reset" {
		return false
	}
	target, admin := false, false
	for i, old := range before.Accounts {
		next := t.Next.Accounts[i]
		if old.Operator.ID == a.ActorID && !old.Disabled {
			for _, c := range old.Operator.Capabilities {
				if c == ManageAccounts {
					admin = true
				}
			}
		}
		if old.Operator.ID == a.TargetID {
			target = true
			if next.Operator.ID != old.Operator.ID || next.Operator.Username != old.Operator.Username || a.Previous != old.Revision || a.Current != next.Revision || next.RevocationFloor != old.Revision {
				return false
			}
			if next.Operator.PasswordHash != old.Operator.PasswordHash && a.Operation != "credential_reset" {
				return false
			}
		} else if !reflect.DeepEqual(old, next) {
			return false
		}
	}
	return target && admin
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
		s := frame.snapshot()
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
