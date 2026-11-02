//go:build linux

package operatorauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func journalFactorSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}
func mfaJournalFixture(t *testing.T) (*AccountJournal, string) {
	t.Helper()
	_, store, _, _ := accountFixture(t)
	initial := copySnapshot(store.snapshot)
	for i := range initial.Accounts {
		initial.Accounts[i].Factor = &AccountFactor{Version: FactorVersion, Generation: 1, State: "active", Secret: journalFactorSecret(t), LastStep: 100}
	}
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "accounts.jsonl")
	j, e := CreateAccountJournal(path, initial)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path
}
func journalFactorTransition(before AccountSnapshot, operation string) AccountTransition {
	next := copySnapshot(before)
	next.Revision++
	old := before.Accounts[1]
	target := &next.Accounts[1]
	actor := old.Operator.ID
	switch operation {
	case "factor_use":
		target.Factor.LastStep++
	case "factor_reset":
		actor = before.Accounts[0].Operator.ID
		target.Revision++
		target.RevocationFloor = old.Revision
		key, _ := factorSecret(old.Factor.Secret)
		digest := sha256.Sum256(key)
		clear(key)
		history := append(append([]string(nil), old.Factor.RetiredHashes...), hex.EncodeToString(digest[:]))
		target.Factor = &AccountFactor{Version: FactorVersion, Generation: old.Factor.Generation + 1, State: "enrollment_required", RetiredHashes: history}
	case "factor_enroll":
		target.Revision++
		target.RevocationFloor = old.Revision
		target.Factor.State = "active"
		target.Factor.LastStep = 101
	}
	return AccountTransition{PreviousRevision: before.Revision, Next: next, Audit: AccountAudit{Revision: next.Revision, ActorID: actor, TargetID: old.Operator.ID, Previous: old.Revision, Current: target.Revision, At: 1700000000 + int64(next.Revision), Operation: operation}}
}
func TestMFAJournalFactorUsePersistsWithoutChangingAccountEpoch(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	before, e := j.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	transition := journalFactorTransition(before, "factor_use")
	if e = j.Commit(ctx, transition); e != nil {
		t.Fatal(e)
	}
	// Mutating caller-owned transition records cannot alter committed state.
	transition.Next.Accounts[1].Factor.LastStep = 999
	committed, e := j.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if committed.Accounts[1].Factor.LastStep != 101 || committed.Accounts[1].Revision != before.Accounts[1].Revision || committed.Accounts[1].RevocationFloor != before.Accounts[1].RevocationFloor {
		t.Fatal("factor use mutated authority epoch or exposed mutable snapshot")
	}
	committed.Accounts[1].Factor.LastStep = 888
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenAccountJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	durable, e := reopened.Load(ctx)
	if e != nil || durable.Accounts[1].Factor.LastStep != 101 {
		t.Fatal("durable OTP floor lost", e)
	}
	replay := journalFactorTransition(durable, "factor_use")
	replay.Next.Accounts[1].Factor.LastStep = 101
	if e = reopened.Commit(ctx, replay); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("consumed OTP floor accepted after reopen")
	}
}
func TestMFAJournalRejectsCrossDomainFactorUseMutations(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	before, _ := j.Load(ctx)
	rawBefore, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(rawBefore)
	cases := map[string]func(*AccountTransition){
		"same_step":  func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.LastStep-- },
		"generation": func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.Generation++ },
		"secret":     func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.Secret = journalFactorSecret(t) },
		"authority_epoch": func(tr *AccountTransition) {
			tr.Next.Accounts[1].Revision++
			tr.Next.Accounts[1].RevocationFloor++
			tr.Audit.Current++
		},
		"permissions":   func(tr *AccountTransition) { tr.Next.Accounts[1].Operator.Capabilities = []Capability{Read} },
		"disabled":      func(tr *AccountTransition) { tr.Next.Accounts[1].Disabled = true },
		"other_account": func(tr *AccountTransition) { tr.Next.Accounts[0].Factor.LastStep++ },
		"foreign_actor": func(tr *AccountTransition) { tr.Audit.ActorID = before.Accounts[0].Operator.ID },
		"remove_factor": func(tr *AccountTransition) { tr.Next.Accounts[1].Factor = nil },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			tr := journalFactorTransition(before, "factor_use")
			alter(&tr)
			if e := j.Commit(ctx, tr); !errors.Is(e, ErrAccountConflict) {
				t.Fatalf("invalid transition accepted: %v", e)
			}
		})
	}
	rawAfter, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(rawAfter)
	if !bytes.Equal(rawBefore, rawAfter) {
		t.Fatal("rejected transition changed durable bytes")
	}
}
func TestMFAJournalResetReenrollmentAndOldEpochRejection(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	before, _ := j.Load(ctx)
	reset := journalFactorTransition(before, "factor_reset")
	if e := j.Commit(ctx, reset); e != nil {
		t.Fatal(e)
	}
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenAccountJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	pending, e := reopened.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	factor := pending.Accounts[1].Factor
	if factor.State != "enrollment_required" || factor.Secret != "" || factor.Generation != 2 || pending.Accounts[1].RevocationFloor != 1 {
		t.Fatal("reset did not retain factor requirement and retired epoch")
	}
	enroll := journalFactorTransition(pending, "factor_enroll")
	enroll.Next.Accounts[1].Factor.Secret = before.Accounts[1].Factor.Secret
	if e = reopened.Commit(ctx, enroll); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("retired authenticator secret re-enrolled")
	}
	enroll.Next.Accounts[1].Factor.Secret = journalFactorSecret(t)
	if e = reopened.Commit(ctx, enroll); e != nil {
		t.Fatal(e)
	}
	after, e := reopened.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if after.Accounts[1].Revision != 3 || after.Accounts[1].Factor.Generation != 2 || !reflect.DeepEqual(after.Accounts[0], before.Accounts[0]) {
		t.Fatal("reenrollment changed unrelated account or lost generation")
	}
	if e = reopened.Commit(ctx, reset); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("old reset transition replayed")
	}
	oldFactor := journalFactorTransition(after, "factor_use")
	oldFactor.Next.Accounts[1].Factor = journalFactorCopy(before.Accounts[1].Factor)
	oldFactor.Next.Accounts[1].Factor.LastStep = 999
	if e = reopened.Commit(ctx, oldFactor); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("retired factor substituted through use transition")
	}
}
func TestMFAJournalOrdinaryChangesCannotRemoveFactor(t *testing.T) {
	j, _ := mfaJournalFixture(t)
	before, _ := j.Load(context.Background())
	for _, op := range []string{"permissions", "disable", "credential_reset", "session_reset"} {
		t.Run(op, func(t *testing.T) {
			tr := journalFactorTransition(before, "factor_reset")
			tr.Audit.Operation = op
			tr.Next.Accounts[1].Factor = nil
			if e := j.Commit(context.Background(), tr); !errors.Is(e, ErrAccountConflict) {
				t.Fatal("ordinary change downgraded factor requirement")
			}
		})
	}
}
func factorProposalBytes(t *testing.T, s AccountSnapshot, secret string) []byte {
	t.Helper()
	a := s.Accounts[1]
	raw, e := json.Marshal(struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Secret           string `json:"secret"`
	}{"tracebolt.operator-factor-proposal.v1", s.AuthorityID, a.Operator.ID, a.Revision, secret})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestMFAFactorProposalProtectedFileAndExactBinding(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	s, _ := j.Load(ctx)
	secret := journalFactorSecret(t)
	raw := factorProposalBytes(t, s, secret)
	defer clear(raw)
	proposal := path + ".factor-" + s.Accounts[1].Operator.ID + ".json"
	if e := os.WriteFile(proposal, raw, 0600); e != nil {
		t.Fatal(e)
	}
	got, e := j.ReadFactorProposal(ctx, s.Accounts[1].Operator.ID, 1)
	if e != nil || got != secret {
		t.Fatal("protected proposal refused", e)
	}
	if _, e = j.ReadFactorProposal(ctx, s.Accounts[1].Operator.ID, 2); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("stale target revision accepted")
	}
	if _, e = j.ReadFactorProposal(ctx, "../../other", 1); !errors.Is(e, ErrAccountConflict) {
		t.Fatal("caller path accepted")
	}
	if e = os.Chmod(proposal, 0644); e != nil {
		t.Fatal(e)
	}
	if got, e = j.ReadFactorProposal(ctx, s.Accounts[1].Operator.ID, 1); !errors.Is(e, ErrConfiguration) || got != "" {
		t.Fatal("unprotected factor proposal accepted")
	}
	if e = os.Remove(proposal); e != nil {
		t.Fatal(e)
	}
	other := filepath.Join(filepath.Dir(path), "protected-target")
	if e = os.WriteFile(other, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(other, proposal); e != nil {
		t.Fatal(e)
	}
	if _, e = j.ReadFactorProposal(ctx, s.Accounts[1].Operator.ID, 1); !errors.Is(e, ErrConfiguration) {
		t.Fatal("symlink factor proposal accepted")
	}
}
func TestMFAFactorProposalParserRejectsNoncanonicalAndUnboundMaterial(t *testing.T) {
	_, store, _, _ := accountFixture(t)
	s := store.snapshot
	secret := journalFactorSecret(t)
	raw := factorProposalBytes(t, s, secret)
	defer clear(raw)
	cases := map[string][]byte{
		"duplicate":      bytes.Replace(raw, []byte(`"expectedRevision":1`), []byte(`"expectedRevision":1,"expectedRevision":1`), 1),
		"unknown":        bytes.Replace(raw, []byte(`"secret":`), []byte(`"extra":1,"secret":`), 1),
		"authority":      bytes.Replace(raw, []byte(s.AuthorityID), []byte("authority_22222222222222222222222222222222"), 1),
		"revision":       bytes.Replace(raw, []byte(`"expectedRevision":1`), []byte(`"expectedRevision":2`), 1),
		"secret_case":    bytes.Replace(raw, []byte(secret), []byte(strings.ToLower(secret)), 1),
		"secret_short":   bytes.Replace(raw, []byte(secret), []byte(secret[:len(secret)-1]), 1),
		"secret_padding": bytes.Replace(raw, []byte(secret), []byte(secret+"===="), 1),
		"null":           []byte("null"), "trailing": append(bytes.Clone(raw), 'x'), "oversize": []byte(strings.Repeat(" ", 4097)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer clear(data)
			if got, e := parseFactorProposal(data, s.AuthorityID, s.Accounts[1].Operator.ID, 1); !errors.Is(e, ErrConfiguration) || got != "" {
				t.Fatal("invalid factor proposal accepted")
			}
		})
	}
}

func TestMFAJournalLegacyFramesRemainExactAndFactorDowngradeFails(t *testing.T) {
	_, store, _, _ := accountFixture(t)
	frame := frameFor(store.snapshot, "", nil)
	current, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(current)
	// This is the old decoder's complete record schema, not a permissive map.
	type legacyAccount struct {
		ID              string       `json:"id"`
		Username        string       `json:"username"`
		PasswordHash    string       `json:"passwordHash"`
		Capabilities    []Capability `json:"capabilities"`
		Revision        uint64       `json:"revision"`
		RevocationFloor uint64       `json:"revocationFloor"`
		Disabled        bool         `json:"disabled"`
	}
	type legacyFrame struct {
		AuthorityID string          `json:"authorityId"`
		Profile     string          `json:"profile"`
		Version     string          `json:"version"`
		Revision    uint64          `json:"revision"`
		Previous    string          `json:"previous"`
		Accounts    []legacyAccount `json:"accounts"`
		Audit       *AccountAudit   `json:"audit"`
	}
	var old legacyFrame
	decoder := json.NewDecoder(bytes.NewReader(current))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&old); e != nil {
		t.Fatal("password-only frame changed old schema", e)
	}
	encoded, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(encoded)
	if !bytes.Equal(current, encoded) {
		t.Fatal("legacy canonical frame bytes changed")
	}
	frame.Accounts[1].Factor = storedFactorFor(&AccountFactor{Version: FactorVersion, Generation: 1, State: FactorActive, Secret: journalFactorSecret(t)})
	active, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(active)
	decoder = json.NewDecoder(bytes.NewReader(active))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&old) == nil {
		t.Fatal("legacy decoder silently adopted MFA authority")
	}
}

func TestMFAJournalResetRequiresActualFactorAdministratorAndExactRetirement(t *testing.T) {
	j, _ := mfaJournalFixture(t)
	before, _ := j.Load(context.Background())
	cases := map[string]func(*AccountTransition){
		"read_only_actor":    func(tr *AccountTransition) { tr.Audit.ActorID = before.Accounts[1].Operator.ID },
		"missing_retirement": func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.RetiredHashes = nil },
		"wrong_retirement": func(tr *AccountTransition) {
			tr.Next.Accounts[1].Factor.RetiredHashes = []string{strings.Repeat("a", 64)}
		},
		"remove_requirement":    func(tr *AccountTransition) { tr.Next.Accounts[1].Factor = nil },
		"keep_old_secret":       func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.Secret = before.Accounts[1].Factor.Secret },
		"keep_old_replay_floor": func(tr *AccountTransition) { tr.Next.Accounts[1].Factor.LastStep = before.Accounts[1].Factor.LastStep },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			tr := journalFactorTransition(before, "factor_reset")
			alter(&tr)
			if e := j.Commit(context.Background(), tr); !errors.Is(e, ErrAccountConflict) {
				t.Fatal("unsafe factor reset admitted")
			}
		})
	}
}

func TestMFAJournalUsesCompactCounterFramesWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	before, _ := j.Load(ctx)
	tr := journalFactorTransition(before, "factor_use")
	if e := j.Commit(ctx, tr); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("unexpected frame count")
	}
	counter := lines[1]
	if len(counter) > 768 || bytes.Contains(counter, []byte(`"accounts"`)) || bytes.Contains(counter, []byte(`"secret"`)) || bytes.Contains(counter, []byte(`"passwordHash"`)) || bytes.Contains(counter, []byte(before.Accounts[1].Factor.Secret)) {
		t.Fatal("OTP frame copied credentials or full roster")
	}
	var f accountFrame
	if e = json.Unmarshal(counter, &f); e != nil || f.FactorUse == nil || f.Accounts != nil || f.FactorUse.Generation != 1 || f.FactorUse.LastStep != 101 {
		t.Fatal("counter frame is not narrowly bound", e)
	}
	t.Logf("compact OTP frame: %d bytes", len(counter))
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenAccountJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	got, e := reopened.Load(ctx)
	if e != nil || !reflect.DeepEqual(got, tr.Next) {
		t.Fatal("compact replay changed account authority", e)
	}
}

func TestMFAJournalRejectsMalformedCompactReplay(t *testing.T) {
	ctx := context.Background()
	j, path := mfaJournalFixture(t)
	before, _ := j.Load(ctx)
	tr := journalFactorTransition(before, "factor_use")
	if e := j.Commit(ctx, tr); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	cases := map[string]func(*accountFrame){
		"generation":      func(f *accountFrame) { f.FactorUse.Generation++ },
		"noop":            func(f *accountFrame) { f.FactorUse.LastStep = 100 },
		"global_revision": func(f *accountFrame) { f.Revision++; f.Audit.Revision++ },
		"account_epoch":   func(f *accountFrame) { f.Audit.Current++; f.Audit.Previous++ },
		"actor":           func(f *accountFrame) { f.Audit.ActorID = before.Accounts[0].Operator.ID },
		"target":          func(f *accountFrame) { f.Audit.TargetID = "operator_00000000000000000000000000000003" },
		"authority":       func(f *accountFrame) { f.AuthorityID = "authority_22222222222222222222222222222222" },
		"operation":       func(f *accountFrame) { f.Audit.Operation = "permissions" },
		"missing_audit":   func(f *accountFrame) { f.Audit = nil },
		"mixed":           func(f *accountFrame) { f.Accounts = frameFor(before, "", nil).Accounts },
		"full_factor_use": func(f *accountFrame) { f.FactorUse = nil; f.Accounts = frameFor(tr.Next, "", nil).Accounts },
		"missing_counter": func(f *accountFrame) { f.FactorUse = nil },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			var f accountFrame
			if e := json.Unmarshal(lines[1], &f); e != nil {
				t.Fatal(e)
			}
			alter(&f)
			encoded, e := json.Marshal(f)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(encoded)
			invalid := append(append(append([]byte(nil), lines[0]...), '\n'), encoded...)
			invalid = append(invalid, '\n')
			defer clear(invalid)
			altered := path + "." + name
			if e = os.WriteFile(altered, invalid, 0600); e != nil {
				t.Fatal(e)
			}
			loaded, e := OpenAccountJournal(altered)
			if loaded != nil {
				loaded.Close()
			}
			if !errors.Is(e, ErrAuthorityUncertain) {
				t.Fatal("malformed compact history accepted")
			}
		})
	}
	t.Run("first_frame", func(t *testing.T) {
		var f accountFrame
		_ = json.Unmarshal(lines[1], &f)
		f.Previous = ""
		f.Revision = 1
		f.Audit.Revision = 1
		data, _ := json.Marshal(f)
		defer clear(data)
		data = append(data, '\n')
		altered := path + ".first"
		if e := os.WriteFile(altered, data, 0600); e != nil {
			t.Fatal(e)
		}
		loaded, e := OpenAccountJournal(altered)
		if loaded != nil {
			loaded.Close()
		}
		if !errors.Is(e, ErrAuthorityUncertain) {
			t.Fatal("first frame was compact instead of complete authority")
		}
	})
}

func TestMFAFactorPublicJSONRedactsSecretsButJournalRetainsThem(t *testing.T) {
	j, _ := mfaJournalFixture(t)
	snapshot, _ := j.Load(context.Background())
	secret := snapshot.Accounts[1].Factor.Secret
	for _, v := range []any{snapshot, snapshot.Accounts[1], snapshot.Accounts[1].Factor} {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(`"secret"`)) {
			clear(raw)
			t.Fatal("public JSON exposed factor secret")
		}
		clear(raw)
	}
	frame := frameFor(snapshot, "", nil)
	raw, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if !bytes.Contains(raw, []byte(secret)) {
		t.Fatal("private journal wire lost factor credential")
	}
	if !reflect.DeepEqual(frame.snapshot(), snapshot) {
		t.Fatal("private factor wire did not round-trip")
	}
}
