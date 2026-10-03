package enrollmentstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

func TestReopenExactStatesAndIssuanceAtomicity(t *testing.T) {
	f, s, path := fixtureStore(t)
	ctx := context.Background()
	snapshot, err := s.CreateInvitation(ctx, f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	reopen := func() {
		t.Helper()
		s.Close()
		s = f.open(t, path)
		got, err := s.Get(ctx, snapshot.InvitationID)
		if err != nil || got != snapshot {
			t.Fatalf("reopen mismatch: %v", err)
		}
	}
	reopen()
	snapshot, err = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: control(snapshot, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	snapshot, err = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: control(snapshot, 3), DeviceID: id("agent", 1), KeyFingerprint: snapshot.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	snapshot, err = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: control(snapshot, 4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 86400})
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	intent, err := s.SigningIntent(ctx, snapshot.InvitationID, snapshot.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	cert := f.issue(t, intent)
	c := control(snapshot, 5)
	snapshot, err = s.CommitIssued(ctx, c, cert)
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	retry, err := s.CommitIssued(ctx, c, cert)
	if err != nil || retry != snapshot {
		t.Fatalf("issuance retry: %v", err)
	}
	err = s.transact(ctx, func(tx *transaction) error {
		if !bytes.Equal(tx.credentials[snapshot.InvitationID].DER, cert.DER()) {
			t.Fatal("DER was not atomically persisted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c = control(snapshot, 6)
	snapshot, err = s.Activate(ctx, c, f.activation(t, cert, c))
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	snapshot, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control(snapshot, 7), State: enrollmentstate.Revoked})
	if err != nil {
		t.Fatal(err)
	}
	reopen()
	c.Now++
	if _, err = s.Activate(ctx, c, f.activation(t, cert, c)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal(err)
	}
}
func TestNoInvalidProofStaleCASOrCanceledMutation(t *testing.T) {
	f, s, _ := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	c := control(snapshot, 5)
	wrong := c
	wrong.ExpectedRevision--
	if _, err := s.CommitIssued(ctx, wrong, cert); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := s.CommitIssued(ctx, c, enrollmentcrypto.VerifiedCertificate{}); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.CommitIssued(canceled, c, cert); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	err := s.transact(ctx, func(tx *transaction) error {
		if _, err := tx.engine.CommitIssued(ctx, c, cert); err != nil {
			return err
		}
		tx.credentials[snapshot.InvitationID] = credential{DER: cert.DER()}
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, snapshot.InvitationID)
	if err != nil || got != snapshot {
		t.Fatal("failed operation changed lifecycle")
	}
	var count int
	if s.db.QueryRow("SELECT count(*) FROM enrollment_credentials").Scan(&count) != nil || count != 0 {
		t.Fatal("failed operation retained credential")
	}
}
func TestIndependentStoresSerializeClaimAndPreserveVerifierTombstone(t *testing.T) {
	f, s, path := fixtureStore(t)
	other := f.open(t, path)
	ctx := context.Background()
	snapshot, err := s.CreateInvitation(ctx, f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	proof := f.claim(t)
	command := enrollmentstate.ClaimCommand{Control: control(snapshot, 2), ClaimID: f.challenge.ClaimID}
	var wg sync.WaitGroup
	var failed atomic.Int32
	for n := range 24 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store := s
			if n%2 == 1 {
				store = other
			}
			out, err := store.Claim(ctx, command, proof)
			if err != nil || out.Revision != 2 {
				failed.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatal("independent exact claims did not converge")
	}
	snapshot, err = s.Get(ctx, snapshot.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control(snapshot, 3), State: enrollmentstate.Canceled})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = f.open(t, path)
	create := f.createCommand()
	create.InvitationID = id("invite", 2)
	create.RequestID = id("request", 9)
	if _, err = s.CreateInvitation(ctx, create); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("reused retained invitation verifier")
	}
}
func TestIndependentIssuerAndRevocationRace(t *testing.T) {
	f, s, path := fixtureStore(t)
	other := f.open(t, path)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	var wg sync.WaitGroup
	var issueErr, revokeErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, issueErr = s.CommitIssued(ctx, control(snapshot, 5), cert) }()
	go func() {
		defer wg.Done()
		_, revokeErr = other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control(snapshot, 7), State: enrollmentstate.Revoked})
	}()
	wg.Wait()
	got, err := s.Get(ctx, snapshot.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State == enrollmentstate.Revoked {
		if revokeErr != nil || !errors.Is(issueErr, enrollmentstate.ErrState) {
			t.Fatalf("revocation did not win cleanly %v %v", issueErr, revokeErr)
		}
	} else if got.State == enrollmentstate.Issued {
		if issueErr != nil || !errors.Is(revokeErr, enrollmentstate.ErrConflict) {
			t.Fatalf("CAS race failed %v %v", issueErr, revokeErr)
		}
	} else {
		t.Fatal("invalid race result")
	}
}
func TestReopenRejectsCorruptOrPartialCredentialsAndBinding(t *testing.T) {
	for _, kind := range []string{"missing-credential", "corrupt-ledger", "wrong-version", "extra-credential", "empty-ledger", "wrong-binding"} {
		t.Run(kind, func(t *testing.T) {
			f, s, path := fixtureStore(t)
			snapshot, intent := f.toIntent(t, s)
			if _, err := s.CommitIssued(context.Background(), control(snapshot, 5), f.issue(t, intent)); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-credential":
				s.db.Exec("DELETE FROM enrollment_credentials")
			case "corrupt-ledger":
				s.db.Exec("UPDATE enrollment_state SET ledger=?", []byte("corrupt"))
			case "wrong-version":
				s.db.Exec("PRAGMA user_version=9")
			case "extra-credential":
				s.db.Exec("INSERT INTO enrollment_credentials(invitation_id,body) VALUES(?,?)", id("invite", 9), []byte(`{}`))
			case "empty-ledger":
				s.db.Exec("DELETE FROM enrollment_state")
			case "wrong-binding":
				f.config.Binding.Origin = "https://other.example"
			}
			s.Close()
			got, err := Open(path, f.config, f.issuerDER)
			if got != nil {
				got.Close()
			}
			if !errors.Is(err, ErrStorage) {
				t.Fatalf("accepted %s: %v", kind, err)
			}
		})
	}
}
func TestFilesystemProtectionAndRedaction(t *testing.T) {
	for _, kind := range []string{"file-mode", "directory-mode", "file-symlink", "ancestor-symlink", "hardlink", "sidecar-symlink", "sidecar-mode"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			base := t.TempDir()
			dir := filepath.Join(base, "private")
			if os.Mkdir(dir, 0700) != nil {
				t.Fatal("mkdir")
			}
			path := filepath.Join(dir, "state.sqlite")
			switch kind {
			case "file-mode":
				os.WriteFile(path, nil, 0644)
			case "directory-mode":
				os.Chmod(dir, 0755)
			case "file-symlink":
				target := filepath.Join(base, "target")
				os.WriteFile(target, nil, 0600)
				os.Symlink(target, path)
			case "ancestor-symlink":
				os.Symlink(dir, filepath.Join(base, "alias"))
				path = filepath.Join(base, "alias", "state.sqlite")
			case "hardlink":
				os.WriteFile(path, nil, 0600)
				os.Link(path, filepath.Join(dir, "link"))
			case "sidecar-symlink":
				os.Symlink(filepath.Join(base, "target"), path+"-wal")
			case "sidecar-mode":
				os.WriteFile(path+"-wal", nil, 0644)
			}
			s, err := Open(path, f.config, f.issuerDER)
			if s != nil {
				s.Close()
			}
			if !errors.Is(err, ErrStorage) {
				t.Fatalf("accepted insecure %s", kind)
			}
		})
	}
	f, s, path := fixtureStore(t)
	if _, err := s.CreateInvitation(context.Background(), f.createCommand()); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{s, *s} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, value)
			if !strings.Contains(out, "redacted") || strings.Contains(out, path) || strings.Contains(out, f.createCommand().InvitationHash) {
				t.Fatal("store formatting leaked private state")
			}
		}
		raw, _ := json.Marshal(value)
		if string(raw) != `{"contentsRedacted":true}` {
			t.Fatal("store JSON leaked")
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := privateStateFile(path + suffix); err != nil {
			t.Fatal("SQLite sidecar not private")
		}
	}
}
func TestExpiryAtBoundaryAndQuotaAcrossRestart(t *testing.T) {
	f := newFixture(t)
	f.config.InvitationLimit = 1
	path := filepath.Join(t.TempDir(), "private", "state.sqlite")
	s := f.open(t, path)
	snapshot, err := s.CreateInvitation(context.Background(), f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = f.open(t, path)
	c := f.createCommand()
	c.InvitationID = id("invite", 2)
	c.RequestID = id("request", 9)
	c.InvitationHash = strings.Repeat("a", 64)
	if _, err = s.CreateInvitation(context.Background(), c); !errors.Is(err, enrollmentstate.ErrCapacity) {
		t.Fatal(err)
	}
	c = f.createCommand()
	c.Now = snapshot.DeadlineAt
	if _, err = s.CreateInvitation(context.Background(), c); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), snapshot.InvitationID)
	if err != nil || got != snapshot {
		t.Fatal("expiry mutated record")
	}
}

func TestIndependentStoresBindOnlyOneCompetingGeneratedKey(t *testing.T) {
	f, s, path := fixtureStore(t)
	other := f.open(t, path)
	g := newFixture(t)
	g.challenge = f.challenge
	g.secret = f.secret
	ctx := context.Background()
	snapshot, err := s.CreateInvitation(ctx, f.createCommand())
	if err != nil {
		t.Fatal(err)
	}
	proofs := []enrollmentcrypto.VerifiedClaim{f.claim(t), g.claim(t)}
	cmd := enrollmentstate.ClaimCommand{Control: control(snapshot, 2), ClaimID: f.challenge.ClaimID}
	var wg sync.WaitGroup
	var successes [2]atomic.Int32
	var failed atomic.Int32
	for n := range 16 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store := s
			if n%2 == 1 {
				store = other
			}
			_, err := store.Claim(ctx, cmd, proofs[n%2])
			if err == nil {
				successes[n%2].Add(1)
			} else if !errors.Is(err, enrollmentstate.ErrConflict) {
				failed.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if failed.Load() != 0 || !(successes[0].Load() == 8 && successes[1].Load() == 0 || successes[0].Load() == 0 && successes[1].Load() == 8) {
		t.Fatal("competing generated keys did not converge on exactly one binding")
	}
}
func TestChangedLiveSchemaOrFilesystemFailsClosed(t *testing.T) {
	for _, kind := range []string{"extra-trigger", "sidecar-permission", "replaced-inode"} {
		t.Run(kind, func(t *testing.T) {
			f, s, path := fixtureStore(t)
			ctx := context.Background()
			snapshot, err := s.CreateInvitation(ctx, f.createCommand())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "extra-trigger":
				_, err = s.db.Exec("CREATE TRIGGER fixture_extra AFTER UPDATE ON enrollment_state BEGIN SELECT 1; END")
			case "sidecar-permission":
				err = os.Chmod(path+"-wal", 0644)
			case "replaced-inode":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.WriteFile(path, nil, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control(snapshot, 8), State: enrollmentstate.Canceled}); !errors.Is(err, ErrStorage) {
				t.Fatal("live corrupted store was still authoritative")
			}
		})
	}
}

func TestRejectExistingEmptyOrForeignDatabaseWithoutMutation(t *testing.T) {
	for _, kind := range []string{"empty", "foreign-sqlite", "malformed-bytes", "malformed-ledger"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			dir := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "state.sqlite")
			switch kind {
			case "empty":
				if os.WriteFile(path, nil, 0600) != nil {
					t.Fatal("fixture write")
				}
			case "malformed-bytes":
				if os.WriteFile(path, []byte("disposable invalid storage"), 0600) != nil {
					t.Fatal("fixture write")
				}
			case "foreign-sqlite":
				if os.WriteFile(path, nil, 0600) != nil {
					t.Fatal("fixture write")
				}
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec("CREATE TABLE foreign_fixture(id INTEGER)"); err != nil {
					t.Fatal(err)
				}
				db.Close()
			case "malformed-ledger":
				s := f.open(t, path)
				if _, err := s.db.Exec("UPDATE enrollment_state SET ledger=?", []byte("invalid")); err != nil {
					t.Fatal(err)
				}
				s.Close()
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s, err := Open(path, f.config, f.issuerDER)
			if s != nil {
				s.Close()
			}
			if !errors.Is(err, ErrStorage) {
				t.Fatal("adopted unknown existing database")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected existing database was modified")
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err = os.Lstat(path + suffix); !os.IsNotExist(err) {
					t.Fatal("rejected existing database created sidecar")
				}
			}
		})
	}
}
