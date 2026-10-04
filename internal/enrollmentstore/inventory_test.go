package enrollmentstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
)

func completeFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	f.challenge.CollectionProfile = f.config.Binding.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	path := filepath.Join(t.TempDir(), "private", "complete.sqlite")
	s := f.open(t, path)
	snap, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	var e error
	snap, e = s.CommitIssued(context.Background(), control(snap, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	c := control(snap, 6)
	snap, e = s.Activate(context.Background(), c, f.activation(t, cert, c))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, cert
}
func completeGeneration(t testing.TB, device string, seq uint64, n int, at time.Time) (InventoryBinding, fullinventory.Manifest, []fullinventory.Chunk) {
	t.Helper()
	generation, e := inventorywire.GenerationID(device, seq)
	if e != nil {
		t.Fatal(e)
	}
	items := make([]linuxpackages.PackageRow, n)
	for i := range items {
		name := fmt.Sprintf("fixture-%06d", i)
		items[i] = linuxpackages.PackageRow{Name: name, Version: "1.2.3-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.2.3-1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	m, chunks, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Rows: items, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := fullinventory.ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	return InventoryBinding{seq, generation, hash}, m, chunks
}
func stageComplete(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b InventoryBinding, m fullinventory.Manifest, chunks []fullinventory.Chunk, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal(e)
	}
	for _, c := range chunks {
		if _, e := s.InventoryAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at); e != nil {
			t.Fatal(e)
		}
	}
}
func promoteComplete(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b InventoryBinding, m fullinventory.Manifest, chunks []fullinventory.Chunk, at time.Time) {
	t.Helper()
	stageComplete(t, s, snap, cert, b, m, chunks, at)
	if _, e := s.InventoryFinalize(context.Background(), snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal(e)
	}
}
func TestCompleteInventoryRealAuthorityPaginationRetryAndRestart(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 7, 769, at)
	begin, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at.Add(time.Second))
	if e != nil || retry != begin {
		t.Fatalf("begin retry refreshed receipt: %+v %v", retry, e)
	}
	for i, c := range chunks {
		got, e := s.InventoryAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(2*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		again, e := s.InventoryAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(3*time.Second))
		if e != nil || again != got {
			t.Fatalf("chunk retry changed: %+v %v", again, e)
		}
		if i == 0 {
			got, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(3*time.Second))
			if !errors.Is(e, inventoryledger.ErrIncomplete) || !reflect.DeepEqual(got, inventoryledger.Completion{}) {
				t.Fatal("partial promotion", e)
			}
		}
		at = at.Add(3 * time.Second)
	}
	completed, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second))
	if e != nil || completed.Manifest.ObservedCount != 769 {
		t.Fatal(e)
	}
	again, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second))
	if e != nil || !reflect.DeepEqual(again, completed) {
		t.Fatal("completion retry changed", e)
	}
	if e = s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("abort completed", e)
	}
	s.Close()
	s = f.open(t, path)
	now := at.Add(3 * time.Second)
	status, e := s.InventoryView(ctx, snap.Approval.DeviceID, now)
	if e != nil || status.Complete == nil || status.Complete.Manifest.ObservedCount != 769 || status.CompleteBinding != b {
		t.Fatalf("reopen status: %+v %v", status, e)
	}
	var got []linuxpackages.PackageRow
	req := inventoryledger.PageRequest{Limit: 37}
	for {
		page, e := s.InventoryPage(ctx, snap.Approval.DeviceID, req, now)
		if e != nil || page.TotalRows != 769 || page.Binding != b {
			t.Fatalf("page: %+v %v", page, e)
		}
		got = append(got, page.Items...)
		if page.Exhausted {
			break
		}
		req.Cursor = page.NextCursor
	}
	if len(got) != 769 {
		t.Fatal("prefix or duplicate", len(got))
	}
	for i, p := range got {
		if p.Name != fmt.Sprintf("fixture-%06d", i) {
			t.Fatal("order or duplication", i)
		}
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snap.InvitationID].Replay.Sequence != 0 {
			t.Fatal("inventory advanced telemetry domain")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestCompleteInventoryFailureCleanupAndDurableFloor(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 513, at)
	promoteComplete(t, s, snap, cert, old, m, chunks, at)
	next, m2, chunks2 := completeGeneration(t, snap.Approval.DeviceID, 2, 700, at.Add(time.Second))
	stageComplete(t, s, snap, cert, next, m2, chunks2[:2], at.Add(time.Second))
	if e := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	status, e := s.InventoryStatus(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(3*time.Second))
	if e != nil || status.CompleteBinding != old || status.Transfer.State != "failed" {
		t.Fatalf("failure hid old complete: %+v %v", status, e)
	}
	for {
		clean, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, next.GenerationID, at.Add(3*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if clean.Done {
			break
		}
	}
	s.Close()
	s = f.open(t, path)
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), old, m, at.Add(4*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("floor erased by cleanup", e)
	}
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), next, m2, at.Add(4*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("aborted binding reused", e)
	}
	generation, _ := inventorywire.GenerationID(snap.Approval.DeviceID, 3)
	failure := InventoryFailureReport{3, generation, at.Add(4 * time.Second), "source_missing"}
	receipt, e := s.InventoryFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.InventoryFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(6*time.Second))
	if e != nil || retry != receipt {
		t.Fatal("failure retry refreshed age", e)
	}
	failure.Reason = "source_invalid"
	if _, e = s.InventoryFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(7*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("failure mutated", e)
	}
	view, e := s.InventoryView(ctx, snap.Approval.DeviceID, at.Add(7*time.Second))
	if e != nil || view.Failure == nil || view.CompleteBinding != old || view.Complete.Manifest.ObservedCount != 513 {
		t.Fatalf("failure erased completion: %+v %v", view, e)
	}
}
func TestCompleteInventoryExpiryRetainsMetadataAndInvalidatesPages(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at.Add(-time.Hour))
	promoteComplete(t, s, snap, cert, b, m, chunks, at)
	first, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at)
	if e != nil {
		t.Fatal(e)
	}
	if page, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, Cursor: first.NextCursor}, at.Add(inventoryledger.CursorTTL)); !errors.Is(e, inventoryledger.ErrCursorExpired) || !reflect.DeepEqual(page, InventoryPageResult{}) {
		t.Fatal("expired cursor empty success", e)
	}
	expired := at.Add(23 * time.Hour)
	view, e := s.InventoryView(ctx, snap.Approval.DeviceID, expired)
	if e != nil || view.Complete == nil || view.Complete.State != "expired" || view.Complete.Manifest.ObservedCount != 300 {
		t.Fatalf("expired complete metadata lost: %+v %v", view, e)
	}
	if page, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, expired); !errors.Is(e, inventoryledger.ErrExpired) || !reflect.DeepEqual(page, InventoryPageResult{}) {
		t.Fatal("expired page empty success", e)
	}
	pending, m2, _ := completeGeneration(t, snap.Approval.DeviceID, 2, 300, expired)
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), pending, m2, expired); e != nil {
		t.Fatal(e)
	}
	view, e = s.InventoryView(ctx, snap.Approval.DeviceID, expired.Add(inventoryledger.StagingTTL))
	if e != nil || view.Transfer.State != "expired" || view.Complete.State != "expired" {
		t.Fatal("separate expiry", e)
	}
	for {
		r, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, pending.GenerationID, expired.Add(inventoryledger.StagingTTL))
		if e != nil {
			t.Fatal(e)
		}
		if r.Done {
			break
		}
	}
	view, e = s.InventoryView(ctx, snap.Approval.DeviceID, expired.Add(inventoryledger.StagingTTL))
	if e != nil || view.Transfer.State != "expired" {
		t.Fatal("pending metadata disappeared", e)
	}
}
func TestCompleteInventoryAuthorityBindingsAndRevocation(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	if _, e := s.InventoryBegin(ctx, snap.InvitationID, strings.Repeat("1", 64), b, m, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("wrong cert", e)
	}
	other, mOther, _ := completeGeneration(t, id("agent", 9), 1, 300, at)
	if _, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), other, mOther, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("device-bound generation bypass", e)
	}
	stageComplete(t, s, snap, cert, b, m, chunks, at)
	if _, e := s.InventoryStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("clock regression", e)
	}
	bad := b
	bad.Sequence++
	if _, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), bad, at); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("sequence rebind", e)
	}
	second := f.open(t, path)
	revoke := control(snap, 50)
	revoke.Now = at.Add(time.Second).Unix()
	if _, e := second.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if out, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) || !reflect.DeepEqual(out, inventoryledger.Completion{}) {
		t.Fatal("revoked promotion", e)
	}
	if _, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked read", e)
	}
	if _, e := s.InventoryView(ctx, snap.Approval.DeviceID, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked metadata", e)
	}
}
func TestCompleteInventoryStrictReopenAndLegacyCompatibility(t *testing.T) {
	t.Run("complete-extra-index", func(t *testing.T) {
		f, s, path, _, _ := completeFixture(t)
		if _, e := s.db.Exec(`CREATE INDEX rogue ON fi_rows(generation)`); e != nil {
			t.Fatal(e)
		}
		s.Close()
		before, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if got, e := Open(path, f.config, f.issuerDER); e == nil {
			got.Close()
			t.Fatal("rogue schema accepted")
		}
		after, _ := os.ReadFile(path)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("reopen mutated foreign schema")
		}
	})
	t.Run("binding", func(t *testing.T) {
		f, s, path, _, _ := completeFixture(t)
		s.Close()
		f.config.Binding.InstanceID = id("manager", 99)
		if got, e := Open(path, f.config, f.issuerDER); e == nil {
			got.Close()
			t.Fatal("foreign binding adopted")
		}
	})
	t.Run("quota-binding", func(t *testing.T) {
		f, s, path, _, _ := completeFixture(t)
		limits := inventoryLimits()
		limits.GlobalBytes--
		raw, _ := json.Marshal(limits)
		if _, e := s.db.Exec(`UPDATE fi_meta SET limits=?`, raw); e != nil {
			t.Fatal(e)
		}
		s.Close()
		if got, e := Open(path, f.config, f.issuerDER); e == nil {
			got.Close()
			t.Fatal("changed quota adopted")
		}
	})
	t.Run("legacy", func(t *testing.T) {
		f, s, path := fixtureStore(t)
		s.Close()
		f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
		f.config.RecordLimit = 25
		f.config.InvitationLimit = 25
		f.config.PendingLimit = 25
		before, _ := os.ReadFile(path)
		if got, e := Open(path, f.config, f.issuerDER); e == nil {
			got.Close()
			t.Fatal("legacy adopted")
		}
		after, _ := os.ReadFile(path)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("legacy mutated")
		}
	})
	t.Run("identity-limit", func(t *testing.T) {
		f := newFixture(t)
		f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
		f.config.RecordLimit = 26
		if got, e := Open(filepath.Join(t.TempDir(), "private", "db"), f.config, f.issuerDER); e == nil {
			got.Close()
			t.Fatal("26 identities allowed")
		}
	})
}
func TestCompleteInventoryRollbackSuppressesProvisionalWrites(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	injected := errors.New("synthetic rollback")
	e := s.transact(ctx, func(tx *transaction) error {
		if _, e := s.inventoryAuthority(tx, snap.InvitationID, cert.CertificateHash(), at); e != nil {
			return e
		}
		if _, e := completeLedger().Begin(ctx, tx.conn, snap.Approval.DeviceID, m, at); e != nil {
			return e
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	var n int
	if s.db.QueryRow(`SELECT count(*) FROM fi_generations`).Scan(&n) != nil || n != 0 {
		t.Fatal("rollback retained generation")
	}
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal("rollback spent floor", e)
	}
	// A context cancellation at COMMIT's persistence boundary must return no
	// provisional result; this injection uses the shared real transaction runner.
	var got inventoryledger.Completion
	canceled, cancel := context.WithCancel(ctx)
	got, e = inventoryledger.CommitResult(canceled, func(ctx context.Context, action func(inventoryledger.Transaction) error) error {
		return s.transact(ctx, func(tx *transaction) error {
			if e := action(tx.conn); e != nil {
				return e
			}
			cancel()
			return nil
		})
	}, func(tx inventoryledger.Transaction) (inventoryledger.Completion, error) {
		return inventoryledger.Completion{Manifest: m, StartedAt: at, CompletedAt: at}, nil
	})
	if !errors.Is(e, context.Canceled) || !reflect.DeepEqual(got, inventoryledger.Completion{}) {
		t.Fatal("uncertain commit advertised completion", e)
	}
}
func TestCompleteInventoryAdmissionAndWALReservation(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	s.inventoryCalls <- struct{}{}
	if _, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); !errors.Is(e, ErrInventoryBusy) {
		t.Fatal("unbounded admission", e)
	}
	<-s.inventoryCalls
	if e := s.transact(ctx, func(tx *transaction) error {
		var spill, pages int64
		if tx.conn.QueryRowContext(ctx, `PRAGMA cache_spill`).Scan(&spill) != nil || spill != 0 || tx.conn.QueryRowContext(ctx, `PRAGMA max_page_count`).Scan(&pages) != nil || pages != completeInventoryPages {
			t.Fatal("capacity pragmas not pinned")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// Separate raw fixture proves the cap expression without allocating a giant
	// inventory or altering a live WAL. A sparse file is ordinary ephemeral data.
	path := filepath.Join(t.TempDir(), "capacity.sqlite")
	db, e := sql.Open("sqlite", "file:"+path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA cache_spill=OFF", "PRAGMA max_page_count=131072", "CREATE TABLE fixture(id INTEGER)"} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	c, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	fake := &Store{&storeState{path: path}}
	wal, e := os.OpenFile(path+"-wal", os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = wal.Truncate(CompleteInventoryWALBytes); e != nil {
		t.Fatal(e)
	}
	wal.Close()
	if fake.inventoryCapacityBeforeCommit(ctx, c) == nil {
		t.Fatal("oversubscribed commit admitted")
	}
}

func TestCompleteInventoryCommitFailureSuppressesPromotion(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	stageComplete(t, s, snap, cert, b, m, chunks, at)
	got, e := inventoryledger.CommitResult(ctx, func(ctx context.Context, action func(inventoryledger.Transaction) error) error {
		return s.transact(ctx, func(tx *transaction) error {
			if _, e := s.inventoryAuthority(tx, snap.InvitationID, cert.CertificateHash(), at); e != nil {
				return e
			}
			if e := action(tx.conn); e != nil {
				return e
			}
			// This is a real SQLite deferred-constraint COMMIT failure, not a mocked
			// error string. The credential deletion must roll back with the promotion.
			if _, e := tx.conn.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON"); e != nil {
				return e
			}
			_, e := tx.conn.ExecContext(ctx, `DELETE FROM enrollment_credentials WHERE invitation_id=?`, snap.InvitationID)
			return e
		})
	}, func(tx inventoryledger.Transaction) (inventoryledger.Completion, error) {
		return completeLedger().Promote(ctx, tx, snap.Approval.DeviceID, b.GenerationID, at)
	})
	if !errors.Is(e, ErrStorage) || errors.Is(e, ErrBusy) || !reflect.DeepEqual(got, inventoryledger.Completion{}) {
		t.Fatal("failed COMMIT advertised result or retryable busy", e)
	}
	view, e := s.InventoryView(ctx, snap.Approval.DeviceID, at)
	if e != nil || view.Complete != nil || view.Transfer == nil || view.Transfer.State != "pending" {
		t.Fatal("failed COMMIT persisted promotion", e)
	}
	if _, e = s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal("rollback lost staged generation or credential", e)
	}
}

func TestCompleteInventoryInitialBusyAndRevocationRace(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	other := f.open(t, path)
	c, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	if _, e = other.db.ExecContext(ctx, "PRAGMA busy_timeout=1"); e != nil {
		t.Fatal(e)
	}
	got, e := other.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
	if !errors.Is(e, ErrBusy) || !reflect.DeepEqual(got, inventoryledger.BeginReceipt{}) {
		t.Fatal("initial busy leaked result or classification", e)
	}
	c.ExecContext(ctx, "ROLLBACK")
	c.Close()
	other.db.ExecContext(ctx, "PRAGMA busy_timeout=5000")
	stageComplete(t, s, snap, cert, b, m, chunks, at)
	start := make(chan struct{})
	finalized := make(chan error, 1)
	revoked := make(chan error, 1)
	go func() {
		<-start
		_, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second))
		finalized <- e
	}()
	go func() {
		<-start
		control := control(snap, 77)
		control.Now = at.Add(time.Second).Unix()
		_, e := other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked})
		revoked <- e
	}()
	close(start)
	finalizeError, revokeError := <-finalized, <-revoked
	if revokeError != nil || finalizeError != nil && !errors.Is(finalizeError, enrollmentstate.ErrState) {
		t.Fatal("authority race", finalizeError, revokeError)
	}
	if _, e = s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("post-revoke cache accepted", e)
	}
	var state string
	if s.db.QueryRow(`SELECT state FROM fi_generations WHERE device=? AND generation=?`, snap.Approval.DeviceID, b.GenerationID).Scan(&state) != nil {
		t.Fatal("generation lost")
	}
	if finalizeError == nil && state != "current" || finalizeError != nil && state != "staging" {
		t.Fatal("non-atomic promotion race", state)
	}
}

func TestCompleteInventoryQuotaPreservesPreviousAndReservation(t *testing.T) {
	if testing.Short() {
		t.Skip("synthetic48MiB runtime generation quota")
	}
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	promoteComplete(t, s, snap, cert, old, m, chunks, at)
	gen, _ := inventorywire.GenerationID(snap.Approval.DeviceID, 2)
	items := make([]linuxpackages.PackageRow, 75000)
	for i := range items {
		name := fmt.Sprintf("quota-%06d", i)
		items[i] = linuxpackages.PackageRow{Name: name, Version: "1." + strings.Repeat("2", 120), Architecture: "amd64", SourcePackage: name, SourceVersion: "1." + strings.Repeat("2", 120), SourceMapping: "binary-default", InstallState: "installed"}
	}
	m, chunks, e := fullinventory.Build(ctx, fullinventory.SourceInventory{GenerationID: gen, CollectedAt: at, Rows: items, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	h, _ := fullinventory.ManifestDigest(m)
	b := InventoryBinding{2, gen, h}
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal(e)
	}
	rejected := false
	for _, chunk := range chunks {
		var before int64
		if e = s.db.QueryRow(`SELECT stored_bytes FROM fi_budget WHERE scope=''`).Scan(&before); e != nil {
			t.Fatal(e)
		}
		receipt, e := s.InventoryAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunk, at)
		if errors.Is(e, inventoryledger.ErrQuota) {
			rejected = true
			var after int64
			if s.db.QueryRow(`SELECT stored_bytes FROM fi_budget WHERE scope=''`).Scan(&after) != nil || after != before || !reflect.DeepEqual(receipt, inventoryledger.ChunkReceipt{}) {
				t.Fatal("quota spent bytes or returned receipt")
			}
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if !rejected {
		t.Fatal("generation quota not exercised")
	}
	if _, e = s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at); !errors.Is(e, inventoryledger.ErrIncomplete) {
		t.Fatal("quota-truncated prefix promoted", e)
	}
	view, e := s.InventoryView(ctx, snap.Approval.DeviceID, at)
	if e != nil || view.CompleteBinding != old || view.Complete.Manifest.ObservedCount != 300 || view.Transfer.State != "pending" {
		t.Fatal("quota erased old generation", e)
	}
	var heldRows int64
	if s.db.QueryRow(`SELECT held_rows FROM fi_budget WHERE scope=''`).Scan(&heldRows) != nil || heldRows != 75300 {
		t.Fatal("declared reservation lost", heldRows)
	}
}

func TestCompleteInventoryRetiredCursorRemainsPinnedAndZeroIsExplicit(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	first, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	promoteComplete(t, s, snap, cert, first, m, chunks, at)
	p, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at)
	if e != nil {
		t.Fatal(e)
	}
	empty, m2, c2 := completeGeneration(t, snap.Approval.DeviceID, 2, 0, at.Add(time.Second))
	promoteComplete(t, s, snap, cert, empty, m2, c2, at.Add(time.Second))
	oldPage, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10, Cursor: p.NextCursor, GenerationID: first.GenerationID}, at.Add(2*time.Second))
	if e != nil || oldPage.Binding != first || len(oldPage.Items) != 10 || oldPage.Items[0].Name != "fixture-000010" {
		t.Fatal("cursor mixed generation", e)
	}
	zero, e := s.InventoryPage(ctx, snap.Approval.DeviceID, inventoryledger.PageRequest{Limit: 10}, at.Add(2*time.Second))
	if e != nil || zero.Binding != empty || zero.TotalRows != 0 || len(zero.Items) != 0 || !zero.Exhausted || zero.Manifest.GenerationID != empty.GenerationID {
		t.Fatalf("valid explicit zero mishandled: %+v %v", zero, e)
	}
	if _, e = s.InventoryCleanup(ctx, snap.Approval.DeviceID, first.GenerationID, at.Add(2*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("live cursor data cleaned", e)
	}
	view, e := s.InventoryView(ctx, snap.Approval.DeviceID, at.Add(2*time.Second))
	if e != nil || view.CompleteBinding != empty || view.Complete.State != "complete" || view.Complete.Manifest.ObservedCount != 0 || !view.Complete.ExpiresAt.Equal(m2.CollectedAt.Add(inventoryledger.ObservationTTL)) {
		t.Fatal("explicit complete zero status", e)
	}
}

func TestCompleteInventoryWrongProfileAndNotActivatedFailClosed(t *testing.T) {
	_, legacy, _ := fixtureStore(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, id("agent", 1), 1, 300, at)
	if _, e := legacy.InventoryBegin(ctx, id("invite", 1), strings.Repeat("1", 64), b, m, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("legacy granted inventory", e)
	}
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	f.challenge.CollectionProfile = f.config.Binding.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	s := f.open(t, filepath.Join(t.TempDir(), "private", "db"))
	snap, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	snap, e := s.CommitIssued(ctx, control(snap, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("unactivated inventory granted", e)
	}
}

func TestCompleteInventoryMaintenanceReclaimsAfterRevocationAndExpiry(t *testing.T) {
	for _, mode := range []string{"revoked", "certificate_expired", "state_expired"} {
		t.Run(mode, func(t *testing.T) {
			f, s, path, snap, cert := completeFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			retired, m1, c1 := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
			promoteComplete(t, s, snap, cert, retired, m1, c1, at)
			current, m2, c2 := completeGeneration(t, snap.Approval.DeviceID, 2, 400, at.Add(time.Second))
			promoteComplete(t, s, snap, cert, current, m2, c2, at.Add(time.Second))
			pending, m3, c3 := completeGeneration(t, snap.Approval.DeviceID, 3, 600, at.Add(2*time.Second))
			stageComplete(t, s, snap, cert, pending, m3, c3[:2], at.Add(2*time.Second))
			now := at.Add(16 * time.Minute)
			wantAgentError := enrollmentstate.ErrState
			if mode == "revoked" {
				ctrl := control(snap, 91)
				ctrl.Now = at.Add(3 * time.Second).Unix()
				if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctrl, State: enrollmentstate.Revoked}); e != nil {
					t.Fatal(e)
				}
			} else {
				now = time.Unix(snap.Intent.NotAfter+1, 0).UTC()
				wantAgentError = enrollmentstate.ErrExpired
				if mode == "state_expired" {
					ctrl := control(snap, 91)
					ctrl.Now = now.Unix()
					if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctrl, State: enrollmentstate.Expired}); e != nil {
						t.Fatal(e)
					}
					wantAgentError = enrollmentstate.ErrState
				}
			}
			if mode == "revoked" {
				if _, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, pending.GenerationID, at.Add(4*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
					t.Fatal("revocation bypassed staging eligibility", e)
				}
			}
			for _, binding := range []InventoryBinding{retired, pending} {
				for {
					result, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, binding.GenerationID, now)
					if e != nil {
						t.Fatal("eligible non-current cleanup blocked", e)
					}
					if result.RowsDeleted > inventoryledger.MaxCleanupRows || result.ChunksDeleted > inventoryledger.MaxCleanupChunks {
						t.Fatal("cleanup unbounded")
					}
					if result.Done {
						break
					}
				}
			}
			if _, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, current.GenerationID, now); !errors.Is(e, inventoryledger.ErrConflict) {
				t.Fatal("maintenance deleted current", e)
			}
			if _, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, current.GenerationID, now.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
				t.Fatal("maintenance clock reversed", e)
			}
			if _, e := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), retired, m1, now); !errors.Is(e, wantAgentError) {
				t.Fatal("maintenance relaxed agent guard", e)
			}
			if _, e := s.InventoryView(ctx, snap.Approval.DeviceID, now); !errors.Is(e, wantAgentError) {
				t.Fatal("maintenance relaxed read guard", e)
			}
			var heldRows, generations int64
			if s.db.QueryRow(`SELECT held_rows,generations FROM fi_budget WHERE scope=''`).Scan(&heldRows, &generations) != nil || heldRows != 400 || generations != 1 {
				t.Fatal("non-current reservations stranded", heldRows, generations)
			}
			s.Close()
			s = f.open(t, path)
			if e := s.transact(ctx, func(tx *transaction) error {
				r := tx.inventory[snap.InvitationID]
				if r.Binding != pending || !r.LastAt.Equal(at.Add(2*time.Second)) || r.MaintenanceAt == nil || !r.MaintenanceAt.Equal(now) {
					t.Fatal("maintenance changed floor/receipt or lost clock")
				}
				stored, e := tx.engine.Get(snap.InvitationID)
				if e != nil || stored.Approval.DeviceID != snap.Approval.DeviceID || stored.Issuance.CertificateHash != cert.CertificateHash() {
					t.Fatal("maintenance rewrote identity")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			var retained string
			if s.db.QueryRow(`SELECT current_generation FROM fi_devices WHERE device=?`, snap.Approval.DeviceID).Scan(&retained) != nil || retained != current.GenerationID {
				t.Fatal("current pointer lost")
			}
		})
	}
}

func TestCompleteInventoryMaintenanceClockConstrainsActiveAuthority(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	stageComplete(t, s, snap, cert, b, m, chunks[:1], at)
	if e := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	clean, e := s.InventoryCleanup(ctx, snap.Approval.DeviceID, b.GenerationID, at.Add(10*time.Second))
	if e != nil || !clean.Done {
		t.Fatal(e)
	}
	generation, _ := inventorywire.GenerationID(snap.Approval.DeviceID, 2)
	failure := InventoryFailureReport{Sequence: 2, GenerationID: generation, AttemptedAt: at.Add(5 * time.Second), Reason: "source_missing"}
	if _, e = s.InventoryFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(5*time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("agent clock reversed after maintenance", e)
	}
	if _, e = s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at.Add(11*time.Second)); !errors.Is(e, inventoryledger.ErrConflict) {
		t.Fatal("maintenance reset replay floor", e)
	}
	if _, e = s.InventoryFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(11*time.Second)); e != nil {
		t.Fatal("valid later authority clock blocked", e)
	}
}
