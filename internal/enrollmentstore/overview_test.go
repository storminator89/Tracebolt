package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"reflect"
	"strings"
	"testing"
	"time"
)

func overviewFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	f, s, path, snap, cert := completeFixture(t)
	if e := s.InitializeOverview(context.Background()); e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, cert
}
func overviewGeneration(t testing.TB, device string, seq uint64, n int, at time.Time) (OverviewBinding, overviewgeneration.Manifest, []overviewgeneration.Chunk) {
	t.Helper()
	generation, e := overviewwire.GenerationID(device, "processes", seq)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := completeoverview.Empty(id("sample", 900), at, completeoverview.ReasonReadFailed)
	count := uint64(n)
	snapshot.Processes.Meta = completeoverview.SectionMeta{GenerationID: snapshot.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: count}}
	for i := 0; i < n; i++ {
		snapshot.Processes.Items = append(snapshot.Processes.Items, completeoverview.Process{PID: uint32(i + 1), Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	}
	m, c, e := overviewgeneration.Build(context.Background(), snapshot, "processes", generation, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := overviewgeneration.ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	return OverviewBinding{"processes", seq, generation, hash}, m, c
}
func stageOverview(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b OverviewBinding, m overviewgeneration.Manifest, chunks []overviewgeneration.Chunk, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal(e)
	}
	for _, c := range chunks {
		if _, e := s.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at); e != nil {
			t.Fatal(e)
		}
	}
}

func promoteOverview(t *testing.T, s *Store, snap enrollmentstate.Snapshot, cert enrollmentcrypto.VerifiedCertificate, b OverviewBinding, m overviewgeneration.Manifest, chunks []overviewgeneration.Chunk, at time.Time) {
	t.Helper()
	stageOverview(t, s, snap, cert, b, m, chunks, at)
	if _, e := s.OverviewFinalize(context.Background(), snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal(e)
	}
}

func TestCompleteOverviewRealAuthorityPaginationRetryAndRestart(t *testing.T) {
	f, s, path, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 7, 769, at)
	begin, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at.Add(time.Second))
	if e != nil || retry != begin {
		t.Fatalf("begin retry refreshed receipt: %+v %v", retry, e)
	}
	for i, c := range chunks {
		got, e := s.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(2*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		again, e := s.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at.Add(3*time.Second))
		if e != nil || again != got {
			t.Fatalf("chunk retry changed: %+v %v", again, e)
		}
		if i == 0 {
			got, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(3*time.Second))
			if !errors.Is(e, overviewledger.ErrIncomplete) || !reflect.DeepEqual(got, overviewledger.Completion{}) {
				t.Fatal("partial promotion", e)
			}
		}
		at = at.Add(3 * time.Second)
	}
	completed, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second))
	if e != nil || completed.Manifest.ObservedCount != 769 {
		t.Fatal(e)
	}
	again, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second))
	if e != nil || !reflect.DeepEqual(again, completed) {
		t.Fatal("completion retry changed", e)
	}
	if e = s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("abort completed", e)
	}
	s.Close()
	s = f.open(t, path)
	now := at.Add(3 * time.Second)
	status, e := s.OverviewView(ctx, snap.Approval.DeviceID, now)
	if e != nil || status.Processes.Complete == nil || status.Processes.Complete.Manifest.ObservedCount != 769 || status.Processes.CompleteBinding != b {
		t.Fatalf("reopen status: %+v %v", status, e)
	}
	var got []overviewgeneration.Row
	req := overviewledger.PageRequest{Section: "processes", Limit: 37}
	for {
		page, e := s.OverviewPage(ctx, snap.Approval.DeviceID, req, now)
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
		if p.Process == nil || p.Process.PID != uint32(i+1) {
			t.Fatal("order or duplication", i)
		}
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if tx.credentials[snap.InvitationID].Replay.Sequence != 0 {
			t.Fatal("overview advanced telemetry domain")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestCompleteOverviewFailureCleanupAndDurableFloor(t *testing.T) {
	f, s, path, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 513, at)
	promoteOverview(t, s, snap, cert, old, m, chunks, at)
	next, m2, chunks2 := overviewGeneration(t, snap.Approval.DeviceID, 2, 700, at.Add(time.Second))
	stageOverview(t, s, snap, cert, next, m2, chunks2[:2], at.Add(time.Second))
	if e := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	status, e := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(3*time.Second))
	if e != nil || status.CompleteBinding != old || status.Transfer.State != "failed" {
		t.Fatalf("failure hid old complete: %+v %v", status, e)
	}
	for {
		clean, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", next.GenerationID, at.Add(3*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if clean.Done {
			break
		}
	}
	s.Close()
	s = f.open(t, path)
	if _, e = s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), old, m, at.Add(4*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("floor erased by cleanup", e)
	}
	if _, e = s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), next, m2, at.Add(4*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("aborted binding reused", e)
	}
	generation, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "processes", 3)
	failure := OverviewFailureReport{"processes", 3, generation, at.Add(4 * time.Second), "source_missing"}
	receipt, e := s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	retry, e := s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(6*time.Second))
	if e != nil || retry != receipt {
		t.Fatal("failure retry refreshed age", e)
	}
	failure.Reason = "source_invalid"
	if _, e = s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(7*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("failure mutated", e)
	}
	view, e := s.OverviewView(ctx, snap.Approval.DeviceID, at.Add(7*time.Second))
	if e != nil || view.Processes.Failure == nil || view.Processes.CompleteBinding != old || view.Processes.Complete.Manifest.ObservedCount != 513 {
		t.Fatalf("failure erased completion: %+v %v", view, e)
	}
}

func TestCompleteOverviewExpiryRetainsMetadataAndInvalidatesPages(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at.Add(-time.Hour))
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	first, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 10}, at)
	if e != nil {
		t.Fatal(e)
	}
	if page, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 10, Cursor: first.NextCursor}, at.Add(overviewledger.CursorTTL)); !errors.Is(e, overviewledger.ErrCursorExpired) || !reflect.DeepEqual(page, OverviewPageResult{}) {
		t.Fatal("expired cursor empty success", e)
	}
	expired := at.Add(23 * time.Hour)
	view, e := s.OverviewView(ctx, snap.Approval.DeviceID, expired)
	if e != nil || view.Processes.Complete == nil || view.Processes.Complete.State != "expired" || view.Processes.Complete.Manifest.ObservedCount != 300 {
		t.Fatalf("expired complete metadata lost: %+v %v", view, e)
	}
	if page, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 10}, expired); !errors.Is(e, overviewledger.ErrExpired) || !reflect.DeepEqual(page, OverviewPageResult{}) {
		t.Fatal("expired page empty success", e)
	}
	pending, m2, _ := overviewGeneration(t, snap.Approval.DeviceID, 2, 300, expired)
	if _, e = s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), pending, m2, expired); e != nil {
		t.Fatal(e)
	}
	view, e = s.OverviewView(ctx, snap.Approval.DeviceID, expired.Add(overviewledger.StagingTTL))
	if e != nil || view.Processes.Transfer.State != "expired" || view.Processes.Complete.State != "expired" {
		t.Fatal("separate expiry", e)
	}
	for {
		r, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", pending.GenerationID, expired.Add(overviewledger.StagingTTL))
		if e != nil {
			t.Fatal(e)
		}
		if r.Done {
			break
		}
	}
	view, e = s.OverviewView(ctx, snap.Approval.DeviceID, expired.Add(overviewledger.StagingTTL))
	if e != nil || view.Processes.Transfer.State != "expired" {
		t.Fatal("pending metadata disappeared", e)
	}
}

func TestCompleteOverviewAuthorityBindingsAndRevocation(t *testing.T) {
	f, s, path, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	if _, e := s.OverviewBegin(ctx, snap.InvitationID, strings.Repeat("1", 64), b, m, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("wrong cert", e)
	}
	other, mOther, _ := overviewGeneration(t, id("agent", 9), 1, 300, at)
	if _, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), other, mOther, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("device-bound generation bypass", e)
	}
	stageOverview(t, s, snap, cert, b, m, chunks, at)
	if _, e := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("clock regression", e)
	}
	bad := b
	bad.Sequence++
	if _, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), bad, at); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("sequence rebind", e)
	}
	second := f.open(t, path)
	revoke := control(snap, 50)
	revoke.Now = at.Add(time.Second).Unix()
	if _, e := second.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if out, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) || !reflect.DeepEqual(out, overviewledger.Completion{}) {
		t.Fatal("revoked promotion", e)
	}
	if _, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 10}, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked read", e)
	}
	if _, e := s.OverviewView(ctx, snap.Approval.DeviceID, at.Add(2*time.Second)); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked metadata", e)
	}
}

func TestCompleteOverviewRollbackSuppressesProvisionalWrites(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	injected := errors.New("synthetic rollback")
	e := s.transact(ctx, func(tx *transaction) error {
		if _, e := s.overviewAuthority(tx, snap.InvitationID, cert.CertificateHash(), "processes", at); e != nil {
			return e
		}
		if _, e := overviewLedger().Begin(ctx, tx.conn, overviewDevice(snap.Approval.DeviceID, "processes"), m, at); e != nil {
			return e
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	var n int
	if s.db.QueryRow(`SELECT count(*) FROM co_generations`).Scan(&n) != nil || n != 0 {
		t.Fatal("rollback retained generation")
	}
	if _, e = s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
		t.Fatal("rollback spent floor", e)
	}
	// A context cancellation at COMMIT's persistence boundary must return no
	// provisional result; this injection uses the shared real transaction runner.
	var got overviewledger.Completion
	canceled, cancel := context.WithCancel(ctx)
	got, e = overviewledger.CommitResult(canceled, func(ctx context.Context, action func(overviewledger.Transaction) error) error {
		return s.transact(ctx, func(tx *transaction) error {
			if e := action(tx.conn); e != nil {
				return e
			}
			cancel()
			return nil
		})
	}, func(tx overviewledger.Transaction) (overviewledger.Completion, error) {
		return overviewledger.Completion{Manifest: m, StartedAt: at, CompletedAt: at}, nil
	})
	if !errors.Is(e, context.Canceled) || !reflect.DeepEqual(got, overviewledger.Completion{}) {
		t.Fatal("uncertain commit advertised completion", e)
	}
}

func TestCompleteOverviewCommitFailureSuppressesPromotion(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	stageOverview(t, s, snap, cert, b, m, chunks, at)
	got, e := overviewledger.CommitResult(ctx, func(ctx context.Context, action func(overviewledger.Transaction) error) error {
		return s.transact(ctx, func(tx *transaction) error {
			if _, e := s.overviewAuthority(tx, snap.InvitationID, cert.CertificateHash(), "processes", at); e != nil {
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
	}, func(tx overviewledger.Transaction) (overviewledger.Completion, error) {
		return overviewLedger().Promote(ctx, tx, overviewDevice(snap.Approval.DeviceID, "processes"), b.GenerationID, at)
	})
	if !errors.Is(e, ErrStorage) || errors.Is(e, ErrBusy) || !reflect.DeepEqual(got, overviewledger.Completion{}) {
		t.Fatal("failed COMMIT advertised result or retryable busy", e)
	}
	view, e := s.OverviewView(ctx, snap.Approval.DeviceID, at)
	if e != nil || view.Processes.Complete != nil || view.Processes.Transfer == nil || view.Processes.Transfer.State != "pending" {
		t.Fatal("failed COMMIT persisted promotion", e)
	}
	if _, e = s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal("rollback lost staged generation or credential", e)
	}
}

func TestCompleteOverviewMaintenanceReclaimsAfterRevocationAndExpiry(t *testing.T) {
	for _, mode := range []string{"revoked", "certificate_expired", "state_expired"} {
		t.Run(mode, func(t *testing.T) {
			f, s, path, snap, cert := overviewFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			retired, m1, c1 := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
			promoteOverview(t, s, snap, cert, retired, m1, c1, at)
			current, m2, c2 := overviewGeneration(t, snap.Approval.DeviceID, 2, 400, at.Add(time.Second))
			promoteOverview(t, s, snap, cert, current, m2, c2, at.Add(time.Second))
			pending, m3, c3 := overviewGeneration(t, snap.Approval.DeviceID, 3, 600, at.Add(2*time.Second))
			stageOverview(t, s, snap, cert, pending, m3, c3[:2], at.Add(2*time.Second))
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
				if _, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", pending.GenerationID, at.Add(4*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
					t.Fatal("revocation bypassed staging eligibility", e)
				}
			}
			for _, binding := range []OverviewBinding{retired, pending} {
				for {
					result, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", binding.GenerationID, now)
					if e != nil {
						t.Fatal("eligible non-current cleanup blocked", e)
					}
					if result.RowsDeleted > overviewledger.MaxCleanupRows || result.ChunksDeleted > overviewledger.MaxCleanupChunks {
						t.Fatal("cleanup unbounded")
					}
					if result.Done {
						break
					}
				}
			}
			if _, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", current.GenerationID, now); !errors.Is(e, overviewledger.ErrConflict) {
				t.Fatal("maintenance deleted current", e)
			}
			if _, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", current.GenerationID, now.Add(-time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
				t.Fatal("maintenance clock reversed", e)
			}
			if _, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), retired, m1, now); !errors.Is(e, wantAgentError) {
				t.Fatal("maintenance relaxed agent guard", e)
			}
			if _, e := s.OverviewView(ctx, snap.Approval.DeviceID, now); !errors.Is(e, wantAgentError) {
				t.Fatal("maintenance relaxed read guard", e)
			}
			var heldRows, generations int64
			if s.db.QueryRow(`SELECT held_rows,generations FROM co_budget WHERE scope=''`).Scan(&heldRows, &generations) != nil || heldRows != 400 || generations != 1 {
				t.Fatal("non-current reservations stranded", heldRows, generations)
			}
			s.Close()
			s = f.open(t, path)
			if e := s.transact(ctx, func(tx *transaction) error {
				r := tx.overview[overviewRecordKey(snap.InvitationID, "processes")]
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
			if s.db.QueryRow(`SELECT current_generation FROM co_devices WHERE device=?`, overviewDevice(snap.Approval.DeviceID, "processes")).Scan(&retained) != nil || retained != current.GenerationID {
				t.Fatal("current pointer lost")
			}
		})
	}
}

func TestCompleteOverviewMaintenanceClockConstrainsActiveAuthority(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 300, at)
	stageOverview(t, s, snap, cert, b, m, chunks[:1], at)
	if e := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	clean, e := s.OverviewCleanup(ctx, snap.Approval.DeviceID, "processes", b.GenerationID, at.Add(10*time.Second))
	if e != nil || !clean.Done {
		t.Fatal(e)
	}
	generation, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "processes", 2)
	failure := OverviewFailureReport{Section: "processes", Sequence: 2, GenerationID: generation, AttemptedAt: at.Add(5 * time.Second), Reason: "source_missing"}
	if _, e = s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(5*time.Second)); !errors.Is(e, enrollmentstate.ErrInvalid) {
		t.Fatal("agent clock reversed after maintenance", e)
	}
	if _, e = s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at.Add(11*time.Second)); !errors.Is(e, overviewledger.ErrConflict) {
		t.Fatal("maintenance reset replay floor", e)
	}
	if _, e = s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), failure, at.Add(11*time.Second)); e != nil {
		t.Fatal("valid later authority clock blocked", e)
	}
}

func TestCompleteOverviewAddOnlyInitializationPreservesExistingBytes(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, chunks := completeGeneration(t, snap.Approval.DeviceID, 8, 300, at)
	stageComplete(t, s, snap, cert, b, m, chunks[:1], at)
	queries := []string{`SELECT ledger FROM enrollment_state WHERE id=1`, `SELECT body FROM enrollment_credentials LIMIT 1`, `SELECT body FROM enrollment_inventory_authority LIMIT 1`, `SELECT manifest FROM fi_generations LIMIT 1`, `SELECT checkpoint FROM fi_generations LIMIT 1`, `SELECT body FROM fi_chunks LIMIT 1`, `SELECT body FROM fi_rows LIMIT 1`, `SELECT cursor_key FROM enrollment_inventory_meta WHERE id=1`}
	before := make([][]byte, len(queries))
	for i, q := range queries {
		if e := s.db.QueryRow(q).Scan(&before[i]); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.OverviewView(ctx, snap.Approval.DeviceID, at); !errors.Is(e, ErrOverviewNotConfigured) {
		t.Fatal("uninitialized extension accepted", e)
	}
	if e := s.InitializeOverview(ctx); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeOverview(ctx); e != nil {
		t.Fatal("idempotent init", e)
	}
	for i, q := range queries {
		var after []byte
		if e := s.db.QueryRow(q).Scan(&after); e != nil || !bytes.Equal(before[i], after) {
			t.Fatal("init changed baseline byte", i, e)
		}
	}
	var version int
	if s.db.QueryRow(`PRAGMA user_version`).Scan(&version) != nil || version != 3 {
		t.Fatal("schema reset")
	}
	s.Close()
	s = f.open(t, path)
	for _, c := range chunks[1:] {
		if _, e := s.InventoryAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, c, at); e != nil {
			t.Fatal("old pending continuation", e)
		}
	}
	if _, e := s.InventoryFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, at); e != nil {
		t.Fatal(e)
	}
}

func TestCompleteOverviewRejectsPartialExtensionWithoutAdoption(t *testing.T) {
	f, s, path, _, _ := completeFixture(t)
	if _, e := s.db.Exec(overviewMetaSchema); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeOverview(context.Background()); !errors.Is(e, ErrStorage) {
		t.Fatal("partial schema adopted", e)
	}
	s.Close()
	if reopened, e := Open(path, f.config, f.issuerDER); e == nil {
		reopened.Close()
		t.Fatal("partial extension reopened")
	}
}

func TestCompleteOverviewVolumeDisplayOrderPagingAndByteAccounting(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	source := completeoverview.Empty(id("sample", 800), at, completeoverview.ReasonReadFailed)
	count := uint64(120)
	source.Volumes.Meta = completeoverview.SectionMeta{GenerationID: source.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: count}}
	for i := 0; i < 120; i++ {
		source.Volumes.Items = append(source.Volumes.Items, completeoverview.Volume{ID: fmt.Sprintf("mount_%d", 120-i), MountPoint: fmt.Sprintf("/fixture/%04d/", i) + strings.Repeat(`"`, 4000), Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_8_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	}
	gen, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "volumes", 1)
	m, chunks, e := overviewgeneration.Build(ctx, source, "volumes", gen, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := overviewgeneration.ManifestDigest(m)
	b := OverviewBinding{"volumes", 1, gen, hash}
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	var got []overviewgeneration.Row
	q := overviewledger.PageRequest{Section: "volumes", Limit: 100}
	pages := 0
	for {
		p, e := s.OverviewPage(ctx, snap.Approval.DeviceID, q, at)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(p)
		if len(raw) > overviewledger.MaxPageBytes {
			t.Fatal("response unbounded", len(raw))
		}
		got = append(got, p.Items...)
		pages++
		if p.Exhausted {
			break
		}
		if p.NextCursor == "" || len(p.NextCursor) > overviewledger.MaxCursorBytes {
			t.Fatal("cursor bound")
		}
		q.Cursor = p.NextCursor
	}
	if len(got) != 120 || pages < 2 {
		t.Fatal("truncated or not byte bounded", len(got), pages)
	}
	for i, r := range got {
		if r.Volume == nil || r.Volume.ID != source.Volumes.Items[i].ID {
			t.Fatal("canonical order leaked into display order", i)
		}
	}
	var actual, stored int64
	query := `SELECT (SELECT coalesce(sum(length(manifest)+length(checkpoint)),0) FROM co_generations)+(SELECT coalesce(sum(length(body)),0) FROM co_chunks)+(SELECT coalesce(sum(length(body)+length(CAST(display_key AS BLOB))),0) FROM co_rows)`
	if s.db.QueryRow(query).Scan(&actual) != nil || s.db.QueryRow(`SELECT stored_bytes FROM co_budget WHERE scope=''`).Scan(&stored) != nil || stored != actual {
		t.Fatal("display key absent from logical accounting", actual, stored)
	}
}

func TestCompleteOverviewSharedBudgetRejectsAcrossDomains(t *testing.T) {
	_, s, _, _, _ := overviewFixture(t)
	ctx := context.Background()
	injected := errors.New("rollback fixture")
	e := s.transact(ctx, func(tx *transaction) error {
		if _, e := tx.conn.ExecContext(ctx, `UPDATE fi_budget SET stored_bytes=? WHERE scope=''`, inventoryLimits().GlobalBytes-1); e != nil {
			return e
		}
		if e := sharedInventoryBudget(ctx, tx); e != nil {
			return e
		}
		if _, e := tx.conn.ExecContext(ctx, `UPDATE co_budget SET stored_bytes=2 WHERE scope=''`); e != nil {
			return e
		}
		if e := sharedInventoryBudget(ctx, tx); !errors.Is(e, inventoryledger.ErrQuota) {
			t.Fatal("independent domains exceeded shared limit", e)
		}
		return injected
	})
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	var bytes int64
	if s.db.QueryRow(`SELECT stored_bytes FROM fi_budget WHERE scope=''`).Scan(&bytes) != nil || bytes != 0 {
		t.Fatal("quota fixture persisted")
	}
}

func TestCompleteOverviewStableRetiredCursorSearchAndZero(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 3000, at)
	promoteOverview(t, s, snap, cert, old, m, chunks, at)
	first, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", GenerationID: old.GenerationID, Limit: 100}, at)
	if e != nil {
		t.Fatal(e)
	}
	search := overviewledger.PageRequest{Section: "processes", GenerationID: old.GenerationID, Limit: 100, Search: "not-in-fixture"}
	scan, e := s.OverviewPage(ctx, snap.Approval.DeviceID, search, at)
	if e != nil || len(scan.Items) != 0 || scan.Exhausted || !scan.SearchIncomplete || scan.ScannedRows != overviewledger.MaxScanRows {
		t.Fatal("bounded search lied or stalled", e)
	}
	search.Cursor = scan.NextCursor
	last, e := s.OverviewPage(ctx, snap.Approval.DeviceID, search, at)
	if e != nil || !last.Exhausted || len(last.Items) != 0 || last.ScannedRows != 3000-overviewledger.MaxScanRows {
		t.Fatal("search continuation lost tail", e)
	}
	for _, req := range []overviewledger.PageRequest{{Section: "processes", GenerationID: old.GenerationID, Limit: 99, Cursor: first.NextCursor}, {Section: "processes", GenerationID: old.GenerationID, Limit: 100, Search: "1", Cursor: first.NextCursor}, {Section: "volumes", GenerationID: old.GenerationID, Limit: 100, Cursor: first.NextCursor}} {
		if _, e := s.OverviewPage(ctx, snap.Approval.DeviceID, req, at); !errors.Is(e, overviewledger.ErrCursor) {
			t.Fatal("cursor query/section rebind", e)
		}
	}
	next, m2, c2 := overviewGeneration(t, snap.Approval.DeviceID, 2, 0, at.Add(time.Second))
	promoteOverview(t, s, snap, cert, next, m2, c2, at.Add(time.Second))
	pinned, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", GenerationID: old.GenerationID, Limit: 100, Cursor: first.NextCursor}, at.Add(time.Second))
	if e != nil || pinned.Binding != old || pinned.Items[0].Process.PID != 101 {
		t.Fatal("old cursor changed generation", e)
	}
	empty, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", GenerationID: next.GenerationID, Limit: 100}, at.Add(time.Second))
	if e != nil || !empty.Exhausted || empty.TotalRows != 0 || empty.Items == nil || len(empty.Items) != 0 {
		t.Fatal("successful zero confused with missing", e)
	}
	if _, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", GenerationID: old.GenerationID, Limit: 100, Cursor: first.NextCursor}, at.Add(overviewledger.CursorTTL)); !errors.Is(e, overviewledger.ErrCursorExpired) {
		t.Fatal("expired retained cursor succeeded", e)
	}
}
