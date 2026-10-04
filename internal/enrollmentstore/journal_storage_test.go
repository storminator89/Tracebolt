package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/systemwire"
)

func journalFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate, time.Time) {
	t.Helper()
	f, s, path, snap, cert := systemLongFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	saveSystemFixture(t, s, snap, cert, 1, systemFixtureSnapshot(t, snap.Approval.DeviceID, 1, 0, at), at)
	return f, s, path, snap, cert, at
}
func journalQuery(at time.Time) journalview.Query {
	return journalview.Query{Unit: "fixture.service", Start: at.Add(-time.Minute), End: at, MaxPriority: 6}
}
func journalClaim(d journalrequest.Description) journalrequest.Claim {
	return journalrequest.Claim{Identity: d.Identity, PolicyDigest: "sha256:" + strings.Repeat("1", 64)}
}
func journalResult(d journalrequest.Description) journalrequest.Result {
	return journalrequest.Result{Claim: journalClaim(d), ResultDigest: "sha256:" + strings.Repeat("2", 64)}
}
func createJournal(t *testing.T, s *Store, snap enrollmentstate.Snapshot, at time.Time, expectedFloor uint64) journalrequest.Description {
	t.Helper()
	d, e := s.CreateJournalRequest(context.Background(), snap.Approval.DeviceID, expectedFloor, journalQuery(at), at)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func journalBody(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var b []byte
	if e := s.db.QueryRow(`SELECT body FROM enrollment_system_authority WHERE invitation_id=?`, id).Scan(&b); e != nil {
		t.Fatal(e)
	}
	return b
}

func TestJournalNotReadyDoesNotInventSystemReceipt(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if d, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(at), at); !errors.Is(e, journalrequest.ErrNotReady) || d.Identity.ID != "" {
		t.Fatal("invented query", e)
	}
	if _, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), at); !errors.Is(e, journalrequest.ErrNotReady) {
		t.Fatal(e)
	}
	if _, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at); !errors.Is(e, journalrequest.ErrNotReady) {
		t.Fatal(e)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM enrollment_system_authority`).Scan(&n)
	if n != 0 {
		t.Fatal("invented system authority")
	}
}

func TestJournalCreateClaimResultRetryAndRestart(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	if d.Identity.Sequence != 1 || d.DeviceID != snap.Approval.DeviceID || d.CertificateHash != cert.CertificateHash() || !d.ExpiresAt.Equal(at.Add(15*time.Minute)) {
		t.Fatal("incorrect description")
	}
	peek, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), at)
	if e != nil || peek != d {
		t.Fatal("peek mismatch", e)
	}
	rawBefore := journalBody(t, s, snap.InvitationID)
	if _, e = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); !errors.Is(e, journalrequest.ErrConflict) {
		t.Fatal("result before claim accepted", e)
	}
	if !bytes.Equal(rawBefore, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("failed result mutated record")
	}
	claimAt := at.Add(time.Second)
	grant, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), claimAt)
	if e != nil || grant.Description != d || grant.PolicyDigest != journalClaim(d).PolicyDigest {
		t.Fatal("claim failed", e)
	}
	// Independently reopen before using the grant: consumption already committed.
	other := f.open(t, path)
	if g, e := other.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), claimAt); !errors.Is(e, journalrequest.ErrConsumed) || g.Description.Identity.ID != "" {
		t.Fatal("reissued authorization", e)
	}
	if _, e = other.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), claimAt); !errors.Is(e, journalrequest.ErrConsumed) {
		t.Fatal("claimed work peeked", e)
	}
	receipt, e := other.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	original := journalBody(t, other, snap.InvitationID)
	retry, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at.Add(10*time.Minute))
	if e != nil || retry != receipt || !bytes.Equal(original, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("retry refreshed receipt", e)
	}
	conflict := journalResult(d)
	conflict.ResultDigest = "sha256:" + strings.Repeat("3", 64)
	if _, e = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), conflict, at.Add(10*time.Minute)); !errors.Is(e, journalrequest.ErrConflict) {
		t.Fatal("replacement accepted", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	status, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at.Add(10*time.Minute))
	if e != nil || status.State != journalrequest.Accepted || status.ContentStatus != "unavailable" || status.Receipt == nil || *status.Receipt != receipt {
		t.Fatal("restart invented content/changed metadata", e)
	}
	if _, e = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at.Add(10*time.Minute)); !errors.Is(e, journalrequest.ErrConsumed) {
		t.Fatal("restart regranted", e)
	}
}

func TestJournalCompetingClaimsExactlyOneCommittedGrant(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	other := f.open(t, path)
	type result struct {
		g journalrequest.Grant
		e error
	}
	ch := make(chan result, 2)
	var wg sync.WaitGroup
	for _, store := range []*Store{s, other} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			g, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at)
			ch <- result{g, e}
		}(store)
	}
	wg.Wait()
	close(ch)
	grants := 0
	for r := range ch {
		if r.e == nil {
			grants++
		} else if !errors.Is(r.e, journalrequest.ErrConsumed) || r.g.Description.Identity.ID != "" {
			t.Fatal("unexpected losing claim", r.e)
		}
	}
	if grants != 1 {
		t.Fatal("grant count", grants)
	}
}

func TestJournalExactQueryPolicyLeafAndCancellationBinding(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	for _, mutate := range []func(*journalrequest.Claim){func(c *journalrequest.Claim) { c.Identity.ID = "journal_" + strings.Repeat("f", 32) }, func(c *journalrequest.Claim) { c.Identity.Sequence++ }, func(c *journalrequest.Claim) { c.Identity.QueryDigest = "sha256:" + strings.Repeat("e", 64) }} {
		c := journalClaim(d)
		mutate(&c)
		if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), c, at); !errors.Is(e, journalrequest.ErrConflict) {
			t.Fatal("unbound claim", e)
		}
	}
	wrongLeaf := strings.Repeat("f", 64)
	if _, e := s.PeekJournalRequest(ctx, snap.InvitationID, wrongLeaf, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal(e)
	}
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, wrongLeaf, journalClaim(d), at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal(e)
	}
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
		t.Fatal(e)
	}
	bad := journalResult(d)
	bad.Claim.PolicyDigest = "sha256:" + strings.Repeat("f", 64)
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), bad, at); !errors.Is(e, journalrequest.ErrConflict) {
		t.Fatal("wrong policy result", e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, wrongLeaf, journalResult(d), at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("wrong leaf result", e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); e != nil {
		t.Fatal(e)
	}
	if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	canceled := journalBody(t, s, snap.InvitationID)
	if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, at.Add(2*time.Second)); e != nil || !bytes.Equal(canceled, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("cancel retry refreshed", e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at.Add(2*time.Second)); !errors.Is(e, journalrequest.ErrCanceled) {
		t.Fatal("canceled result shown", e)
	}
	if _, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), at.Add(2*time.Second)); !errors.Is(e, journalrequest.ErrCanceled) {
		t.Fatal(e)
	}
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at.Add(2*time.Second)); !errors.Is(e, journalrequest.ErrCanceled) {
		t.Fatal(e)
	}
	st, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at.Add(2*time.Second))
	if e != nil || st.State != journalrequest.Canceled || st.Receipt != nil || st.ContentStatus != "unavailable" {
		t.Fatal("cancel exposed result", e)
	}
	newer := createJournal(t, s, snap, at.Add(3*time.Second), 1)
	if newer.Identity.Sequence != 2 || newer.Identity.ID == d.Identity.ID {
		t.Fatal("cancel reset floor")
	}
	if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, at.Add(3*time.Second)); !errors.Is(e, journalrequest.ErrConflict) {
		t.Fatal("old cancellation replaced new request", e)
	}
}

func TestJournalExpiryFloorAndOrdinaryReportPreservation(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); e != nil {
		t.Fatal(e)
	}
	var before systemRecord
	json.Unmarshal(journalBody(t, s, snap.InvitationID), &before)
	// Ordinary reports carry no journal field but preserve the full query record.
	reportAt := at.Add(time.Second)
	saveSystemFixture(t, s, snap, cert, 2, systemFixtureSnapshot(t, snap.Approval.DeviceID, 2, 0, reportAt), reportAt)
	var after systemRecord
	json.Unmarshal(journalBody(t, s, snap.InvitationID), &after)
	oldQuery, _ := json.Marshal(before.JournalRequest)
	newQuery, _ := json.Marshal(after.JournalRequest)
	if !bytes.Equal(oldQuery, newQuery) {
		t.Fatal("ordinary report reset/refreshed query")
	}
	expiry := d.ExpiresAt
	for name, call := range map[string]func() error{
		"peek": func() error {
			_, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), expiry)
			return e
		},
		"claim": func() error {
			_, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), expiry)
			return e
		},
		"result retry": func() error {
			_, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), expiry)
			return e
		},
	} {
		if e := call(); !errors.Is(e, journalrequest.ErrExpired) {
			t.Fatal(name, e)
		}
	}
	st, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, expiry)
	if e != nil || st.State != journalrequest.Expired || st.Receipt != nil {
		t.Fatal("expired result exposed", e)
	}
	// Ordinary retention cleanup preserves the independent floor across restart.
	cleanupAt := at.Add(SystemRetention + time.Second)
	if _, e = s.SystemCleanup(ctx, snap.Approval.DeviceID, cleanupAt); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	newer := createJournal(t, s, snap, cleanupAt, 1)
	if newer.Identity.Sequence != 2 {
		t.Fatal("expiry/cleanup/restart reset floor")
	}
}

func TestJournalRevokeSuppressesEveryOperation(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); e != nil {
		t.Fatal(e)
	}
	revoke := control(snap, 7)
	revoke.Now = at.Add(time.Second).Unix()
	if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	now := at.Add(2 * time.Second)
	for name, call := range map[string]func() error{
		"create": func() error {
			_, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(now), now)
			return e
		},
		"peek": func() error {
			_, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), now)
			return e
		},
		"claim": func() error {
			_, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), now)
			return e
		},
		"result": func() error {
			_, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), now)
			return e
		},
		"cancel": func() error { return s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, now) },
		"status": func() error {
			st, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, now)
			if st.Description.Identity.ID != "" || st.Receipt != nil {
				t.Fatal("revocation exposed metadata")
			}
			return e
		},
	} {
		if e := call(); !errors.Is(e, enrollmentstate.ErrState) {
			t.Fatal(name, e)
		}
	}
}

func TestJournalOldAuthorityBytesRemainIdentical(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	raw := journalBody(t, s, snap.InvitationID)
	var current systemRecord
	if json.Unmarshal(raw, &current) != nil {
		t.Fatal("decode")
	}
	legacy := struct {
		Receipt          systemwire.Receipt      `json:"receipt"`
		Latest           *systemSnapshotMeta     `json:"latest"`
		Services         *systemComplete         `json:"services"`
		Sockets          *systemComplete         `json:"sockets"`
		MaintenanceAt    *time.Time              `json:"maintenanceAt"`
		EndpointIdentity *endpointIdentityRecord `json:"endpointIdentity,omitempty"`
	}{current.Receipt, current.Latest, current.Services, current.Sockets, current.MaintenanceAt, current.EndpointIdentity}
	old, _ := json.Marshal(legacy)
	again, _ := json.Marshal(current)
	if !bytes.Equal(raw, old) || !bytes.Equal(raw, again) || bytes.Contains(raw, []byte("journal")) {
		t.Fatal("absent optional field changed legacy bytes")
	}
	if _, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), at); !errors.Is(e, journalrequest.ErrNotFound) {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("read created query/floor")
	}
}

func TestJournalMetadataOverflowRollsBackWithoutFloor(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	original := journalBody(t, s, snap.InvitationID)
	e := s.transact(ctx, func(tx *transaction) error {
		system := tx.system[snap.InvitationID]
		// Synthetic cap probe reaches the size check before any SQL mutation.
		system.Receipt.BodyHash = strings.Repeat("x", systemMetadataLimit)
		q, e := journalrequest.New(snap.Approval.DeviceID, cert.CertificateHash(), 1, journalQuery(at), at)
		if e != nil {
			return e
		}
		return s.saveJournalRecord(ctx, tx, snap, system, q)
	})
	if !errors.Is(e, ErrSystemCapacity) || !bytes.Equal(original, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("overflow mutated authority", e)
	}
	if d := createJournal(t, s, snap, at, 0); d.Identity.Sequence != 1 {
		t.Fatal("failed request burned or reset floor")
	}
}

func TestJournalStaleRecordedLeafCannotAuthorizeAfterLeafChange(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	// Simulate a previously recorded leaf; historical metadata remains readable
	// structurally but is never authority under a different current leaf.
	e := s.transact(ctx, func(tx *transaction) error {
		system := tx.system[snap.InvitationID]
		query := *system.JournalRequest
		query.Description.CertificateHash = strings.Repeat("f", 64)
		return s.saveJournalRecord(ctx, tx, snap, system, query)
	})
	if e != nil {
		t.Fatal(e)
	}
	for name, call := range map[string]func() error{
		"peek": func() error {
			_, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), at)
			return e
		},
		"claim": func() error {
			g, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at)
			if g.Description.Identity.ID != "" {
				t.Fatal("stale leaf grant")
			}
			return e
		},
		"result": func() error {
			_, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at)
			return e
		},
		"cancel": func() error { return s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, at) },
		"status": func() error { _, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at); return e },
	} {
		if e := call(); !errors.Is(e, enrollmentstate.ErrProof) {
			t.Fatal(name, e)
		}
	}
	// Only a new explicit operator request may bind current identity and advance.
	newer := createJournal(t, s, snap, d.ExpiresAt, 1)
	if newer.Identity.Sequence != 2 || newer.CertificateHash != cert.CertificateHash() {
		t.Fatal("new request did not advance/bind leaf")
	}
}

func TestJournalCredentialExpiryAndBackwardClockSuppress(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	claimAt := at.Add(time.Minute)
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), claimAt); e != nil {
		t.Fatal(e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); !errors.Is(e, journalrequest.ErrInvalid) {
		t.Fatal("backdated result accepted", e)
	}
	now := time.Unix(snap.Intent.NotAfter, 0).UTC()
	for name, call := range map[string]func() error{
		"create": func() error {
			_, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(now), now)
			return e
		},
		"peek": func() error {
			_, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), now)
			return e
		},
		"claim": func() error {
			_, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), now)
			return e
		},
		"result": func() error {
			_, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), now)
			return e
		},
		"cancel": func() error { return s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, now) },
		"status": func() error { _, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, now); return e },
	} {
		if e := call(); !errors.Is(e, enrollmentstate.ErrExpired) {
			t.Fatal(name, e)
		}
	}
}

func TestJournalClaimRollbackNeverReturnsGrant(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	before := journalBody(t, s, snap.InvitationID)
	// A canceled transaction cannot return a grant or consume work. The inverse
	// (committed claim with a lost response) is tested by the restart retry case.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	g, e := s.ClaimJournalRequest(canceled, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at)
	if !errors.Is(e, context.Canceled) || g.Description.Identity.ID != "" || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("failed claim leaked grant/mutated authority", e)
	}
}

func TestJournalCorruptRecordFailsClosedAndCannotReset(t *testing.T) {
	f, s, path, snap, _, at := journalFixture(t)
	ctx := context.Background()
	createJournal(t, s, snap, at, 0)
	var r systemRecord
	if e := json.Unmarshal(journalBody(t, s, snap.InvitationID), &r); e != nil {
		t.Fatal(e)
	}
	r.JournalRequest.Description.Budgets.MaxRows++
	bad, _ := json.Marshal(r)
	if _, e := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, bad, snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(at), at); !errors.Is(e, ErrStorage) {
		t.Fatal("corruption reset as new work", e)
	}
	if _, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at); !errors.Is(e, ErrStorage) {
		t.Fatal("corruption treated as no data", e)
	}
	s.Close()
	reopened, e := Open(path, f.config, f.issuerDER)
	if reopened != nil {
		reopened.Close()
		t.Fatal("corrupt authority reopened")
	}
	if !errors.Is(e, ErrStorage) {
		t.Fatal(e)
	}
}

func TestJournalSequenceExhaustionFailsWithoutWrap(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	e := s.transact(ctx, func(tx *transaction) error {
		q, e := journalrequest.New(snap.Approval.DeviceID, cert.CertificateHash(), ^uint64(0), journalQuery(at), at)
		if e != nil {
			return e
		}
		return s.saveJournalRecord(ctx, tx, snap, tx.system[snap.InvitationID], q)
	})
	if e != nil {
		t.Fatal(e)
	}
	before := journalBody(t, s, snap.InvitationID)
	if _, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, ^uint64(0), journalQuery(at), at.Add(journalrequest.Lifetime)); !errors.Is(e, ErrSystemCapacity) || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("sequence wrapped or mutated", e)
	}
}

func TestJournalCreateRejectsLivePendingAndClaimedWork(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	// A nonzero expected floor cannot manufacture an absent record.
	if d, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 1, journalQuery(at), at); !errors.Is(e, journalrequest.ErrConflict) || d.Identity.ID != "" {
		t.Fatal("nonzero absent floor accepted", e)
	}
	d := createJournal(t, s, snap, at, 0)
	for _, state := range []string{journalrequest.Pending, journalrequest.Claimed} {
		before := journalBody(t, s, snap.InvitationID)
		if newer, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, d.Identity.Sequence, journalQuery(at), at); !errors.Is(e, journalrequest.ErrConflict) || newer.Identity.ID != "" || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
			t.Fatal("live work silently replaced", state, e)
		}
		if state == journalrequest.Pending {
			if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
				t.Fatal(e)
			}
		}
	}
	// Expiry is a valid explicit replacement boundary even for consumed work.
	newer := createJournal(t, s, snap, d.ExpiresAt, d.Identity.Sequence)
	if newer.Identity.Sequence != 2 {
		t.Fatal("expired floor not advanced")
	}
}

func TestJournalConcurrentAndStaleCreatesCannotAdvanceTwice(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	other := f.open(t, path)
	type result struct {
		d journalrequest.Description
		e error
	}
	run := func(expected uint64, now time.Time) journalrequest.Description {
		t.Helper()
		ch := make(chan result, 2)
		var wg sync.WaitGroup
		for _, store := range []*Store{s, other} {
			wg.Add(1)
			go func(s *Store) {
				defer wg.Done()
				d, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, expected, journalQuery(now), now)
				ch <- result{d, e}
			}(store)
		}
		wg.Wait()
		close(ch)
		successes := 0
		var out journalrequest.Description
		for r := range ch {
			if r.e == nil {
				successes++
				out = r.d
			} else if !errors.Is(r.e, journalrequest.ErrConflict) || r.d.Identity.ID != "" {
				t.Fatal("unexpected losing create", r.e)
			}
		}
		if successes != 1 || out.Identity.Sequence != expected+1 {
			t.Fatal("CAS admitted competing creates", successes)
		}
		return out
	}
	d := run(0, at)
	// Accepted work may be replaced only using its exact retained floor.
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); e != nil {
		t.Fatal(e)
	}
	before := journalBody(t, s, snap.InvitationID)
	if _, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(at), at); !errors.Is(e, journalrequest.ErrConflict) || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("stale POST advanced accepted record", e)
	}
	newer := run(d.Identity.Sequence, at)
	if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, newer.Identity, at); e != nil {
		t.Fatal(e)
	}
	// The prior request's create CAS remains stale after later cancellation.
	if _, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, d.Identity.Sequence, journalQuery(at), at); !errors.Is(e, journalrequest.ErrConflict) {
		t.Fatal("stale canceled-floor create accepted", e)
	}
	final := createJournal(t, s, snap, at, newer.Identity.Sequence)
	if final.Identity.Sequence != 3 {
		t.Fatal("matching canceled-floor create rejected")
	}
}

func TestJournalObservedExpirySurvivesRestartAndClockReversal(t *testing.T) {
	for _, startingState := range []string{journalrequest.Pending, journalrequest.Accepted} {
		for _, operation := range []string{"status", "peek", "claim", "result", "cancel"} {
			t.Run(startingState+"/"+operation, func(t *testing.T) {
				f, s, path, snap, cert, at := journalFixture(t)
				ctx := context.Background()
				d := createJournal(t, s, snap, at, 0)
				if startingState == journalrequest.Accepted {
					if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); e != nil {
						t.Fatal(e)
					}
					if _, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at); e != nil {
						t.Fatal(e)
					}
				}
				var before systemRecord
				if e := json.Unmarshal(journalBody(t, s, snap.InvitationID), &before); e != nil {
					t.Fatal(e)
				}
				expiry := d.ExpiresAt
				switch operation {
				case "status":
					st, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, expiry)
					if e != nil || st.State != journalrequest.Expired || st.Receipt != nil || st.ContentStatus != "unavailable" {
						t.Fatal("expiry status", e)
					}
				case "peek":
					out, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), expiry)
					if !errors.Is(e, journalrequest.ErrExpired) || out.Identity.ID != "" {
						t.Fatal("expired peek leaked description", e)
					}
				case "claim":
					out, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), expiry)
					if !errors.Is(e, journalrequest.ErrExpired) || out.Description.Identity.ID != "" {
						t.Fatal("expired claim leaked grant", e)
					}
				case "result":
					out, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), expiry)
					if !errors.Is(e, journalrequest.ErrExpired) || out.Identity.ID != "" {
						t.Fatal("expired result leaked receipt", e)
					}
				case "cancel":
					if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, expiry); !errors.Is(e, journalrequest.ErrExpired) {
						t.Fatal("expiry cancel", e)
					}
				}
				// Reopen before reversing time. The outcome above must have committed.
				if e := s.Close(); e != nil {
					t.Fatal(e)
				}
				s = f.open(t, path)
				var after systemRecord
				if e := json.Unmarshal(journalBody(t, s, snap.InvitationID), &after); e != nil {
					t.Fatal(e)
				}
				a, b := before.JournalRequest, after.JournalRequest
				if b.State != journalrequest.Expired || b.ExpiredAt == nil || !b.ExpiredAt.Equal(expiry) || a.Description != b.Description {
					t.Fatal("terminal observation was not persisted exactly")
				}
				// Original claim/receipt timestamps remain unchanged; no age slides.
				oldReceipt, _ := json.Marshal(a.Receipt)
				newReceipt, _ := json.Marshal(b.Receipt)
				oldClaim, _ := json.Marshal(a.ClaimedAt)
				newClaim, _ := json.Marshal(b.ClaimedAt)
				if !bytes.Equal(oldReceipt, newReceipt) || !bytes.Equal(oldClaim, newClaim) {
					t.Fatal("expiry refreshed old receipt/claim")
				}
				latched := journalBody(t, s, snap.InvitationID)
				reversed := at.Add(time.Minute)
				st, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, reversed)
				if e != nil || st.State != journalrequest.Expired || st.Receipt != nil || st.ContentStatus != "unavailable" {
					t.Fatal("clock reversal resurrected status", e)
				}
				if out, e := s.PeekJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), reversed); !errors.Is(e, journalrequest.ErrExpired) || out.Identity.ID != "" {
					t.Fatal("clock reversal resurrected peek", e)
				}
				if out, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), reversed); !errors.Is(e, journalrequest.ErrExpired) || out.Description.Identity.ID != "" {
					t.Fatal("clock reversal resurrected grant", e)
				}
				if out, e := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), reversed); !errors.Is(e, journalrequest.ErrExpired) || out.Identity.ID != "" {
					t.Fatal("clock reversal resurrected result", e)
				}
				if e := s.CancelJournalRequest(ctx, snap.Approval.DeviceID, d.Identity, reversed); !errors.Is(e, journalrequest.ErrExpired) {
					t.Fatal("clock reversal erased terminal expiry", e)
				}
				if _, e := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, d.Identity.Sequence, journalQuery(reversed), reversed); !errors.Is(e, journalrequest.ErrInvalid) {
					t.Fatal("new query backdated before terminal observation", e)
				}
				if !bytes.Equal(latched, journalBody(t, s, snap.InvitationID)) {
					t.Fatal("expiry retries rewrote terminal metadata")
				}
				// A new explicit request at a nondecreasing clock advances the old floor.
				newer := createJournal(t, s, snap, expiry, d.Identity.Sequence)
				if newer.Identity.Sequence != 2 {
					t.Fatal("latched expiry reset floor")
				}
			})
		}
	}
}

func TestJournalExpiryCommitFailureIsNotReportedAsExpiry(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	before := journalBody(t, s, snap.InvitationID)
	canceled, cancel := context.WithCancel(ctx)
	defer cancel()
	// Deterministically cancel after the terminal UPDATE but before COMMIT.
	// The transaction wrapper must return the real failure and roll everything
	// back, rather than reporting its deferred expiry outcome as committed.
	e := s.journalTransaction(canceled, d.ExpiresAt, func(tx *transaction) error {
		authority, system, e := s.journalAuthority(tx, snap.InvitationID, cert.CertificateHash(), d.ExpiresAt)
		if e != nil {
			return e
		}
		query, e := currentJournal(system, authority, &d.Identity)
		if e != nil {
			return e
		}
		expired, e := s.journalExpired(canceled, tx, authority, system, query, d.ExpiresAt)
		if e != nil {
			return e
		}
		if !expired {
			t.Fatal("fixture did not reach expiry")
		}
		cancel()
		return journalrequest.ErrExpired
	})
	if e == nil || errors.Is(e, journalrequest.ErrExpired) {
		t.Fatal("commit failure disguised as expiry", e)
	}
	if !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("failed terminal commit was retained")
	}
	// A later successful observation commits expiry and suppresses work.
	if out, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), d.ExpiresAt); !errors.Is(e, journalrequest.ErrExpired) || out.Description.Identity.ID != "" {
		t.Fatal("retry expiry", e)
	}
}
