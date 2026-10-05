package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
)

func generationReport(at time.Time, revision, sequence uint64) journalgeneration.Report {
	return journalgeneration.Report{SchemaVersion: journalgeneration.ReportSchemaVersion, Tuple: journalgeneration.Tuple{Revision: revision, Generation: strings.Repeat(string(rune('a'+revision-1)), 64), PolicyDigest: "sha256:" + strings.Repeat(string(rune('1'+revision-1)), 64)}, Sequence: sequence, ObservedAt: at}
}
func TestJournalGenerationMigrationCASAndRestart(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	report := generationReport(at, 1, 1)
	if got, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); err != nil || !journalgeneration.EqualReport(got, report) {
		t.Fatal("report", err)
	}
	status, err := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at)
	if err != nil || status.State != journalrequest.Canceled || status.Description != d {
		t.Fatal("migration did not cancel without changing floor", err)
	}
	if _, err = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("old claim", err)
	}
	if _, err = s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 1, journalQuery(at), at); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("v1 fallback", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	view, err := s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, at)
	if err != nil || view == nil || view.PolicyGeneration != report.Tuple || !view.Fresh {
		t.Fatal("floor lost on reopen", err)
	}
	created, err := s.CreateJournalRequestWithGeneration(ctx, snap.Approval.DeviceID, 1, journalQuery(at), report.Tuple, at)
	if err != nil || created.SchemaVersion != journalrequest.SchemaVersionV2 || created.PolicyGeneration != report.Tuple || created.Identity.Sequence != 2 {
		t.Fatal("v2 create", err)
	}
	if _, err = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalrequest.Claim{Identity: created.Identity, PolicyDigest: "sha256:" + strings.Repeat("9", 64)}, at); !errors.Is(err, journalrequest.ErrInvalid) {
		t.Fatal("wrong policy claim", err)
	}
	if _, err = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(created), at); err != nil {
		t.Fatal(err)
	}
	next := generationReport(at.Add(time.Second), 2, 2)
	if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(created), at.Add(time.Second)); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("old result after report", err)
	}
	if _, err = s.CreateJournalRequestWithGeneration(ctx, snap.Approval.DeviceID, 2, journalQuery(at), report.Tuple, at.Add(time.Second)); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("silently rebound CAS", err)
	}
}
func TestJournalGenerationRetriesNeverRefreshAndExpiryLatches(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	report := generationReport(at, 1, 1)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); err != nil {
		t.Fatal(err)
	}
	original := journalBody(t, s, snap.InvitationID)
	for _, now := range []time.Time{at.Add(time.Minute), at.Add(2 * time.Minute)} {
		if got, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, now); err != nil || !journalgeneration.EqualReport(got, report) || !bytes.Equal(original, journalBody(t, s, snap.InvitationID)) {
			t.Fatal("retry refreshed metadata", err)
		}
	}
	stale := at.Add(JournalGenerationMaxAge)
	if got, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, stale); err != nil || !journalgeneration.EqualReport(got, report) {
		t.Fatal("expired exact report retry", err)
	}
	var latched journalGenerationRecord
	var full systemRecord
	if err := json.Unmarshal(journalBody(t, s, snap.InvitationID), &full); err != nil {
		t.Fatal(err)
	}
	latched = *full.JournalGeneration
	if !journalgeneration.EqualReport(latched.Report, report) || !latched.ReceivedAt.Equal(at) || latched.ExpiredAt == nil || !latched.ExpiredAt.Equal(stale) {
		t.Fatal("retry changed age or failed to latch expiry")
	}
	if _, err := s.CreateJournalRequestWithGeneration(ctx, snap.Approval.DeviceID, 0, journalQuery(stale), report.Tuple, stale); !errors.Is(err, ErrJournalGenerationStale) {
		t.Fatal("stale report authorized", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	if _, err := s.CreateJournalRequestWithGeneration(ctx, snap.Approval.DeviceID, 0, journalQuery(at), report.Tuple, at); !errors.Is(err, ErrJournalGenerationStale) {
		t.Fatal("clock reversal revived report", err)
	}
	view, err := s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, at)
	if err != nil || view.Fresh || !view.ReceivedAt.Equal(at) || !view.ExpiresAt.Equal(stale) {
		t.Fatal("freshness/age", err)
	}
	refreshed := report
	refreshed.Sequence++
	refreshed.ObservedAt = stale.Add(time.Second)
	if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), refreshed, refreshed.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateJournalRequestWithGeneration(ctx, snap.Approval.DeviceID, 0, journalQuery(refreshed.ObservedAt), report.Tuple, refreshed.ObservedAt); err != nil {
		t.Fatal("fresh report rejected", err)
	}
}
func TestJournalGenerationRejectsReplayConflictAndOldTimeWithoutMutation(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	report := generationReport(at, 2, 3)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); err != nil {
		t.Fatal(err)
	}
	before := journalBody(t, s, snap.InvitationID)
	mutations := []func(*journalgeneration.Report){
		func(r *journalgeneration.Report) { r.Sequence-- }, func(r *journalgeneration.Report) { r.Tuple.Revision-- },
		func(r *journalgeneration.Report) { r.Tuple.Generation = strings.Repeat("e", 64) },
		func(r *journalgeneration.Report) { r.Tuple.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
		func(r *journalgeneration.Report) { r.ObservedAt = r.ObservedAt.Add(time.Second) },
		func(r *journalgeneration.Report) { r.Sequence++ },
		func(r *journalgeneration.Report) { r.Sequence++; r.ObservedAt = r.ObservedAt.Add(-time.Second) },
		func(r *journalgeneration.Report) {
			r.Sequence++
			r.Tuple.Revision++
			r.ObservedAt = r.ObservedAt.Add(2 * time.Second)
		},
	}
	for i, mutate := range mutations {
		bad := report
		mutate(&bad)
		if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), bad, at.Add(time.Second)); err == nil || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
			t.Fatalf("accepted/mutated conflict %d: %v", i, err)
		}
	}
}
func TestJournalGenerationAcceptedContentMetadataKeepsOriginalExpiry(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	d := createJournal(t, s, snap, at, 0)
	if _, err := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), at)
	if err != nil {
		t.Fatal(err)
	}
	report := generationReport(at.Add(time.Second), 1, 1)
	if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, report.ObservedAt); err != nil {
		t.Fatal(err)
	}
	status, err := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, report.ObservedAt)
	if err != nil || status.State != journalrequest.Accepted || status.Description != d || status.Receipt == nil || *status.Receipt != receipt {
		t.Fatal("amendment changed original cached authority", err)
	}
	if _, err = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), report.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("old result retry accepted", err)
	}
}
func TestJournalGenerationCorruptionNeverFallsBack(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	report := generationReport(at, 1, 1)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); err != nil {
		t.Fatal(err)
	}
	var record systemRecord
	if err := json.Unmarshal(journalBody(t, s, snap.InvitationID), &record); err != nil {
		t.Fatal(err)
	}
	record.JournalGeneration.Report.Tuple.Revision = 0
	bad, _ := json.Marshal(record)
	if _, err := s.db.Exec(`UPDATE enrollment_system_authority SET body=? WHERE invitation_id=?`, bad, snap.InvitationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJournalRequest(ctx, snap.Approval.DeviceID, 0, journalQuery(at), at); !errors.Is(err, ErrStorage) {
		t.Fatal("corruption fallback", err)
	}
	s.Close()
	reopened, err := Open(path, f.config, f.issuerDER)
	if reopened != nil {
		reopened.Close()
		t.Fatal("corrupt floor reopened")
	}
	if !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
}
func TestJournalGenerationForeignLeafAndCanceledTransaction(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	report := generationReport(at, 1, 1)
	before := journalBody(t, s, snap.InvitationID)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, strings.Repeat("f", 64), report, at); err == nil || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("foreign leaf mutated", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := s.AcceptJournalGeneration(canceled, snap.InvitationID, cert.CertificateHash(), report, at); err == nil || got.Sequence != 0 || !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
		t.Fatal("uncommitted report returned", err)
	}
}

func TestJournalGenerationSerializesClaimAndResultRaces(t *testing.T) {
	for _, operation := range []string{"claim", "result"} {
		t.Run(operation, func(t *testing.T) {
			f, s, path, snap, cert, at := journalFixture(t)
			ctx := context.Background()
			d := createJournal(t, s, snap, at, 0)
			if operation == "result" {
				if _, err := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), at); err != nil {
					t.Fatal(err)
				}
			}
			other := f.open(t, path)
			now := at.Add(time.Second)
			report := generationReport(now, 1, 1)
			start := make(chan struct{})
			reported := make(chan error, 1)
			acted := make(chan error, 1)
			go func() {
				<-start
				_, err := other.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, now)
				reported <- err
			}()
			go func() {
				<-start
				var err error
				if operation == "claim" {
					_, err = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), now)
				} else {
					_, err = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), now)
				}
				acted <- err
			}()
			close(start)
			if err := <-reported; err != nil {
				t.Fatal("report transaction", err)
			}
			actionErr := <-acted
			if actionErr != nil && !errors.Is(actionErr, journalrequest.ErrConflict) {
				t.Fatal("action race", actionErr)
			}
			status, err := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, now)
			if err != nil {
				t.Fatal(err)
			}
			want := journalrequest.Canceled
			if operation == "result" && actionErr == nil {
				want = journalrequest.Accepted
			}
			if status.State != want || status.Description != d {
				t.Fatal("nonserial generation transition", status.State, want)
			}
			if _, err = s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalClaim(d), now); !errors.Is(err, journalrequest.ErrConflict) {
				t.Fatal("postreport old claim", err)
			}
			if _, err = s.AcceptJournalResult(ctx, snap.InvitationID, cert.CertificateHash(), journalResult(d), now); !errors.Is(err, journalrequest.ErrConflict) {
				t.Fatal("postreport old result", err)
			}
			view, err := s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, now)
			if err != nil || view == nil || view.PolicyGeneration != report.Tuple {
				t.Fatal("floor lost in racing save", err)
			}
		})
	}
}

func TestJournalGenerationReplaysCannotReplaceHigherTupleOrReuseGeneration(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	old := generationReport(at, 1, 1)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), old, at); err != nil {
		t.Fatal(err)
	}
	for _, same := range []string{"generation", "policy"} {
		next := generationReport(at.Add(time.Second), 2, 2)
		if same == "generation" {
			next.Tuple.Generation = old.Tuple.Generation
		} else {
			next.Tuple.PolicyDigest = old.Tuple.PolicyDigest
		}
		if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, next.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
			t.Fatal("revision reused "+same, err)
		}
	}
	next := generationReport(at.Add(time.Second), 2, 2)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, next.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), old, next.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("lower revision retry accepted", err)
	}
}

func TestJournalGenerationPermissionSummaryIsBoundDurableAndDetached(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	report := generationReport(at, 1, 1)
	report.SchemaVersion = journalgeneration.ReportVersionV2
	report.PolicyEnabled = true
	report.ServiceAuthorization = journalgeneration.ExactUnits
	report.AllowedUnits = []string{"a.service", "b.service"}
	accepted, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at)
	if err != nil {
		t.Fatal(err)
	}
	accepted.AllowedUnits[0] = "mutated.service"
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	view, err := s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, at)
	if err != nil || view.SchemaVersion != "tracebolt.journal-generation-view.v2" || view.PolicyEnabled == nil || !*view.PolicyEnabled || view.AllowedUnits == nil || (*view.AllowedUnits)[0] != "a.service" {
		t.Fatal("summary lost/aliased", err)
	}
	(*view.AllowedUnits)[0] = "mutated.service"
	before := journalBody(t, s, snap.InvitationID)
	for _, change := range []func(*journalgeneration.Report){
		func(r *journalgeneration.Report) { r.PolicyEnabled = false }, func(r *journalgeneration.Report) { r.AllowedUnits = []string{"a.service"} },
		func(r *journalgeneration.Report) {
			r.ServiceAuthorization = journalgeneration.AllSystemServices
			r.AllowedUnits = []string{}
		},
		func(r *journalgeneration.Report) {
			r.SchemaVersion = journalgeneration.ReportVersion
			r.PolicyEnabled = false
			r.ServiceAuthorization = ""
			r.AllowedUnits = nil
		},
	} {
		next := journalgeneration.CloneReport(report)
		next.Sequence++
		next.ObservedAt = at.Add(time.Second)
		change(&next)
		if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, next.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
			t.Fatal("same tuple summary changed", err)
		}
		if !bytes.Equal(before, journalBody(t, s, snap.InvitationID)) {
			t.Fatal("conflict changed durable report")
		}
	}
	next := generationReport(at.Add(time.Second), 2, 2)
	if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, next.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("v2 downgraded", err)
	}
	next.SchemaVersion = journalgeneration.ReportVersionV2
	next.PolicyEnabled = true
	next.ServiceAuthorization = journalgeneration.AllSystemServices
	next.AllowedUnits = []string{}
	if _, err = s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), next, next.ObservedAt); err != nil {
		t.Fatal("explicit new tuple broad scope rejected", err)
	}
	view, err = s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, next.ObservedAt.Add(JournalGenerationMaxAge))
	if err != nil || view.Fresh || view.AllowedUnits == nil || *view.AllowedUnits == nil || len(*view.AllowedUnits) != 0 {
		t.Fatal("stale/broad metadata", err)
	}
	_, err = s.JournalRequestStatus(ctx, snap.Approval.DeviceID, next.ObservedAt.Add(JournalGenerationMaxAge))
	if !errors.Is(err, journalrequest.ErrNotFound) {
		t.Fatal("report automatically created capture", err)
	}
}

func TestJournalGenerationLegacySummaryCannotEnrichSameTuple(t *testing.T) {
	_, s, _, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	r := generationReport(at, 1, 1)
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), r, at); err != nil {
		t.Fatal(err)
	}
	r.Sequence++
	r.ObservedAt = at.Add(time.Second)
	r.SchemaVersion = journalgeneration.ReportVersionV2
	r.ServiceAuthorization = journalgeneration.ExactUnits
	r.AllowedUnits = []string{"a.service"}
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), r, r.ObservedAt); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("silent same-policy disclosure migration", err)
	}
}
