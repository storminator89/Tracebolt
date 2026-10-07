package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"testing"
	"time"
)

func TestV4GenerationAdmitsOnlyExactBoundedAIRequestAndKeepsConsumeFloor(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	device := snap.Approval.DeviceID
	old := generationReport(at, 1, 1)
	old.SchemaVersion = journalgeneration.ReportVersionV2
	old.PolicyEnabled = true
	old.ServiceAuthorization = journalgeneration.AllSystemServices
	old.AllowedUnits = []string{}
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), old, at); err != nil {
		t.Fatal(err)
	}
	report := generationReport(at.Add(time.Second), 2, 2)
	report.SchemaVersion = journalgeneration.ReportVersionV3
	report.PolicyEnabled = true
	report.ServiceAuthorization = journalgeneration.AllSystemServices
	report.AllowedUnits = []string{}
	report.BrowsingContract = journalview.BrowseContract
	at = at.Add(time.Second)
	// An authorization report cannot change scope under the old generation.
	forged := report
	forged.Tuple = old.Tuple
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), forged, at); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("same-generation scope promotion", err)
	}
	if _, err := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); err != nil {
		t.Fatal(err)
	}
	q := journalview.Query{Unit: "new-future.service", Start: at.Add(-5 * time.Minute), End: at, MaxPriority: 4}
	if _, err := s.CreateJournalRequestWithGeneration(ctx, device, 0, q, old.Tuple, at); !errors.Is(err, journalrequest.ErrConflict) {
		t.Fatal("old AI approval reused", err)
	}
	d, err := s.CreateJournalRequestWithGeneration(ctx, device, 0, q, report.Tuple, at)
	if err != nil || d.SchemaVersion != journalrequest.SchemaVersionV2 || d.Query != q || d.Budgets != journalrequest.FixedBudgets() {
		t.Fatal("new bounded capture expanded", err)
	}
	claim := journalrequest.Claim{Identity: d.Identity, PolicyDigest: report.Tuple.PolicyDigest}
	if _, err := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), claim, at); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t, path)
	if _, err := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), claim, at.Add(time.Second)); !errors.Is(err, journalrequest.ErrConsumed) {
		t.Fatal("restart replayed bounded capture", err)
	}
	status, err := s.JournalRequestStatus(ctx, device, at.Add(time.Second))
	if err != nil || status.Description != d || status.ContentStatus != "unavailable" {
		t.Fatal("restart adopted content or renewed expiry", err)
	}
}
