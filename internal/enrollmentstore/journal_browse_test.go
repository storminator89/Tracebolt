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

func TestRetainedBrowseRequiresNewReportedGrantAndKeepsConsumeFloor(t *testing.T) {
	f, s, path, snap, cert, at := journalFixture(t)
	ctx := context.Background()
	device := snap.Approval.DeviceID
	q := journalQuery(at)
	q.BrowseMode = journalview.BrowseMode
	q.Start = time.Unix(0, 0).UTC()
	q.Unit = "new-future.service"
	old := generationReport(at, 1, 1)
	old.SchemaVersion = journalgeneration.ReportVersionV2
	old.PolicyEnabled = true
	old.ServiceAuthorization = journalgeneration.AllSystemServices
	old.AllowedUnits = []string{}
	if _, e := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), old, at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CreateJournalRequestWithGeneration(ctx, device, 0, q, old.Tuple, at); !errors.Is(e, journalrequest.ErrNotReady) {
		t.Fatal("existing all-service grant promoted", e)
	}
	report := generationReport(at.Add(time.Second), 2, 2)
	report.SchemaVersion = journalgeneration.ReportVersionV3
	report.PolicyEnabled = true
	report.ServiceAuthorization = journalgeneration.AllSystemServices
	report.AllowedUnits = []string{}
	report.BrowsingContract = journalview.BrowseContract
	at = at.Add(time.Second)
	if _, e := s.AcceptJournalGeneration(ctx, snap.InvitationID, cert.CertificateHash(), report, at); e != nil {
		t.Fatal(e)
	}
	d, e := s.CreateJournalRequestWithGeneration(ctx, device, 0, q, report.Tuple, at)
	if e != nil || d.SchemaVersion != journalrequest.SchemaVersionV3 {
		t.Fatal("new scoped request", e)
	}
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalrequest.Claim{Identity: d.Identity, PolicyDigest: d.PolicyGeneration.PolicyDigest}, at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.CreateJournalRequestWithGeneration(ctx, device, 1, q, report.Tuple, at.Add(time.Second)); !errors.Is(e, ErrBusy) {
		t.Fatal("page rate budget missing", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s = f.open(t, path)
	if _, e := s.ClaimJournalRequest(ctx, snap.InvitationID, cert.CertificateHash(), journalrequest.Claim{Identity: d.Identity, PolicyDigest: d.PolicyGeneration.PolicyDigest}, at.Add(2*time.Second)); !errors.Is(e, journalrequest.ErrConsumed) {
		t.Fatal("restart replay recollects", e)
	}
	status, e := s.JournalRequestStatus(ctx, device, at.Add(2*time.Second))
	if e != nil || status.Description != d || status.ContentStatus != "unavailable" {
		t.Fatal("restart changed original request/expiry", e)
	}
}
