package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowssecuritycoverage"
	"strings"
	"testing"
	"time"
)

func coverageStoreFrame(t *testing.T, seq uint64, at time.Time, useful bool) []byte {
	t.Helper()
	var f lanstore.Frame
	if json.Unmarshal(windowsUpdatesStoreFrame(t, seq, at), &f) != nil {
		t.Fatal("fixture")
	}
	r := windowssecuritycoverage.Request{Consent: windowssecuritycoverage.Consent{GrantID: strings.Repeat("6", 32)}, GenerationID: f.WindowsInventory.GenerationID, CollectedAt: at}
	s := windowssecuritycoverage.Empty(r, windowssecuritycoverage.ErrBudget.Error())
	if useful {
		name := "private-antivirus"
		count := uint32(1)
		s.Antivirus = windowssecuritycoverage.Antivirus{Quality: "observed", ReportedCount: &count, Rows: []windowssecuritycoverage.Product{{Index: 0, Name: &name, State: "on", SignatureStatus: "up-to-date"}}}
		s.TPM = windowssecuritycoverage.TPM{Quality: "observed", Presence: "present", Version: "2.0"}

	}

	f.SchemaVersion = lanstore.FrameWindowsSecurityCoverageVersion
	f.WindowsSecurityCoverage = &s
	b, _ := json.Marshal(f)
	return b
}
func TestWindowsSecurityCoverageRetentionExpiryOmissionAndReplacement(t *testing.T) {
	for _, change := range []string{"expiry", "omission", "replacement"} {
		t.Run(change, func(t *testing.T) {
			_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			for i := uint64(1); i <= 2; i++ {
				when := at.Add(time.Duration(i-1) * 30 * time.Second)
				if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), coverageStoreFrame(t, i, when, i == 1), when); e != nil {
					t.Fatal(e)
				}
			}
			now := at.Add(30 * time.Second)
			view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext == nil || view.RetainedContext.SecurityCoverage == nil || !view.RetainedContext.SecurityCoverage.CollectedAt.Equal(at) || view.SecurityCoverage.Antivirus.Reason != windowssecuritycoverage.ErrBudget.Error() {
				t.Fatal("retention lost original source/failure", e)
			}
			if change == "expiry" {
				view, e = view.RecheckAt(at.Add(24 * time.Hour))
				if e != nil || view.RetainedContext != nil && view.RetainedContext.SecurityCoverage != nil || view.SecurityCoverage == nil {
					t.Fatal("expiry changed latest or retained old data", e)
				}
				return
			}
			var f lanstore.Frame
			now = now.Add(30 * time.Second)
			json.Unmarshal(coverageStoreFrame(t, 3, now, false), &f)
			if change == "omission" {
				f.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
				f.WindowsSecurityCoverage = nil
			} else {
				f.WindowsSecurityCoverage.GrantID = strings.Repeat("7", 32)
			}
			b, _ := json.Marshal(f)
			if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), b, now); e != nil {
				t.Fatal(e)
			}
			view, e = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
			if e != nil || view.RetainedContext != nil && view.RetainedContext.SecurityCoverage != nil {
				t.Fatal("old grant kept private serial", e)
			}
		})
	}
}

func TestWindowsSecurityCoverageUnknownOnlyDoesNotRefreshUsefulCapture(t *testing.T) {
	_, s, _, identity, cert := activeWindowsStoreTTL(t, "http-test", 48*time.Hour)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), coverageStoreFrame(t, 1, at, true), at); e != nil {
		t.Fatal(e)
	}
	now := at.Add(30 * time.Second)
	var f lanstore.Frame
	json.Unmarshal(coverageStoreFrame(t, 2, now, false), &f)
	count := uint32(1)
	f.WindowsSecurityCoverage.Antivirus = windowssecuritycoverage.Antivirus{Quality: "partial", Reason: windowssecuritycoverage.ErrMetadata.Error(), ReportedCount: &count, Rows: []windowssecuritycoverage.Product{{Index: 0, State: "unknown", SignatureStatus: "unknown"}}}
	raw, _ := json.Marshal(f)
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, now); e != nil {
		t.Fatal(e)
	}
	view, e := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, now)
	if e != nil || view.RetainedContext == nil || view.RetainedContext.SecurityCoverage == nil || !view.RetainedContext.SecurityCoverage.CollectedAt.Equal(at) || view.SecurityCoverage.Antivirus.Quality != "partial" {
		t.Fatal("unknown-only capture refreshed useful source", e)
	}
}
