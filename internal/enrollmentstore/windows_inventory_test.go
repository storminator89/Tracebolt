package enrollmentstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"path/filepath"
	"testing"
	"time"
)

func activeWindowsStore(t *testing.T, profile string) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = windowsmanaged.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	f.challenge.CollectionProfile = windowsmanaged.CollectionProfile
	if profile == "http-test" {
		f.config.Binding.Profile = profile
		f.config.Binding.Origin = "http://manager.example"
		f.challenge.Profile = profile
		f.challenge.Origin = f.config.Binding.Origin
	}
	path := filepath.Join(t.TempDir(), "private", "windows.sqlite")
	s := f.open(t, path)
	ctx := context.Background()
	create := f.createCommand()
	create.Platform = "windows"
	v, e := s.CreateInvitation(ctx, create)
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(v, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(v, 3), DeviceID: id("agent", 1), KeyFingerprint: v.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(v, 4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := s.SigningIntent(ctx, v.InvitationID, v.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := f.issue(t, intent)
	v, e = s.CommitIssued(ctx, f.control(v, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	control := f.control(v, 6)
	v, e = s.Activate(ctx, control, f.activation(t, cert, control))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, v, cert
}
func windowsStoreFrame(t *testing.T, sequence uint64, at time.Time) []byte {
	t.Helper()
	value := 42.0
	metric := model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Synthetic measured fixture", CollectedAt: at}
	r := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Windows fixture", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Fixture", Scope: "Explicit hostname scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "fixture-windows"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Fixture", Scope: "Bounded process scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 12, Name: "fixture.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Fixture", Scope: "Denied service scope", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Fixture", Scope: "Partial software scope", Quality: "limited", Rows: []windowsinventory.Software{{Name: "Fixture app", Version: "1", Publisher: "Fixture", RegistryView: "64"}}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Fixture", Scope: "Explicit interface scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 1, Name: "Fixture", Address: "192.0.2.8", PrefixLength: 24}}}}
	snap, d, err := windowsmanaged.FromReport(r, fmt.Sprintf("sample_%032x", sequence))
	if err != nil {
		t.Fatal(err)
	}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameWindowsInventoryVersion, Sequence: sequence, Observation: b, WindowsInventory: &snap})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestWindowsInventoryDurableViewRetryHistoryAndScope(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, s, path, v, cert := activeWindowsStore(t, profile)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			raw := windowsStoreFrame(t, 1, at)
			first, err := s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), raw, at)
			if err != nil {
				t.Fatal(err)
			}
			view, err := s.WindowsInventoryView(ctx, v.Approval.DeviceID, at)
			if err != nil || view.Status != "fresh" || view.Snapshot == nil || view.Snapshot.Hostname.Rows[0].Value != "fixture-windows" || view.Snapshot.Processes.Rows[0].PID != 12 || view.Snapshot.Services.Quality != "denied" || view.Snapshot.Software.Quality != "partial" {
				t.Fatal("Windows store projection lost scoped evidence", err)
			}
			history, err := s.ResourceHistory(ctx, v.Approval.DeviceID, at)
			if err != nil || len(history.Points) != 1 || history.Points[0].CPU.Value == nil || *history.Points[0].CPU.Value != 42 {
				t.Fatal("shared metrics history missing", err)
			}
			s.Close()
			s = f.open(t, path)
			retry, err := s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
			if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) {
				t.Fatal("retry refreshed original receipt", err)
			}
			stale, err := s.WindowsInventoryView(ctx, v.Approval.DeviceID, at.Add(3*time.Minute))
			if err != nil || stale.Status != "stale" || stale.Snapshot == nil || !stale.Snapshot.CollectedAt.Equal(at) {
				t.Fatal("stale capture renewed or hidden", err)
			}
			if _, err = s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), sampleFrame(t, 2, at.Add(time.Minute)), at.Add(time.Minute)); !errors.Is(err, enrollmentstate.ErrProof) {
				t.Fatal("Windows identity accepted Linux/basic payload", err)
			}
			sameCapture := windowsStoreFrame(t, 2, at)
			if _, err = s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), sameCapture, at.Add(time.Second)); !errors.Is(err, lanstore.ErrReplay) {
				t.Fatal("equal capture advanced generation", err)
			}
			next := windowsStoreFrame(t, 2, at.Add(time.Minute))
			if _, err = s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), next, at.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			ctl := control(v, 20)
			ctl.Now = at.Add(2 * time.Minute).Unix()
			if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			revoked, err := s.WindowsInventoryView(ctx, v.Approval.DeviceID, at.Add(2*time.Minute))
			if err != nil || revoked.Status != "revoked" || revoked.Snapshot != nil {
				t.Fatal("revoked identity exposed inventory", err)
			}
		})
	}
}
func TestWindowsInventoryCannotBeWrittenIntoBasicStore(t *testing.T) {
	_, s, _, v, cert := activeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveObservation(context.Background(), v.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 1, at), at); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("Windows scope silently admitted under basic identity", err)
	}
}

func TestWindowsInventoryViewRechecksClockFreshnessAndExpiry(t *testing.T) {
	_, s, _, v, cert := activeWindowsStore(t, "tls")
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveObservation(ctx, v.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 1, at), at); err != nil {
		t.Fatal(err)
	}
	view, err := s.WindowsInventoryView(ctx, v.Approval.DeviceID, at)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := view.RecheckAt(at.Add(121 * time.Second))
	if err != nil || stale.Status != "stale" || stale.Snapshot == nil || !stale.Snapshot.CollectedAt.Equal(at) {
		t.Fatal("slow response falsely kept fresh capture")
	}
	expired, err := view.RecheckAt(time.Unix(v.Intent.NotAfter, 0).UTC())
	if err != nil || expired.Status != "revoked" || expired.Snapshot != nil {
		t.Fatal("slow response outlived identity")
	}
	if _, err = view.RecheckAt(at.Add(-time.Nanosecond)); err == nil {
		t.Fatal("clock rollback accepted")
	}
}
