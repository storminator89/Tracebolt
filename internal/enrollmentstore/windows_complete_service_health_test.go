package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
	"testing"
	"time"
)

func TestCompleteServiceHealthOriginalGenerationBeyondPreview(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	f.grant(t)
	ctx := context.Background()
	messages := f.messages(t, 9, 2051, f.at)
	for _, m := range messages {
		if _, e := f.apply(t, m, f.at.Add(4*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	// Unrelated telemetry counter and receipt must stay separate.
	if _, e := f.s.SaveObservation(ctx, f.snap.InvitationID, f.cert.CertificateHash(), windowsStoreFrame(t, 80, f.at.Add(5*time.Second)), f.at.Add(5*time.Second)); e != nil {
		t.Fatal(e)
	}
	selected := windowsservicehealth.WithCompleteSelections(ctx, map[string][]string{f.snap.Approval.DeviceID: {"InventedService02050"}})
	rows, e := f.s.WindowsCapacityInputs(selected, f.at.Add(6*time.Second))
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	in := rows[0]
	sample := in.Services.Complete
	if sample == nil || sample.Source.Sequence != 9 || sample.Source.RowCount != 2051 || len(sample.Rows) != 1 || sample.Rows[0].Name != "InventedService02050" || !sample.Source.CapturedAt.Equal(f.at) || !sample.Source.ReceivedAt.Equal(f.at.Add(4*time.Second)) || in.Sequence != 80 || !in.ReceivedAt.Equal(f.at.Add(5*time.Second)) {
		t.Fatal("independent provenance or exact selection lost", sample, in.Sequence, e)
	}
	base, e := f.s.WindowsCapacityInputs(ctx, f.at.Add(7*time.Second))
	if e != nil || base[0].Services.Complete != nil {
		t.Fatal("unsolicited complete read", e)
	}
	f.s.Close()
	f.s = f.f.open(t, f.path)
	again, e := f.s.WindowsCapacityInputs(selected, f.at.Add(8*time.Second))
	if e != nil || again[0].Services.Complete.Source != sample.Source {
		t.Fatal("restart refreshed source", e)
	}
	stale, e := f.s.WindowsCapacityInputs(selected, f.at.Add(301*time.Second))
	if e != nil || stale[0].Services.Complete != nil {
		t.Fatal("stale source admitted", e)
	}
}
func TestCompleteServiceHealthPartialDisabledMissingAndRevoked(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	f.grant(t)
	ctx := context.Background()
	id := f.snap.Approval.DeviceID
	selected := windowsservicehealth.WithCompleteSelections(ctx, map[string][]string{id: {"InventedService00199"}})
	messages := f.messages(t, 1, 200, f.at)
	if _, e := f.apply(t, messages[0], f.at); e != nil {
		t.Fatal(e)
	}
	read := func(now time.Time) *windowsservicehealth.CompleteSample {
		rows, e := f.s.WindowsCapacityInputs(selected, now)
		if e != nil {
			t.Fatal(e)
		}
		return rows[0].Services.Complete
	}
	if read(f.at) != nil {
		t.Fatal("partial prefix admitted")
	}
	for _, m := range messages[1:] {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	if read(f.at) == nil {
		t.Fatal("complete missing")
	}
	failed := windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "failure", DeviceID: id, Consent: f.consent, Sequence: 2, AttemptedAt: &f.at, Reason: "unavailable"}
	if _, e := f.apply(t, failed, f.at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if read(f.at.Add(time.Second)) != nil {
		t.Fatal("failed newer source silently reused older complete")
	}
	f.consent.Enabled = false
	f.consent.Revision++
	f.consent.ChangedAt = f.at.Add(2 * time.Second)
	if _, e := f.apply(t, f.scope(), f.consent.ChangedAt); e != nil {
		t.Fatal(e)
	}
	if read(f.consent.ChangedAt) != nil {
		t.Fatal("disabled scope admitted")
	}
	cmd := control(f.snap, 20)
	cmd.Now = f.at.Add(3 * time.Second).Unix()
	if _, e := f.s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: cmd, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	if read(f.at.Add(3*time.Second)) != nil {
		t.Fatal("revoked source disclosed")
	}
}
func TestCompleteServiceHealthLeaseExactSourceAndUsedStateLoss(t *testing.T) {
	f := newFullServicesFixture(t, "tls")
	f.grant(t)
	for _, m := range f.messages(t, 1, 1, f.at) {
		if _, e := f.apply(t, m, f.at); e != nil {
			t.Fatal(e)
		}
	}
	ctx := windowsservicehealth.WithCompleteSelections(context.Background(), map[string][]string{f.snap.Approval.DeviceID: {"InventedService00000"}})
	rows, e := f.s.WindowsCapacityInputs(ctx, f.at)
	if e != nil {
		t.Fatal(e)
	}
	in := windowsservicehealth.Input{Input: rows[0].Input, Sample: rows[0].Services, Complete: true, CurrentLeaf: rows[0].CurrentLeaf}
	p := in.Sample.Complete.Source
	in.Selection = &p
	now := f.at
	called := false
	if e := f.s.WithWindowsCompleteServiceAuthority(ctx, in, func() time.Time { return now }, func(guard func(time.Time) error) error { called = true; return guard(now) }); e != nil || !called {
		t.Fatal(e)
	}
	// The original anchor and exact expiry do not identify the active leaf.
	rotated := in
	rotated.CurrentLeaf = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	called = false
	if e := f.s.WithWindowsCompleteServiceAuthority(ctx, rotated, func() time.Time { return now }, func(func(time.Time) error) error { called = true; return nil }); e == nil || called {
		t.Fatal("changed current leaf with same original anchor and expiry admitted")
	}
	bad := p
	bad.ManifestSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	in.Selection = &bad
	called = false
	if e := f.s.WithWindowsCompleteServiceAuthority(ctx, in, func() time.Time { return now }, func(guard func(time.Time) error) error { called = true; return nil }); e == nil || called {
		t.Fatal("changed generation admitted")
	}
	// Deliberate data-loss fixture: used authority cannot be reconstructed.
	if _, e := f.s.db.ExecContext(context.Background(), `DELETE FROM wfs_authority`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.WindowsCapacityInputs(ctx, now); e == nil {
		t.Fatal("lost used source became default off")
	}
}
