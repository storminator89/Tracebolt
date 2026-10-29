package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/windowsservice"
)

type recoveryStatusFixture struct {
	layout                            windowsservice.Layout
	files                             map[string][]byte
	reads, inspections                int
	failRead, failInspect, changeRead int
	changeService                     bool
	cancelAt                          int
	cancel                            context.CancelFunc
}

func recoveryStatusCase(t *testing.T) *recoveryStatusFixture {
	t.Helper()
	f := reconcileSetupCase(t)
	var i readSetupIntent
	var r installReceipt
	_ = json.Unmarshal(f.intent, &i)
	_ = json.Unmarshal(f.receipt, &r)
	i.Consent = freshReadAdminSetupConsent(false)
	i.Plan.Layout.StateRoot = "fixture-state"
	r.Service.Layout = i.Plan.Layout
	r.Service.ServiceSID = "fixture-SID"
	r.Version = 12
	r.ReadSetup = &readSetupProgress{Consent: i.Consent, Phase: "claim-started"}
	intent, _ := json.Marshal(i)
	receipt, _ := json.Marshal(r)
	root := i.Plan.Layout.StateRoot + "-installer"
	return &recoveryStatusFixture{layout: i.Plan.Layout, files: map[string][]byte{
		filepath.Join(root, "intent.json"):  intent,
		filepath.Join(root, "receipt.json"): receipt,
	}}
}

func (f *recoveryStatusFixture) read(path string, max int64) ([]byte, error) {
	f.reads++
	if f.cancel != nil && f.cancelAt == f.reads {
		f.cancel()
	}
	raw, ok := f.files[path]
	if !ok || max != 64<<10 {
		return nil, errors.New("unexpected private path")
	}
	if f.failRead == f.reads {
		return append([]byte(nil), raw...), errors.New("private read/close failure")
	}
	if f.changeRead == f.reads {
		return append(append([]byte(nil), raw...), ' '), nil
	}
	return append([]byte(nil), raw...), nil
}

func (f *recoveryStatusFixture) inspect(_ context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
	f.inspections++
	if f.failInspect == f.inspections {
		return windowsservice.Snapshot{}, errors.New("private SCM error")
	}
	s := pendingObservationSnapshot(r)
	if f.changeService && f.inspections > 1 {
		s.State = windowsservice.Running
	}
	return s, nil
}

func (f *recoveryStatusFixture) mutateReceipt(t *testing.T, change func(*installReceipt)) {
	t.Helper()
	path := filepath.Join(f.layout.StateRoot+"-installer", "receipt.json")
	var r installReceipt
	if json.Unmarshal(f.files[path], &r) != nil {
		t.Fatal("fixture")
	}
	change(&r)
	f.files[path], _ = json.Marshal(r)
}

func TestReadAdminRecoveryStatusIsBoundedProvisionalAndReadOnly(t *testing.T) {
	for _, phase := range []string{"install-started", "claim-started", "activation-started", "grants-started", "grants-incomplete", "grants-verified"} {
		t.Run(phase, func(t *testing.T) {
			f := recoveryStatusCase(t)
			f.mutateReceipt(t, func(r *installReceipt) { r.ReadSetup.Phase = phase })
			before, _ := json.Marshal(f.files)
			got, err := inspectReadAdminRecovery(context.Background(), f.layout, f.read, f.inspect)
			after, _ := json.Marshal(f.files)
			raw, _ := json.Marshal(got)
			if err != nil || got.Phase != phase || got.Recovery != "no-resume-authority" || got.Evidence != "protected-file-snapshot-not-manifest-verified" || got.Service != "process-visible-owned-stopped-disabled" || len(raw) > 512 || f.reads != 4 || f.inspections != 2 || !bytes.Equal(before, after) {
				t.Fatal("diagnostic escaped its read-only provisional boundary", err)
			}
			for _, private := range []string{"fixture-state", "fixture-SID", "fixture-id", strings.Repeat("a", 64)} {
				if bytes.Contains(raw, []byte(private)) {
					t.Fatal("private receipt metadata escaped")
				}
			}
		})
	}
}

func TestReadAdminRecoveryStatusRejectsUnprovedOrChangingEvidence(t *testing.T) {
	for n := 1; n <= 4; n++ {
		f := recoveryStatusCase(t)
		f.failRead = n
		assertRecoveryStatusRejected(t, f)
	}
	for _, n := range []int{3, 4} {
		f := recoveryStatusCase(t)
		f.changeRead = n
		assertRecoveryStatusRejected(t, f)
	}
	for n := 1; n <= 2; n++ {
		f := recoveryStatusCase(t)
		f.failInspect = n
		assertRecoveryStatusRejected(t, f)
	}
	f := recoveryStatusCase(t)
	f.changeService = true
	assertRecoveryStatusRejected(t, f)
	for _, mutate := range []func(*installReceipt){
		func(r *installReceipt) { r.Version = 11 },
		func(r *installReceipt) { r.Prepared = false },
		func(r *installReceipt) { r.Service.Version = 1 },
		func(r *installReceipt) { r.Service.Complete = false },
		func(r *installReceipt) { r.Service.InstallationID = "replacement" },
		func(r *installReceipt) { r.Service.ExecutableSHA256 = strings.Repeat("f", 64) },
		func(r *installReceipt) { r.Service.ConfigurationSHA256 = strings.Repeat("f", 64) },
		func(r *installReceipt) { r.Service.Layout.StateRoot = "foreign" },
		func(r *installReceipt) { r.ReadSetup = nil },
		func(r *installReceipt) { r.ReadSetup.Consent.Acknowledged = false },
		func(r *installReceipt) { r.ReadSetup.Consent.Scopes = r.ReadSetup.Consent.Scopes[:20] },
		func(r *installReceipt) { r.ReadSetup.Phase = "startup-transition-started" },
		func(r *installReceipt) { r.ReadSetup.Phase = "configured" },
		func(r *installReceipt) { r.ReadSetup.Phase = "private-unrecognized-text" },
	} {
		f := recoveryStatusCase(t)
		f.mutateReceipt(t, mutate)
		assertRecoveryStatusRejected(t, f)
	}
	for _, name := range []string{"intent.json", "receipt.json"} {
		for _, malformed := range []func([]byte) []byte{
			func(b []byte) []byte { return append(b, ' ') },
			func(b []byte) []byte { return append([]byte(`{"unknown":true,`), b[1:]...) },
			func(b []byte) []byte { return append([]byte(`{"version":12,"version":12,`), b[1:]...) },
			func(b []byte) []byte { return append(append([]byte(nil), b...), b...) },
			func([]byte) []byte { return bytes.Repeat([]byte("x"), (64<<10)+1) },
			func([]byte) []byte { return nil },
		} {
			f := recoveryStatusCase(t)
			path := filepath.Join(f.layout.StateRoot+"-installer", name)
			f.files[path] = malformed(f.files[path])
			assertRecoveryStatusRejected(t, f)
		}
	}
}

func assertRecoveryStatusRejected(t *testing.T, f *recoveryStatusFixture) {
	t.Helper()
	got, err := inspectReadAdminRecovery(context.Background(), f.layout, f.read, f.inspect)
	if err != errLifecycle || !reflect.DeepEqual(got, readAdminRecoveryStatus{}) {
		t.Fatal("unproved status escaped", err)
	}
}

func TestReadAdminRecoveryStatusRejectsMissingOrIsolatedService(t *testing.T) {
	for _, mutate := range []func(*windowsservice.Snapshot){
		func(s *windowsservice.Snapshot) { *s = windowsservice.Snapshot{} },
		func(s *windowsservice.Snapshot) { s.State = windowsservice.Running },
		func(s *windowsservice.Snapshot) { s.Configuration.StartType = 2 },
		func(s *windowsservice.Snapshot) { s.ServiceSID = "other" },
	} {
		f := recoveryStatusCase(t)
		got, err := inspectReadAdminRecovery(context.Background(), f.layout, f.read, func(ctx context.Context, r windowsservice.Receipt) (windowsservice.Snapshot, error) {
			s, e := f.inspect(ctx, r)
			mutate(&s)
			return s, e
		})
		if err != errLifecycle || got != (readAdminRecoveryStatus{}) {
			t.Fatal("false absence or changed service accepted")
		}
	}
}

func TestReadAdminRecoveryStatusCancellationAndCLI(t *testing.T) {
	f0 := recoveryStatusCase(t)
	for _, ctx := range []context.Context{nil, canceledRecoveryContext()} {
		if got, err := inspectReadAdminRecovery(ctx, f0.layout, f0.read, f0.inspect); err != errLifecycle || got != (readAdminRecoveryStatus{}) || f0.reads != 0 || f0.inspections != 0 {
			t.Fatal("invalid context reached native dependencies")
		}
	}
	for n := 1; n <= 4; n++ {
		f := recoveryStatusCase(t)
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel, f.cancelAt = cancel, n
		got, err := inspectReadAdminRecovery(ctx, f.layout, f.read, f.inspect)
		cancel()
		if err != errLifecycle || got != (readAdminRecoveryStatus{}) {
			t.Fatal("canceled evidence escaped")
		}
	}
	for _, args := range [][]string{
		{"--read-admin-recovery-status", "--apply"},
		{"--read-admin-recovery-status", "--insecure-http-test"},
		{"--read-admin-recovery-status", "--bootstrap-file=private-path"},
		{"--read-admin-recovery-status", "--enroll"},
		{"--read-admin-recovery-status", "--windows-inventory"},
		{"--read-admin-recovery-status", "--automatic-certificate-renewal"},
	} {
		var out, stderr bytes.Buffer
		if runWith(context.Background(), args, &out, &stderr, func(context.Context, request, io.Writer, io.Writer) (any, error) {
			t.Fatal("invalid flags dispatched")
			return nil, nil
		}) != 2 || out.Len() != 0 || strings.Contains(stderr.String(), "private-path") {
			t.Fatal("unsafe CLI accepted")
		}
	}
	f := recoveryStatusCase(t)
	var out, stderr bytes.Buffer
	calls := 0
	op := func(ctx context.Context, r request, _, _ io.Writer) (any, error) {
		calls++
		if r.mode != "read-admin-recovery-status" {
			t.Fatal("wrong dispatch")
		}
		return inspectReadAdminRecovery(ctx, f.layout, f.read, f.inspect)
	}
	if runWith(context.Background(), []string{"--read-admin-recovery-status"}, &out, &stderr, op) != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(out.String(), "no-resume-authority") {
		t.Fatal("status command failed")
	}
	f.failInspect = f.inspections + 1
	out.Reset()
	stderr.Reset()
	if runWith(context.Background(), []string{"--read-admin-recovery-status"}, &out, &stderr, op) != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "private") {
		t.Fatal("error leaked or became usable output")
	}
}

func canceledRecoveryContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
