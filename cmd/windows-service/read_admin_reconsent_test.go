package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"reflect"
	"strings"
	"testing"
)

type reconsentFixture struct {
	installed                           installReceipt
	original                            []byte
	files                               map[string][]byte
	fail                                string
	state                               windowsservice.State
	identity                            string
	existing                            string
	creates, writes, configures, checks int
}

func newReconsentFixture() *reconsentFixture {
	f := &reconsentFixture{installed: installReceipt{Version: 1, Prepared: true, Service: windowsservice.Receipt{Version: 1, Complete: true, Layout: windowsservice.Layout{EnrollmentRoot: "fixture", Executable: `C:\Program Files\Tracebolt\tracebolt-windows-service.exe`}}}, files: map[string][]byte{}, state: windowsservice.Stopped, identity: strings.Repeat("a", 64), existing: "absent"}
	f.original, _ = json.Marshal(f.installed)
	return f
}
func (f *reconsentFixture) err(step string) error {
	if f.fail == step {
		return errors.New("fixture")
	}
	return nil
}
func (f *reconsentFixture) Read(name string) ([]byte, error) {
	return append([]byte(nil), f.files[name]...), f.err("read")
}
func (f *reconsentFixture) Write(name string, raw []byte) error {
	f.writes++
	var r readAdminReconsentReceipt
	if json.Unmarshal(raw, &r) != nil {
		return errLifecycle
	}
	if e := f.err(r.Phase); e != nil {
		return e
	}
	f.files[name] = append([]byte(nil), raw...)
	return nil
}
func (f *reconsentFixture) Verify() error { return f.err("verify-journal") }
func (f *reconsentFixture) Close() error  { return f.err("close") }
func (f *reconsentFixture) hooks() readAdminReconsentSteps {
	return readAdminReconsentSteps{
		executable: func() (string, error) {
			if f.fail == "external-binary" {
				return `C:\Downloads\tracebolt-windows-service.exe`, nil
			}
			return f.installed.Service.Layout.Executable, f.err("executable")
		},
		inspect: func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
			f.checks++
			return windowsservice.Snapshot{State: f.state}, f.err("inspect")
		},
		originalReceipt: func() ([]byte, error) { return append([]byte(nil), f.original...), f.err("original") },
		identity:        func(string, lanclient.WindowsCapabilityConsent) (string, error) { return f.identity, f.err("identity") },
		preview: func(_ string, c lanclient.WindowsCapabilityConsent, guard func() error) ([]lanclient.WindowsReadAdminScopeState, error) {
			if e := guard(); e != nil {
				return nil, e
			}
			states := []lanclient.WindowsReadAdminScopeState{}
			for i, scope := range c.Scopes[1:] {
				s := lanclient.WindowsReadAdminScopeState{Scope: scope}
				if i < 4 {
					s.Enabled = true
					s.SHA256 = strings.Repeat("d", 64)
				}
				states = append(states, s)
			}
			return states, f.err("preview")
		},
		preserve: func(string, lanclient.WindowsCapabilityConsent, []lanclient.WindowsReadAdminScopeState) error {
			return f.err("preserve")
		},
		existingPhase: func() (string, error) { return f.existing, f.err("existing") },
		compatibility: func(context.Context) error { return f.err("compatibility") },
		create:        func() (setupJournal, error) { f.creates++; return f, f.err("create") },
		configure: func(_ string, c lanclient.WindowsCapabilityConsent, guard func() error) (lanclient.WindowsCapabilityConsentResult, error) {
			f.configures++
			r := lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: []string{}}
			for i, scope := range c.Scopes[1:] {
				if e := guard(); e != nil {
					r.FailedScope = scope
					return r, e
				}
				if i == 5 && f.fail == "partial" {
					r.FailedScope = scope
					return r, errLifecycle
				}
				if i == 5 && f.fail == "live-running" {
					f.state = windowsservice.Running
				}
				if i == 5 && f.fail == "live-identity" {
					f.identity = strings.Repeat("b", 64)
				}
				if i == 5 && f.fail == "live-receipt" {
					f.original = append(f.original, ' ')
				}
				if i == 5 && f.fail == "live-phase" {
					f.files["receipt.json"] = []byte(`{}`)
				}
				if e := guard(); e != nil {
					r.FailedScope = scope
					return r, e
				}
				r.AppliedScopes = append(r.AppliedScopes, scope)
			}
			return r, f.err("configure")
		},
		digests: func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			return readAdminDigestFixture(), f.err("digests")
		},
	}
}
func TestReadAdminReconsentPreviewIsReadOnlyAndTruthful(t *testing.T) {
	f := newReconsentFixture()
	out, e := readAdminReconsent(context.Background(), request{mode: "read-admin-preview"}, f.installed, f.hooks())
	if e != nil || out.Status != "ready-for-explicit-reconsent" || f.creates != 0 || f.writes != 0 || f.configures != 0 || out.ServiceStartRequested || len(out.Scopes) != 11 {
		t.Fatal(out, e)
	}
	if len(out.Groups) != 5 || out.Groups[0].ServiceTokenAccess != "not_verified" {
		t.Fatal("provider access invented")
	}
}
func TestReadAdminReconsentOneExplicitScopeExtensionPreservesOriginalReceipt(t *testing.T) {
	f := newReconsentFixture()
	original := append([]byte(nil), f.original...)
	out, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks())
	if e != nil || out.Status != "configured-service-remains-stopped" || out.ServiceStartRequested || f.creates != 1 || f.configures != 1 || f.checks < 22 || !bytes.Equal(original, f.original) {
		t.Fatal(out, e, f.checks)
	}
	var r readAdminReconsentReceipt
	if json.Unmarshal(f.files["receipt.json"], &r) != nil || r.Phase != "configured" || r.SchemaVersion != readAdminReconsentVersion || len(r.GrantDigests) != 11 || !reflect.DeepEqual(r.Consent, readAdminSetupConsent(false)) {
		t.Fatal("wrong receipt")
	}
	f.existing = "configured"
	f.creates, f.writes, f.configures = 0, 0, 0
	if _, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks()); e == nil || f.creates != 0 || f.writes != 0 || f.configures != 0 {
		t.Fatal("completed store replayed")
	}
}
func TestReadAdminReconsentRejectsMissingAuthorityBeforeCreation(t *testing.T) {
	for _, fail := range []string{"external-binary", "executable", "original", "inspect", "identity", "existing", "preview", "compatibility"} {
		f := newReconsentFixture()
		f.fail = fail
		if _, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks()); e == nil || f.creates != 0 || f.configures != 0 {
			t.Fatal(fail, e)
		}
	}
	for _, state := range []windowsservice.State{windowsservice.Running, windowsservice.StartPending, windowsservice.StopPending} {
		f := newReconsentFixture()
		f.state = state
		if _, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks()); e == nil || f.creates != 0 {
			t.Fatal("nonstopped admitted")
		}
	}
	f := newReconsentFixture()
	f.existing = "grants-incomplete"
	if _, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks()); e == nil || f.creates != 0 {
		t.Fatal("partial store adopted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f = newReconsentFixture()
	if _, e := readAdminReconsent(ctx, request{mode: "read-admin-enable"}, f.installed, f.hooks()); e == nil || f.creates != 0 {
		t.Fatal("canceled mutation")
	}
}
func TestReadAdminReconsentEveryFailureRetainsPartialEvidenceAndNeverStarts(t *testing.T) {
	for _, fail := range []string{"create", "intent-recorded", "grants-started", "verify-journal", "partial", "preserve", "configure", "digests", "configured", "close", "live-running", "live-identity", "live-receipt", "live-phase"} {
		t.Run(fail, func(t *testing.T) {
			f := newReconsentFixture()
			f.fail = fail
			out, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, f.hooks())
			if e == nil || out.ServiceStartRequested || !out.OriginalStateRetained || f.creates > 1 {
				t.Fatal(out, e)
			}
			if fail == "partial" {
				var r readAdminReconsentReceipt
				json.Unmarshal(f.files["receipt.json"], &r)
				if r.Phase != "grants-incomplete" || len(r.Grants.AppliedScopes) != 5 || r.Grants.FailedScope == "" {
					t.Fatal("partial lost", r)
				}
			}
			if strings.HasPrefix(fail, "live-") {
				if len(out.Grants.AppliedScopes) != 5 || out.Grants.FailedScope == "" {
					t.Fatal("scope continued after lost authority", out)
				}
			}
		})
	}
}
func TestReadAdminCLIRequiresExplicitNewAcknowledgementAndFullDisclosure(t *testing.T) {
	for _, args := range [][]string{{"--read-admin-enable"}, {"--read-admin-enable", "--apply"}, {"--read-admin-preview", "--apply"}, {"--read-admin-preview", "--twelve-read-admin-scopes"}, {"--read-admin-enable", "--apply", "--twelve-read-admin-scopes", "--windows-inventory"}, {"--read-admin-enable", "--apply", "--twelve-read-admin-scopes", "--start"}} {
		calls := 0
		code := runWith(context.Background(), args, io.Discard, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) { calls++; return nil, nil })
		if code != 2 || calls != 0 {
			t.Fatal(args, code, calls)
		}
	}
	for _, mode := range []string{"read-admin-preview", "read-admin-enable"} {
		args := []string{"--" + mode, "--insecure-http-test"}
		if mode == "read-admin-enable" {
			args = append(args, "--apply", "--twelve-read-admin-scopes")
		}
		var out bytes.Buffer
		calls := 0
		code := runWith(context.Background(), args, &out, io.Discard, func(_ context.Context, r request, _ io.Writer, _ io.Writer) (any, error) {
			calls++
			if r.mode != mode || !r.insecureHTTP || !strings.Contains(out.String(), "personal") || !strings.Contains(out.String(), "plaintext") {
				t.Fatal("incomplete pre-dispatch disclosure")
			}
			return nil, nil
		})
		if code != 0 || calls != 1 {
			t.Fatal(args, code, calls)
		}
	}
}

func TestReadAdminReconsentReportsOnlyFiniteBlockedScope(t *testing.T) {
	for _, scope := range []string{lanclient.WindowsReadAdminScopes()[6], "private-path-or-native-prose"} {
		f := newReconsentFixture()
		h := f.hooks()
		h.preview = func(string, lanclient.WindowsCapabilityConsent, func() error) ([]lanclient.WindowsReadAdminScopeState, error) {
			return nil, &lanclient.WindowsReadAdminScopeError{Scope: scope}
		}
		out, e := readAdminReconsent(context.Background(), request{mode: "read-admin-enable"}, f.installed, h)
		if e == nil || f.creates != 0 {
			t.Fatal("unavailable grant mutated")
		}
		if scope == lanclient.WindowsReadAdminScopes()[6] {
			if out.BlockedScope != scope || out.Status != "existing-scope-state-unavailable" {
				t.Fatal("scope hidden")
			}
		} else if out.BlockedScope != "" {
			t.Fatal("untrusted diagnostic escaped")
		}
	}
}
func TestReadAdminCLIFailedOuterLeaseNeverPrintsCompletion(t *testing.T) {
	var out bytes.Buffer
	code := runWith(context.Background(), []string{"--read-admin-enable", "--apply", "--twelve-read-admin-scopes"}, &out, io.Discard, func(context.Context, request, io.Writer, io.Writer) (any, error) {
		return readAdminReconsentResult{Status: "configured-service-remains-stopped", OriginalStateRetained: true}, errLifecycle
	})
	if code != 1 || strings.Contains(out.String(), `"status":"configured-service-remains-stopped"`) || !strings.Contains(out.String(), `"status":"receipt-release-unverified"`) {
		t.Fatal("lease failure reported as completion")
	}
}

func TestReadAdminAndServiceActionSetupRejectMixedAuthority(t *testing.T) {
	// Both public dispatch orders must reject the other operation's flags
	// before a native operation or a policy-file read can be reached.
	for _, args := range [][]string{
		{"--service-actions-setup", "--policy-file", "unread-fixture", "--read-admin-preview"},
		{"--service-actions-setup", "--policy-file", "unread-fixture", "--apply", "--approve", "sha256:fixture", "--twelve-read-admin-scopes"},
		{"--read-admin-preview", "--service-actions-setup"},
		{"--read-admin-enable", "--apply", "--twelve-read-admin-scopes", "--service-actions-setup"},
		{"--read-admin-enable", "--apply", "--twelve-read-admin-scopes", "--policy-file", "unread-fixture"},
	} {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), args, &out, &stderr); code != 2 || out.Len() != 0 {
			t.Fatal("mixed read/control consent reached an operation", args, code)
		}
	}
}
