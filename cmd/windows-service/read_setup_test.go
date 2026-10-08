package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsvolumes"
)

type readSetupFixture struct {
	steps        []string
	fail         string
	raw          []byte
	record       installReceipt
	configured   int
	started      int
	transitioned int
	partial      bool
}

func (f *readSetupFixture) call(step string) error {
	f.steps = append(f.steps, step)
	if f.fail == step {
		return errors.New("synthetic failure")
	}
	return nil
}
func (f *readSetupFixture) Write(name string, raw []byte) error {
	if err := f.call("write-" + name); err != nil {
		return err
	}
	if name == "receipt.json" {
		f.raw = append([]byte(nil), raw...)
		if json.Unmarshal(raw, &f.record) != nil {
			return errLifecycle
		}
	}
	return nil
}
func (f *readSetupFixture) Close() error { return f.call("close") }
func readSetupConsentFixture() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV3, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: readSetupScopes(), Acknowledged: true}
}
func (f *readSetupFixture) hooks() readSetupSteps {
	layout := windowsservice.Layout{EnrollmentRoot: "fixture-enrollment"}
	receipt := windowsservice.Receipt{Version: 2, Complete: true, Layout: layout, InstallationID: "fixture-installation", ServiceSID: "fixture-SID"}
	return readSetupSteps{
		setup: setupSteps{
			plan: func(context.Context) (windowsservice.InstallPlan, error) {
				return windowsservice.InstallPlan{Layout: layout, Configuration: windowsservice.Configuration{StartType: 4}}, f.call("plan")
			},
			readBootstrap:     func(string) ([]byte, error) { return []byte("fixture"), f.call("bootstrap") },
			validateBootstrap: func([]byte) error { return f.call("validate") },
			createJournal:     func(windowsservice.Layout) (setupJournal, error) { return f, f.call("journal") },
			apply: func(context.Context, windowsservice.InstallPlan) (windowsservice.Receipt, error) {
				return receipt, f.call("install-disabled")
			},
			prepare:     func(windowsservice.Layout, windowsservice.Receipt, []byte) error { return f.call("prepare") },
			verifyOwned: func(context.Context, windowsservice.Receipt) error { return f.call("verify-disabled") },
			enroll:      func(context.Context, windowsservice.Layout) error { return f.call("claim") },
			start: func(_ context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
				f.started++
				if !completeReadSetup(f.record) || r.Version != 1 {
					return windowsservice.ApplyResult{}, errLifecycle
				}
				return windowsservice.ApplyResult{Requested: true}, f.call("start")
			},
		},
		updateReceipt: func(_ windowsservice.Layout, previous, next []byte) error {
			if !bytes.Equal(previous, f.raw) {
				return errLifecycle
			}
			var record installReceipt
			if json.Unmarshal(next, &record) != nil {
				return errLifecycle
			}
			if err := f.call(record.ReadSetup.Phase); err != nil {
				return err
			}
			f.raw = append([]byte(nil), next...)
			f.record = record
			return nil
		},
		ensureFreshScopes: func(windowsservice.Receipt) error { return f.call("fresh-scopes") },
		activateIdentity:  func(context.Context, windowsservice.Receipt) error { return f.call("activate-identity") },
		identity: func(string, lanclient.WindowsCapabilityConsent) (string, error) {
			return strings.Repeat("a", 64), f.call("identity")
		},
		configure: func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
			f.configured++
			if !reflect.DeepEqual(c, readSetupConsentFixture()) {
				return lanclient.WindowsCapabilityConsentResult{}, errLifecycle
			}
			if f.partial {
				return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: readSetupScopes()[1:3], FailedScope: readSetupScopes()[3]}, errLifecycle
			}
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: readSetupScopes()[1:]}, f.call("configure")
		},
		verifyGrants: func(string, lanclient.WindowsCapabilityConsent) error { return f.call("verify-grants") },
		grantDigests: func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			return readSetupDigestFixture(), f.call("grant-digests")
		},
		activateStartup: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Receipt, error) {
			f.transitioned++
			if f.record.ReadSetup.Phase != "startup-transition-started" {
				return windowsservice.Receipt{}, errLifecycle
			}
			r.Version = 1
			r.ConfigurationSHA256 = strings.Repeat("c", 64)
			return r, f.call("activate-startup")
		},
	}
}
func TestFreshReadSetupOneConsentBeforeFirstStart(t *testing.T) {
	f := &readSetupFixture{}
	if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks()); err != nil {
		t.Fatal(err)
	}
	if f.configured != 1 || f.transitioned != 1 || f.started != 1 || !completeReadSetup(f.record) {
		t.Fatal("missing one-shot combined setup")
	}
	before := func(a, b string) {
		t.Helper()
		ai, bi := -1, -1
		for i, s := range f.steps {
			if s == a {
				ai = i
			}
			if s == b {
				bi = i
			}
		}
		if ai < 0 || bi < 0 || ai >= bi {
			t.Fatal("wrong order", a, b, f.steps)
		}
	}
	before("write-intent.json", "install-disabled")
	before("activate-identity", "configure")
	before("verify-grants", "grant-digests")
	before("grant-digests", "grants-verified")
	before("grants-verified", "activate-startup")
	before("configured", "start")
}
func TestFreshReadSetupEveryFailureRetainsStateWithoutStart(t *testing.T) {
	for _, stage := range []string{"plan", "bootstrap", "validate", "journal", "write-intent.json", "install-disabled", "write-receipt.json", "fresh-scopes", "prepare", "close", "verify-disabled", "claim-started", "claim", "activation-started", "activate-identity", "identity", "grants-started", "configure", "verify-grants", "grant-digests", "grants-verified", "startup-transition-started", "activate-startup", "configured"} {
		t.Run(stage, func(t *testing.T) {
			f := &readSetupFixture{fail: stage}
			if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks()); err == nil {
				t.Fatal("failed stage returned success")
			}
			if f.started != 0 {
				t.Fatal("started incomplete setup")
			}
		})
	}
}
func TestFreshReadSetupPartialGrantOutcomeRetained(t *testing.T) {
	f := &readSetupFixture{partial: true}
	if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks()); err == nil {
		t.Fatal("partial grant success")
	}
	p := f.record.ReadSetup
	if p.Phase != "grants-incomplete" || !reflect.DeepEqual(p.Grants.AppliedScopes, readSetupScopes()[1:3]) || p.Grants.FailedScope != readSetupScopes()[3] || f.started != 0 || f.transitioned != 0 {
		t.Fatal("lost partial outcome")
	}
}
func TestFreshReadSetupRejectsOldConsentAndMissingScopesWithoutOperations(t *testing.T) {
	for _, mutate := range []func(*lanclient.WindowsCapabilityConsent){func(c *lanclient.WindowsCapabilityConsent) {
		c.SchemaVersion = lanclient.WindowsCapabilityConsentVersionV2
	}, func(c *lanclient.WindowsCapabilityConsent) { c.Scopes = c.Scopes[:4] }, func(c *lanclient.WindowsCapabilityConsent) { c.Acknowledged = false }, func(c *lanclient.WindowsCapabilityConsent) { c.Scopes[0], c.Scopes[1] = c.Scopes[1], c.Scopes[0] }} {
		f := &readSetupFixture{}
		c := readSetupConsentFixture()
		mutate(&c)
		if _, err := setupReadObservation(context.Background(), "fixture", c, f.hooks()); err == nil || len(f.steps) != 0 {
			t.Fatal("unapproved scope executed")
		}
	}
}
func TestFreshReadSetupHasNoPublicCommand(t *testing.T) {
	for _, args := range [][]string{{"--read-setup", "--apply"}, {"--install", "--apply", "--windows-observation"}} {
		calls := 0
		var out bytes.Buffer
		code := runWith(context.Background(), args, &out, &out, func(context.Context, request, io.Writer, io.Writer) (any, error) { calls++; return nil, nil })
		if code != 2 || calls != 0 {
			t.Fatal("unreleased command exposed")
		}
	}
}

func TestFreshReadSetupConsentDisclosesEveryScopeAndHTTPRisk(t *testing.T) {
	for _, http := range []bool{false, true} {
		c := readSetupConsentFixture()
		c.InsecureHTTPAcknowledged = http
		var out bytes.Buffer
		if err := writeReadSetupDisclosure(&out, c); err != nil {
			t.Fatal(err)
		}
		for _, notice := range []string{enrollmentclient.WindowsInventoryPrivacy, windowseventhealth.Privacy, windowsvolumes.Privacy, windowsprocessmetrics.Privacy, windowsnetwork.Privacy} {
			if !strings.Contains(out.String(), notice) {
				t.Fatal("missing scope notice")
			}
		}
		for _, notice := range []string{enrollmentclient.WindowsInventoryHTTPPrivacy, windowseventhealth.HTTPPrivacy, windowsvolumes.HTTPPrivacy, windowsprocessmetrics.HTTPPrivacy, windowsnetwork.HTTPPrivacy} {
			if strings.Contains(out.String(), notice) != http {
				t.Fatal("HTTP disclosure mismatch")
			}
		}
	}
	if writeReadSetupDisclosure(shortReadSetupWriter{}, readSetupConsentFixture()) == nil {
		t.Fatal("short disclosure accepted")
	}
}

type shortReadSetupWriter struct{}

func (shortReadSetupWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestFreshReadSetupCanceledContextNeverMutates(t *testing.T) {
	f := &readSetupFixture{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := setupReadObservation(ctx, "fixture", readSetupConsentFixture(), f.hooks()); err == nil || len(f.steps) != 0 {
		t.Fatal("canceled setup mutated")
	}
}
func TestFreshReadSetupRejectsAutomaticPlanBeforeJournal(t *testing.T) {
	f := &readSetupFixture{}
	h := f.hooks()
	h.setup.plan = func(context.Context) (windowsservice.InstallPlan, error) {
		return windowsservice.InstallPlan{Configuration: windowsservice.Configuration{StartType: 2}}, nil
	}
	if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h); err == nil || len(f.steps) != 0 {
		t.Fatal("automatic service entered setup")
	}
}
func TestFreshReadSetupIdentityReplacementAndReceiptMismatchNeverTransition(t *testing.T) {
	for _, replaceIdentity := range []bool{false, true} {
		f := &readSetupFixture{}
		h := f.hooks()
		if replaceIdentity {
			count := 0
			h.identity = func(string, lanclient.WindowsCapabilityConsent) (string, error) {
				count++
				if count > 1 {
					return strings.Repeat("b", 64), nil
				}
				return strings.Repeat("a", 64), nil
			}
		} else {
			h.updateReceipt = func(windowsservice.Layout, []byte, []byte) error { return errLifecycle }
		}
		if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), h); err == nil || f.transitioned != 0 || f.started != 0 {
			t.Fatal("identity/receipt mismatch transitioned")
		}
	}
}

func TestFreshReadSetupReceiptStrictAndLegacyUnchanged(t *testing.T) {
	legacy := installReceipt{Version: 1, Service: windowsservice.Receipt{Version: 1, Complete: true}, Prepared: true}
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("readSetup")) {
		t.Fatal("legacy bytes changed")
	}
	if _, err := decodeInstallReceipt(raw, legacy.Service.Layout); err != nil {
		t.Fatal(err)
	}
	f := &readSetupFixture{}
	if _, err := setupReadObservation(context.Background(), "fixture", readSetupConsentFixture(), f.hooks()); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInstallReceipt(f.raw, f.record.Service.Layout); err != nil {
		t.Fatal("complete v2 rejected", err)
	}
	for _, mutate := range []func(*installReceipt){
		func(r *installReceipt) { r.ReadSetup.Phase = "startup-transition-started" },
		func(r *installReceipt) { r.Service.Version = 2 },
		func(r *installReceipt) { r.ReadSetup.SenderBinding = strings.Repeat("z", 64) },
		func(r *installReceipt) { r.ReadSetup.Grants.AppliedScopes = r.ReadSetup.Grants.AppliedScopes[:3] },
		func(r *installReceipt) { r.ReadSetup.Consent.Acknowledged = false },
		func(r *installReceipt) { r.Version = 1 },
	} {
		var r installReceipt
		if json.Unmarshal(f.raw, &r) != nil {
			t.Fatal("fixture")
		}
		mutate(&r)
		bad, _ := json.Marshal(r)
		if _, err := decodeInstallReceipt(bad, r.Service.Layout); err == nil {
			t.Fatal("incomplete/unapproved receipt accepted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), ' '), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"prepared":true`), []byte(`"prepared":true,"unknown":true`), 1)} {
		if _, err := decodeInstallReceipt(bad, legacy.Service.Layout); err == nil {
			t.Fatal("noncanonical receipt accepted")
		}
	}
}

func readSetupDigestFixture() []lanclient.WindowsCapabilityGrantDigest {
	var result []lanclient.WindowsCapabilityGrantDigest
	for _, scope := range readSetupScopes()[1:] {
		result = append(result, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("d", 64)})
	}
	return result
}
