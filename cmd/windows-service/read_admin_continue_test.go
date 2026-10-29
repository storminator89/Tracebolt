package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
)

type continuationFixture struct {
	intent, receipt                                              []byte
	trace                                                        []string
	failAt, step                                                 int
	writes, resumes, configured, activated, started              int
	ready, failAfterWrite, changedBinding, changedDeadline       bool
	expireOn                                                     string
	clock                                                        int64
	digestCalls, identityCalls, tamperDigestAt, tamperIdentityAt int
}

func continuationCase(t *testing.T) *continuationFixture {
	t.Helper()
	f := recoveryStatusCase(t)
	root := f.layout.StateRoot + "-installer"
	return &continuationFixture{intent: f.files[filepath.Join(root, "intent.json")], receipt: f.files[filepath.Join(root, "receipt.json")], clock: 100}
}

func (f *continuationFixture) record() installReceipt {
	var r installReceipt
	_ = json.Unmarshal(f.receipt, &r)
	return r
}

func (f *continuationFixture) call(name string) error {
	f.step++
	f.trace = append(f.trace, name)
	if f.expireOn == name {
		f.clock = 200
	}
	if f.failAt == f.step {
		return errors.New("private fixture failure")
	}
	return nil
}

func continuationDigests(c lanclient.WindowsCapabilityConsent) []lanclient.WindowsCapabilityGrantDigest {
	var result []lanclient.WindowsCapabilityGrantDigest
	for _, scope := range c.Scopes[1:] {
		result = append(result, lanclient.WindowsCapabilityGrantDigest{Scope: scope, SHA256: strings.Repeat("d", 64)})
	}
	return result
}

func (f *continuationFixture) hooks(t *testing.T) readAdminContinuationSteps {
	t.Helper()
	return readAdminContinuationSteps{
		now: func() time.Time { return time.Unix(f.clock, 0) },
		verify: func(_ context.Context, expected []byte) error {
			if e := f.call("verify"); e != nil {
				return e
			}
			if !bytes.Equal(expected, f.receipt) {
				return errLifecycle
			}
			return nil
		},
		absent: func() error { return f.call("absent") },
		enrollment: func() (enrollmentclient.ServiceRecoveryState, error) {
			if e := f.call("enrollment"); e != nil {
				return enrollmentclient.ServiceRecoveryState{}, e
			}
			binding := strings.Repeat("e", 64)
			deadline := int64(200)
			if f.changedBinding && f.resumes > 0 {
				binding = strings.Repeat("f", 64)
			}
			if f.changedDeadline && f.resumes > 0 {
				deadline++
			}
			return enrollmentclient.ServiceRecoveryState{Binding: binding, DeadlineAt: deadline, Ready: f.ready}, nil
		},
		resume: func(context.Context) error {
			if f.record().ReadSetup.Phase != "recovery-activation-started" {
				t.Fatal("network before durable fence")
			}
			f.resumes++
			if e := f.call("resume"); e != nil {
				return e
			}
			f.ready = true
			return nil
		},
		update: func(previous, next []byte) error {
			if !bytes.Equal(previous, f.receipt) {
				t.Fatal("receipt overwritten without compare")
			}
			if e := f.call("write"); e != nil {
				return e
			}
			f.writes++
			f.receipt = append([]byte(nil), next...)
			if f.failAfterWrite {
				return errors.New("uncertain durable write")
			}
			return nil
		},
		identity: func(string, lanclient.WindowsCapabilityConsent) (string, error) {
			f.identityCalls++
			value := strings.Repeat("b", 64)
			if f.identityCalls == f.tamperIdentityAt {
				value = strings.Repeat("f", 64)
			}
			return value, f.call("identity")
		},
		configure: func(_ string, c lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error) {
			if f.record().ReadSetup.Phase != "grants-started" || f.record().ReadSetup.SenderBinding != strings.Repeat("b", 64) {
				t.Fatal("grant before identity fence")
			}
			f.configured++
			return lanclient.WindowsCapabilityConsentResult{MetadataScopeVerified: true, AppliedScopes: c.Scopes[1:]}, f.call("configure")
		},
		verifyGrants: func(string, lanclient.WindowsCapabilityConsent) error { return f.call("verify-grants") },
		grantDigests: func(_ string, c lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error) {
			f.digestCalls++
			d := continuationDigests(c)
			if f.digestCalls == f.tamperDigestAt {
				d[0].SHA256 = strings.Repeat("f", 64)
			}
			return d, f.call("digests")
		},
		activate: func(_ context.Context, r windowsservice.Receipt) (windowsservice.Receipt, error) {
			p := f.record().ReadSetup
			if p.Phase != "startup-transition-started" || !validReadSetupConsentDigests(p.Consent, p.GrantDigests) {
				t.Fatal("startup before durable verified grants")
			}
			f.activated++
			if e := f.call("activate"); e != nil {
				return windowsservice.Receipt{}, e
			}
			r.Version = 1
			r.ConfigurationSHA256 = strings.Repeat("c", 64)
			return r, nil
		},
		start: func(_ context.Context, r windowsservice.Receipt) (windowsservice.ApplyResult, error) {
			if !completeReadSetup(f.record()) || r.Version != 1 {
				t.Fatal("start before completed receipt")
			}
			f.started++
			return windowsservice.ApplyResult{Requested: true}, f.call("start")
		},
	}
}

func (f *continuationFixture) plan(t *testing.T) readAdminContinuationPlan {
	t.Helper()
	p, e := continueReadAdmin(context.Background(), f.intent, f.receipt, false, "", f.hooks(t))
	if e != nil || p.Status != "review-required-one-attempt" {
		t.Fatal("plan", e)
	}
	f.step = 0
	f.trace = nil
	return p
}

func TestReadAdminContinuationPlansWithoutMutationThenCompletesOriginalScopes(t *testing.T) {
	for _, phase := range []string{"claim-started", "activation-started"} {
		t.Run(phase, func(t *testing.T) {
			f := continuationCase(t)
			r := f.record()
			r.ReadSetup.Phase = phase
			f.receipt, _ = json.Marshal(r)
			before := append([]byte(nil), f.receipt...)
			p := f.plan(t)
			if f.writes+f.resumes+f.configured+f.activated+f.started != 0 || !bytes.Equal(before, f.receipt) {
				t.Fatal("plan mutated")
			}
			got, e := continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t))
			if e != nil || got.Status != "configured-start-requested" || f.resumes != 1 || f.configured != 1 || f.activated != 1 || f.started != 1 || !completeReadSetup(f.record()) {
				t.Fatal("continuation", e)
			}
			f.trace = nil
			if _, e = continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t)); e == nil || len(f.trace) != 0 {
				t.Fatal("completed attempt replayed")
			}
		})
	}
}

func TestReadAdminContinuationEveryFailurePreservesFenceAndNeverReplays(t *testing.T) {
	baseline := continuationCase(t)
	p := baseline.plan(t)
	if _, e := continueReadAdmin(context.Background(), baseline.intent, baseline.receipt, true, p.Approval, baseline.hooks(t)); e != nil {
		t.Fatal(e)
	}
	for n := 1; n <= len(baseline.trace); n++ {
		f := continuationCase(t)
		p := f.plan(t)
		f.failAt = n
		got, e := continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t))
		if e == nil || got != (readAdminContinuationPlan{}) {
			t.Fatalf("failure %d returned success", n)
		}
		if f.writes > 0 {
			counts := []int{f.resumes, f.configured, f.activated, f.started}
			f.failAt = 0
			if _, e = continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t)); e == nil || !reflect.DeepEqual(counts, []int{f.resumes, f.configured, f.activated, f.started}) {
				t.Fatalf("failure %d replayed", n)
			}
		}
	}
	f := continuationCase(t)
	p = f.plan(t)
	f.failAfterWrite = true
	if _, e := continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t)); e == nil || f.resumes != 0 || f.record().ReadSetup.Phase != "recovery-activation-started" {
		t.Fatal("uncertain fence allowed network")
	}
}

func TestReadAdminContinuationRejectsChangedAuthorityExpiryAndUnreviewedState(t *testing.T) {
	for _, mutate := range []func(*installReceipt){
		func(r *installReceipt) { r.Version = 11 },
		func(r *installReceipt) { r.Prepared = false },
		func(r *installReceipt) { r.Service.InstallationID = "replacement" },
		func(r *installReceipt) { r.ReadSetup.Consent.InsecureHTTPAcknowledged = true },
		func(r *installReceipt) { r.ReadSetup.Phase = "grants-started" },
		func(r *installReceipt) { r.ReadSetup.Phase = "recovery-activation-started" },
		func(r *installReceipt) { r.ReadSetup.Phase = "startup-transition-started" },
		func(r *installReceipt) { r.ReadSetup.SenderBinding = strings.Repeat("b", 64) },
		func(r *installReceipt) { r.ReadSetup.Grants.MetadataScopeVerified = true },
	} {
		f := continuationCase(t)
		r := f.record()
		mutate(&r)
		f.receipt, _ = json.Marshal(r)
		if _, e := continueReadAdmin(context.Background(), f.intent, f.receipt, false, "", f.hooks(t)); e == nil || len(f.trace) != 0 {
			t.Fatal("invalid state reached hooks")
		}
	}
	for _, change := range []string{"binding", "deadline", "expired", "expire-resume", "expire-activate", "approval"} {
		f := continuationCase(t)
		p := f.plan(t)
		switch change {
		case "binding":
			f.changedBinding = true
		case "deadline":
			f.changedDeadline = true
		case "expired":
			f.clock = 200
		case "expire-resume":
			f.expireOn = "resume"
		case "expire-activate":
			f.expireOn = "activate"
		case "approval":
			p.Approval = "sha256:" + strings.Repeat("0", 64)
		}
		if _, e := continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t)); e == nil || f.started != 0 {
			t.Fatal("changed authority accepted", change)
		}
		if (change == "binding" || change == "deadline" || change == "expire-resume") && f.configured != 0 {
			t.Fatal("changed enrollment reached grants")
		}
		if (change == "expired" || change == "approval") && f.writes != 0 {
			t.Fatal("invalid approval/expiry mutated")
		}
	}
}

func TestReadAdminContinuationLiveAuthorityChangesBlockStartup(t *testing.T) {
	for _, change := range []string{"digest-before-activate", "digest-before-start", "sender-before-activate", "sender-before-start", "expire-at-fence"} {
		f := continuationCase(t)
		p := f.plan(t)
		switch change {
		case "digest-before-activate":
			f.tamperDigestAt = 2
		case "digest-before-start":
			f.tamperDigestAt = 3
		case "sender-before-activate":
			f.tamperIdentityAt = 3
		case "sender-before-start":
			f.tamperIdentityAt = 4
		case "expire-at-fence":
			f.expireOn = "write"
		}
		if _, err := continueReadAdmin(context.Background(), f.intent, f.receipt, true, p.Approval, f.hooks(t)); err == nil || f.started != 0 {
			t.Fatal("changed authority reached start", change)
		}
		if (change == "digest-before-activate" || change == "sender-before-activate") && f.activated != 0 {
			t.Fatal("changed authority reached activation")
		}
		if change == "expire-at-fence" && f.resumes != 0 {
			t.Fatal("deadline passed before network")
		}
	}
}

func TestReadAdminContinuationCLIRequiresExactSeparateAcknowledgement(t *testing.T) {
	for _, args := range [][]string{{"--apply"}, {"--acknowledge-read-admin-recovery"}, {"--approve=private-secret"}, {"--insecure-http-test"}, {"--bootstrap-file=private-path"}, {"--apply", "--acknowledge-read-admin-recovery", "--approve=private-secret"}} {
		var out, stderr bytes.Buffer
		if runReadAdminContinuation(context.Background(), args, &out, &stderr, func(context.Context, readAdminContinuationRequest) (readAdminContinuationPlan, error) {
			t.Fatal("bad flags dispatched")
			return readAdminContinuationPlan{}, nil
		}) != 2 || out.Len() != 0 || strings.Contains(stderr.String(), "private-") {
			t.Fatal("unsafe flags or output")
		}
	}
	for _, apply := range []bool{false, true} {
		var out, stderr bytes.Buffer
		args := []string{}
		pin := "sha256:" + strings.Repeat("a", 64)
		if apply {
			args = []string{"--apply", "--approve=" + pin, "--acknowledge-read-admin-recovery"}
		}
		calls := 0
		code := runReadAdminContinuation(context.Background(), args, &out, &stderr, func(_ context.Context, r readAdminContinuationRequest) (readAdminContinuationPlan, error) {
			calls++
			if r.apply != apply || apply && r.approval != pin {
				t.Fatal("approval changed")
			}
			return readAdminContinuationPlan{Status: "fixture"}, nil
		})
		if code != 0 || calls != 1 || stderr.Len() != 0 || !strings.Contains(out.String(), "fixture") || strings.Contains(out.String(), "Fresh Windows observation setup creates") {
			t.Fatal("dispatch")
		}
	}
	var out, stderr bytes.Buffer
	if runReadAdminContinuation(context.Background(), nil, &out, &stderr, func(context.Context, readAdminContinuationRequest) (readAdminContinuationPlan, error) {
		return readAdminContinuationPlan{}, errors.New("private-ledger-and-key")
	}) != 1 || strings.Contains(out.String()+stderr.String(), "private-ledger-and-key") {
		t.Fatal("failure leaked")
	}
}
