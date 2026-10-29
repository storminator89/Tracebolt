package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
)

type readAdminContinuationSteps struct {
	now func() time.Time
	// verify pins original intent and expected receipt under the existing
	// exclusive, manifest-verified installer lease, and inspects the owned SCM
	// service. No callback may create/adopt/repair the installation.
	verify       func(context.Context, []byte) error
	absent       func() error
	enrollment   func() (enrollmentclient.ServiceRecoveryState, error)
	resume       func(context.Context) error
	update       func([]byte, []byte) error
	identity     func(string, lanclient.WindowsCapabilityConsent) (string, error)
	configure    func(string, lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error)
	verifyGrants func(string, lanclient.WindowsCapabilityConsent) error
	grantDigests func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error)
	activate     func(context.Context, windowsservice.Receipt) (windowsservice.Receipt, error)
	start        func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error)
}

type readAdminContinuationPlan struct {
	SchemaVersion string `json:"schemaVersion"`
	Phase         string `json:"phase"`
	Approval      string `json:"approval"`
	DeadlineAt    int64  `json:"deadlineAt"`
	Status        string `json:"status"`
}

// continueReadAdmin is a one-attempt source coordinator. Planning has no write
// callback invocation. Apply fences the original receipt BEFORE network activity;
// uncertainty cannot be submitted again. Only a committed same-key claim with
// absent extension roots is admitted. There is no invitation or install hook.
func continueReadAdmin(ctx context.Context, intentRaw, receiptRaw []byte, apply bool, approval string, h readAdminContinuationSteps) (readAdminContinuationPlan, error) {
	zero := readAdminContinuationPlan{}
	if ctx == nil || ctx.Err() != nil || h.now == nil || h.verify == nil || h.absent == nil || h.enrollment == nil || h.resume == nil || h.update == nil || h.identity == nil || h.configure == nil || h.verifyGrants == nil || h.grantDigests == nil || h.activate == nil || h.start == nil || apply != (approval != "") || len(intentRaw) == 0 || len(intentRaw) > 64<<10 || len(receiptRaw) == 0 || len(receiptRaw) > 64<<10 {
		return zero, errLifecycle
	}
	var intent readSetupIntent
	var r installReceipt
	if !canonicalRecoveryRecord(intentRaw, &intent) || !canonicalRecoveryRecord(receiptRaw, &r) {
		return zero, errLifecycle
	}
	p := r.ReadSetup
	if p == nil || r.Version != 12 || !r.Prepared || r.Service.Version != 2 || !r.Service.Complete || !reflect.DeepEqual(p.Consent, freshReadAdminSetupConsent(false)) || !reflect.DeepEqual(intent.Consent, p.Consent) ||
		(p.Phase != "claim-started" && p.Phase != "activation-started") || p.SenderBinding != "" || !reflect.DeepEqual(p.Grants, lanclient.WindowsCapabilityConsentResult{}) || len(p.GrantDigests) != 0 {
		return zero, errLifecycle
	}
	plan := intent.Plan
	config, _ := json.Marshal(plan.Configuration)
	digest := sha256.Sum256(config)
	if plan.Existing.Exists || plan.Configuration.StartType != 4 || plan.Layout != r.Service.Layout || plan.InstallationID != r.Service.InstallationID || plan.ExecutableSHA256 != r.Service.ExecutableSHA256 || hex.EncodeToString(digest[:]) != r.Service.ConfigurationSHA256 {
		return zero, errLifecycle
	}
	if h.verify(ctx, receiptRaw) != nil || h.absent() != nil {
		return zero, errLifecycle
	}
	original, err := h.enrollment()
	if err != nil || !validReadSetupBinding(original.Binding) || original.DeadlineAt <= h.now().Unix() || ctx.Err() != nil {
		return zero, errLifecycle
	}
	// Fixed domain and length framing prevent cross-command or field ambiguity.
	pin, _ := json.Marshal(struct {
		Domain   string
		Intent   []byte
		Receipt  []byte
		Binding  string
		Deadline int64
	}{"tracebolt.read-admin-continuation.v1", intentRaw, receiptRaw, original.Binding, original.DeadlineAt})
	digest = sha256.Sum256(pin)
	result := readAdminContinuationPlan{"tracebolt.windows-read-admin-continuation-plan.v1", p.Phase, "sha256:" + hex.EncodeToString(digest[:]), original.DeadlineAt, "review-required-one-attempt"}
	if !apply {
		return result, nil
	}
	if approval != result.Approval {
		return zero, errLifecycle
	}
	previous := append([]byte(nil), receiptRaw...)
	defer func() { clear(previous) }()
	save := func(phase string) error {
		if ctx.Err() != nil || h.verify(ctx, previous) != nil {
			return errLifecycle
		}
		p.Phase = phase
		next, err := json.Marshal(r)
		if err != nil || h.update(previous, next) != nil {
			return errLifecycle
		}
		clear(previous)
		previous = next
		return nil
	}
	checkEnrollment := func(ready bool) error {
		s, err := h.enrollment()
		if err != nil || ctx.Err() != nil || h.now().Unix() >= original.DeadlineAt || s.Binding != original.Binding || s.DeadlineAt != original.DeadlineAt || ready && !s.Ready {
			return errLifecycle
		}
		return nil
	}
	if h.absent() != nil || checkEnrollment(false) != nil || save("recovery-activation-started") != nil {
		return zero, errLifecycle
	}
	if checkEnrollment(false) != nil || h.resume(ctx) != nil || checkEnrollment(true) != nil || h.verify(ctx, previous) != nil || h.absent() != nil {
		return zero, errLifecycle
	}
	path := filepath.Join(r.Service.Layout.EnrollmentRoot, "agent.json")
	binding, err := h.identity(path, p.Consent)
	if err != nil || !validReadSetupBinding(binding) {
		return zero, errLifecycle
	}
	p.SenderBinding = binding
	if save("grants-started") != nil {
		return zero, errLifecycle
	}
	grants, err := h.configure(path, p.Consent)
	p.Grants = grants
	if err != nil {
		_ = save("grants-incomplete")
		return zero, errLifecycle
	}
	if !grants.MetadataScopeVerified || grants.FailedScope != "" || !reflect.DeepEqual(grants.AppliedScopes, p.Consent.Scopes[1:]) || h.verifyGrants(path, p.Consent) != nil {
		return zero, errLifecycle
	}
	p.GrantDigests, err = h.grantDigests(path, p.Consent)
	if err != nil || !validReadSetupConsentDigests(p.Consent, p.GrantDigests) {
		return zero, errLifecycle
	}
	current, err := h.identity(path, p.Consent)
	if err != nil || current != binding || checkEnrollment(true) != nil || save("grants-verified") != nil || save("startup-transition-started") != nil {
		return zero, errLifecycle
	}
	liveDigests, err := h.grantDigests(path, p.Consent)
	current, identityErr := h.identity(path, p.Consent)
	if err != nil || identityErr != nil || current != binding || !reflect.DeepEqual(liveDigests, p.GrantDigests) || h.verifyGrants(path, p.Consent) != nil || checkEnrollment(true) != nil || h.verify(ctx, previous) != nil {
		return zero, errLifecycle
	}
	activated, err := h.activate(ctx, r.Service)
	expected := r.Service
	expected.Version = 1
	expected.ConfigurationSHA256 = activated.ConfigurationSHA256
	if err != nil || activated != expected || !validReadSetupBinding(activated.ConfigurationSHA256) {
		return zero, errLifecycle
	}
	// verify still expects the staged service. Finalization after the proven
	// automatic transition uses only the adapter's exact compare-and-write.
	r.Service = activated
	p.Phase = "configured"
	if !completeReadSetup(r) || ctx.Err() != nil || checkEnrollment(true) != nil {
		return zero, errLifecycle
	}
	next, _ := json.Marshal(r)
	if h.update(previous, next) != nil {
		return zero, errLifecycle
	}
	liveDigests, err = h.grantDigests(path, p.Consent)
	current, identityErr = h.identity(path, p.Consent)
	if err != nil || identityErr != nil || current != binding || !reflect.DeepEqual(liveDigests, p.GrantDigests) || h.verifyGrants(path, p.Consent) != nil || checkEnrollment(true) != nil || ctx.Err() != nil {
		return zero, errLifecycle
	}
	started, err := h.start(ctx, activated)
	if err != nil || !started.Requested {
		return zero, errLifecycle
	}
	result.Status = "configured-start-requested"
	return result, nil
}
