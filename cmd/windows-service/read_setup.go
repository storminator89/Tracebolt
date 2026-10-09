package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsvolumes"
)

// No CLI dispatch exists for this fresh-only coordinator. Release/provenance,
// native acceptance and exact released-artifact provenance remain gates. The
// separate Setup preview supplies the explicit human combined-consent entry.
type readSetupProgress struct {
	Consent       lanclient.WindowsCapabilityConsent       `json:"consent"`
	Phase         string                                   `json:"phase"`
	SenderBinding string                                   `json:"senderBinding,omitempty"`
	Grants        lanclient.WindowsCapabilityConsentResult `json:"grants"`
	GrantDigests  []lanclient.WindowsCapabilityGrantDigest `json:"grantDigests"`
}
type readSetupSteps struct {
	setup setupSteps
	// updateReceipt must compare exact previous protected bytes before replacing.
	updateReceipt     func(windowsservice.Layout, []byte, []byte) error
	ensureFreshScopes func(windowsservice.Receipt) error
	activateIdentity  func(context.Context, windowsservice.Receipt) error
	identity          func(string, lanclient.WindowsCapabilityConsent) (string, error)
	configure         func(string, lanclient.WindowsCapabilityConsent) (lanclient.WindowsCapabilityConsentResult, error)
	verifyGrants      func(string, lanclient.WindowsCapabilityConsent) error
	grantDigests      func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error)
	activateStartup   func(context.Context, windowsservice.Receipt) (windowsservice.Receipt, error)
}

func readSetupScopes() []string {
	return []string{enrollmentcrypto.CollectionProfileWindowsInventory, windowseventhealth.Scope, windowsvolumes.Scope, windowsprocessmetrics.Scope, windowsnetwork.Scope}
}
func validateReadSetupConsent(c lanclient.WindowsCapabilityConsent) error {
	if c.Validate() != nil || c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV3 || !reflect.DeepEqual(c.Scopes, readSetupScopes()) {
		return errLifecycle
	}
	return nil
}
func completeReadSetup(r installReceipt) bool {
	p := r.ReadSetup
	return r.Version == 2 && r.Prepared && r.Service.Version == 1 && r.Service.Complete && p != nil && validateReadSetupConsent(p.Consent) == nil && p.Phase == "configured" && validReadSetupBinding(p.SenderBinding) && p.Grants.MetadataScopeVerified && p.Grants.FailedScope == "" && reflect.DeepEqual(p.Grants.AppliedScopes, readSetupScopes()[1:]) && validReadSetupDigests(p.GrantDigests)
}

type readSetupJournal struct {
	setupJournal
	write func(string, []byte) error
}

func (s readSetupJournal) Write(name string, raw []byte) error { return s.write(name, raw) }

// setupReadObservation reuses the ordinary create-only transaction and journal.
// SCM stays DISABLED throughout claim, same-identity activation and all grants.
// One upfront exact acknowledgement is reused; manager trust approval is separate.
// Partial scope writes and indeterminate startup transitions remain fenced for
// explicit read-only reconciliation. There is no retry, rollback or adoption.
func setupReadObservation(ctx context.Context, bootstrap string, consent lanclient.WindowsCapabilityConsent, hooks readSetupSteps) (any, error) {
	if ctx == nil || validateReadSetupConsent(consent) != nil || hooks.updateReceipt == nil || hooks.ensureFreshScopes == nil || hooks.activateIdentity == nil || hooks.identity == nil || hooks.configure == nil || hooks.verifyGrants == nil || hooks.grantDigests == nil || hooks.activateStartup == nil || hooks.setup.plan == nil || hooks.setup.createJournal == nil || hooks.setup.prepare == nil || hooks.setup.enroll == nil || hooks.setup.verifyOwned == nil || hooks.setup.start == nil {
		return nil, setupFailed("fresh_validate", errLifecycle)
	}
	consent.Scopes = append([]string(nil), consent.Scopes...)
	s := hooks.setup
	progress := &readSetupProgress{Consent: consent, Phase: "install-started"}
	var retained installReceipt
	var previous []byte
	s.plan = func(ctx context.Context) (p windowsservice.InstallPlan, err error) {
		defer func() {
			if err != nil {
				err = setupFailed("fresh_plan", err)
			}
		}()
		p, err = hooks.setup.plan(ctx)
		if err != nil {
			return p, err
		}
		if p.Configuration.StartType != 4 {
			return p, errLifecycle
		}
		return p, nil
	}
	s.createJournal = func(layout windowsservice.Layout) (result setupJournal, err error) {
		defer func() {
			if err != nil {
				err = setupFailed("journal_create", err)
			}
		}()
		journal, err := hooks.setup.createJournal(layout)
		if err != nil || journal == nil {
			return nil, setupFailedCategory("journal_create", setupCauseCategory(err), errLifecycle)
		}
		return readSetupJournal{journal, func(name string, raw []byte) error {
			switch name {
			case "intent.json":
				var plan windowsservice.InstallPlan
				if json.Unmarshal(raw, &plan) != nil {
					return errLifecycle
				}
				raw, err = json.Marshal(readSetupIntent{plan, consent})
			case "receipt.json":
				if json.Unmarshal(raw, &retained) != nil || retained.Service.Version != 2 {
					return errLifecycle
				}
				retained.Version = 2
				retained.ReadSetup = progress
				raw, err = json.Marshal(retained)
			default:
				return errLifecycle
			}
			if err != nil {
				return err
			}
			if err = journal.Write(name, raw); err != nil {
				return err
			}
			if name == "receipt.json" {
				previous = append([]byte(nil), raw...)
			}
			return nil
		}}, nil
	}
	save := func(phase string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		progress.Phase = phase
		raw, err := json.Marshal(retained)
		if err != nil {
			return err
		}
		if err = hooks.updateReceipt(retained.Service.Layout, previous, raw); err != nil {
			return err
		}
		previous = raw
		return nil
	}
	s.prepare = func(layout windowsservice.Layout, receipt windowsservice.Receipt, raw []byte) (err error) {
		stage := "runtime_receipt"
		defer func() {
			if err != nil {
				err = setupFailed(stage, err)
			}
		}()
		if receipt.Version != 2 || !receipt.Complete {
			return errLifecycle
		}
		stage = "scopes_absent"
		if err := hooks.ensureFreshScopes(receipt); err != nil {
			return err
		}
		stage = "runtime_prepare"
		return hooks.setup.prepare(layout, receipt, raw)
	}
	s.enroll = func(ctx context.Context, layout windowsservice.Layout) (err error) {
		stage := "enrollment_layout"
		defer func() {
			if err != nil {
				err = setupFailed(stage, err)
			}
		}()
		if layout != retained.Service.Layout {
			return errLifecycle
		}
		stage = "claim_record"
		if err := save("claim-started"); err != nil {
			return err
		}
		stage = "enrollment"
		if err := hooks.setup.enroll(ctx, layout); err != nil {
			return err
		}
		stage = "owned_after_claim"
		if err := hooks.setup.verifyOwned(ctx, retained.Service); err != nil {
			return err
		}
		stage = "activation_record"
		if err := save("activation-started"); err != nil {
			return err
		}
		stage = "identity_activate"
		if err := hooks.activateIdentity(ctx, retained.Service); err != nil {
			return err
		}
		stage = "owned_after_activation"
		if err := hooks.setup.verifyOwned(ctx, retained.Service); err != nil {
			return err
		}
		path := filepath.Join(layout.EnrollmentRoot, "agent.json")
		stage = "identity_read"
		binding, err := hooks.identity(path, consent)
		if err != nil || !validReadSetupBinding(binding) {
			return errLifecycle
		}
		progress.SenderBinding = binding
		stage = "grants_record"
		if err = save("grants-started"); err != nil {
			return err
		}
		stage = "grants_configure"
		result, grantErr := hooks.configure(path, consent)
		progress.Grants = result
		if grantErr != nil {
			// FailedScope may have an indeterminate write. If receipt update also
			// fails, the earlier grants-started record still forbids startup.
			_ = save("grants-incomplete")
			return grantErr
		}
		stage = "grants_result"
		if !result.MetadataScopeVerified || result.FailedScope != "" || !reflect.DeepEqual(result.AppliedScopes, readSetupScopes()[1:]) {
			return errLifecycle
		}
		stage = "grants_verify"
		if err = hooks.verifyGrants(path, consent); err != nil {
			return err
		}
		stage = "grants_digests"
		progress.GrantDigests, err = hooks.grantDigests(path, consent)
		if err != nil || !validReadSetupDigests(progress.GrantDigests) {
			return errLifecycle
		}
		stage = "identity_recheck"
		current, err := hooks.identity(path, consent)
		if err != nil || current != binding {
			return errLifecycle
		}
		stage = "owned_after_grants"
		if err = hooks.setup.verifyOwned(ctx, retained.Service); err != nil {
			return err
		}
		stage = "grants_verified_record"
		return save("grants-verified")
	}
	s.start = func(ctx context.Context, receipt windowsservice.Receipt) (result windowsservice.ApplyResult, err error) {
		stage := "startup_receipt"
		defer func() {
			if err != nil {
				err = setupFailed(stage, err)
			}
		}()
		if receipt != retained.Service || progress.Phase != "grants-verified" {
			return windowsservice.ApplyResult{}, errLifecycle
		}
		stage = "startup_record"
		if err := save("startup-transition-started"); err != nil {
			return windowsservice.ApplyResult{}, err
		}
		stage = "startup_activate"
		activated, err := hooks.activateStartup(ctx, receipt)
		if err != nil {
			return windowsservice.ApplyResult{}, err
		}
		expected := receipt
		expected.Version = 1
		expected.ConfigurationSHA256 = activated.ConfigurationSHA256
		stage = "startup_verify"
		if activated != expected || !validReadSetupBinding(activated.ConfigurationSHA256) {
			return windowsservice.ApplyResult{}, errLifecycle
		}
		retained.Service = activated
		stage = "configured_record"
		if err = save("configured"); err != nil {
			return windowsservice.ApplyResult{}, err
		}
		stage = "configured_verify"
		if !completeReadSetup(retained) {
			return windowsservice.ApplyResult{}, errLifecycle
		}
		stage = "service_start"
		return hooks.setup.start(ctx, activated)
	}
	return setup(ctx, bootstrap, s)
}

func validReadSetupBinding(binding string) bool {
	raw, err := hex.DecodeString(binding)
	return err == nil && len(raw) == 32 && binding == strings.ToLower(binding)
}

// All five notices form one local choice; none implies manager approval or a
// grant to an external AI provider. The separate Setup preview reuses this text.
func writeReadSetupDisclosure(out io.Writer, c lanclient.WindowsCapabilityConsent) error {
	if out == nil || validateReadSetupConsent(c) != nil {
		return errLifecycle
	}
	notices := []string{
		"Fresh Windows observation setup creates one persistent LocalService service and protected endpoint identity. One explicit choice covers every read scope below; public fingerprint/comparison approval in the manager remains mandatory.",
		enrollmentclient.WindowsInventoryPrivacy, windowseventhealth.Privacy, windowsvolumes.Privacy, windowsprocessmetrics.Privacy, windowsnetwork.Privacy,
	}
	if c.InsecureHTTPAcknowledged {
		notices = append(notices, enrollmentclient.WindowsInventoryHTTPPrivacy, windowseventhealth.HTTPPrivacy, windowsvolumes.HTTPPrivacy, windowsprocessmetrics.HTTPPrivacy, windowsnetwork.HTTPPrivacy)
	}
	for _, notice := range notices {
		text := notice + "\n"
		if n, err := io.WriteString(out, text); err != nil || n != len(text) {
			return io.ErrShortWrite
		}
	}
	return nil
}

type readSetupIntent struct {
	Plan    windowsservice.InstallPlan         `json:"plan"`
	Consent lanclient.WindowsCapabilityConsent `json:"consent"`
}

func validReadSetupDigests(values []lanclient.WindowsCapabilityGrantDigest) bool {
	scopes := readSetupScopes()[1:]
	if len(values) != len(scopes) {
		return false
	}
	for i, value := range values {
		if value.Scope != scopes[i] || !validReadSetupBinding(value.SHA256) {
			return false
		}
	}
	return true
}
