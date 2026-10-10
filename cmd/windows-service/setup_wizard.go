package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssetup"
	"localrmm/internal/windowssetupui"
)

type setupWizardOutcomeError struct {
	beforeMutation bool
	cause          error
}

func (*setupWizardOutcomeError) Error() string {
	return "Setup did not complete; inspect the reported phase"
}
func (e *setupWizardOutcomeError) Unwrap() error { return e.cause }

var errSetupRemovalPending = errors.New("service removal remains pending; files and private state are retained")

func setupWizardConsent() lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV3, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: readSetupScopes(), Acknowledged: true}
}
func setupWizardHTTPDisclosure() string {
	var out bytes.Buffer
	consent := setupWizardConsent()
	consent.InsecureHTTPAcknowledged = true
	_ = writeReadSetupDisclosure(&out, consent)
	return out.String()
}

func setupWizardDisclosure() string {
	var out bytes.Buffer
	_ = writeReadSetupDisclosure(&out, setupWizardConsent())
	out.WriteString("\nThis is an unsigned, unreleased fresh-host Setup preview. It supports exactly the five disclosed read scopes. HTTPS is the default; a matching disposable HTTP-test bootstrap requires a separate plaintext-risk acknowledgement. Setup creates app-only protected directories and one limited LocalService service. No upgrade, repair, transport fallback, startup-metadata scope or automatic manager approval is included.\n\nAfter you choose Install, an interrupted or rejected enrollment may leave a disabled service and protected identity/state. Setup cannot reset or retry that installation. Keep all state for administrator review. Cancel before Install makes no installation changes. The dedicated hidden-input console displays public trust and accepts the invitation without echo. Keep it open until Setup finishes.\n\nUninstall removes only the receipt-owned service; executable, public bootstrap, identity, counters and grants remain. Manager trust is not revoked. Reinstallation remains blocked by retained state.")
	return out.String()
}
func setupWizardBootstrap(raw []byte) (enrollmentclient.Bootstrap, error) {
	b, err := enrollmentclient.ParseBootstrap(raw)
	if err != nil || validateWindowsBootstrapConsent(b, enrollmentcrypto.CollectionProfileWindowsInventory, b.Profile == "http-test") != nil {
		return enrollmentclient.Bootstrap{}, enrollmentclient.ErrBootstrap
	}
	return b, nil
}
func setupWizardAcknowledgedBootstrap(raw []byte, insecureAcknowledged bool) (enrollmentclient.Bootstrap, lanclient.WindowsCapabilityConsent, error) {
	b, err := setupWizardBootstrap(raw)
	if err != nil || validateWindowsBootstrapConsent(b, enrollmentcrypto.CollectionProfileWindowsInventory, insecureAcknowledged) != nil {
		return enrollmentclient.Bootstrap{}, lanclient.WindowsCapabilityConsent{}, enrollmentclient.ErrBootstrap
	}
	consent := setupWizardConsent()
	consent.InsecureHTTPAcknowledged = insecureAcknowledged
	return b, consent, nil
}

func setupWizardPreview(raw []byte) (windowssetupui.TrustPreview, error) {
	b, err := setupWizardBootstrap(raw)
	if err != nil {
		return windowssetupui.TrustPreview{}, err
	}
	p := windowssetupui.TrustPreview{ManagerID: b.ManagerInstanceID, EnrollmentOrigin: b.EnrollmentOrigin, AgentOrigin: b.AgentOrigin, HTTPTest: b.Profile == "http-test"}
	for _, field := range []struct{ label, value string }{{"Server CA", b.ServerCAPEM}, {"Issuer root", b.IssuerRootPEM}, {"Issuer", b.IssuerPEM}} {
		rest := []byte(field.value)
		for len(bytes.TrimSpace(rest)) > 0 {
			block, next := pem.Decode(rest)
			if block == nil {
				return windowssetupui.TrustPreview{}, enrollmentclient.ErrBootstrap
			}
			sum := sha256.Sum256(block.Bytes)
			p.Fingerprints = append(p.Fingerprints, hex.EncodeToString(sum[:]))
			rest = next
		}
	}
	return p, nil
}

type setupWizardInstallSteps struct {
	validate      func([]byte) error
	compatibility func(context.Context, []byte) error
	preflight     func(context.Context) error
	console       func() (func() error, error)
	provision     func(context.Context, []byte) (string, func() error, error)
	install       func(context.Context, string) error
}

// All untrusted public input and manager compatibility are checked before
// console allocation or the first disk/service/key/grant write. There is no
// automatic rollback, mutation retry or post-failure re-enrollment.
func setupWizardInstall(ctx context.Context, raw []byte, s setupWizardInstallSteps, progress func(string)) (err error) {
	mutationAttempted := false
	defer func() {
		if err != nil {
			err = &setupWizardOutcomeError{!mutationAttempted, err}
		}
	}()
	if ctx == nil || s.validate == nil || s.compatibility == nil || s.preflight == nil || s.console == nil || s.provision == nil || s.install == nil || progress == nil {
		return errLifecycle
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = s.validate(raw); err != nil {
		return err
	}
	progress("Checking this package and the fresh-host installation boundary.")
	if err = s.preflight(ctx); err != nil {
		return err
	}
	progress("Checking the selected manager's Windows Setup compatibility. An older manager must be updated before installation.")
	if err = s.compatibility(ctx, raw); err != nil {
		return windowssetup.ErrCompatibility
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	closeConsole, err := s.console()
	if err != nil || closeConsole == nil {
		return errLifecycle
	}
	defer func() {
		if e := closeConsole(); err == nil && e != nil {
			err = e
		}
	}()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	progress("Creating fresh protected application files. Cancellation after this point retains partial state and cannot be retried automatically.")
	mutationAttempted = true
	path, closePackage, err := s.provision(ctx, raw)
	if closePackage != nil {
		defer func() {
			if e := closePackage(); err == nil && e != nil {
				err = e
			}
		}()
	}
	if err != nil {
		return err
	}
	if path == "" || closePackage == nil {
		return errLifecycle
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = s.install(ctx, path); err != nil {
		return err
	}
	progress("Service start requested. Check the manager for the first accepted report; reporting and reboot persistence are not verified by Setup.")
	return nil
}

type setupWizardRemovalSteps struct {
	receipt      func() (windowsservice.Receipt, error)
	inspectOwned func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)
	inspect      func(context.Context) (windowsservice.Snapshot, error)
	stop         func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error)
	remove       func(context.Context, windowsservice.Receipt) (windowsservice.ApplyResult, error)
	pending      func(error) bool
	wait         func(context.Context) error
}

func setupWizardUninstall(ctx context.Context, s setupWizardRemovalSteps, progress func(string)) (err error) {
	step := "validate"
	var detail error
	defer func() {
		if err != nil {
			if detail == nil {
				detail = err
			}
			err = &removalFailure{step: step, original: err, detail: detail}
		}
	}()
	if ctx == nil || s.receipt == nil || s.inspectOwned == nil || s.inspect == nil || s.stop == nil || s.remove == nil || s.pending == nil || s.wait == nil || progress == nil {
		return errLifecycle
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	step = "context"
	if ctx.Err() != nil {
		return ctx.Err()
	}
	step = "receipt"
	r, err := s.receipt()
	if err != nil {
		return err
	}
	step = "owned"
	snap, err := s.inspectOwned(ctx, r)
	if err != nil {
		return err
	}
	step = "state"
	if snap.State != windowsservice.Running && snap.State != windowsservice.Stopped {
		return errSetupRemovalPending
	}
	if snap.State == windowsservice.Running {
		progress("Stopping the exact receipt-owned service once. Files, identity and grants will remain.")
		step = "stop"
		if _, err = s.stop(ctx, r); err != nil {
			return err
		}
		for {
			step = "stop-observe"
			snap, err = s.inspectOwned(ctx, r)
			if err != nil {
				return err
			}
			if snap.State == windowsservice.Stopped {
				break
			}
			step = "stop-state"
			if snap.State != windowsservice.Running && snap.State != windowsservice.StopPending {
				return errSetupRemovalPending
			}
			step = "stop-wait"
			if detail = s.wait(ctx); detail != nil {
				return errSetupRemovalPending
			}
		}
	}
	step = "pre-delete"
	if ctx.Err() != nil {
		return ctx.Err()
	}
	progress("Requesting removal of the owned, stopped service. Waiting for SCM to confirm absence.")
	step = "delete"
	result, err := s.remove(ctx, r)
	if err != nil {
		return err
	}
	step = "delete-result"
	if !result.Requested || !result.DeletePending || !result.StateRetained {
		return errSetupRemovalPending
	}
	progress("Service deletion is pending. Waiting for SCM to confirm absence.")
	for {
		step = "absence-inspect"
		snap, err = s.inspect(ctx)
		if err != nil {
			detail = err
			if s.pending(err) {
				step = "absence-wait"
				detail = s.wait(ctx)
				if detail == nil {
					continue
				}
			}
			return errSetupRemovalPending
		}
		if !snap.Exists {
			break
		}
		step = "absence-owned"
		if _, err = s.inspectOwned(ctx, r); err != nil {
			detail = err
			if s.pending(err) {
				step = "absence-wait"
				detail = s.wait(ctx)
				if detail == nil {
					continue
				}
			}
			return errSetupRemovalPending
		}
		step = "absence-wait"
		if detail = s.wait(ctx); detail != nil {
			return errSetupRemovalPending
		}
	}
	progress("Service removal confirmed. Executable, public bootstrap and all private state remain; manager trust was not revoked. Reinstallation remains blocked.")
	return nil
}
