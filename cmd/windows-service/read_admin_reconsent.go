package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"path/filepath"
	"reflect"
	"strings"
)

const readAdminReconsentVersion = "tracebolt.windows-read-admin-reconsent.v1"

type readAdminReconsentReceipt struct {
	SchemaVersion         string                                   `json:"schemaVersion"`
	OriginalReceiptSHA256 string                                   `json:"originalReceiptSHA256"`
	SenderBinding         string                                   `json:"senderBinding"`
	Consent               lanclient.WindowsCapabilityConsent       `json:"consent"`
	OriginalScopes        []lanclient.WindowsReadAdminScopeState   `json:"originalScopes"`
	Phase                 string                                   `json:"phase"`
	Grants                lanclient.WindowsCapabilityConsentResult `json:"grants"`
	GrantDigests          []lanclient.WindowsCapabilityGrantDigest `json:"grantDigests"`
}

type readAdminReconsentResult struct {
	Status                string                                   `json:"status"`
	Scopes                []lanclient.WindowsReadAdminScopeState   `json:"scopes,omitempty"`
	Groups                []lanclient.WindowsReadAdminGroup        `json:"groups,omitempty"`
	Grants                lanclient.WindowsCapabilityConsentResult `json:"grants"`
	ServiceStartRequested bool                                     `json:"serviceStartRequested"`
	BlockedScope          string                                   `json:"blockedScope,omitempty"`
	OriginalStateRetained bool                                     `json:"originalStateRetained"`
}

type readAdminReconsentSteps struct {
	executable      func() (string, error)
	inspect         func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error)
	originalReceipt func() ([]byte, error)
	identity        func(string, lanclient.WindowsCapabilityConsent) (string, error)
	preview         func(string, lanclient.WindowsCapabilityConsent, func() error) ([]lanclient.WindowsReadAdminScopeState, error)
	preserve        func(string, lanclient.WindowsCapabilityConsent, []lanclient.WindowsReadAdminScopeState) error
	existingPhase   func() (string, error)
	compatibility   func(context.Context) error
	create          func() (setupJournal, error)
	configure       func(string, lanclient.WindowsCapabilityConsent, func() error) (lanclient.WindowsCapabilityConsentResult, error)
	digests         func(string, lanclient.WindowsCapabilityConsent) ([]lanclient.WindowsCapabilityGrantDigest, error)
}

// Explicit one-time local reconsent. It is not binary upgrade, recovery, Start,
// enrollment or promotion of the original installer receipt. All scopes are
// previewed before create-only phase evidence, with live guards at each grant.
func readAdminReconsent(ctx context.Context, r request, installed installReceipt, h readAdminReconsentSteps) (out readAdminReconsentResult, err error) {
	out = readAdminReconsentResult{Status: "blocked", OriginalStateRetained: true}
	if ctx == nil || (r.mode != "read-admin-preview" && r.mode != "read-admin-enable") || h.executable == nil || h.inspect == nil || h.originalReceipt == nil || h.identity == nil || h.preview == nil || h.preserve == nil || h.existingPhase == nil || h.compatibility == nil || h.create == nil || h.configure == nil || h.digests == nil {
		return out, errLifecycle
	}
	consent := readAdminSetupConsent(r.insecureHTTP)
	original, e := h.originalReceipt()
	if e != nil {
		return out, e
	}
	decoded, e := decodeInstallReceipt(original, installed.Service.Layout)
	if e != nil || !reflect.DeepEqual(decoded, installed) {
		return out, errLifecycle
	}
	path := filepath.Join(installed.Service.Layout.EnrollmentRoot, "agent.json")
	binding := ""
	guard := func() error {
		if e := lifecycleContextError(ctx); e != nil {
			return e
		}
		executable, e := h.executable()
		if e != nil || installed.Service.Layout.Executable == "" || !strings.EqualFold(executable, installed.Service.Layout.Executable) {
			return errLifecycle
		}
		current, e := h.originalReceipt()
		if e != nil || !bytes.Equal(current, original) {
			return errLifecycle
		}
		snapshot, e := h.inspect(ctx, installed.Service)
		if e != nil || snapshot.State != windowsservice.Stopped {
			return errLifecycle
		}
		currentBinding, e := h.identity(path, consent)
		if e != nil || !validReadSetupBinding(currentBinding) || binding != "" && currentBinding != binding {
			return errLifecycle
		}
		binding = currentBinding
		return nil
	}
	if e := guard(); e != nil {
		return out, e
	}
	phase, e := h.existingPhase()
	if e != nil {
		return out, e
	}
	if phase != "absent" {
		out.Status = "existing-reconsent-state-retained"
		return out, errLifecycle
	}
	states, e := h.preview(path, consent, guard)
	if e != nil || !validReadAdminScopeStates(consent, states) {
		var scopeError *lanclient.WindowsReadAdminScopeError
		if errors.As(e, &scopeError) {
			for _, scope := range consent.Scopes[1:] {
				if scopeError.Scope == scope {
					out.Status = "existing-scope-state-unavailable"
					out.BlockedScope = scope
				}
			}
		}
		return out, errLifecycle
	}
	if e := guard(); e != nil {
		return out, e
	}
	out.Scopes, out.Groups = states, lanclient.WindowsReadAdminGroups()
	if e := h.compatibility(ctx); e != nil {
		out.Status = "manager-compatibility-required"
		return out, e
	}
	if e := guard(); e != nil {
		return out, e
	}
	if r.mode == "read-admin-preview" {
		out.Status = "ready-for-explicit-reconsent"
		return out, nil
	}
	journal, e := h.create()
	if journal != nil {
		defer func() {
			err = joinLifecycleErrors(err, journal.Close())
			if err != nil && out.Status == "configured-service-remains-stopped" {
				out.Status = "receipt-release-unverified"
			}
		}()
	}
	if e != nil || journal == nil {
		return out, errLifecycle
	}
	digest := sha256.Sum256(original)
	retained := readAdminReconsentReceipt{SchemaVersion: readAdminReconsentVersion, OriginalReceiptSHA256: hex.EncodeToString(digest[:]), SenderBinding: binding, Consent: consent, OriginalScopes: states, Phase: "intent-recorded"}
	raw, e := json.Marshal(retained)
	if e != nil || journal.Write("intent.json", raw) != nil {
		return out, errLifecycle
	}
	var previous []byte
	save := func(phase string) error {
		if e := guard(); e != nil {
			return e
		}
		if journal.Verify() != nil {
			return errLifecycle
		}
		if previous != nil {
			reader, ok := journal.(interface{ Read(string) ([]byte, error) })
			if !ok {
				return errLifecycle
			}
			current, e := reader.Read("receipt.json")
			if e != nil || !bytes.Equal(current, previous) {
				return errLifecycle
			}
		}
		retained.Phase = phase
		raw, e := json.Marshal(retained)
		if e != nil {
			return e
		}
		if e = journal.Write("receipt.json", raw); e != nil {
			return e
		}
		previous = raw
		return journal.Verify()
	}
	if e := save("grants-started"); e != nil {
		return out, e
	}
	phaseGuard := func() error {
		if e := guard(); e != nil {
			return e
		}
		if journal.Verify() != nil || retained.Phase != "grants-started" {
			return errLifecycle
		}
		reader, ok := journal.(interface{ Read(string) ([]byte, error) })
		if !ok {
			return errLifecycle
		}
		current, e := reader.Read("receipt.json")
		if e != nil || !bytes.Equal(current, previous) {
			return errLifecycle
		}
		return h.preserve(path, consent, states)
	}
	result, e := h.configure(path, consent, phaseGuard)
	retained.Grants, out.Grants = result, result
	if e != nil {
		out.Status = "grants-incomplete-state-retained"
		_ = save("grants-incomplete")
		return out, e
	}
	if !result.MetadataScopeVerified || result.FailedScope != "" || !reflect.DeepEqual(result.AppliedScopes, consent.Scopes[1:]) {
		return out, errLifecycle
	}
	if e := phaseGuard(); e != nil {
		return out, e
	}
	retained.GrantDigests, e = h.digests(path, consent)
	if e != nil || !validReadSetupConsentDigests(consent, retained.GrantDigests) {
		return out, errLifecycle
	}
	if e := phaseGuard(); e != nil {
		return out, e
	}
	if e := save("configured"); e != nil {
		return out, e
	}
	if e := guard(); e != nil {
		return out, e
	}
	out.Status = "configured-service-remains-stopped"
	return out, nil
}

func validReadAdminScopeStates(c lanclient.WindowsCapabilityConsent, states []lanclient.WindowsReadAdminScopeState) bool {
	if c.Validate() != nil || c.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV5 || len(states) != len(c.Scopes)-1 {
		return false
	}
	for i, s := range states {
		if s.Scope != c.Scopes[i+1] || s.Enabled && !validReadSetupBinding(s.SHA256) || !s.Enabled && s.SHA256 != "" {
			return false
		}
	}
	return true
}
