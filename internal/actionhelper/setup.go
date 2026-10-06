package actionhelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

const (
	SetupTargetVersion  = "tracebolt.action-setup-target.v1"
	SetupIntentVersion  = "tracebolt.action-setup-intent.v1"
	SetupStartedVersion = "tracebolt.action-ledger-started.v1"
	SetupIntentPath     = "/var/lib/tracebolt-agent-installer/action-setup-intent.json"
	SetupStartedPath    = "/var/lib/tracebolt-agent-installer/action-ledger-started.json"
	SetupCompletePath   = "/var/lib/tracebolt-agent-installer/action-setup-complete.json"
)

// SetupIntent binds a separately approved installation plan to the exact local
// policy, public command key and existing endpoint incarnation. It lives outside
// the action ledger so losing that directory cannot authorize initialization.
type SetupIntent struct {
	Version           string `json:"version"`
	PlanDigest        string `json:"planDigest"`
	RootPolicyDigest  string `json:"rootPolicyDigest"`
	KeyID             string `json:"keyId"`
	EndpointID        string `json:"endpointId"`
	IncarnationDigest string `json:"incarnationDigest"`
}

type SetupTargetResult struct {
	SchemaVersion    string      `json:"schemaVersion"`
	Target           Target      `json:"target"`
	UnitPolicyDigest string      `json:"unitPolicyDigest"`
	ObservedState    Observation `json:"observedState"`
}

// ValidateSetupPolicy shares the runtime's canonical decoder and verifier.
// Validation is pure; it neither provisions nor accepts any local grant.
func ValidateSetupPolicy(raw []byte, key ed25519.PublicKey) (Policy, error) {
	return decodePolicy(raw, key)
}

// SetupTargetDigest exposes the exact reviewed target fingerprint used in a
// signed permit. It validates the bounded target shape, not review completeness.
func SetupTargetDigest(target Target) (string, error) { return targetDigest(target) }

// SetupConfigurationDigest fingerprints only the complete fixed show-property
// projection. It is not permission to execute or a substitute for local review.
func SetupConfigurationDigest(raw []byte) (string, error) {
	p, err := parseProperties(raw, configurationProperties)
	if err != nil {
		return "", err
	}
	return configurationDigest(p), nil
}

// CheckSetupTarget validates existing review pins through protected input reads
// and fixed systemctl show calls only. No action, ledger or helper socket opens.
func CheckSetupTarget(ctx context.Context, target Target) (SetupTargetResult, error) {
	return checkSetupTarget(ctx, target, rootIdentity, newSystemdBackend().Check)
}

func checkSetupTarget(ctx context.Context, target Target, identity func() error, check func(context.Context, Target) (Observation, error)) (SetupTargetResult, error) {
	if ctx == nil || ctx.Err() != nil || identity() != nil {
		return SetupTargetResult{}, ErrRejected
	}
	digest, err := targetDigest(target)
	if err != nil {
		return SetupTargetResult{}, ErrRejected
	}
	observation, err := check(ctx, target)
	if err != nil || ctx.Err() != nil || identity() != nil || (observation != Active && observation != Inactive && observation != Failed && observation != Unknown) {
		return SetupTargetResult{}, ErrRejected
	}
	return SetupTargetResult{SchemaVersion: SetupTargetVersion, Target: target, UnitPolicyDigest: digest, ObservedState: observation}, nil
}

// InitializeSetupLedger is create-only. The separately provisioned fixed
// authority and setup intent must match these canonical bytes; a permanent
// exclusive started fence is fsynced BEFORE actionstate.Initialize is called.
// Any failure leaves the fence intact. Runtime Run never calls this function.
func InitializeSetupLedger(ctx context.Context, canonicalPolicyBytes []byte, publicKey ed25519.PublicKey) error {
	return initializeSetupLedger(ctx, canonicalPolicyBytes, publicKey, rootIdentity, beginSetupInitialization,
		func(ctx context.Context, verifier actionpermit.Verifier) error {
			state, err := actionstate.Initialize(ctx, StateDirectory, verifier)
			if err != nil {
				return err
			}
			return state.Close()
		})
}

func initializeSetupLedger(ctx context.Context, raw []byte, key ed25519.PublicKey, identity func() error,
	begin func(context.Context, Policy, ed25519.PublicKey) error, initialize func(context.Context, actionpermit.Verifier) error) error {
	if ctx == nil || ctx.Err() != nil || identity() != nil {
		return ErrRejected
	}
	p, err := decodePolicy(raw, key)
	if err != nil {
		return ErrRejected
	}
	verifier, err := policyVerifier(p, key)
	if err != nil || begin(ctx, p, key) != nil || ctx.Err() != nil || identity() != nil {
		return ErrRejected
	}
	return initialize(ctx, verifier)
}

// RunSetupInitialize only reads the fixed preprovided policy and public key;
// it cannot select a different state directory, key, identity or reset mode.
func RunSetupInitialize(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || rootIdentity() != nil {
		return ErrRejected
	}
	a, err := loadAuthority()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(a.Policy)
	if err != nil {
		return ErrRejected
	}
	return InitializeSetupLedger(ctx, raw, a.PublicKey)
}

func decodeSetupIntent(raw []byte, p Policy, key ed25519.PublicKey) (SetupIntent, error) {
	var intent SetupIntent
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &intent) != nil {
		return SetupIntent{}, ErrRejected
	}
	canonical, _ := json.Marshal(intent)
	policy, _ := json.Marshal(p)
	if !bytes.Equal(raw, canonical) || intent.Version != SetupIntentVersion || !actionpermit.ValidDigest(intent.PlanDigest) ||
		intent.RootPolicyDigest != actionpermit.Digest(policy) || intent.KeyID != actionpermit.Digest(key) ||
		intent.KeyID != p.KeyID || intent.EndpointID != p.EndpointID || intent.IncarnationDigest != p.IncarnationDigest {
		return SetupIntent{}, ErrRejected
	}
	return intent, nil
}
