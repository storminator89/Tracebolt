// Package native contains default-off acceptance operations for one disposable
// Windows machine. Constructing a Driver is inert. A controller must supply its
// live, exact-source authority on every mutating call; a receipt is not authority.
package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowsservice"
)

// Guard must check the controller's in-memory approval, exact source/artifact
// binding and lifetime. There is deliberately no environment-variable grant.
type Guard interface{ Check() bool }

type Stage string

const (
	StageIdle       Stage = "idle"
	StagePreflight  Stage = "preflight"
	StageProvision  Stage = "provision"
	StageInstall    Stage = "install"
	StagePrepare    Stage = "prepare"
	StageClaim      Stage = "claim"
	StageStart      Stage = "start"
	StageToken      Stage = "token"
	StageStatus     Stage = "status"
	StageContinuity Stage = "state-continuity"
	StageProbe      Stage = "probe"
	StageStop       Stage = "stop"
	StageUninstall  Stage = "uninstall"
	StageCleanup    Stage = "cleanup"
)

type Reason string

const (
	ReasonNone         Reason = "none"
	ReasonGuard        Reason = "approval-required"
	ReasonUnsupported  Reason = "unsupported-platform"
	ReasonPrerequisite Reason = "ancestor-prerequisite"
	ReasonExisting     Reason = "existing-resource"
	ReasonArtifact     Reason = "artifact-mismatch"
	ReasonOwnership    Reason = "ownership-rejected"
	ReasonOperation    Reason = "operation-failed"
	ReasonTimeout      Reason = "deadline-or-cancellation"
	ReasonState        Reason = "state-rejected"
)

// Evidence is the entire report surface. It has no paths, native errors,
// receipt IDs, token contents, key bytes or telemetry.
type Evidence struct {
	Stage                  Stage  `json:"stage"`
	Reason                 Reason `json:"reason"`
	Prerequisites          bool   `json:"prerequisites"`
	Provisioned            bool   `json:"provisioned"`
	Installed              bool   `json:"installed"`
	Prepared               bool   `json:"prepared"`
	ClaimCommitted         bool   `json:"claim_committed"`
	Running                bool   `json:"running"`
	LimitedToken           bool   `json:"limited_token"`
	Ready                  bool   `json:"ready"`
	IdentityRetained       bool   `json:"identity_retained"`
	SenderFloorRetained    bool   `json:"sender_floor_retained"`
	PendingPresent         bool   `json:"pending_present"`
	PendingBytesRetained   bool   `json:"pending_bytes_retained"`
	UnrelatedServiceDenied bool   `json:"unrelated_service_denied"`
	Stopped                bool   `json:"stopped"`
	Uninstalled            bool   `json:"uninstalled"`
	UninstallStateRetained bool   `json:"uninstall_state_retained"`
	Cleaned                bool   `json:"cleaned"`
	CleanupRetained        bool   `json:"cleanup_retained"`
}

var ErrAcceptance = errors.New("native acceptance operation refused or incomplete")

// Options names only input artifacts. Native destinations and all service
// arguments are fixed; there is no destination/service/account option.
// Format methods intentionally redact even the public source paths.
type Options struct {
	Selection          profile.Selection
	ServiceArtifact    string
	ServiceSHA256      string
	ControllerArtifact string
	ControllerSHA256   string
}

func (Options) String() string               { return "<native acceptance artifacts>" }
func (Options) GoString() string             { return "<native acceptance artifacts>" }
func (Options) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("<native acceptance artifacts>")) }
func (Options) MarshalJSON() ([]byte, error) { return []byte(`{"artifacts_redacted":true}`), nil }

type platformState interface{ platformState() }
type Driver struct {
	mu                     sync.Mutex
	options                Options
	evidence               Evidence
	state                  platformState
	receipt                windowsservice.Receipt
	bootstrap              enrollmentclient.Bootstrap
	prerequisiteCheck      string
	prerequisiteDiagnostic *PrerequisiteDiagnostic
}

func (*Driver) String() string             { return "<native acceptance driver>" }
func (*Driver) GoString() string           { return "<native acceptance driver>" }
func (*Driver) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("<native acceptance driver>")) }

// New validates values only. It performs no filesystem, SCM, token or key action.
func New(o Options) (*Driver, error) {
	if (o.Selection != (profile.Selection{}) && o.Selection.Validate() != nil) || o.ServiceArtifact == "" || o.ControllerArtifact == "" || !validDigest(o.ServiceSHA256) || !validDigest(o.ControllerSHA256) {
		return nil, ErrAcceptance
	}
	return &Driver{options: o, evidence: Evidence{Stage: StageIdle, Reason: ReasonNone}}, nil
}
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}
func (d *Driver) Evidence() Evidence {
	if d == nil {
		return Evidence{Stage: StageIdle, Reason: ReasonState}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.evidence
}
func (d *Driver) enter(ctx context.Context, g Guard, stage Stage) bool {
	d.evidence.Stage, d.evidence.Reason = stage, ReasonNone
	if ctx == nil || ctx.Err() != nil {
		d.evidence.Reason = ReasonTimeout
		return false
	}
	if g == nil || !g.Check() {
		d.evidence.Reason = ReasonGuard
		return false
	}
	scope, ok := g.(interface{ Selection() profile.Selection })
	if !ok || d.options.Selection.Validate() != nil || scope.Selection() != d.options.Selection {
		d.evidence.Reason = ReasonGuard
		return false
	}
	return true
}
func (d *Driver) fail(r Reason) error { d.evidence.Reason = r; return ErrAcceptance }

// Preflight reads only. A refusal requires a separately reviewed provisioning
// prerequisite; this package never repairs any existing ancestor ACL.
func (d *Driver) Preflight(ctx context.Context) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evidence.Stage, d.evidence.Reason = StagePreflight, ReasonNone
	if ctx == nil || ctx.Err() != nil {
		return d.fail(ReasonTimeout)
	}
	return d.preflight(ctx)
}
func (d *Driver) Provision(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageProvision) {
		return ErrAcceptance
	}
	return d.provision(ctx, g)
}
func (d *Driver) Prepare(ctx context.Context, g Guard, publicBootstrap []byte) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StagePrepare) {
		return ErrAcceptance
	}
	return d.prepare(ctx, g, publicBootstrap)
}

// Claim commits only a pending enrollment. The invitation callback and display
// remain in memory; the ordinary service resumes approval and sends reports.
func (d *Driver) Claim(ctx context.Context, g Guard, secret func(context.Context) ([]byte, error), display func(enrollmentclient.TrustDisplay) error) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageClaim) {
		return ErrAcceptance
	}
	return d.claim(ctx, g, secret, display)
}
func (d *Driver) Start(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageStart) {
		return ErrAcceptance
	}
	return d.start(ctx, g)
}

// InspectToken queries the actual running main service process token. It never
// impersonates, logs on, adjusts privileges or falls back to the controller token.
func (d *Driver) InspectToken(ctx context.Context) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evidence.Stage, d.evidence.Reason = StageToken, ReasonNone
	if ctx == nil || ctx.Err() != nil {
		return d.fail(ReasonTimeout)
	}
	return d.inspectToken(ctx)
}

// Status reads the receipt-bound SCM status; it does not treat Running as a
// manager approval or report assertion.
func (d *Driver) Status(ctx context.Context) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evidence.Stage, d.evidence.Reason = StageStatus, ReasonNone
	if ctx == nil || ctx.Err() != nil {
		return d.fail(ReasonTimeout)
	}
	return d.status(ctx)
}

// StateContinuity is read-only and requires the owned service to be stopped.
// The first ready observation pins the sender binding and durable counter floor;
// later calls reject a changed identity or a counter moving backwards.
func (d *Driver) StateContinuity(ctx context.Context) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evidence.Stage, d.evidence.Reason = StageContinuity, ReasonNone
	if ctx == nil || ctx.Err() != nil {
		return d.fail(ReasonTimeout)
	}
	return d.stateContinuity(ctx)
}
func (d *Driver) Probe(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageProbe) {
		return ErrAcceptance
	}
	return d.probe(ctx, g)
}
func (d *Driver) Stop(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageStop) {
		return ErrAcceptance
	}
	return d.stop(ctx, g)
}

// CleanupStop is solely for failure cleanup. It still requires the exact completed
// receipt and live approval, but permits a failed stopped service to be removed.
// It must never be counted as an orderly acceptance Stop.
func (d *Driver) CleanupStop(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageStop) {
		return ErrAcceptance
	}
	return d.cleanupStop(ctx, g)
}
func (d *Driver) Uninstall(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageUninstall) {
		return ErrAcceptance
	}
	return d.uninstall(ctx, g)
}
func (d *Driver) Cleanup(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageCleanup) {
		return ErrAcceptance
	}
	return d.cleanup(ctx, g)
}

// RunProbe is only for the fixed internal SCM mode of the acceptance controller.
// Its Guard must be minted after read-only verification of that fixed SCM mode;
// a command argument alone must never constitute authority. The probe only reads.
func RunProbe(ctx context.Context, g Guard) error {
	if ctx == nil || ctx.Err() != nil || g == nil || !g.Check() {
		return ErrAcceptance
	}
	return runProbeRuntime(ctx)
}
