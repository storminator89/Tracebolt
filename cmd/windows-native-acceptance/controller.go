package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/windowsacceptance/fixture"
	"localrmm/internal/windowsacceptance/gate"
	"localrmm/internal/windowsacceptance/native"
	"localrmm/internal/windowsacceptance/profile"
)

type driver interface {
	Evidence() native.Evidence
	Preflight(context.Context) error
	Provision(context.Context, native.Guard) error
	Prepare(context.Context, native.Guard, []byte) error
	Claim(context.Context, native.Guard, func(context.Context) ([]byte, error), func(enrollmentclient.TrustDisplay) error) error
	Start(context.Context, native.Guard) error
	InspectToken(context.Context) error
	Status(context.Context) error
	StateContinuity(context.Context) error
	Probe(context.Context, native.Guard) error
	Stop(context.Context, native.Guard) error
	CleanupStop(context.Context, native.Guard) error
	Uninstall(context.Context, native.Guard) error
	Cleanup(context.Context, native.Guard) error
}
type peer interface {
	Bootstrap() enrollmentclient.Bootstrap
	Secret(context.Context) ([]byte, error)
	Approve(string, string) error
	Evidence() fixture.Evidence
	ToggleUnavailable(bool)
	Close() error
}
type controllerHooks struct {
	newDriver     func(native.Options) (driver, error)
	startPeer     func(context.Context, profile.Selection) (peer, error)
	startExpanded func(context.Context, profile.Selection) (peer, error)
	pause         func(context.Context, time.Duration) error
	now           func() time.Time
}

func executeNative(ctx context.Context, g *gate.Grant, o native.Options) gate.Report {
	return executeWith(ctx, g, o, controllerHooks{newDriver: func(o native.Options) (driver, error) { return native.New(o) }, startPeer: func(c context.Context, selected profile.Selection) (peer, error) {
		return fixture.StartSelected(c, selected)
	}, startExpanded: func(c context.Context, selected profile.Selection) (peer, error) {
		return fixture.StartExpanded(c, selected)
	}, pause: pause, now: time.Now})
}
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func await(ctx context.Context, bound time.Duration, h controllerHooks, condition func() bool) error {
	c, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	for {
		if condition() {
			return nil
		}
		if err := h.pause(c, 250*time.Millisecond); err != nil {
			return err
		}
	}
}
func certificateHash(raw string) string {
	b, rest := pem.Decode([]byte(raw))
	if b == nil || len(rest) != 0 || b.Type != "CERTIFICATE" {
		return ""
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return ""
	}
	s := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(s[:])
}
func executeWith(ctx context.Context, g *gate.Grant, o native.Options, h controllerHooks) (r gate.Report) {
	r = gate.NewSelectedReport(g.Source(), g.Selection())
	if g.ExtensionsApproved() {
		z := profile.ZeroExtensionObservation()
		r.Extensions = &z
		r.Schema = gate.ExpandedSchema
	}
	if ctx == nil || !g.Check() || h.newDriver == nil || h.startPeer == nil || h.pause == nil || h.now == nil {
		r.Reason = native.ReasonGuard
		return r
	}
	if o.Selection != (profile.Selection{}) && o.Selection != g.Selection() {
		r.Reason = native.ReasonGuard
		return r
	}
	if o.Expanded != g.ExtensionsApproved() {
		r.Reason = native.ReasonGuard
		return r
	}
	o.Selection = g.Selection()
	d, err := h.newDriver(o)
	if err != nil {
		r.Reason = native.ReasonArtifact
		return r
	}
	var f peer
	attempted := false
	stage := "prerequisites"
	defer func() {
		if recover() != nil {
			r.Status = "failed"
			r.Stage = stage
			r.Reason = native.ReasonOperation
			r.Mark(stage, "fail")
		}
		if f != nil {
			defer func() {
				closeErr := f.Close()
				// Close freezes peer authority/receipts before terminal evidence.
				// A handler accepted during native cleanup must not disappear.
				e := f.Evidence()
				r.Inventory = e.Inventory
				if r.Extensions != nil {
					x := e.Extensions
					r.Extensions = &x
				}
				r.LoopbackPeerExercised = e.Frames > 0
				r.NativeInventorySenderExercised = g.Selection().Inventory() && e.Inventory.Frames > 0 && e.Frames > 0
				if closeErr != nil || !e.Closed {
					r.Status = "failed"
					r.Stage = "owned_cleanup"
					r.Reason = native.ReasonOperation
					r.Mark("owned_cleanup", "fail")
				}
				// Preserve earlier lifecycle, native cleanup or peer-close failure.
				if r.Status == "passed_native_subset" && g.Selection().Inventory() && (!r.Inventory.Usable() || r.Extensions != nil && !r.Extensions.Usable()) {
					r.Status = "failed"
					r.Stage = "profile_report"
					r.Reason = native.ReasonOperation
					r.Mark("profile_report", "fail")
				}
			}()
		}
		if attempted {
			c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			// Failure cleanup uses only a completed same-process ownership receipt.
			// Partial installs intentionally remain fenced; Cleanup cannot adopt them.
			if e := d.Evidence(); e.Installed && !e.Uninstalled {
				if d.CleanupStop(c, g) == nil {
					_ = d.Uninstall(c, g)
				}
			}
			if d.Cleanup(c, g) != nil {
				r.Status = "failed"
				r.Stage = "owned_cleanup"
				r.Reason = d.Evidence().Reason
				r.Mark("owned_cleanup", "fail")
			} else {
				r.Mark("owned_cleanup", "pass")
			}
		}
		r.Native = d.Evidence()
	}()
	step := func(name string, fn func() error) bool {
		stage = name
		r.Stage = name
		if err := fn(); err != nil {
			r.Status = "failed"
			r.Reason = d.Evidence().Reason
			if r.Reason == native.ReasonNone {
				r.Reason = native.ReasonOperation
			}
			r.Mark(name, "fail")
			return false
		}
		r.Mark(name, "pass")
		return true
	}
	if d.Preflight(ctx) != nil {
		r.Status = "blocked"
		r.Reason = d.Evidence().Reason
		r.Mark(stage, "blocked")
		return r
	}
	r.Mark(stage, "pass")
	attempted = true
	r.NativeActionsAttempted = true
	if !step("app_only_provisioning", func() error { return d.Provision(ctx, g) }) {
		return r
	}
	if g.ExtensionsApproved() {
		if h.startExpanded == nil {
			r.Reason = native.ReasonGuard
			return r
		}
		f, err = h.startExpanded(ctx, g.Selection())
	} else {
		f, err = h.startPeer(ctx, g.Selection())
	}
	if err != nil {
		r.Stage = "service_prepare"
		r.Reason = native.ReasonOperation
		r.Mark(r.Stage, "fail")
		return r
	}
	b := f.Bootstrap()
	raw, err := json.Marshal(b)
	if err != nil {
		return r
	}
	defer clear(raw)
	if !step("service_prepare", func() error { return d.Prepare(ctx, g, raw) }) {
		return r
	}
	var fingerprint, comparison string
	display := func(t enrollmentclient.TrustDisplay) error {
		tlsMatch := !g.Selection().HTTPTest() && certificateHash(b.ServerCAPEM) != "" && len(t.ServerCAFingerprints) == 1 && t.ServerCAFingerprints[0] == certificateHash(b.ServerCAPEM)
		httpMatch := g.Selection().HTTPTest() && b.ServerCAPEM == "" && len(t.ServerCAFingerprints) == 0
		if (!tlsMatch && !httpMatch) || t.HTTPTest != g.Selection().HTTPTest() || t.Profile != g.Selection().Transport || t.CollectionProfile != g.Selection().CollectionProfile || b.Profile != g.Selection().Transport || b.CollectionProfile != g.Selection().CollectionProfile || certificateHash(b.IssuerRootPEM) == "" || certificateHash(b.IssuerPEM) == "" || t.ManagerInstanceID != b.ManagerInstanceID || t.EnrollmentOrigin != b.EnrollmentOrigin || t.AgentOrigin != b.AgentOrigin || t.InvitationID != b.InvitationID || t.IssuerRootFingerprint != certificateHash(b.IssuerRootPEM) || t.IssuerFingerprint != certificateHash(b.IssuerPEM) || len(t.KeyFingerprint) != 64 || t.ComparisonCode == "" {
			return errors.New("fixture public trust mismatch")
		}
		fingerprint, comparison = t.KeyFingerprint, t.ComparisonCode
		return nil
	}
	if !step("pending_claim", func() error {
		if d.Claim(ctx, g, f.Secret, display) != nil || len(fingerprint) != 64 || comparison == "" {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	if !step("limited_token", func() error {
		if d.Start(ctx, g) != nil {
			return native.ErrAcceptance
		}
		return d.InspectToken(ctx)
	}) {
		return r
	}
	pendingAt := h.now()
	if !step("pending_stop_identity", func() error {
		if h.pause(ctx, 5*time.Second) != nil || h.now().Sub(pendingAt) < 5*time.Second || f.Evidence().Frames != 0 {
			return native.ErrAcceptance
		}
		if d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().IdentityRetained || d.Evidence().Ready {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	if !step("delayed_approval_report", func() error {
		if d.Start(ctx, g) != nil || f.Approve(fingerprint, comparison) != nil {
			return native.ErrAcceptance
		}
		if await(ctx, 90*time.Second, h, func() bool { e := f.Evidence(); return e.Frames > 0 && e.LastSequence > 0 && e.Platform == "windows" }) != nil {
			return native.ErrAcceptance
		}
		if d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().Ready || !d.Evidence().SenderFloorRetained {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	if !step("profile_report", func() error {
		if g.ExtensionsApproved() {
			extended, ok := d.(interface {
				ConfigureCapabilities(context.Context, native.Guard) error
			})
			if !ok || extended.ConfigureCapabilities(ctx, g) != nil || d.Start(ctx, g) != nil {
				return native.ErrAcceptance
			}
			// Keep the ordinary service running for real CPU deltas, not only a
			// first-sample/null CPU frame. No injected collector or clock.
			if await(ctx, 90*time.Second, h, func() bool { return f.Evidence().Extensions.Usable() }) != nil {
				return native.ErrAcceptance
			}
			if d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().Ready || !d.Evidence().SenderFloorRetained {
				return native.ErrAcceptance
			}
		}
		e := f.Evidence()
		r.Inventory = e.Inventory
		r.LoopbackPeerExercised = e.Frames > 0
		r.NativeInventorySenderExercised = g.Selection().Inventory() && e.Inventory.Frames > 0
		if e.CollectionProfile != g.Selection().CollectionProfile || e.Transport != g.Selection().Transport || !r.LoopbackPeerExercised || (g.Selection().Inventory() && !e.Inventory.Usable()) {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	if !step("unrelated_service_denied", func() error { return d.Probe(ctx, g) }) {
		return r
	}
	baseline := f.Evidence()
	f.ToggleUnavailable(true)
	if !step("outage_pending_retained", func() error {
		if d.Start(ctx, g) != nil {
			return native.ErrAcceptance
		}
		if await(ctx, 90*time.Second, h, func() bool { return f.Evidence().UnavailableRequests > baseline.UnavailableRequests }) != nil {
			return native.ErrAcceptance
		}
		e := f.Evidence()
		if e.Frames != baseline.Frames || e.LastSequence != baseline.LastSequence || d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().PendingPresent {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	outage := f.Evidence()
	if !step("outage_restart_same_bytes", func() error {
		if d.Start(ctx, g) != nil {
			return native.ErrAcceptance
		}
		if await(ctx, 90*time.Second, h, func() bool { return f.Evidence().UnavailableRequests > outage.UnavailableRequests }) != nil {
			return native.ErrAcceptance
		}
		if d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().PendingPresent || !d.Evidence().PendingBytesRetained {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	f.ToggleUnavailable(false)
	if !step("recovery_same_identity", func() error {
		if d.Start(ctx, g) != nil {
			return native.ErrAcceptance
		}
		if await(ctx, 90*time.Second, h, func() bool {
			e := f.Evidence()
			return e.Frames > baseline.Frames && e.LastSequence > baseline.LastSequence && (!g.ExtensionsApproved() || e.Extensions.Usable())
		}) != nil {
			return native.ErrAcceptance
		}
		if d.Stop(ctx, g) != nil || d.StateContinuity(ctx) != nil || !d.Evidence().IdentityRetained || !d.Evidence().SenderFloorRetained || d.Evidence().PendingPresent {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	if !step("uninstall_retains_state", func() error {
		if d.Uninstall(ctx, g) != nil || !d.Evidence().UninstallStateRetained {
			return native.ErrAcceptance
		}
		return nil
	}) {
		return r
	}
	r.Status = "passed_native_subset"
	r.Stage = "owned_cleanup"
	r.Reason = native.ReasonNone
	return r
}
