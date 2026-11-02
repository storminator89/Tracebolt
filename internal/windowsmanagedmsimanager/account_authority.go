package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"sort"
	"sync/atomic"
)

type accountHold struct {
	actor  string
	epoch  uint64
	caps   []operatorauth.Capability
	active *atomic.Bool
}
type accountHoldKey struct{}

func capsFor(kind string, scheduled bool) []operatorauth.Capability {
	c := operatorauth.WindowsManagedMSIInstall
	if kind == "deliver" {
		c = operatorauth.WindowsManagedMSIDeliver
	}
	caps := []operatorauth.Capability{c}
	if scheduled {
		caps = append(caps, operatorauth.WindowsManagedMSISchedule)
	}
	return caps
}
func hasAccountHold(ctx context.Context, actor string, epoch uint64, caps []operatorauth.Capability) bool {
	holds, _ := ctx.Value(accountHoldKey{}).([]accountHold)
	for _, h := range holds {
		if h.actor != actor || h.epoch != epoch || h.active == nil || !h.active.Load() {
			continue
		}
		all := true
		for _, c := range caps {
			found := false
			for _, v := range h.caps {
				found = found || v == c
			}
			all = all && found
		}
		if all {
			return true
		}
	}
	return false
}
func leaseAccount(ctx context.Context, admit operatorauth.ActorAdmission, actor string, epoch uint64, caps []operatorauth.Capability) (context.Context, func(), error) {
	if admit == nil {
		return ctx, func() {}, nil
	}
	guarded, release, e := admit(ctx, actor, epoch, caps...)
	if e != nil {
		return ctx, nil, msi.ErrAuthority
	}
	active := &atomic.Bool{}
	active.Store(true)
	holds, _ := guarded.Value(accountHoldKey{}).([]accountHold)
	holds = append(append([]accountHold(nil), holds...), accountHold{actor: actor, epoch: epoch, caps: caps, active: active})
	return context.WithValue(guarded, accountHoldKey{}, holds), func() {
		if active.Swap(false) {
			release()
		}
	}, nil
}
func (m *Manager) ConfigureAccountAuthority(admit operatorauth.ActorAdmission) error {
	if m == nil || admit == nil {
		return msi.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accountAuthority != nil {
		return msi.ErrConflict
	}
	m.accountAuthority = admit
	return nil
}
func (r *Registry) ConfigureAccountAuthority(admit operatorauth.ActorAdmission) error {
	if r == nil || admit == nil {
		return msi.ErrInvalid
	}
	for _, m := range r.ordered {
		if e := m.ConfigureAccountAuthority(admit); e != nil {
			return e
		}
	}
	if r.artifact != nil {
		r.artifact.mu.Lock()
		defer r.artifact.mu.Unlock()
		if r.artifact.accountAuthority != nil {
			return msi.ErrConflict
		}
		r.artifact.accountAuthority = admit
	}
	return nil
}
func (m *Manager) beginAccount(ctx context.Context, actor, kind string, scheduled bool) (context.Context, func(), error) {
	if m == nil || ctx == nil {
		return ctx, nil, msi.ErrInvalid
	}
	return leaseAccount(ctx, m.accountAuthority, actor, operatorauth.ApprovalEpochFromContext(ctx), capsFor(kind, scheduled))
}
func (m *ArtifactManager) beginAccount(ctx context.Context, actor string) (context.Context, func(), error) {
	if m == nil || ctx == nil {
		return ctx, nil, msi.ErrInvalid
	}
	return leaseAccount(ctx, m.accountAuthority, actor, operatorauth.ApprovalEpochFromContext(ctx), capsFor("deliver", false))
}

// Snapshot discovery finishes before actor acquisition. Every use is compared
// again against the exact durable permit/epoch inside the subsequent transaction.
func (m *Manager) accountSnapshot(ctx context.Context) (msi.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return msi.Record{}, msi.ErrUncertain
	}
	return m.store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, m.configurationCheck), m.binding, m.key.Public().(ed25519.PublicKey))
}
func (m *Manager) beginBackground(ctx context.Context, mode string, raw []byte, digest string) (context.Context, func(), error) {
	if m == nil || ctx == nil {
		return ctx, nil, msi.ErrInvalid
	}
	if m.accountAuthority == nil {
		return ctx, func() {}, nil
	}
	r, e := m.accountSnapshot(ctx)
	if e != nil {
		return ctx, nil, e
	}
	needs := []accountHold{}
	add := func(raw []byte) error {
		if len(raw) == 0 {
			return nil
		}
		p, e := msi.VerifyPermit(raw, r.PublicKey)
		if e != nil {
			return e
		}
		needs = append(needs, accountHold{actor: p.ActorID, epoch: r.AccountEpochs[msi.Digest(raw)], caps: capsFor(p.Kind, p.ScheduleDigest != "")})
		return nil
	}
	switch mode {
	case "poll":
		if r.Schedule != nil && !r.Schedule.Terminal() && r.Schedule.PermitIssuedAt == 0 {
			a := r.Schedule.Approval
			needs = append(needs, accountHold{actor: a.ActorID, epoch: r.AccountEpochs[a.Digest], caps: capsFor("install", true)})
		}
		if len(r.RetirePermit) > 0 && len(r.RetiredReport) == 0 && r.RetireClaimedAt == 0 {
			e = add(r.RetirePermit)
		} else if len(r.DeliveryPermit) > 0 && len(r.DeliveryReport) == 0 {
			e = add(r.DeliveryPermit)
		} else if len(r.ReadinessPermit) > 0 && r.ReadinessClaimedAt == 0 {
			e = add(r.ReadinessPermit)
		} else if len(r.InstallPermit) > 0 && r.InstallClaimedAt == 0 {
			e = add(r.InstallPermit)
		}
	case "chunk":
		e = add(r.DeliveryPermit)
	case "report":
		if r.Schedule != nil && !r.Schedule.Terminal() && r.Schedule.PermitIssuedAt == 0 {
			a := r.Schedule.Approval
			needs = append(needs, accountHold{actor: a.ActorID, epoch: r.AccountEpochs[a.Digest], caps: capsFor("install", true)})
		}
	case "response":
		if digest != "" {
			if digest != msi.Digest(r.DeliveryPermit) {
				return ctx, nil, msi.ErrConflict
			}
			raw = r.DeliveryPermit
		}
		if len(raw) > 0 {
			found := false
			for _, exact := range [][]byte{r.DeliveryPermit, r.ReadinessPermit, r.InstallPermit, r.RetirePermit} {
				found = found || bytes.Equal(raw, exact)
			}
			if !found {
				return ctx, nil, msi.ErrConflict
			}
			e = add(raw)
		}
	}
	if e != nil {
		return ctx, nil, e
	}
	// Coalesce one actor/epoch and acquire actors in stable order. Different epochs
	// for the same actor cannot be promoted by a later approval.
	merged := map[string]accountHold{}
	for _, n := range needs {
		old, ok := merged[n.actor]
		if ok && old.epoch != n.epoch {
			return ctx, nil, msi.ErrAuthority
		}
		if !ok {
			merged[n.actor] = n
			continue
		}
		for _, c := range n.caps {
			found := false
			for _, v := range old.caps {
				found = found || v == c
			}
			if !found {
				old.caps = append(old.caps, c)
			}
		}
		merged[n.actor] = old
	}
	actors := make([]string, 0, len(merged))
	for actor := range merged {
		actors = append(actors, actor)
	}
	sort.Strings(actors)
	releases := []func(){}
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, actor := range actors {
		n := merged[actor]
		var done func()
		ctx, done, e = leaseAccount(ctx, m.accountAuthority, n.actor, n.epoch, n.caps)
		if e != nil {
			release()
			return ctx, nil, e
		}
		releases = append(releases, done)
	}
	return ctx, release, nil
}

// BeginResponseAdmission is retained by transport across bounded response I/O.
func (m *Manager) BeginResponseAdmission(ctx context.Context, raw []byte, digest string) (context.Context, func(), error) {
	return m.beginBackground(ctx, "response", raw, digest)
}

func (m *Manager) bindAccountEpochs(ctx context.Context, before msi.Record, after *msi.Record) error {
	if m.accountAuthority == nil {
		return nil
	}
	old := before.AccountEpochKeys()
	next := after.AccountEpochKeys()
	epochs := map[string]uint64{}
	for key := range next {
		if epoch := before.AccountEpochs[key]; epoch != 0 {
			epochs[key] = epoch
		}
	}
	if after.Schedule != nil && !old[after.Schedule.Approval.Digest] {
		a := after.Schedule.Approval
		epoch := operatorauth.ApprovalEpochFromContext(ctx)
		if !hasAccountHold(ctx, a.ActorID, epoch, capsFor("install", true)) {
			return msi.ErrAuthority
		}
		if epoch != 0 {
			epochs[a.Digest] = epoch
		}
	}
	for _, raw := range [][]byte{after.DeliveryPermit, after.ReadinessPermit, after.InstallPermit, after.RetirePermit} {
		if len(raw) == 0 {
			continue
		}
		key := msi.Digest(raw)
		if old[key] {
			continue
		}
		p, e := msi.VerifyPermit(raw, after.PublicKey)
		if e != nil {
			return e
		}
		epoch := operatorauth.ApprovalEpochFromContext(ctx)
		if p.ScheduleDigest != "" {
			epoch = epochs[p.ScheduleDigest]
		}
		if !hasAccountHold(ctx, p.ActorID, epoch, capsFor(p.Kind, p.ScheduleDigest != "")) {
			return msi.ErrAuthority
		}
		if epoch != 0 {
			epochs[key] = epoch
		}
	}
	// Claims cannot change without a held lease for their original saved epoch.
	for _, pair := range []struct {
		raw       []byte
		old, next int64
	}{{after.DeliveryPermit, before.DeliveryClaimedAt, after.DeliveryClaimedAt}, {after.ReadinessPermit, before.ReadinessClaimedAt, after.ReadinessClaimedAt}, {after.InstallPermit, before.InstallClaimedAt, after.InstallClaimedAt}, {after.RetirePermit, before.RetireClaimedAt, after.RetireClaimedAt}} {
		if pair.old == pair.next || pair.next == 0 {
			continue
		}
		p, e := msi.VerifyPermit(pair.raw, after.PublicKey)
		if e != nil || !hasAccountHold(ctx, p.ActorID, epochs[msi.Digest(pair.raw)], capsFor(p.Kind, p.ScheduleDigest != "")) {
			return msi.ErrAuthority
		}
	}
	if len(epochs) == 0 {
		after.AccountEpochs = nil
	} else {
		after.AccountEpochs = epochs
	}
	return nil
}

// AccountAuthorityConfigured is immutable after startup configuration.
func (m *Manager) AccountAuthorityConfigured() bool { return m != nil && m.accountAuthority != nil }
