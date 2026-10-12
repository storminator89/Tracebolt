package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	mu                              sync.Mutex
	store                           msi.TransactionStore
	binding                         msi.Binding
	key                             ed25519.PrivateKey
	spool                           *Spool
	now                             func() time.Time
	configurationCheck              func() error
	deliveryAllowed, installAllowed func(string) bool
	failed                          bool
}

func Open(ctx context.Context, store msi.TransactionStore, b msi.Binding, key ed25519.PrivateKey, spool *Spool, clock func() time.Time, check func() error) (*Manager, error) {
	if ctx == nil || store == nil || b.Validate() != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) || msi.Digest(key.Public().(ed25519.PublicKey)) != b.KeyID || spool == nil || clock == nil || check == nil {
		return nil, msi.ErrInvalid
	}
	e := store.WindowsManagedMSIEnrollmentBinding()
	if e.InstanceID != b.ManagerID || e.Profile != "tls" || e.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil, msi.ErrAuthority
	}
	r, err := store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, check), b, key.Public().(ed25519.PublicKey))
	if err != nil || r.Validate() != nil {
		return nil, msi.ErrIntegrity
	}
	if r.Artifact == nil {
		if spool.validateRecord(false, false, 0) != nil {
			return nil, msi.ErrIntegrity
		}
	} else if spool.validateRecord(true, r.Artifact.CompletedAt != 0, r.Artifact.Package.Size) != nil {
		return nil, msi.ErrIntegrity
	}
	return &Manager{store: store, binding: b, key: bytes.Clone(key), spool: spool, now: clock, configurationCheck: check}, nil
}
func (m *Manager) Binding() msi.Binding {
	if m == nil {
		return msi.Binding{}
	}
	return m.binding
}
func (m *Manager) MatchesBinding(b enrollmentstate.Binding) bool {
	return m != nil && m.store != nil && m.store.WindowsManagedMSIEnrollmentBinding() == b
}
func (m *Manager) MatchesStore(s msi.TransactionStore) bool {
	return m != nil && m.store != nil && s != nil && reflect.ValueOf(s).Comparable() && reflect.ValueOf(m.store).Comparable() && m.store == s
}
func (m *Manager) ConfigureOperatorPolicy(delivery, install func(string) bool) error {
	if m == nil || delivery == nil || install == nil {
		return msi.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deliveryAllowed != nil || m.installAllowed != nil {
		return msi.ErrConflict
	}
	m.deliveryAllowed, m.installAllowed = delivery, install
	return nil
}
func (m *Manager) OperatorPolicyConfigured() bool {
	return m != nil && m.deliveryAllowed != nil && m.installAllowed != nil
}
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
	clear(m.key)
}
func (m *Manager) PublicKeys() []ed25519.PublicKey {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return nil
	}
	r, e := m.store.ReadRegisteredWindowsManagedMSI(context.Background(), m.binding, m.key.Public().(ed25519.PublicKey))
	if e != nil {
		return nil
	}
	return []ed25519.PublicKey{bytes.Clone(r.PublicKey), bytes.Clone(r.ExecutorPublicKey)}
}
func (m *Manager) allowed(actor, kind string) bool {
	if !enrollmentcrypto.ValidID(actor, "operator_") {
		return false
	}
	if kind == "deliver" {
		return m.deliveryAllowed != nil && m.deliveryAllowed(actor)
	}
	return m.installAllowed != nil && m.installAllowed(actor)
}
func (m *Manager) transaction(ctx context.Context, actor, kind string, fn func(*msi.Record, msi.Current, int64) error) (msi.Record, error) {
	if m == nil || m.failed || ctx == nil {
		return msi.Record{}, msi.ErrUncertain
	}
	ctx = msi.WithFinalCheck(ctx, func() error {
		if e := m.configurationCheck(); e != nil {
			return e
		}
		if actor != "" && !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		return nil
	})
	r, _, e := m.store.WindowsManagedMSITransaction(ctx, m.binding, m.key.Public().(ed25519.PublicKey), m.now().UTC(), func(r *msi.Record, c msi.Current, at time.Time) error {
		if actor != "" && !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		return fn(r, c, at.Unix())
	})
	if e == msi.ErrUncertain || e == msi.ErrIntegrity {
		m.failed = true
	}
	return r, e
}
func (m *Manager) ReserveUpload(ctx context.Context, actor string, selection msi.Selection, native string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !msi.ValidSelection(selection) || !msi.ValidDigest(native) {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, n int64) error {
		if r.Artifact != nil {
			return msi.ErrConsumed
		}
		r.Artifact = &msi.Artifact{Package: selection, NativeAcceptanceDigest: native, IntentAt: n, PrefixDigest: msi.Digest(nil)}
		return nil
	})
	return e
}

type UploadChunk struct {
	PackageDigest string `json:"packageDigest"`
	Index         uint32 `json:"index"`
	Digest        string `json:"digest"`
	Data          []byte `json:"data"`
}

func (m *Manager) Upload(ctx context.Context, actor string, q UploadChunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q.Index >= msi.MaxChunks || len(q.Data) == 0 || len(q.Data) > msi.MaxChunkBytes || !msi.ValidDigest(q.PackageDigest) || msi.Digest(q.Data) != q.Digest {
		return msi.ErrInvalid
	}
	var duplicate bool
	r, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, _ int64) error {
		a := r.Artifact
		if a == nil || a.CompletedAt != 0 || a.Package.SHA256 != q.PackageDigest {
			return msi.ErrConsumed
		}
		offset := int64(q.Index) * msi.MaxChunkBytes
		if offset < a.Offset && offset+int64(len(q.Data)) == a.Offset && q.Digest == a.LastChunkDigest {
			duplicate = true
			return nil
		}
		if offset != a.Offset || len(q.Data) != int(min(int64(msi.MaxChunkBytes), a.Package.Size-a.Offset)) {
			return msi.ErrConflict
		}
		if a.PendingDigest != "" && (a.PendingDigest != q.Digest || a.PendingIndex != q.Index || a.PendingSize != len(q.Data)) {
			return msi.ErrConflict
		}
		a.PendingDigest = q.Digest
		a.PendingIndex = q.Index
		a.PendingSize = len(q.Data)
		return nil
	})
	if e != nil || duplicate {
		return e
	}
	exact := *r.Artifact
	check := func() error {
		_, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, _ int64) error {
			if r.Artifact == nil || *r.Artifact != exact {
				return msi.ErrConflict
			}
			return nil
		})
		return e
	}
	prefix, e := m.spool.Append(ctx, exact, q.Data, check)
	if e != nil {
		return msi.ErrUncertain
	}
	_, e = m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, _ int64) error {
		if r.Artifact == nil || *r.Artifact != exact {
			return msi.ErrConflict
		}
		a := r.Artifact
		a.Offset += int64(a.PendingSize)
		a.PrefixDigest = prefix
		a.LastChunkDigest = a.PendingDigest
		a.PendingIndex = 0
		a.PendingDigest = ""
		a.PendingSize = 0
		return nil
	})
	return e
}
func (m *Manager) CompleteUpload(ctx context.Context, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, _ int64) error {
		a := r.Artifact
		if a == nil || a.CompletedAt != 0 || a.Offset != a.Package.Size || a.PrefixDigest != a.Package.SHA256 || a.PendingDigest != "" {
			return msi.ErrConflict
		}
		return nil
	})
	if e != nil {
		return e
	}
	exact := *r.Artifact
	check := func() error {
		_, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, _ int64) error {
			if r.Artifact == nil || *r.Artifact != exact {
				return msi.ErrConflict
			}
			return nil
		})
		return e
	}
	if _, e = m.spool.ReadChunk(ctx, exact.Package, 0, check); e != nil {
		return msi.ErrUncertain
	}
	_, e = m.transaction(ctx, actor, "deliver", func(r *msi.Record, _ msi.Current, n int64) error {
		if r.Artifact == nil || *r.Artifact != exact {
			return msi.ErrConflict
		}
		r.Artifact.CompletedAt = n
		return nil
	})
	return e
}
func (m *Manager) Deliver(ctx context.Context, actor, id string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ack || !msi.ValidTransferID(id) {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "deliver", func(r *msi.Record, c msi.Current, n int64) error {
		if r.Artifact == nil || r.Artifact.CompletedAt == 0 {
			return msi.ErrUnavailable
		}
		if r.TransferID != "" {
			return msi.ErrConsumed
		}
		p := msi.Permit{Version: msi.Version, Kind: "deliver", TransferID: id, Binding: m.binding, LeafDigest: c.LeafDigest, Package: r.Artifact.Package, NativeAcceptanceDigest: r.Artifact.NativeAcceptanceDigest, ActorID: actor, IssuedAt: n, ExpiresAt: min(n+86400, r.Grant.ExpiresAt, c.LeafNotAfter)}
		raw, e := msi.SignPermit(p, m.key)
		if e != nil {
			return e
		}
		r.TransferID = id
		r.DeliveryPermit = raw
		return nil
	})
	return e
}
func (m *Manager) Review(ctx context.Context, actor string, packageReview, terms, maintenance bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !packageReview || !terms || !maintenance {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "install", func(r *msi.Record, c msi.Current, n int64) error {
		if !r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged {
			return msi.ErrAuthority
		}
		if len(r.InstallPermit) != 0 {
			return msi.ErrConsumed
		}
		sequence := uint64(1)
		if len(r.ReadinessPermit) != 0 {
			old, e := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
			if e != nil || n < old.ExpiresAt || old.Sequence+1 <= old.Sequence {
				return msi.ErrConsumed
			}
			sequence = old.Sequence + 1
		}
		d, e := msi.VerifyReport(r.DeliveryReport, r.ExecutorPublicKey)
		if e != nil || d.State != "imported" {
			return msi.ErrUnavailable
		}
		p := msi.Permit{Version: msi.Version, Kind: "readiness", TransferID: r.TransferID, Binding: m.binding, LeafDigest: c.LeafDigest, Package: r.Artifact.Package, NativeAcceptanceDigest: r.Artifact.NativeAcceptanceDigest, ActorID: actor, IssuedAt: n, ExpiresAt: min(n+60, r.Grant.ExpiresAt, c.LeafNotAfter), Sequence: sequence, MaintenanceUntil: min(n+600, r.Grant.ExpiresAt, c.LeafNotAfter), PackageReviewAccepted: true, TermsAccepted: true}
		r.ReadinessPermit, e = msi.SignPermit(p, m.key)
		if e == nil {
			r.ReadinessClaimedAt = 0
			r.ReadinessReport = nil
		}
		return e
	})
	return e
}
func (m *Manager) Approve(ctx context.Context, actor, readinessDigest string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ack || !msi.ValidDigest(readinessDigest) {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "install", func(r *msi.Record, c msi.Current, n int64) error {
		if !r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged {
			return msi.ErrAuthority
		}
		if len(r.InstallPermit) != 0 {
			return msi.ErrConsumed
		}
		ready, e := msi.VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
		rp, pe := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
		if e != nil || pe != nil || ready.State != "ready" || msi.Digest(r.ReadinessReport) != readinessDigest || rp.ActorID != actor {
			return msi.ErrConflict
		}
		if n >= rp.ExpiresAt || n < ready.CapturedAt || n-ready.CapturedAt > 60 {
			return msi.ErrExpired
		}
		p := rp
		p.Kind = "install"
		p.LeafDigest = c.LeafDigest
		p.IssuedAt = n
		p.ExpiresAt = min(rp.ExpiresAt, ready.CapturedAt+60, c.LeafNotAfter, r.Grant.ExpiresAt)
		p.ReadinessDigest = readinessDigest
		r.InstallPermit, e = msi.SignPermit(p, m.key)
		return e
	})
	return e
}
func (m *Manager) Poll(ctx context.Context) (msi.PollResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out msi.PollResponse
	var actor, kind string
	var deadline int64
	ctx = msi.WithFinalCheck(ctx, func() error {
		if actor != "" && !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		if deadline != 0 && m.now().Unix() >= deadline {
			return msi.ErrExpired
		}
		return nil
	})
	_, e := m.transaction(ctx, "", "", func(r *msi.Record, c msi.Current, n int64) error {
		var raw []byte
		var claim *int64
		if len(r.DeliveryPermit) != 0 && len(r.DeliveryReport) == 0 {
			raw = r.DeliveryPermit
			claim = &r.DeliveryClaimedAt
		} else if len(r.ReadinessPermit) != 0 && r.ReadinessClaimedAt == 0 {
			raw = r.ReadinessPermit
			claim = &r.ReadinessClaimedAt
		} else if len(r.InstallPermit) != 0 && r.InstallClaimedAt == 0 {
			raw = r.InstallPermit
			claim = &r.InstallClaimedAt
		} else {
			return nil
		}
		p, e := msi.VerifyPermit(raw, r.PublicKey)
		if e != nil {
			return e
		}
		actor, kind = p.ActorID, p.Kind
		deadline = p.ExpiresAt
		if !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		if n >= p.ExpiresAt || p.ExpiresAt > c.LeafNotAfter || p.LeafDigest != c.LeafDigest {
			return msi.ErrExpired
		}
		if kind != "deliver" && (!r.Grant.InstallEnabled || !r.Grant.InstallAcknowledged) {
			return msi.ErrAuthority
		}
		if *claim == 0 {
			*claim = n
		}
		out.Permit = bytes.Clone(raw)
		return nil
	})
	if e != nil {
		return msi.PollResponse{}, e
	}
	return out, nil
}
func (m *Manager) Chunk(ctx context.Context, q msi.ChunkRequest) (msi.Chunk, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var p msi.Permit
	var actor string
	check := func() error {
		_, e := m.transaction(ctx, "", "", func(r *msi.Record, c msi.Current, n int64) error {
			var e error
			p, e = msi.VerifyPermit(r.DeliveryPermit, r.PublicKey)
			if e != nil || r.DeliveryClaimedAt == 0 || len(r.DeliveryReport) != 0 || q.TransferID != r.TransferID || q.PermitDigest != msi.Digest(r.DeliveryPermit) || q.Index >= msi.MaxChunks || int64(q.Index)*msi.MaxChunkBytes >= p.Package.Size {
				return msi.ErrInvalid
			}
			actor = p.ActorID
			if !m.allowed(actor, "deliver") {
				return msi.ErrAuthority
			}
			if n >= p.ExpiresAt || p.ExpiresAt > c.LeafNotAfter || p.LeafDigest != c.LeafDigest {
				return msi.ErrExpired
			}
			return nil
		})
		return e
	}
	ctx = msi.WithFinalCheck(ctx, func() error {
		if actor != "" && !m.allowed(actor, "deliver") {
			return msi.ErrAuthority
		}
		if p.ExpiresAt != 0 && m.now().Unix() >= p.ExpiresAt {
			return msi.ErrExpired
		}
		return nil
	})
	if e := check(); e != nil {
		return msi.Chunk{}, e
	}
	data, e := m.spool.ReadChunk(ctx, p.Package, q.Index, check)
	if e != nil {
		return msi.Chunk{}, e
	}
	if e = check(); e != nil {
		return msi.Chunk{}, e
	}
	return msi.Chunk{TransferID: q.TransferID, Index: q.Index, PermitDigest: q.PermitDigest, Digest: msi.Digest(data), Data: data}, nil
}
func (m *Manager) Report(ctx context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, e := m.transaction(ctx, "", "", func(r *msi.Record, _ msi.Current, n int64) error {
		report, e := msi.VerifyReport(raw, r.ExecutorPublicKey)
		if e != nil || report.Binding != m.binding || report.TransferID != r.TransferID || r.Artifact == nil || report.Package != r.Artifact.Package || report.NativeAcceptanceDigest != r.Artifact.NativeAcceptanceDigest || report.CapturedAt > n {
			return msi.ErrAuthority
		}
		var dest *[]byte
		var permit []byte
		var claim int64
		switch report.Kind {
		case "delivery":
			dest = &r.DeliveryReport
			permit = r.DeliveryPermit
			claim = r.DeliveryClaimedAt
		case "readiness":
			dest = &r.ReadinessReport
			permit = r.ReadinessPermit
			claim = r.ReadinessClaimedAt
		case "result":
			dest = &r.ResultReport
			permit = r.InstallPermit
			claim = r.InstallClaimedAt
		default:
			return msi.ErrInvalid
		}
		if len(*dest) != 0 {
			if bytes.Equal(*dest, raw) {
				return nil
			}
			return msi.ErrConsumed
		}
		p, e := msi.VerifyPermit(permit, r.PublicKey)
		if e != nil || claim == 0 || report.CapturedAt < claim || report.PermitDigest != msi.Digest(permit) {
			return msi.ErrAuthority
		}
		if report.Kind != "result" && !(report.Kind == "delivery" && report.State == "intervention_required") && (n >= p.ExpiresAt || report.CapturedAt >= p.ExpiresAt) {
			return msi.ErrExpired
		}
		if report.Kind == "result" && (report.Result.JobID != "software_"+strings.TrimPrefix(r.TransferID, "transfer_") || report.Result.EnvelopeDigest != report.PermitDigest) {
			return msi.ErrAuthority
		}
		*dest = bytes.Clone(raw)
		return nil
	})
	return e
}

type View struct {
	Version                string         `json:"version"`
	DeviceID               string         `json:"deviceId"`
	ServerNow              int64          `json:"serverNow"`
	State                  string         `json:"state"`
	Package                *msi.Selection `json:"package"`
	NativeAcceptanceDigest string         `json:"nativeAcceptanceDigest"`
	TransferID             string         `json:"transferId"`
	ReadinessDigest        string         `json:"readinessDigest"`
	ExpiresAt              int64          `json:"expiresAt"`
	Readiness              *msi.Readiness `json:"readiness"`
	Result                 *msi.Result    `json:"result"`
	UploadOffset           int64          `json:"uploadOffset"`
	UploadPendingDigest    string         `json:"uploadPendingDigest"`
	CanReview              bool           `json:"canReview"`
}

func (m *Manager) View(ctx context.Context) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var v View
	_, e := m.transaction(ctx, "", "", func(r *msi.Record, _ msi.Current, n int64) error {
		v = View{Version: msi.Version, DeviceID: m.binding.DeviceID, ServerNow: n, State: "empty", TransferID: r.TransferID}
		if r.Artifact != nil {
			p := r.Artifact.Package
			v.Package = &p
			v.UploadOffset = r.Artifact.Offset
			v.UploadPendingDigest = r.Artifact.PendingDigest
			v.NativeAcceptanceDigest = r.Artifact.NativeAcceptanceDigest
			v.State = "upload_incomplete"
			if r.Artifact.CompletedAt != 0 {
				v.State = "uploaded"
			}
		}
		if len(r.DeliveryPermit) != 0 {
			v.State = "delivery_pending"
			p, _ := msi.VerifyPermit(r.DeliveryPermit, r.PublicKey)
			v.ExpiresAt = p.ExpiresAt
		}
		if len(r.DeliveryReport) != 0 {
			report, _ := msi.VerifyReport(r.DeliveryReport, r.ExecutorPublicKey)
			v.State = report.State
			v.CanReview = report.State == "imported" && len(r.InstallPermit) == 0
		}
		if len(r.ReadinessPermit) != 0 {
			v.State = "readiness_pending"
			p, _ := msi.VerifyPermit(r.ReadinessPermit, r.PublicKey)
			v.ExpiresAt = p.ExpiresAt
			v.CanReview = v.CanReview && n >= p.ExpiresAt
		}
		if len(r.ReadinessReport) != 0 {
			report, _ := msi.VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
			v.Readiness = report.Readiness
			v.ReadinessDigest = msi.Digest(r.ReadinessReport)
			v.State = report.State
		}
		if len(r.InstallPermit) != 0 {
			v.State = "approved"
		}
		if r.InstallClaimedAt != 0 {
			v.State = "claimed"
		}
		if len(r.ResultReport) != 0 {
			report, _ := msi.VerifyReport(r.ResultReport, r.ExecutorPublicKey)
			v.Result = report.Result
			v.State = "complete"
		}
		if v.ExpiresAt != 0 && n >= v.ExpiresAt {
			if v.State == "claimed" || v.State == "delivery_pending" && r.DeliveryClaimedAt != 0 || v.State == "readiness_pending" && r.ReadinessClaimedAt != 0 {
				v.State = "intervention_required"
			} else if v.State == "delivery_pending" || v.State == "readiness_pending" || v.State == "ready" || v.State == "approved" {
				v.State = "expired"
			}
		}
		return nil
	})
	if e != nil {
		return View{}, e
	}
	return v, nil
}

// CheckRelease is the final small transaction after serialization/storage waits.
// It never creates or retries a claim, permit, chunk, installation or report.
func (m *Manager) CheckRelease(ctx context.Context, raw []byte, deliveryDigest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var actor, kind string
	var deadline, floor int64
	ctx = msi.WithFinalCheck(ctx, func() error {
		if actor != "" && !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		if deadline != 0 && m.now().Unix() >= deadline {
			return msi.ErrExpired
		}
		return nil
	})
	committed, e := m.transaction(ctx, "", "", func(r *msi.Record, c msi.Current, n int64) error {
		deadline = min(r.Grant.ExpiresAt, c.LeafNotAfter)
		floor = max(n, r.ClockFloor, c.LeafNotBefore)
		if deliveryDigest != "" {
			if deliveryDigest != msi.Digest(r.DeliveryPermit) || len(r.DeliveryReport) != 0 {
				return msi.ErrConflict
			}
			raw = r.DeliveryPermit
		}
		if len(raw) == 0 {
			return nil
		}
		p, e := msi.VerifyPermit(raw, r.PublicKey)
		if e != nil {
			return e
		}
		actor, kind = p.ActorID, p.Kind
		deadline = min(deadline, p.ExpiresAt)
		if !m.allowed(actor, kind) || p.Binding != r.Grant.Binding {
			return msi.ErrAuthority
		}
		if n >= p.ExpiresAt || p.ExpiresAt > c.LeafNotAfter || p.LeafDigest != c.LeafDigest {
			return msi.ErrExpired
		}
		return nil
	})
	if e != nil {
		return e
	}
	// The transaction may wait in UPDATE, validation or COMMIT after its final
	// callback. Recheck non-storage authority after it returns, then sample the
	// live clock last. Refusal never rolls back or reconstructs an existing claim.
	if e = m.configurationCheck(); e != nil {
		return e
	}
	if e = msi.CheckFinal(ctx); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	floor = max(floor, committed.ClockFloor)
	fresh := m.now().Unix()
	if fresh < floor || deadline == 0 || fresh >= deadline {
		return msi.ErrExpired
	}
	return nil
}
