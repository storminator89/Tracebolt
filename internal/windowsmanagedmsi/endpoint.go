package windowsmanagedmsi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/keyvalidation"
	fence "localrmm/internal/windowsmutationfence"
	prepared "localrmm/internal/windowssoftwarejob"
)

// Storage is the separate installer-only, pinned, atomically durable namespace.
// A failed write must poison it. Opening never creates missing used state.
type Storage interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Verify() error
}

// Payload owns the exact managed file/ancestors. Open verifies the complete
// acknowledged prefix and permits only the pending chunk's identical tail.
// Append syncs bytes before returning; Complete verifies hash and native metadata.
// No method takes an external path, URL, filename or arbitrary property.
type Payload interface {
	Create(context.Context, Selection) (json.RawMessage, error)
	Open(context.Context, json.RawMessage, int64, string, *ChunkIntent) error
	Append(context.Context, int64, []byte) (string, error)
	Complete(context.Context, Selection) (json.RawMessage, error)
	Close() error
}

// Installer keeps custody on one owner thread through the fixed native call.
// It must invoke CheckInstallStart immediately before the native dispatch.
type Installer interface {
	Inspect(context.Context, json.RawMessage, Selection, int64) (Readiness, error)
	Install(context.Context, json.RawMessage, Readiness) (NativeResult, error)
}
type CurrentCheck func(context.Context, Binding) (Current, error)

type ChunkIntent struct {
	Index  uint32 `json:"index"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
}
type EndpointRecord struct {
	Mutation            *fence.Roster   `json:"mutation,omitempty"`
	MutationCompletion  *fence.Receipt  `json:"mutationCompletion,omitempty"`
	Version             string          `json:"version"`
	Grant               Grant           `json:"grant"`
	ManagerPublicKey    []byte          `json:"managerPublicKey"`
	ExecutorPublicKey   []byte          `json:"executorPublicKey"`
	ClockFloor          int64           `json:"clockFloor"`
	Delivery            []byte          `json:"delivery,omitempty"`
	CreationStarted     bool            `json:"creationStarted"`
	Custody             json.RawMessage `json:"custody,omitempty"`
	Offset              int64           `json:"offset"`
	PrefixDigest        string          `json:"prefixDigest"`
	Pending             *ChunkIntent    `json:"pending,omitempty"`
	FinalizationStarted bool            `json:"finalizationStarted"`
	ImportReceipt       json.RawMessage `json:"importReceipt,omitempty"`
	InterventionReport  []byte          `json:"interventionReport,omitempty"`
	DeliveryReport      []byte          `json:"deliveryReport,omitempty"`
	ReadinessPermit     []byte          `json:"readinessPermit,omitempty"`
	ReadinessReport     []byte          `json:"readinessReport,omitempty"`
	InstallPermit       []byte          `json:"installPermit,omitempty"`
	Attempted           bool            `json:"attempted"`
	ResultReport        []byte          `json:"resultReport,omitempty"`
}

func NewEndpointRecord(g Grant, manager, executor []byte, at int64) (EndpointRecord, error) {
	r := EndpointRecord{Version: Version, Grant: g, ManagerPublicKey: bytes.Clone(manager), ExecutorPublicKey: bytes.Clone(executor), ClockFloor: at, PrefixDigest: Digest(nil)}
	return r, r.Validate()
}
func (r EndpointRecord) Validate() error {
	if r.validateMutationCompletion() != nil {
		return ErrIntegrity
	}
	if !(r.Version == Version && r.Mutation == nil && r.Grant.MutationPlanDigest == "" || r.Version == CoordinatedEndpointVersion && ValidMutationRoster(r.Mutation, r.Grant)) || r.Grant.Validate() != nil || !keyvalidation.Ed25519(r.ManagerPublicKey) || !keyvalidation.Ed25519(r.ExecutorPublicKey) || Digest(r.ManagerPublicKey) != r.Grant.Binding.KeyID || Digest(r.ExecutorPublicKey) != r.Grant.Binding.ExecutorKeyID || !ValidTime(r.ClockFloor) || !ValidDigest(r.PrefixDigest) || len(r.Custody) > 4096 || len(r.ImportReceipt) > 4096 {
		return ErrIntegrity
	}
	if len(r.Delivery) == 0 {
		if r.CreationStarted || r.FinalizationStarted || r.Custody != nil || r.Offset != 0 || r.Pending != nil || r.ImportReceipt != nil || r.DeliveryReport != nil || r.InterventionReport != nil || r.ReadinessPermit != nil || r.ReadinessReport != nil || r.InstallPermit != nil || r.Attempted || r.ResultReport != nil {
			return ErrIntegrity
		}
		return nil
	}
	p, e := VerifyPermit(r.Delivery, r.ManagerPublicKey)
	if e != nil || p.Kind != "deliver" || p.Binding != r.Grant.Binding || !r.CreationStarted || p.IssuedAt > r.ClockFloor || r.Offset < 0 || r.Offset > p.Package.Size || r.Offset != p.Package.Size && r.Offset%MaxChunkBytes != 0 {
		return ErrIntegrity
	}
	if r.Offset > 0 && r.Custody == nil || r.Pending != nil && (r.Custody == nil || r.Pending.Index >= MaxChunks || int64(r.Pending.Index)*MaxChunkBytes != r.Offset || r.Pending.Size != int(min(int64(MaxChunkBytes), p.Package.Size-r.Offset)) || !ValidDigest(r.Pending.Digest)) {
		return ErrIntegrity
	}
	if r.FinalizationStarted && (r.Custody == nil || r.Offset != p.Package.Size || r.Pending != nil || r.ImportReceipt != nil || len(r.DeliveryReport) > 0) {
		return ErrIntegrity
	}
	if r.ImportReceipt != nil && (r.Offset != p.Package.Size || r.Pending != nil || r.PrefixDigest != p.Package.SHA256) {
		return ErrIntegrity
	}
	if len(r.InterventionReport) > 0 {
		v, e := VerifyReport(r.InterventionReport, r.ExecutorPublicKey)
		if e != nil || v.Kind != "delivery" || v.State != "intervention_required" || v.Binding != p.Binding || v.TransferID != p.TransferID || v.PermitDigest != Digest(r.Delivery) || v.Package != p.Package || v.Offset != r.Offset || v.NativeAcceptanceDigest != p.NativeAcceptanceDigest || v.CapturedAt > r.ClockFloor || r.ImportReceipt != nil || len(r.ReadinessPermit) > 0 || len(r.InstallPermit) > 0 {
			return ErrIntegrity
		}
	}
	if len(r.DeliveryReport) > 0 {
		v, e := VerifyReport(r.DeliveryReport, r.ExecutorPublicKey)
		if e != nil || v.Kind != "delivery" || v.State != "imported" || v.Binding != p.Binding || v.TransferID != p.TransferID || v.PermitDigest != Digest(r.Delivery) || v.Package != p.Package || r.ImportReceipt == nil || v.CapturedAt > r.ClockFloor {
			return ErrIntegrity
		}
	}
	if len(r.ReadinessPermit) > 0 {
		q, e := VerifyPermit(r.ReadinessPermit, r.ManagerPublicKey)
		if e != nil || q.Kind != "readiness" || !samePackage(q, p) || len(r.DeliveryReport) == 0 || q.IssuedAt > r.ClockFloor {
			return ErrIntegrity
		}
		if len(r.ReadinessReport) > 0 {
			v, e := VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
			if e != nil || v.Kind != "readiness" || v.PermitDigest != Digest(r.ReadinessPermit) || v.Package != p.Package || v.Binding != p.Binding || v.TransferID != p.TransferID || v.CapturedAt > r.ClockFloor {
				return ErrIntegrity
			}
		}
	} else if len(r.ReadinessReport) > 0 {
		return ErrIntegrity
	}
	if len(r.InstallPermit) > 0 {
		q, e := VerifyPermit(r.InstallPermit, r.ManagerPublicKey)
		if e != nil || q.Kind != "install" || !samePackage(q, p) || len(r.ReadinessReport) == 0 || q.ReadinessDigest != Digest(r.ReadinessReport) || q.IssuedAt > r.ClockFloor {
			return ErrIntegrity
		}
	} else if r.Attempted || len(r.ResultReport) > 0 {
		return ErrIntegrity
	}
	if len(r.ResultReport) > 0 {
		v, e := VerifyReport(r.ResultReport, r.ExecutorPublicKey)
		if e != nil || v.Kind != "result" || v.PermitDigest != Digest(r.InstallPermit) || v.Result.Attempted != r.Attempted || v.Package != p.Package || v.Binding != p.Binding || v.TransferID != p.TransferID || v.CapturedAt > r.ClockFloor {
			return ErrIntegrity
		}
	}
	return nil
}
func samePackage(a, b Permit) bool {
	return a.TransferID == b.TransferID && a.Binding == b.Binding && a.Package == b.Package && a.NativeAcceptanceDigest == b.NativeAcceptanceDigest
}

type Endpoint struct {
	mutation           *fence.Session
	mutationCapability *fence.Capability
	mu                 sync.Mutex
	store              Storage
	payload            Payload
	installer          Installer
	current            CurrentCheck
	now                func() time.Time
	key                ed25519.PrivateKey
	record             EndpointRecord
	raw                []byte
	failed, running    bool
	done               chan struct{}
}

func OpenEndpoint(store Storage, payload Payload, installer Installer, current CurrentCheck, key ed25519.PrivateKey, now func() time.Time) (*Endpoint, error) {
	return openEndpoint(store, payload, installer, current, key, now, nil)
}
func OpenCoordinatedEndpoint(store Storage, payload Payload, installer Installer, current CurrentCheck, key ed25519.PrivateKey, now func() time.Time, mutation *fence.Session) (*Endpoint, error) {
	if mutation == nil {
		return nil, ErrAuthority
	}
	return openEndpoint(store, payload, installer, current, key, now, mutation)
}
func openEndpoint(store Storage, payload Payload, installer Installer, current CurrentCheck, key ed25519.PrivateKey, now func() time.Time, mutation *fence.Session) (*Endpoint, error) {
	if store == nil || payload == nil || installer == nil || current == nil || now == nil || !validPrivate(key) {
		return nil, ErrInvalid
	}
	raw, e := store.Read("endpoint.json")
	var r EndpointRecord
	if e != nil || Canonical(raw, &r, MaxRecordBytes) != nil || r.Validate() != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), r.ExecutorPublicKey) {
		return nil, ErrIntegrity
	}
	if r.Mutation == nil && mutation != nil || r.Mutation != nil && (mutation == nil || !mutation.Matches(*r.Mutation, fence.ManagedMSI)) {
		return nil, ErrAuthority
	}
	x := &Endpoint{mutation: mutation, store: store, payload: payload, installer: installer, current: current, key: bytes.Clone(key), now: now, record: r, raw: bytes.Clone(raw)}
	if e = x.check(context.Background(), nil); e != nil {
		x.Close()
		return nil, e
	}
	if r.MutationCompletion != nil {
		if e = x.mutation.Recover(context.Background(), *r.MutationCompletion, x.verifyMutationCompletion); e != nil {
			x.Close()
			return nil, e
		}
	}
	if len(r.Delivery) > 0 {
		if len(r.InterventionReport) > 0 {
			return x, nil
		}
		if r.Custody == nil || r.FinalizationStarted {
			_ = x.markIntervention()
			return x, nil
		}
		if r.ImportReceipt == nil {
			if e = payload.Open(context.Background(), r.Custody, r.Offset, r.PrefixDigest, r.Pending); e != nil {
				_ = x.markIntervention()
				return x, nil
			}
		}
	}
	if len(r.Delivery) > 0 && r.ImportReceipt == nil && r.Custody != nil && r.Pending == nil && !r.FinalizationStarted {
		p, _ := VerifyPermit(r.Delivery, r.ManagerPublicKey)
		if r.Offset == p.Package.Size {
			if e = x.finish(context.Background(), p); e != nil && len(x.record.InterventionReport) == 0 {
				_ = x.markIntervention()
			}
		}
	}
	// A process restart cannot reconstruct an execution capability. Even an
	// admitted-but-not-attempted install is intervention-required, never resumed.
	return x, nil
}
func (x *Endpoint) Close() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.failed = true
	clear(x.key)
	if !x.running {
		_ = x.payload.Close()
	}
}
func (x *Endpoint) check(ctx context.Context, p *Permit) error {
	if x.failed || ctx == nil || ctx.Err() != nil || x.store.Verify() != nil {
		return ErrUncertain
	}
	raw, e := x.store.Read("endpoint.json")
	if e != nil || !bytes.Equal(raw, x.raw) {
		x.failed = true
		return ErrIntegrity
	}
	c, e := x.current(ctx, x.record.Grant.Binding)
	if e != nil {
		return e
	}
	n := x.now().UTC().Unix()
	g := x.record.Grant
	if g.Validate() != nil || !g.DeliveryEnabled || !c.Enabled || c.Revoked || c.Binding != g.Binding || !ValidDigest(c.LeafDigest) || !ValidTime(n) || n < x.record.ClockFloor || n < c.LeafNotBefore || n >= c.LeafNotAfter || n >= g.ExpiresAt {
		return ErrAuthority
	}
	if p != nil && (p.Binding != g.Binding || n < p.IssuedAt || n >= p.ExpiresAt || p.ExpiresAt > g.ExpiresAt || p.ExpiresAt > c.LeafNotAfter || p.LeafDigest != c.LeafDigest || p.Kind != "deliver" && !g.InstallEnabled) {
		return ErrExpired
	}
	return ctx.Err()
}
func (x *Endpoint) save() error {
	x.record.ClockFloor = max(x.record.ClockFloor, x.now().UTC().Unix())
	if x.record.Validate() != nil {
		x.failed = true
		return ErrIntegrity
	}
	raw, e := json.Marshal(x.record)
	if e != nil || len(raw) > MaxRecordBytes || x.store.Write("endpoint.json", raw) != nil {
		x.failed = true
		return ErrUncertain
	}
	x.raw = raw
	return nil
}
func (x *Endpoint) report(p Permit, raw []byte, kind, state string, r *Readiness, result *Result) ([]byte, error) {
	v := Report{Version: Version, Kind: kind, Binding: p.Binding, TransferID: p.TransferID, PermitDigest: Digest(raw), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: x.now().UTC().Unix(), Offset: x.record.Offset, State: state, Readiness: r, Result: result}
	if r != nil {
		v.CapturedAt = r.CapturedAt
	}
	if result != nil {
		v.CapturedAt = result.CompletedAt
	}
	return SignReport(v, x.key)
}
func (x *Endpoint) Accept(ctx context.Context, raw []byte) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, e := VerifyPermit(raw, x.record.ManagerPublicKey)
	if e != nil {
		return e
	}
	if e = x.check(ctx, &p); e != nil {
		return e
	}
	if x.mutation != nil && p.Kind != "deliver" && p.SynchronousReviewDigest != SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest) {
		return ErrAuthority
	}
	if len(x.record.InterventionReport) > 0 {
		return ErrConsumed
	}
	switch p.Kind {
	case "deliver":
		if len(x.record.Delivery) > 0 {
			if bytes.Equal(raw, x.record.Delivery) {
				return nil
			}
			return ErrConsumed
		}
		x.record.Delivery = bytes.Clone(raw)
		x.record.CreationStarted = true
		if e = x.save(); e != nil {
			return e
		}
		if e = x.check(ctx, &p); e != nil {
			return e
		}
		receipt, e := x.payload.Create(ctx, p.Package)
		if e != nil {
			return x.markIntervention()
		}
		x.record.Custody = bytes.Clone(receipt)
		if e = x.save(); e != nil {
			return e
		}
		return x.check(ctx, &p)
	case "readiness":
		if x.record.ImportReceipt == nil || len(x.record.DeliveryReport) == 0 || len(x.record.InstallPermit) > 0 {
			return ErrConsumed
		}
		delivery, _ := VerifyPermit(x.record.Delivery, x.record.ManagerPublicKey)
		if !samePackage(p, delivery) {
			return ErrAuthority
		}
		if len(x.record.ReadinessPermit) > 0 {
			old, _ := VerifyPermit(x.record.ReadinessPermit, x.record.ManagerPublicKey)
			if p.Sequence <= old.Sequence {
				if bytes.Equal(raw, x.record.ReadinessPermit) && len(x.record.ReadinessReport) > 0 {
					return nil
				}
				return ErrConsumed
			}
		}
		x.record.ReadinessPermit = bytes.Clone(raw)
		x.record.ReadinessReport = nil
		if e = x.save(); e != nil {
			return e
		}
		if e = x.check(ctx, &p); e != nil {
			return e
		}
		ready, e := x.installer.Inspect(ctx, x.record.ImportReceipt, p.Package, p.MaintenanceUntil)
		if e != nil {
			return e
		}
		if e = x.check(ctx, &p); e != nil {
			return e
		}
		report, e := x.report(p, raw, "readiness", ready.Reason(), &ready, nil)
		if e != nil {
			return e
		}
		x.record.ReadinessReport = report
		if e = x.save(); e != nil {
			return e
		}
		return x.check(ctx, &p)
	case "install":
		if len(x.record.InstallPermit) > 0 {
			return ErrConsumed
		}
		if len(x.record.ReadinessReport) == 0 || p.ReadinessDigest != Digest(x.record.ReadinessReport) {
			return ErrAuthority
		}
		q, _ := VerifyPermit(x.record.ReadinessPermit, x.record.ManagerPublicKey)
		ready, e := VerifyReport(x.record.ReadinessReport, x.record.ExecutorPublicKey)
		if e != nil || !samePackage(p, q) || p.Sequence != q.Sequence || p.MaintenanceUntil != q.MaintenanceUntil || p.ExpiresAt > q.ExpiresAt || p.SynchronousReviewDigest != q.SynchronousReviewDigest || ready.Readiness == nil || ready.State != "ready" {
			return ErrAuthority
		}
		x.record.InstallPermit = bytes.Clone(raw)
		if e = x.save(); e != nil {
			return e
		}
		if e = x.check(ctx, &p); e != nil {
			return e
		}
		if x.mutation != nil {
			capability, err := x.mutation.Reserve(ctx, mutationOwner(p, raw))
			if err != nil {
				return x.finishBlocked(p, raw)
			}
			x.mutationCapability = capability
			// Reserve is a protected transaction; recheck authority after it closes.
			if err = x.check(ctx, &p); err != nil {
				return err
			}
		}
		// Admission and attempted markers are separate durable writes. Neither can
		// be resumed on restart. A live goroutine alone owns the native capability.
		x.record.Attempted = true
		if e = x.save(); e != nil {
			return e
		}
		if e = x.check(ctx, &p); e != nil {
			return e
		}
		if x.mutation != nil {
			if e = x.mutation.Dispatch(ctx, x.mutationCapability); e != nil {
				return e
			}
			if e = x.check(ctx, &p); e != nil {
				return e
			}
		}
		x.running = true
		x.done = make(chan struct{})
		go x.install(p, bytes.Clone(raw), *ready.Readiness)
		return nil
	}
	return ErrInvalid
}
func (x *Endpoint) Chunk(ctx context.Context, c Chunk) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, e := VerifyPermit(x.record.Delivery, x.record.ManagerPublicKey)
	if e != nil || c.Validate(p) != nil || c.PermitDigest != Digest(x.record.Delivery) {
		return ErrInvalid
	}
	if e = x.check(ctx, &p); e != nil {
		return e
	}
	if x.record.ImportReceipt != nil || len(x.record.InterventionReport) > 0 {
		return ErrConsumed
	}
	offset := int64(c.Index) * MaxChunkBytes
	// A lost acknowledgement can repeat only the exact already-written chunk.
	if offset < x.record.Offset {
		if offset+int64(len(c.Data)) != x.record.Offset {
			return ErrConflict
		}
		_, e = x.payload.Append(ctx, offset, c.Data)
		if e != nil {
			return x.markIntervention()
		}
		return x.check(ctx, &p)
	}
	if offset != x.record.Offset {
		return ErrConflict
	}
	intent := ChunkIntent{c.Index, c.Digest, len(c.Data)}
	if x.record.Pending != nil && *x.record.Pending != intent {
		return ErrConflict
	}
	if x.record.Pending == nil {
		x.record.Pending = &intent
		if e = x.save(); e != nil {
			return e
		}
	}
	if e = x.check(ctx, &p); e != nil {
		return e
	}
	digest, e := x.payload.Append(ctx, offset, c.Data)
	if e != nil {
		return x.markIntervention()
	}
	x.record.Offset += int64(len(c.Data))
	x.record.PrefixDigest = digest
	x.record.Pending = nil
	if e = x.save(); e != nil {
		return e
	}
	if e = x.check(ctx, &p); e != nil {
		return e
	}
	if x.record.Offset == p.Package.Size {
		if digest != p.Package.SHA256 {
			return x.markIntervention()
		}
		return x.finish(ctx, p)
	}
	return nil
}
func (x *Endpoint) install(p Permit, raw []byte, ready Readiness) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, startKey{}, func(c context.Context) error {
		x.mu.Lock()
		defer x.mu.Unlock()
		if !x.running || !x.record.Attempted || !bytes.Equal(raw, x.record.InstallPermit) {
			return ErrAuthority
		}
		if x.mutation != nil && nativeInstallStart(c) {
			return x.mutation.CheckStart(c, x.mutationCapability, func() error { return x.check(c, &p) })
		}
		return x.check(c, &p)
	})
	native, e := x.installer.Install(ctx, x.record.ImportReceipt, ready)
	x.mu.Lock()
	defer x.mu.Unlock()
	defer func() { x.running = false; close(x.done) }()
	n := x.now().UTC().Unix()
	r := Result{JobID: "software_" + p.TransferID[len("transfer_"):], EnvelopeDigest: Digest(raw), Attempted: true, Outcome: "uncertain", ReturnCodeKnown: native.ReturnCodeKnown, ReturnCode: native.ReturnCode, RegistrationVerified: native.RegistrationVerified, CompletedAt: n}
	if e == nil {
		switch {
		case native.ReturnCode == 0 && native.RegistrationVerified == Yes:
			r.Outcome = "succeeded"
		case native.ReturnCode == 3010:
			r.Outcome = "restart_required"
		case native.ReturnCode == 1641:
			r.Outcome = "unexpected_restart"
		case native.ReturnCode == 1618:
			r.Outcome = "busy"
		case native.ReturnCode != 0:
			r.Outcome = "failed"
		}
	}
	if !r.ReturnCodeKnown {
		r.ReturnCode = 0
	}
	if r.RegistrationVerified != Yes && r.RegistrationVerified != No {
		r.RegistrationVerified = Unknown
	}
	// Native completion can outlive its admission deadline. Keep the original
	// completion fact durably; retrieval never re-signs with a newer timestamp.
	if !ValidTime(n) || n < x.record.ClockFloor {
		x.failed = true
		return
	}
	report, err := x.report(p, raw, "result", r.Outcome, nil, &r)
	if err != nil {
		x.failed = true
		return
	}
	x.record.ResultReport = report
	if x.mutation != nil && e == nil && r.ReturnCodeKnown && r.Outcome != "uncertain" && r.Outcome != "unexpected_restart" && (r.ReturnCode != 3010 || r.RegistrationVerified == Yes) {
		receipt, err := x.mutationCapability.Completion(Digest(report), "completed", r.CompletedAt)
		if err != nil {
			x.failed = true
			return
		}
		x.record.MutationCompletion = &receipt
	}
	if x.save() != nil {
		return
	}
	if x.record.MutationCompletion != nil {
		_ = x.mutation.Complete(context.Background(), x.mutationCapability, *x.record.MutationCompletion, x.verifyMutationCompletion)
	}
}
func (x *Endpoint) Status(ctx context.Context) (Status, error) {
	s := Status{Version: Version, State: "awaiting_delivery"}
	if x == nil {
		return s, ErrUnavailable
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.check(ctx, nil); e != nil {
		if x.failed {
			s.State = "intervention_required"
			s.Attempted = x.record.Attempted
			return s, nil
		}
		return s, e
	}
	r := x.record
	if len(r.Delivery) == 0 {
		return s, nil
	}
	p, _ := VerifyPermit(r.Delivery, r.ManagerPublicKey)
	if x.mutation != nil {
		snapshot, e := x.mutation.Status(ctx)
		if e != nil {
			return s, e
		}
		captured := x.now().UTC().Unix()
		if e = x.check(ctx, nil); e != nil {
			return s, e
		}
		report := Report{Version: Version, Kind: "mutation", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: Digest(r.Delivery), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: captured, Offset: r.Offset, State: snapshot.Phase, Mutation: &snapshot}
		s.MutationReport, e = SignReport(report, x.key)
		if e != nil {
			return s, e
		}
	}
	s.TransferID = p.TransferID
	s.PermitDigest = Digest(r.Delivery)
	s.NextChunk = uint32((r.Offset + MaxChunkBytes - 1) / MaxChunkBytes)
	s.State = "receiving"
	s.Attempted = r.Attempted
	if len(r.InterventionReport) > 0 {
		s.State = "intervention_required"
		s.Report = bytes.Clone(r.InterventionReport)
		return s, nil
	}
	if r.Custody == nil {
		s.State = "intervention_required"
	}
	if r.ImportReceipt != nil {
		s.State = "imported"
		s.Report = bytes.Clone(r.DeliveryReport)
	}
	if len(r.ReadinessPermit) > 0 {
		s.State = "readiness_pending"
		s.Report = bytes.Clone(r.ReadinessReport)
	}
	if len(r.InstallPermit) > 0 {
		s.State = "intervention_required"
		s.Report = nil
		if x.running {
			s.State = "installing"
		}
	}
	if len(r.ResultReport) > 0 {
		s.Report = bytes.Clone(r.ResultReport)
		v, _ := VerifyReport(s.Report, r.ExecutorPublicKey)
		s.State = v.State
	}
	return s, nil
}

type startKey struct{}

func CheckInstallStart(ctx context.Context, at time.Time) error {
	if ctx == nil || !ValidTime(at.Unix()) {
		return ErrAuthority
	}
	f, ok := ctx.Value(startKey{}).(func(context.Context) error)
	if !ok {
		return ErrAuthority
	}
	return f(ctx)
}

// SameReadinessFacts does not turn observation freshness into package authority.
func SameReadinessFacts(a, b Readiness) bool { return prepared.SameFacts(a, b) }

// Wait preserves the attempt ledger and owned process until its bounded worker returns. It never cancels or retries MSI.
func (x *Endpoint) Wait() {
	x.mu.Lock()
	done := x.done
	running := x.running
	x.mu.Unlock()
	if running && done != nil {
		<-done
	}
}

func (x *Endpoint) finish(ctx context.Context, p Permit) error {
	if e := x.check(ctx, &p); e != nil {
		return e
	}
	if x.record.FinalizationStarted {
		return ErrUncertain
	}
	x.record.FinalizationStarted = true
	if e := x.save(); e != nil {
		return e
	}
	if e := x.check(ctx, &p); e != nil {
		return e
	}
	receipt, e := x.payload.Complete(ctx, p.Package)
	if e != nil {
		return x.markIntervention()
	}
	if e = x.check(ctx, &p); e != nil {
		return x.markIntervention()
	}
	x.record.FinalizationStarted = false
	x.record.ImportReceipt = receipt
	report, e := x.report(p, x.record.Delivery, "delivery", "imported", nil, nil)
	if e != nil {
		return e
	}
	x.record.DeliveryReport = report
	if e = x.save(); e != nil {
		return e
	}
	return x.check(ctx, &p)
}

// markIntervention reports only an already established local delivery failure.
// A trusted original record and current local grant are required. A poisoned or
// uncertain storage write cannot manufacture durable terminal evidence.
func (x *Endpoint) markIntervention() error {
	if x.failed {
		return ErrUncertain
	}
	if e := x.check(context.Background(), nil); e != nil {
		x.failed = true
		return ErrUncertain
	}
	if len(x.record.InterventionReport) > 0 {
		return ErrUncertain
	}
	p, e := VerifyPermit(x.record.Delivery, x.record.ManagerPublicKey)
	if e != nil || len(x.record.ImportReceipt) > 0 {
		x.failed = true
		return ErrIntegrity
	}
	report, e := x.report(p, x.record.Delivery, "delivery", "intervention_required", nil, nil)
	if e != nil {
		x.failed = true
		return ErrIntegrity
	}
	x.record.InterventionReport = report
	if e = x.save(); e != nil {
		return e
	}
	return ErrUncertain
}

// CheckNativeInstallStart is the one final native-dispatch gate. Adapters may
// call CheckInstallStart during preparation; only the call immediately before
// MsiInstallProduct consumes coordinated native admission.
type nativeInstallStartKey struct{}

func nativeInstallStart(ctx context.Context) bool { return ctx.Value(nativeInstallStartKey{}) == true }
func CheckNativeInstallStart(ctx context.Context, at time.Time) error {
	if ctx == nil {
		return ErrAuthority
	}
	return CheckInstallStart(context.WithValue(ctx, nativeInstallStartKey{}, true), at)
}
