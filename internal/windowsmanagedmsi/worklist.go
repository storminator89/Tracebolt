package windowsmanagedmsi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const WorklistVersion = "tracebolt.windows-managed-msi-worklists.v1"
const MaxWorklistRevision = uint64(9007199254740991)
const MaxWorklists = 9
const MaxWorklistBatches = 9
const MaxWorklistBytes = 256 << 10
const MaxWorklistJournalBytes = MaxWorklists*MaxWorklistBytes + 4096

// Manager metadata only. No signed grant/permit/report bytes or payload bytes
// are changed. Persisted acknowledgements are an audit, not deferred authority.
type WorklistTarget struct {
	Name        string  `json:"name"`
	Binding     Binding `json:"binding"`
	TransferID  string  `json:"transferId"`
	JobSequence uint64  `json:"jobSequence,string"`
}
type WorklistGroup struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision uint64 `json:"revision"`
}
type Worklist struct {
	ID                      string           `json:"id"`
	Revision                uint64           `json:"revision"`
	Name                    string           `json:"name"`
	CreatedBy               string           `json:"createdBy"`
	CreatedAt               int64            `json:"createdAt"`
	ArchivedAt              int64            `json:"archivedAt"`
	ArtifactID              string           `json:"artifactId"`
	ArtifactRetiredCount    uint64           `json:"artifactRetiredCount,string"`
	Package                 Selection        `json:"package"`
	NativeAcceptanceDigest  string           `json:"nativeAcceptanceDigest"`
	PublisherStatus         string           `json:"publisherStatus"`
	PublisherEvidenceDigest string           `json:"publisherEvidenceDigest"`
	Group                   WorklistGroup    `json:"group"`
	Targets                 []WorklistTarget `json:"targets"`
	Batches                 []WorklistBatch  `json:"batches"`
}
type WorklistAcknowledgements struct {
	Acknowledged              bool `json:"acknowledged"`
	PackageReviewAccepted     bool `json:"packageReviewAccepted"`
	TermsAccepted             bool `json:"termsAccepted"`
	MaintenanceAcknowledged   bool `json:"maintenanceAcknowledged"`
	SynchronousReviewAccepted bool `json:"synchronousReviewAccepted"`
}

func (a WorklistAcknowledgements) Valid(kind string) bool {
	if kind == "review" {
		return !a.Acknowledged && a.PackageReviewAccepted && a.TermsAccepted && a.MaintenanceAcknowledged && a.SynchronousReviewAccepted
	}
	return (kind == "deliver" || kind == "approve" || kind == "retire") && a.Acknowledged && !a.PackageReviewAccepted && !a.TermsAccepted && !a.MaintenanceAcknowledged && !a.SynchronousReviewAccepted
}

type WorklistRequest struct {
	DeviceID             string `json:"deviceId"`
	Operation            string `json:"operation"`
	ArtifactID           string `json:"artifactId"`
	ArtifactRetiredCount string `json:"artifactRetiredCount"`
	BindingDigest        string `json:"bindingDigest"`
	TransferID           string `json:"transferId"`
	JobSequence          string `json:"jobSequence"`
	ReadinessDigest      string `json:"readinessDigest"`
	ExpiresAt            int64  `json:"expiresAt"`
	// Retirement-only: omission preserves every existing stage's canonical bytes.
	ResultDigest string `json:"resultDigest,omitempty"`
}

func (q WorklistRequest) Valid(kind string) bool {
	n, e := strconv.ParseUint(q.ArtifactRetiredCount, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != q.ArtifactRetiredCount || !enrollmentcrypto.ValidID(q.DeviceID, "agent_") || !ValidDigest(q.ArtifactID) || !ValidDigest(q.BindingDigest) || !ValidTransferID(q.TransferID) || !ValidTime(q.ExpiresAt) {
		return false
	}
	if kind == "deliver" {
		return q.Operation == "deliver" && q.JobSequence == "" && q.ReadinessDigest == "" && q.ResultDigest == ""
	}
	seq, e := strconv.ParseUint(q.JobSequence, 10, 64)
	if e != nil || seq == 0 || strconv.FormatUint(seq, 10) != q.JobSequence {
		return false
	}
	if kind == "retire" {
		return q.Operation == "retire" && q.ReadinessDigest == "" && ValidDigest(q.ResultDigest)
	}
	return q.ResultDigest == "" && (kind == "review" && q.Operation == "review-coordinated" && q.ReadinessDigest == "" || kind == "approve" && q.Operation == "approve" && ValidDigest(q.ReadinessDigest))
}

type WorklistBatchItem struct {
	Request      WorklistRequest `json:"request"`
	State        string          `json:"state"`
	IssuedAt     int64           `json:"issuedAt"`
	PermitDigest string          `json:"permitDigest"`
	JobSequence  uint64          `json:"jobSequence,string"`
}
type WorklistBatch struct {
	ID                 string                   `json:"id"`
	Kind               string                   `json:"kind"`
	ActorID            string                   `json:"actorId"`
	SessionDigest      string                   `json:"sessionDigest"`
	SessionExpiresAt   int64                    `json:"sessionExpiresAt"`
	CreatedAt          int64                    `json:"createdAt"`
	ExpiresAt          int64                    `json:"expiresAt"`
	ClosedAt           int64                    `json:"closedAt"`
	CloseReason        string                   `json:"closeReason"`
	ConfirmationDigest string                   `json:"confirmationDigest"`
	Acknowledgements   WorklistAcknowledgements `json:"acknowledgements"`
	Items              []WorklistBatchItem      `json:"items"`
}

func (b WorklistBatch) Digest() string {
	requests := make([]WorklistRequest, len(b.Items))
	for i, v := range b.Items {
		requests[i] = v.Request
	}
	raw, _ := json.Marshal(struct {
		ID, Kind, Actor, Session       string
		SessionExpiry, Created, Expiry int64
		Acks                           WorklistAcknowledgements
		Requests                       []WorklistRequest
	}{b.ID, b.Kind, b.ActorID, b.SessionDigest, b.SessionExpiresAt, b.CreatedAt, b.ExpiresAt, b.Acknowledgements, requests})
	return Digest(append([]byte("Tracebolt exact MSI batch confirmation v1\x00"), raw...))
}

type WorklistJournal struct {
	Version    string     `json:"version"`
	ManagerID  string     `json:"managerId"`
	KeyID      string     `json:"keyId"`
	Revision   uint64     `json:"revision"`
	ClockFloor int64      `json:"clockFloor"`
	Worklists  []Worklist `json:"worklists"`
}

func WorklistText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func (w Worklist) Validate() error {
	if !enrollmentcrypto.ValidID(w.ID, "worklist_") || w.Revision == 0 || w.Revision > MaxWorklistRevision || !WorklistText(w.Name, 120) || !enrollmentcrypto.ValidID(w.CreatedBy, "operator_") || !ValidTime(w.CreatedAt) || w.ArchivedAt != 0 && (!ValidTime(w.ArchivedAt) || w.ArchivedAt < w.CreatedAt) || !ValidDigest(w.ArtifactID) || !ValidSelection(w.Package) || !ValidDigest(w.NativeAcceptanceDigest) || !ValidPublisherEvidence(w.PublisherStatus, w.PublisherEvidenceDigest) || len(w.Targets) == 0 || len(w.Targets) > MaxDevices || w.Batches == nil || len(w.Batches) > MaxWorklistBatches {
		return ErrIntegrity
	}
	if w.ArtifactID != ArtifactIdentity(Artifact{Package: w.Package, NativeAcceptanceDigest: w.NativeAcceptanceDigest, PublisherStatus: w.PublisherStatus, PublisherEvidenceDigest: w.PublisherEvidenceDigest}) {
		return ErrIntegrity
	}
	if w.Group.ID == "" {
		if w.Group.Name != "" || w.Group.Revision != 0 {
			return ErrIntegrity
		}
	} else if !WorklistText(w.Group.ID, 80) || !WorklistText(w.Group.Name, 120) || w.Group.Revision == 0 || w.Group.Revision > MaxWorklistRevision {
		return ErrIntegrity
	}
	targets := map[string]WorklistTarget{}
	prev := ""
	for _, t := range w.Targets {
		if t.Binding.Validate() != nil || !WorklistText(t.Name, 120) || t.Binding.DeviceID <= prev || (t.TransferID == "") != (t.JobSequence == 0) || t.TransferID != "" && !ValidTransferID(t.TransferID) {
			return ErrIntegrity
		}
		targets[t.Binding.DeviceID] = t
		prev = t.Binding.DeviceID
	}
	open := 0
	ids := map[string]bool{}
	for _, b := range w.Batches {
		if !enrollmentcrypto.ValidID(b.ID, "batch_") || ids[b.ID] || !enrollmentcrypto.ValidID(b.ActorID, "operator_") || !ValidDigest(b.SessionDigest) || !ValidTime(b.CreatedAt) || b.CreatedAt < w.CreatedAt || !ValidTime(b.ExpiresAt) || !ValidTime(b.SessionExpiresAt) || b.ExpiresAt <= b.CreatedAt || b.ExpiresAt > b.CreatedAt+60 || b.ExpiresAt > b.SessionExpiresAt || !b.Acknowledgements.Valid(b.Kind) || b.ConfirmationDigest != b.Digest() || len(b.Items) == 0 || len(b.Items) > len(w.Targets) {
			return ErrIntegrity
		}
		ids[b.ID] = true
		if b.ClosedAt == 0 {
			open++
			if b.CloseReason != "" {
				return ErrIntegrity
			}
		} else if !ValidTime(b.ClosedAt) || b.ClosedAt < b.CreatedAt || (b.CloseReason != "finished" && b.CloseReason != "stopped" && b.CloseReason != "rejected") {
			return ErrIntegrity
		}
		previous := ""
		pending := false
		for _, i := range b.Items {
			q := i.Request
			t, ok := targets[q.DeviceID]
			if !ok || q.DeviceID <= previous || !q.Valid(b.Kind) || q.ArtifactID != w.ArtifactID || q.ArtifactRetiredCount != strconv.FormatUint(w.ArtifactRetiredCount, 10) || q.BindingDigest != BindingDigest(t.Binding) || q.ExpiresAt < b.ExpiresAt {
				return ErrIntegrity
			}
			previous = q.DeviceID
			switch i.State {
			case "not_dispatched":
				pending = true
				if i.IssuedAt != 0 || i.PermitDigest != "" || i.JobSequence != 0 {
					return ErrIntegrity
				}
			case "issued":
				if pending || i.IssuedAt < b.CreatedAt || i.IssuedAt >= b.ExpiresAt || !ValidDigest(i.PermitDigest) || i.JobSequence == 0 || t.TransferID != q.TransferID || t.JobSequence != i.JobSequence {
					return ErrIntegrity
				}
			case "rejected":
				pending = true
				if b.CloseReason != "rejected" || i.IssuedAt != 0 || i.PermitDigest != "" || i.JobSequence != 0 {
					return ErrIntegrity
				}
			default:
				return ErrIntegrity
			}
		}
	}
	if open > 1 || w.ArchivedAt != 0 && open != 0 {
		return ErrIntegrity
	}
	raw, _ := json.Marshal(w)
	if len(raw) > MaxWorklistBytes {
		return ErrIntegrity
	}
	return nil
}
func (j WorklistJournal) Validate() error {
	if (j.Version != WorklistVersion && j.Version != CatalogueWorklistVersion) || !enrollmentcrypto.ValidID(j.ManagerID, "manager_") || !ValidDigest(j.KeyID) || j.Revision == 0 || j.Revision > MaxWorklistRevision || !ValidTime(j.ClockFloor) || j.Worklists == nil || len(j.Worklists) > MaxWorklists {
		return ErrIntegrity
	}
	ids := map[string]bool{}
	active := 0
	activeOccurrences := map[uint64]bool{}
	for _, w := range j.Worklists {
		if w.Validate() != nil || ids[w.ID] || w.CreatedAt > j.ClockFloor || w.ArchivedAt > j.ClockFloor {
			return ErrIntegrity
		}
		ids[w.ID] = true
		for _, b := range w.Batches {
			if b.CreatedAt > j.ClockFloor || b.ClosedAt > j.ClockFloor {
				return ErrIntegrity
			}
			for _, item := range b.Items {
				if item.IssuedAt > j.ClockFloor {
					return ErrIntegrity
				}
			}
		}
		if w.ArchivedAt == 0 {
			active++
			if j.Version == CatalogueWorklistVersion {
				if w.ArtifactRetiredCount == 0 || activeOccurrences[w.ArtifactRetiredCount] {
					return ErrIntegrity
				}
				activeOccurrences[w.ArtifactRetiredCount] = true
			}
		}
		for _, t := range w.Targets {
			if t.Binding.ManagerID != j.ManagerID || t.Binding.KeyID != j.KeyID {
				return ErrIntegrity
			}
		}
	}
	if j.Version == WorklistVersion && (active > 1 || len(j.Worklists)-active > MaxWorklists-1) || j.Version == CatalogueWorklistVersion && active > MaxCatalogueEntries {
		return ErrIntegrity
	}
	raw, _ := json.Marshal(j)
	if len(raw) > MaxWorklistJournalBytes {
		return ErrIntegrity
	}
	return nil
}
func DecodeWorklistJournal(raw []byte) (WorklistJournal, error) {
	var j WorklistJournal
	if Canonical(raw, &j, MaxWorklistJournalBytes) != nil || j.Validate() != nil {
		return j, ErrIntegrity
	}
	return j, nil
}
func (j *WorklistJournal) Find(id string) *Worklist {
	for i := range j.Worklists {
		if j.Worklists[i].ID == id {
			return &j.Worklists[i]
		}
	}
	return nil
}

type WorklistDispatchReference struct {
	WorklistID string `json:"worklistId"`
	BatchID    string `json:"batchId"`
	Item       int    `json:"item"`
}
type WorklistDispatch struct {
	Reference              WorklistDispatchReference
	ActorID, SessionDigest string
	SessionExpiresAt       int64
	Request                WorklistRequest
	Acknowledgements       WorklistAcknowledgements
}
type worklistDispatchKey struct{}

func WithWorklistDispatch(ctx context.Context, d WorklistDispatch) context.Context {
	return context.WithValue(ctx, worklistDispatchKey{}, d)
}
func WorklistDispatchFrom(ctx context.Context) (WorklistDispatch, bool) {
	d, ok := ctx.Value(worklistDispatchKey{}).(WorklistDispatch)
	return d, ok
}
func (j *WorklistJournal) Dispatch(d WorklistDispatch, binding Binding, now int64) (*Worklist, *WorklistBatch, *WorklistBatchItem, error) {
	w := j.Find(d.Reference.WorklistID)
	if w == nil || w.ArchivedAt != 0 {
		return nil, nil, nil, ErrConflict
	}
	for bi := range w.Batches {
		b := &w.Batches[bi]
		if b.ID != d.Reference.BatchID {
			continue
		}
		if b.ClosedAt != 0 || b.ActorID != d.ActorID || b.SessionDigest != d.SessionDigest || b.SessionExpiresAt != d.SessionExpiresAt || now < b.CreatedAt || now >= b.ExpiresAt || d.Reference.Item < 0 || d.Reference.Item >= len(b.Items) {
			return nil, nil, nil, ErrConflict
		}
		i := &b.Items[d.Reference.Item]
		if i.State != "not_dispatched" || i.Request != d.Request || b.Acknowledgements != d.Acknowledgements || i.Request.DeviceID != binding.DeviceID || i.Request.BindingDigest != BindingDigest(binding) {
			return nil, nil, nil, ErrConflict
		}
		for n := 0; n < d.Reference.Item; n++ {
			if b.Items[n].State != "issued" {
				return nil, nil, nil, ErrConflict
			}
		}
		return w, b, i, nil
	}
	return nil, nil, nil, ErrConflict
}

// FinishDispatch is called only alongside the original record's final commit.
func (j *WorklistJournal) FinishDispatch(d WorklistDispatch, before, after Record, now int64, rejected bool) error {
	w, b, i, e := j.Dispatch(d, before.Grant.Binding, now)
	if e != nil {
		return e
	}
	if rejected {
		i.State = "rejected"
		b.ClosedAt = now
		b.CloseReason = "rejected"
	} else {
		if !after.Grant.Reusable() || after.Artifact == nil || after.Jobs == nil || after.ArtifactRetiredCount != w.ArtifactRetiredCount || ArtifactIdentity(*after.Artifact) != w.ArtifactID || after.TransferID != i.Request.TransferID {
			return ErrIntegrity
		}
		if (b.Kind == "review" || b.Kind == "approve") && (before.Schedule != nil || after.Schedule != nil) {
			return ErrConsumed
		}
		var raw, old []byte
		switch b.Kind {
		case "deliver":
			raw, old = after.DeliveryPermit, before.DeliveryPermit
		case "review":
			raw, old = after.ReadinessPermit, before.ReadinessPermit
		case "approve":
			raw, old = after.InstallPermit, before.InstallPermit
		case "retire":
			raw, old = after.RetirePermit, before.RetirePermit
		}
		p, e := VerifyPermit(raw, after.PublicKey)
		if e != nil || len(raw) == 0 || Digest(raw) == Digest(old) || p.ActorID != b.ActorID || p.IssuedAt < b.CreatedAt || p.IssuedAt > now || p.TransferID != i.Request.TransferID || p.JobSequence != after.Jobs.Sequence {
			return ErrIntegrity
		}
		if b.Kind != "deliver" && i.Request.JobSequence != strconv.FormatUint(p.JobSequence, 10) || b.Kind == "approve" && p.ReadinessDigest != i.Request.ReadinessDigest || b.Kind == "retire" && (p.Kind != "retire" || p.RetireResultDigest != i.Request.ResultDigest || Digest(after.ResultReport) != i.Request.ResultDigest) {
			return ErrIntegrity
		}
		i.State = "issued"
		i.IssuedAt = p.IssuedAt
		i.PermitDigest = Digest(raw)
		i.JobSequence = p.JobSequence
		for ti := range w.Targets {
			t := &w.Targets[ti]
			if t.Binding == after.Grant.Binding {
				if t.TransferID != "" && (t.TransferID != after.TransferID || t.JobSequence != after.Jobs.Sequence) {
					return ErrIntegrity
				}
				t.TransferID = after.TransferID
				t.JobSequence = after.Jobs.Sequence
			}
		}
		if d.Reference.Item == len(b.Items)-1 {
			b.ClosedAt = now
			b.CloseReason = "finished"
		}
	}
	if w.Revision >= MaxWorklistRevision || j.Revision >= MaxWorklistRevision {
		return ErrConsumed
	}
	w.Revision++
	j.Revision++
	j.ClockFloor = max(j.ClockFloor, now)
	return j.Validate()
}

type WorklistStore interface {
	ReadWindowsMSIWorklists(context.Context, ed25519.PublicKey) (WorklistJournal, error)
	WindowsMSIWorklistTransaction(context.Context, ed25519.PublicKey, time.Time, []Binding, func(*WorklistJournal, ArtifactRecord, map[string]Record, time.Time) error) (WorklistJournal, error)
}

// Exact retirement is enough to retain the reference in the existing bounded
// MSI ledger instead of in an archived presentation record. Missing history is
// not reconstructed and never qualifies an unresolved reference for pruning.
func WorklistTargetRetired(w Worklist, t WorklistTarget, records map[string]Record) bool {
	if t.TransferID == "" {
		return true
	}
	r, ok := records[t.Binding.DeviceID]
	if !ok || r.Grant.Binding != t.Binding || r.Jobs == nil {
		return false
	}
	if worklistRecordMatches(w, t, r) && len(r.RetiredReport) > 0 {
		report, e := VerifyReport(r.RetiredReport, r.ExecutorPublicKey)
		return e == nil && report.Kind == "retired" && report.JobSequence == t.JobSequence && report.TransferID == t.TransferID
	}
	for _, old := range r.Jobs.Recent {
		if old.TransferID == t.TransferID && old.Sequence == t.JobSequence && old.Package == w.Package && old.NativeAcceptanceDigest == w.NativeAcceptanceDigest && old.PublisherStatus == w.PublisherStatus && old.PublisherEvidenceDigest == w.PublisherEvidenceDigest {
			return true
		}
	}
	return false
}
func worklistRecordMatches(w Worklist, t WorklistTarget, r Record) bool {
	return r.Grant.Binding == t.Binding && r.Grant.Reusable() && r.Artifact != nil && r.ArtifactRetiredCount == w.ArtifactRetiredCount && ArtifactIdentity(*r.Artifact) == w.ArtifactID && r.TransferID == t.TransferID && r.Jobs != nil && r.Jobs.Sequence == t.JobSequence
}
func WorklistReconciled(w Worklist, records map[string]Record) bool {
	if w.ArchivedAt == 0 {
		return false
	}
	for _, b := range w.Batches {
		if b.ClosedAt == 0 {
			return false
		}
	}
	for _, t := range w.Targets {
		if !WorklistTargetRetired(w, t, records) {
			return false
		}
	}
	return true
}
func WorklistBatchReconciled(w Worklist, b WorklistBatch, records map[string]Record) bool {
	if b.ClosedAt == 0 {
		return false
	}
	for _, item := range b.Items {
		if item.State != "issued" {
			continue
		}
		var target *WorklistTarget
		for i := range w.Targets {
			if w.Targets[i].Binding.DeviceID == item.Request.DeviceID {
				target = &w.Targets[i]
			}
		}
		if target == nil {
			return false
		}
		if b.Kind == "retire" {
			if !worklistRetirementReconciled(w, *target, item, records) {
				return false
			}
			continue
		}
		if WorklistTargetRetired(w, *target, records) {
			continue
		}
		r, ok := records[target.Binding.DeviceID]
		if !ok || !worklistRecordMatches(w, *target, r) {
			return false
		}
		switch b.Kind {
		case "deliver":
			report, e := VerifyReport(r.DeliveryReport, r.ExecutorPublicKey)
			if e != nil || report.State != "imported" || report.PermitDigest != item.PermitDigest || Digest(r.DeliveryPermit) != item.PermitDigest {
				return false
			}
		case "review":
			report, e := VerifyReport(r.ReadinessReport, r.ExecutorPublicKey)
			if e == nil && report.Kind == "readiness" && report.PermitDigest == item.PermitDigest && Digest(r.ReadinessPermit) == item.PermitDigest {
				continue
			}
			// The unchanged record transition only replaces readiness after its old
			// deadline and advances its sequence. This is the same exact job, not a
			// new installer attempt. Its target reference remains in the worklist.
			p, e := VerifyPermit(r.ReadinessPermit, r.PublicKey)
			if e != nil || p.Kind != "readiness" || p.Sequence <= 1 || p.IssuedAt <= item.IssuedAt || Digest(r.ReadinessPermit) == item.PermitDigest {
				return false
			}
		default:
			return false // An install approval remains until exact retirement.
		}
	}
	return true
}

// A cleanup request is not reconciled by an issued permit or a settled result.
// Current signed evidence must name its exact permit and reviewed result. Once
// advanced, the existing validated retirement ledger preserves that same result
// and the digest of the signed retirement report; it never reconstructs evidence.
func worklistRetirementReconciled(w Worklist, t WorklistTarget, item WorklistBatchItem, records map[string]Record) bool {
	r, ok := records[t.Binding.DeviceID]
	if !ok || r.Grant.Binding != t.Binding || r.Jobs == nil || item.Request.TransferID != t.TransferID || item.Request.JobSequence != strconv.FormatUint(t.JobSequence, 10) {
		return false
	}
	if worklistRecordMatches(w, t, r) {
		report, e := VerifyReport(r.RetiredReport, r.ExecutorPublicKey)
		return e == nil && report.Kind == "retired" && report.Binding == t.Binding && report.TransferID == t.TransferID && report.JobSequence == t.JobSequence && report.PermitDigest == item.PermitDigest && Digest(r.RetirePermit) == item.PermitDigest && report.Retirement != nil && report.Retirement.ResultDigest == item.Request.ResultDigest
	}
	for _, old := range r.Jobs.Recent {
		if old.TransferID == t.TransferID && old.Sequence == t.JobSequence && old.Package == w.Package && old.NativeAcceptanceDigest == w.NativeAcceptanceDigest && old.PublisherStatus == w.PublisherStatus && old.PublisherEvidenceDigest == w.PublisherEvidenceDigest && old.ResultDigest == item.Request.ResultDigest && ValidDigest(old.RetirementDigest) {
			return true
		}
	}
	return false
}

// Metadata may compact only fully reconciled references proven by the existing
// MSI records in this same transaction. It never changes execution/replay floors,
// a target, occurrence, confirmation, or a retained item's monotonic state.
func WorklistJournalTransition(a, b WorklistJournal, records map[string]Record) error {
	if b.Validate() != nil || a.Version != b.Version || a.ManagerID != b.ManagerID || a.KeyID != b.KeyID || b.Revision != a.Revision+1 || b.Revision == 0 || b.ClockFloor < a.ClockFloor {
		return ErrIntegrity
	}
	oldLists := map[string]bool{}
	for _, w := range a.Worklists {
		oldLists[w.ID] = true
	}
	newCount := 0
	last := -1
	for _, w := range b.Worklists {
		if !oldLists[w.ID] {
			newCount++
			continue
		}
		index := -1
		for i, old := range a.Worklists {
			if old.ID == w.ID {
				index = i
			}
		}
		if index <= last || newCount > 0 {
			return ErrIntegrity
		}
		last = index
	}
	if newCount > 1 {
		return ErrIntegrity
	}
	for _, old := range a.Worklists {
		ptr := b.Find(old.ID)
		if ptr == nil {
			if !WorklistReconciled(old, records) {
				return ErrIntegrity
			}
			continue
		}
		next := *ptr
		if reflect.DeepEqual(old, next) {
			continue
		}
		if next.Revision != old.Revision+1 || next.Revision == 0 || old.ArchivedAt != 0 && next.ArchivedAt != old.ArchivedAt || len(old.Targets) != len(next.Targets) {
			return ErrIntegrity
		}
		x, y := old, next
		x.Revision, y.Revision = 0, 0
		x.ArchivedAt, y.ArchivedAt = 0, 0
		x.Targets, y.Targets = nil, nil
		x.Batches, y.Batches = nil, nil
		if !reflect.DeepEqual(x, y) {
			return ErrIntegrity
		}
		for ti, t := range old.Targets {
			n := next.Targets[ti]
			if t.Name != n.Name || t.Binding != n.Binding || t.TransferID != "" && (t.TransferID != n.TransferID || t.JobSequence != n.JobSequence) {
				return ErrIntegrity
			}
		}
		oldBatches := map[string]bool{}
		for _, ob := range old.Batches {
			oldBatches[ob.ID] = true
		}
		newBatches := 0
		lastBatch := -1
		for _, nb := range next.Batches {
			if !oldBatches[nb.ID] {
				newBatches++
				continue
			}
			index := -1
			for i, ob := range old.Batches {
				if ob.ID == nb.ID {
					index = i
				}
			}
			if index <= lastBatch || newBatches > 0 {
				return ErrIntegrity
			}
			lastBatch = index
		}
		if newBatches > 1 {
			return ErrIntegrity
		}
		for _, ob := range old.Batches {
			var nb *WorklistBatch
			for bi := range next.Batches {
				if next.Batches[bi].ID == ob.ID {
					nb = &next.Batches[bi]
				}
			}
			if nb == nil {
				if !WorklistBatchReconciled(old, ob, records) {
					return ErrIntegrity
				}
				continue
			}
			if ob.Digest() != nb.Digest() || ob.ConfirmationDigest != nb.ConfirmationDigest || ob.ClosedAt != 0 && !reflect.DeepEqual(ob, *nb) {
				return ErrIntegrity
			}
			for ii, oi := range ob.Items {
				ni := nb.Items[ii]
				if oi.State != "not_dispatched" && !reflect.DeepEqual(oi, ni) {
					return ErrIntegrity
				}
			}
		}
	}
	return nil
}
