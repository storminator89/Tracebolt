package windowsmanagedmsimanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	"sort"
	"strconv"
	"time"
)

type WorklistRow struct {
	DeviceID          string      `json:"deviceId"`
	Available         bool        `json:"available"`
	State             string      `json:"state"`
	View              *View       `json:"view,omitempty"`
	HistoricalOutcome string      `json:"historicalOutcome,omitempty"`
	HistoricalResult  *msi.Result `json:"historicalResult,omitempty"`
}
type WorklistView struct {
	msi.Worklist
	ServerNow int64         `json:"serverNow"`
	Rows      []WorklistRow `json:"rows"`
}
type WorklistsView struct {
	Version   string         `json:"version"`
	ServerNow int64          `json:"serverNow"`
	Enabled   bool           `json:"enabled"`
	Worklists []WorklistView `json:"worklists"`
}
type SaveWorklistTarget struct {
	DeviceID      string `json:"deviceId"`
	BindingDigest string `json:"bindingDigest"`
	Name          string `json:"name"`
}
type SaveWorklistRequest struct {
	Name                 string               `json:"name"`
	ArtifactID           string               `json:"artifactId"`
	ArtifactRetiredCount string               `json:"artifactRetiredCount"`
	Targets              []SaveWorklistTarget `json:"targets"`
	Group                msi.WorklistGroup    `json:"group"`
}
type WorklistExcluded struct {
	DeviceID string `json:"deviceId"`
	Reason   string `json:"reason"`
}
type WorklistPreview struct {
	WorklistID string                `json:"worklistId"`
	Revision   uint64                `json:"revision"`
	Kind       string                `json:"kind"`
	Items      []msi.WorklistRequest `json:"items"`
	Excluded   []WorklistExcluded    `json:"excluded"`
}
type ConfirmWorklistBatch struct {
	Revision         uint64                       `json:"revision"`
	Kind             string                       `json:"kind"`
	Items            []msi.WorklistRequest        `json:"items"`
	Acknowledgements msi.WorklistAcknowledgements `json:"acknowledgements"`
}
type WorklistSession struct {
	ActorID, Digest string
	ExpiresAt       int64
}

func worklistID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", msi.ErrUncertain
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func (r *Registry) worklistStore() (msi.WorklistStore, error) {
	if r == nil || len(r.ordered) == 0 || r.artifact == nil || !r.artifact.Reusable() {
		return nil, msi.ErrUnavailable
	}
	s, ok := r.ordered[0].store.(msi.WorklistStore)
	if !ok {
		return nil, msi.ErrUnavailable
	}
	return s, nil
}
func (r *Registry) worklistContext(ctx context.Context, actor, kind string) (context.Context, error) {
	if ctx == nil || r == nil || len(r.ordered) == 0 || !enrollmentcrypto.ValidID(actor, "operator_") {
		return ctx, msi.ErrAuthority
	}
	check := func() error {
		for _, m := range r.ordered {
			if m.configurationCheck() == nil {
				continue
			}
			return msi.ErrAuthority
		}
		m := r.ordered[0]
		if kind == "read" {
			if !m.allowed(actor, "deliver") && !m.allowed(actor, "install") {
				return msi.ErrAuthority
			}
		} else if !m.allowed(actor, kind) {
			return msi.ErrAuthority
		}
		return nil
	}
	if e := check(); e != nil {
		return ctx, e
	}
	return msi.WithFinalCheck(ctx, check), nil
}
func (r *Registry) worklistRead(ctx context.Context, actor string) (msi.WorklistJournal, error) {
	s, e := r.worklistStore()
	if e != nil {
		return msi.WorklistJournal{}, e
	}
	ctx, e = r.worklistContext(ctx, actor, "read")
	if e != nil {
		return msi.WorklistJournal{}, e
	}
	return s.ReadWindowsMSIWorklists(ctx, r.artifact.key)
}
func worklistMatches(w msi.Worklist, rec msi.Record, t msi.WorklistTarget) bool {
	return rec.Grant.Binding == t.Binding && rec.Grant.Reusable() && rec.Artifact != nil && rec.ArtifactRetiredCount == w.ArtifactRetiredCount && msi.ArtifactIdentity(*rec.Artifact) == w.ArtifactID && rec.TransferID == t.TransferID && rec.Jobs != nil && rec.Jobs.Sequence == t.JobSequence
}

type worklistEvidence struct {
	record msi.Record
	err    error
}

// Per-response metadata snapshots avoid re-reading each registry row for every
// archived worklist. No payload or acknowledgement is cached between requests.
func (r *Registry) worklistView(ctx context.Context, w msi.Worklist, cache map[string]worklistEvidence) WorklistView {
	out := WorklistView{Worklist: w, ServerNow: r.artifact.now().Unix(), Rows: []WorklistRow{}}
	for _, t := range w.Targets {
		row := WorklistRow{DeviceID: t.Binding.DeviceID, State: "unavailable"}
		m := r.Manager(t.Binding.DeviceID)
		if m == nil || m.Binding() != t.Binding {
			out.Rows = append(out.Rows, row)
			continue
		}
		pin := msi.BindingDigest(t.Binding)
		evidence, found := cache[pin]
		if !found {
			evidence.record, evidence.err = m.store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, m.configurationCheck), t.Binding, m.key.Public().(ed25519.PublicKey))
			cache[pin] = evidence
		}
		saved, e := evidence.record, evidence.err
		if e != nil {
			out.Rows = append(out.Rows, row)
			continue
		}
		if t.TransferID != "" && saved.Jobs != nil {
			for _, old := range saved.Jobs.Recent {
				if old.TransferID == t.TransferID && old.Sequence == t.JobSequence && old.Package == w.Package && old.NativeAcceptanceDigest == w.NativeAcceptanceDigest && old.PublisherStatus == w.PublisherStatus && old.PublisherEvidenceDigest == w.PublisherEvidenceDigest {
					row.HistoricalOutcome = old.Outcome
					row.State = "historical"
				}
			}
		}
		exact := worklistMatches(w, saved, t)
		if exact && len(saved.ResultReport) != 0 {
			if result, err := msi.VerifyReport(saved.ResultReport, saved.ExecutorPublicKey); err == nil && result.Result != nil {
				row.HistoricalResult = result.Result
				row.State = "historical"
			}
		}
		if w.ArchivedAt != 0 {
			out.Rows = append(out.Rows, row)
			continue
		}
		v, e := m.View(msi.WithCatalogueOccurrence(ctx, w.ArtifactRetiredCount))
		if e != nil {
			row.State = "unavailable"
			out.Rows = append(out.Rows, row)
			continue
		}
		unassigned := t.TransferID == "" && v.TransferID == "" && v.ArtifactID != nil && *v.ArtifactID == w.ArtifactID && v.ArtifactRetiredCount == strconv.FormatUint(w.ArtifactRetiredCount, 10)
		if w.ArchivedAt == 0 && (exact || unassigned) && v.ArtifactID != nil && *v.ArtifactID == w.ArtifactID && v.ArtifactRetiredCount == strconv.FormatUint(w.ArtifactRetiredCount, 10) {
			row.HistoricalResult = nil
			row.Available = true
			row.State = v.State
			row.View = &v
			if unassigned {
				row.State = "not_dispatched"
			}
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}
func (r *Registry) Worklists(ctx context.Context, actor string) (WorklistsView, error) {
	out := WorklistsView{Version: msi.WorklistVersion, Worklists: []WorklistView{}}
	if r != nil && r.artifact != nil {
		out.ServerNow = r.artifact.now().Unix()
	}
	j, e := r.worklistRead(ctx, actor)
	if errors.Is(e, msi.ErrUnavailable) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	out.Version = j.Version
	out.Enabled = true
	cache := map[string]worklistEvidence{}
	for _, w := range j.Worklists {
		out.Worklists = append(out.Worklists, r.worklistView(ctx, w, cache))
	}
	return out, msi.CheckFinal(ctx)
}
func (r *Registry) Worklist(ctx context.Context, actor, id string) (WorklistView, error) {
	j, e := r.worklistRead(ctx, actor)
	if e != nil {
		return WorklistView{}, e
	}
	w := j.Find(id)
	if w == nil {
		return WorklistView{}, msi.ErrUnavailable
	}
	out := r.worklistView(ctx, *w, map[string]worklistEvidence{})
	return out, msi.CheckFinal(ctx)
}
func (r *Registry) worklistWrite(ctx context.Context, actor, kind string, bindings []msi.Binding, fn func(*msi.WorklistJournal, msi.ArtifactRecord, map[string]msi.Record, time.Time) error) (msi.WorklistJournal, error) {
	s, e := r.worklistStore()
	if e != nil {
		return msi.WorklistJournal{}, e
	}
	ctx, e = r.worklistContext(ctx, actor, kind)
	if e != nil {
		return msi.WorklistJournal{}, e
	}
	return s.WindowsMSIWorklistTransaction(ctx, r.artifact.key, r.artifact.now(), bindings, fn)
}
func (r *Registry) SaveWorklist(ctx context.Context, actor string, q SaveWorklistRequest) (WorklistView, error) {
	if !msi.WorklistText(q.Name, 120) || len(q.Targets) == 0 || len(q.Targets) > msi.MaxDevices || !msi.ValidDigest(q.ArtifactID) {
		return WorklistView{}, msi.ErrInvalid
	}
	occ, e := occurrenceNumber(q.ArtifactRetiredCount)
	if e != nil {
		return WorklistView{}, e
	}
	id, e := worklistID("worklist_")
	if e != nil {
		return WorklistView{}, e
	}
	targets := append([]SaveWorklistTarget(nil), q.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].DeviceID < targets[j].DeviceID })
	bindings := []msi.Binding{}
	previous := ""
	for _, t := range targets {
		m := r.Manager(t.DeviceID)
		if m == nil || t.DeviceID <= previous || msi.BindingDigest(m.Binding()) != t.BindingDigest || !msi.WorklistText(t.Name, 120) {
			return WorklistView{}, msi.ErrInvalid
		}
		bindings = append(bindings, m.Binding())
		previous = t.DeviceID
	}
	ctx = msi.WithCatalogueOccurrence(ctx, occ)
	_, e = r.worklistWrite(ctx, actor, "read", bindings, func(j *msi.WorklistJournal, a msi.ArtifactRecord, records map[string]msi.Record, at time.Time) error {
		for _, w := range j.Worklists {
			if w.ArchivedAt == 0 && (j.Version != msi.CatalogueWorklistVersion || w.ArtifactRetiredCount == occ) {
				return msi.ErrConflict
			}
		}
		if len(j.Worklists) >= msi.MaxWorklists && !pruneArchivedWorklist(j, records) {
			return msi.ErrConsumed
		}
		if a.Artifact == nil || a.Artifact.CompletedAt == 0 || a.RetirementStarted || a.Retired || a.RetiredCount != occ || msi.ArtifactIdentity(*a.Artifact) != q.ArtifactID {
			return msi.ErrConflict
		}
		w := msi.Worklist{ID: id, Revision: 1, Name: q.Name, CreatedBy: actor, CreatedAt: at.Unix(), ArtifactID: q.ArtifactID, ArtifactRetiredCount: occ, Package: a.Artifact.Package, NativeAcceptanceDigest: a.Artifact.NativeAcceptanceDigest, PublisherStatus: a.Artifact.PublisherStatus, PublisherEvidenceDigest: a.Artifact.PublisherEvidenceDigest, Group: q.Group, Targets: []msi.WorklistTarget{}, Batches: []msi.WorklistBatch{}}
		for i, t := range targets {
			rec := records[t.DeviceID]
			wt := msi.WorklistTarget{Name: t.Name, Binding: bindings[i]}
			if rec.Artifact != nil && rec.ArtifactRetiredCount == occ && msi.ArtifactIdentity(*rec.Artifact) == q.ArtifactID && rec.TransferID != "" {
				wt.TransferID = rec.TransferID
				wt.JobSequence = rec.Jobs.Sequence
			}
			w.Targets = append(w.Targets, wt)
		}
		if w.Validate() != nil {
			return msi.ErrInvalid
		}
		j.Worklists = append(j.Worklists, w)
		return nil
	})
	if e != nil {
		return WorklistView{}, e
	}
	return r.Worklist(ctx, actor, id)
}
func worklistEligible(w msi.Worklist, t msi.WorklistTarget, v View, kind string, now int64) string {
	if v.ArtifactID == nil || *v.ArtifactID != w.ArtifactID || v.BindingDigest != msi.BindingDigest(t.Binding) || v.ArtifactRetiredCount != strconv.FormatUint(w.ArtifactRetiredCount, 10) {
		return "changed"
	}
	if kind == "deliver" {
		if t.TransferID == "" && v.TransferID == "" && v.State == "uploaded" {
			return ""
		}
		return "not_eligible"
	}
	if t.TransferID == "" || v.TransferID != t.TransferID || v.JobSequence != strconv.FormatUint(t.JobSequence, 10) {
		return "changed"
	}
	if (kind == "review" || kind == "approve") && v.Schedule != nil {
		return "not_eligible"
	}
	if kind == "review" {
		if v.CanReview {
			return ""
		}
		return "not_eligible"
	}
	if kind == "retire" {
		if v.State != "complete" {
			return "not_eligible"
		}
		if !msi.ValidDigest(v.ResultDigest) || !msi.SettledResult(msi.Report{Kind: "result", Result: v.Result}) {
			return "unsettled"
		}
		if now >= v.GrantExpiresAt {
			return "expired"
		}
		if v.Mutation == nil || !v.Mutation.Active || v.Mutation.Blocked || v.Mutation.Phase != "idle" || v.MutationCapturedAt > now || now-v.MutationCapturedAt >= 60 {
			return "busy"
		}
		if !v.CanRetire {
			return "not_eligible"
		}
		return ""
	}
	if kind != "approve" {
		return "not_eligible"
	}
	if v.State != "ready" || !msi.ValidDigest(v.ReadinessDigest) {
		return "not_eligible"
	}
	if now >= v.ExpiresAt {
		return "expired"
	}
	if v.Mutation == nil || !v.Mutation.Active || v.Mutation.Blocked || v.Mutation.Phase != "idle" || v.MutationCapturedAt > now || now-v.MutationCapturedAt >= 60 {
		return "busy"
	}
	return ""
}
func (r *Registry) PreviewWorklist(ctx context.Context, actor, id string, revision uint64, kind string) (WorklistPreview, error) {
	out := WorklistPreview{WorklistID: id, Revision: revision, Kind: kind, Items: []msi.WorklistRequest{}, Excluded: []WorklistExcluded{}}
	if kind != "deliver" && kind != "review" && kind != "approve" && kind != "retire" {
		return out, msi.ErrInvalid
	}
	j, e := r.worklistRead(ctx, actor)
	if e != nil {
		return out, e
	}
	w := j.Find(id)
	if w == nil || w.Revision != revision || w.ArchivedAt != 0 {
		return out, msi.ErrConflict
	}
	for _, b := range w.Batches {
		if b.ClosedAt == 0 {
			return out, msi.ErrConflict
		}
	}
	for _, t := range w.Targets {
		reason := "unavailable"
		m := r.Manager(t.Binding.DeviceID)
		var v View
		if m != nil && m.Binding() == t.Binding {
			v, e = m.View(msi.WithCatalogueOccurrence(ctx, w.ArtifactRetiredCount))
			if e == nil {
				reason = worklistEligible(*w, t, v, kind, r.artifact.now().Unix())
			}
		}
		if reason != "" {
			out.Excluded = append(out.Excluded, WorklistExcluded{t.Binding.DeviceID, reason})
			continue
		}
		q := msi.WorklistRequest{DeviceID: t.Binding.DeviceID, ArtifactID: w.ArtifactID, ArtifactRetiredCount: strconv.FormatUint(w.ArtifactRetiredCount, 10), BindingDigest: msi.BindingDigest(t.Binding), TransferID: t.TransferID, ExpiresAt: min(v.GrantExpiresAt, r.artifact.now().Unix()+60)}
		if kind == "deliver" {
			q.Operation = "deliver"
			q.TransferID, e = worklistID("transfer_")
			if e != nil {
				return out, e
			}
		} else {
			q.JobSequence = strconv.FormatUint(t.JobSequence, 10)
			q.Operation = "review-coordinated"
			if kind == "approve" {
				q.Operation = "approve"
				q.ReadinessDigest = v.ReadinessDigest
				q.ExpiresAt = min(q.ExpiresAt, v.ExpiresAt)
			} else if kind == "retire" {
				q.Operation = "retire"
				q.ResultDigest = v.ResultDigest
				// Installation's earlier readiness/permit expiry is historical.
				// Cleanup reviews today's exact shared-owner status instead.
				q.ExpiresAt = min(q.ExpiresAt, v.MutationCapturedAt+60)
			}
		}
		if !q.Valid(kind) {
			return out, msi.ErrIntegrity
		}
		out.Items = append(out.Items, q)
	}
	return out, msi.CheckFinal(ctx)
}
func (r *Registry) ConfirmWorklist(ctx context.Context, sess WorklistSession, id string, q ConfirmWorklistBatch) (WorklistView, error) {
	if !q.Acknowledgements.Valid(q.Kind) || len(q.Items) == 0 || len(q.Items) > msi.MaxDevices || !msi.ValidDigest(sess.Digest) || !msi.ValidTime(sess.ExpiresAt) {
		return WorklistView{}, msi.ErrInvalid
	}
	batchID, e := worklistID("batch_")
	if e != nil {
		return WorklistView{}, e
	}
	bindings := []msi.Binding{}
	prev := ""
	for _, item := range q.Items {
		m := r.Manager(item.DeviceID)
		if !item.Valid(q.Kind) || m == nil || item.DeviceID <= prev || item.BindingDigest != msi.BindingDigest(m.Binding()) {
			return WorklistView{}, msi.ErrInvalid
		}
		bindings = append(bindings, m.Binding())
		prev = item.DeviceID
	}
	kind := "install"
	if q.Kind == "deliver" {
		kind = "deliver"
	}
	occ, err := occurrenceNumber(q.Items[0].ArtifactRetiredCount)
	if err != nil {
		return WorklistView{}, err
	}
	ctx = msi.WithCatalogueOccurrence(ctx, occ)
	_, e = r.worklistWrite(ctx, sess.ActorID, kind, bindings, func(j *msi.WorklistJournal, a msi.ArtifactRecord, records map[string]msi.Record, at time.Time) error {
		w := j.Find(id)
		if w == nil || w.Revision != q.Revision || w.ArchivedAt != 0 {
			return msi.ErrConflict
		}
		for _, b := range w.Batches {
			if b.ClosedAt == 0 {
				return msi.ErrConflict
			}
		}
		if len(w.Batches) >= msi.MaxWorklistBatches && !pruneWorklistBatch(w, records) {
			return msi.ErrConsumed
		}
		if a.Artifact == nil || a.RetirementStarted || a.Retired || msi.ArtifactIdentity(*a.Artifact) != w.ArtifactID || a.RetiredCount != w.ArtifactRetiredCount {
			return msi.ErrConflict
		}
		b := msi.WorklistBatch{ID: batchID, Kind: q.Kind, ActorID: sess.ActorID, SessionDigest: sess.Digest, SessionExpiresAt: sess.ExpiresAt, CreatedAt: at.Unix(), ExpiresAt: min(at.Unix()+60, sess.ExpiresAt), Acknowledgements: q.Acknowledgements, Items: []msi.WorklistBatchItem{}}
		for _, item := range q.Items {
			var t *msi.WorklistTarget
			for ti := range w.Targets {
				if w.Targets[ti].Binding.DeviceID == item.DeviceID {
					t = &w.Targets[ti]
				}
			}
			if t == nil || t.Binding != records[item.DeviceID].Grant.Binding || item.ArtifactID != w.ArtifactID || item.ArtifactRetiredCount != strconv.FormatUint(w.ArtifactRetiredCount, 10) || item.BindingDigest != msi.BindingDigest(t.Binding) || item.ExpiresAt <= at.Unix() || item.ExpiresAt > at.Unix()+60 {
				return msi.ErrConflict
			}
			rec := records[item.DeviceID]
			if q.Kind == "deliver" {
				if t.TransferID != "" {
					return msi.ErrConsumed
				}
				if rec.TransferID != "" {
					if !rec.Catalogue() && rec.ArtifactRetiredCount >= w.ArtifactRetiredCount || rec.Catalogue() && a.Assignment(rec.Grant.Binding) != nil {
						return msi.ErrConsumed
					}
					if _, e := msi.NextManagerJob(rec); e != nil {
						return e
					}
				}
			} else {
				if !worklistMatches(*w, rec, *t) || item.TransferID != t.TransferID || item.JobSequence != strconv.FormatUint(t.JobSequence, 10) || q.Kind != "retire" && (len(rec.InstallPermit) != 0 || rec.Schedule != nil) {
					return msi.ErrConflict
				}
				if !rec.Grant.InstallEnabled || !rec.Grant.InstallAcknowledged {
					return msi.ErrAuthority
				}
				delivery, de := msi.VerifyReport(rec.DeliveryReport, rec.ExecutorPublicKey)
				if de != nil || delivery.State != "imported" {
					return msi.ErrUnavailable
				}
				if q.Kind == "review" {
					if len(rec.ReadinessPermit) > 0 {
						p, e := msi.VerifyPermit(rec.ReadinessPermit, rec.PublicKey)
						if e != nil || at.Unix() < p.ExpiresAt {
							return msi.ErrConsumed
						}
					}
				} else if q.Kind == "retire" {
					result, e := msi.VerifyReport(rec.ResultReport, rec.ExecutorPublicKey)
					if e != nil || !msi.SettledResult(result) {
						return msi.ErrUncertain
					}
					if len(rec.RetirePermit) != 0 || item.ResultDigest != msi.Digest(rec.ResultReport) {
						return msi.ErrConflict
					}
					shared, e := msi.VerifyReport(rec.MutationReport, rec.ExecutorPublicKey)
					if e != nil || shared.Mutation == nil || !shared.Mutation.Active || shared.Mutation.Blocked || shared.Mutation.Phase != "idle" || shared.CapturedAt > at.Unix() || at.Unix()-shared.CapturedAt >= 60 {
						return msi.ErrUnavailable
					}
					if item.ExpiresAt > min(rec.Grant.ExpiresAt, shared.CapturedAt+60) {
						return msi.ErrExpired
					}
				} else {
					rp, e := msi.VerifyPermit(rec.ReadinessPermit, rec.PublicKey)
					ready, re := msi.VerifyReport(rec.ReadinessReport, rec.ExecutorPublicKey)
					if e != nil || re != nil || rp.ActorID != sess.ActorID || ready.State != "ready" || item.ReadinessDigest != msi.Digest(rec.ReadinessReport) || at.Unix() >= rp.ExpiresAt || at.Unix() < ready.CapturedAt || at.Unix()-ready.CapturedAt >= 60 || item.ExpiresAt > min(rp.ExpiresAt, ready.CapturedAt+60) {
						return msi.ErrExpired
					}
					shared, e := msi.VerifyReport(rec.MutationReport, rec.ExecutorPublicKey)
					if e != nil || shared.Mutation == nil || !shared.Mutation.Active || shared.Mutation.Blocked || shared.Mutation.Phase != "idle" || shared.CapturedAt > at.Unix() || at.Unix()-shared.CapturedAt >= 60 {
						return msi.ErrUnavailable
					}
				}
			}
			b.ExpiresAt = min(b.ExpiresAt, item.ExpiresAt, rec.Grant.ExpiresAt)
			b.Items = append(b.Items, msi.WorklistBatchItem{Request: item, State: "not_dispatched"})
		}
		if b.ExpiresAt <= b.CreatedAt {
			return msi.ErrExpired
		}
		b.ConfirmationDigest = b.Digest()
		w.Batches = append(w.Batches, b)
		w.Revision++
		return nil
	})
	if e != nil {
		return WorklistView{}, e
	}
	return r.Worklist(ctx, sess.ActorID, id)
}
func (r *Registry) CloseWorklistBatch(ctx context.Context, actor, id string, revision uint64, batchID string) (WorklistView, error) {
	_, e := r.worklistWrite(ctx, actor, "read", nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, at time.Time) error {
		w := j.Find(id)
		if w == nil || w.Revision != revision {
			return msi.ErrConflict
		}
		for i := range w.Batches {
			b := &w.Batches[i]
			if b.ID == batchID && b.ClosedAt == 0 {
				b.ClosedAt = at.Unix()
				b.CloseReason = "stopped"
				w.Revision++
				return nil
			}
		}
		return msi.ErrConflict
	})
	if e != nil {
		return WorklistView{}, e
	}
	return r.Worklist(ctx, actor, id)
}
func (r *Registry) ArchiveWorklist(ctx context.Context, actor, id string, revision uint64) (WorklistView, error) {
	_, e := r.worklistWrite(ctx, actor, "read", nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, records map[string]msi.Record, at time.Time) error {
		w := j.Find(id)
		if w == nil || w.Revision != revision || w.ArchivedAt != 0 {
			return msi.ErrConflict
		}
		for _, b := range w.Batches {
			if b.ClosedAt == 0 {
				return msi.ErrConflict
			}
		}
		archived := 0
		for _, old := range j.Worklists {
			if old.ArchivedAt != 0 {
				archived++
			}
		}
		if archived >= msi.MaxWorklists-1 {
			if !pruneArchivedWorklist(j, records) {
				return msi.ErrConsumed
			}
			w = j.Find(id)
		}
		w.ArchivedAt = at.Unix()
		w.Revision++
		return nil
	})
	if e != nil {
		return WorklistView{}, e
	}
	return r.Worklist(ctx, actor, id)
}

// This only narrows a normal, presently authenticated per-device request. It
// does not provide a permit, replay a saved body, or start a stage on the server.
func (r *Registry) BatchDispatchContext(ctx context.Context, sess WorklistSession, ref *msi.WorklistDispatchReference, q msi.WorklistRequest, acks msi.WorklistAcknowledgements) (context.Context, error) {
	if ref == nil {
		return ctx, nil
	}
	j, e := r.worklistRead(ctx, sess.ActorID)
	if e != nil {
		return ctx, e
	}
	w := j.Find(ref.WorklistID)
	if w == nil {
		return ctx, msi.ErrConflict
	}
	for _, b := range w.Batches {
		if b.ID != ref.BatchID {
			continue
		}
		if ref.Item < 0 || ref.Item >= len(b.Items) {
			return ctx, msi.ErrInvalid
		}
		q.ExpiresAt = b.Items[ref.Item].Request.ExpiresAt
		d := msi.WorklistDispatch{Reference: *ref, ActorID: sess.ActorID, SessionDigest: sess.Digest, SessionExpiresAt: sess.ExpiresAt, Request: q, Acknowledgements: acks}
		m := r.Manager(q.DeviceID)
		if m == nil {
			return ctx, msi.ErrAuthority
		}
		if _, _, _, e = j.Dispatch(d, m.Binding(), b.CreatedAt); e != nil {
			return ctx, e
		}
		return msi.WithWorklistDispatch(ctx, d), nil
	}
	return ctx, msi.ErrConflict
}

// Compaction is presentation metadata only, serialized with the same signed
// record snapshot. Unresolved evidence blocks the bound instead of being lost.
func pruneArchivedWorklist(j *msi.WorklistJournal, records map[string]msi.Record) bool {
	for i, w := range j.Worklists {
		if msi.WorklistReconciled(w, records) {
			j.Worklists = append(j.Worklists[:i], j.Worklists[i+1:]...)
			return true
		}
	}
	return false
}
func pruneWorklistBatch(w *msi.Worklist, records map[string]msi.Record) bool {
	for i, b := range w.Batches {
		if msi.WorklistBatchReconciled(*w, b, records) {
			w.Batches = append(w.Batches[:i], w.Batches[i+1:]...)
			return true
		}
	}
	return false
}
