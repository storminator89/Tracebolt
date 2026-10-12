package windowsmanagedmsimanager

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	"strconv"
)

func (m *ArtifactManager) Catalogue() bool { return m != nil && m.spool != nil && m.spool.catalogue }
func (m *Manager) Catalogue() bool         { return m != nil && m.artifact.Catalogue() }
func (r *Registry) Catalogue() bool        { return r != nil && r.artifact.Catalogue() }
func (m *ArtifactManager) spoolFor(r msi.ArtifactRecord) (*Spool, error) {
	if !m.Catalogue() {
		if r.Catalogue() {
			return nil, msi.ErrIntegrity
		}
		return m.spool, nil
	}
	if !r.Catalogue() || r.CatalogueSlot == nil || int(*r.CatalogueSlot) >= len(m.spool.slots) {
		return nil, msi.ErrIntegrity
	}
	return m.spool.slots[*r.CatalogueSlot], nil
}
func (m *ArtifactManager) catalogueContext(ctx context.Context, actor string) (context.Context, error) {
	if !m.Catalogue() || ctx == nil {
		return ctx, msi.ErrUnavailable
	}
	check := func() error {
		if e := m.check(); e != nil {
			return e
		}
		if !enrollmentcrypto.ValidID(actor, "operator_") || m.deliveryAllowed == nil || !m.deliveryAllowed(actor) {
			return msi.ErrAuthority
		}
		return nil
	}
	if e := check(); e != nil {
		return ctx, e
	}
	return msi.WithFinalCheck(ctx, check), nil
}
func (m *ArtifactManager) ReserveCatalogueUpload(ctx context.Context, actor, revision string, selection msi.Selection, native, status, evidence string) error {
	ctx, e := m.catalogueContext(ctx, actor)
	if e != nil {
		return e
	}
	rev, e := occurrenceNumber(revision)
	if e != nil || rev == 0 {
		return msi.ErrInvalid
	}
	store, ok := m.store.(msi.CatalogueStore)
	if !ok {
		return msi.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return msi.ErrUncertain
	}
	_, e = store.ReserveWindowsMSICatalogue(ctx, m.key, m.now(), rev, msi.Artifact{Package: selection, NativeAcceptanceDigest: native, PublisherStatus: status, PublisherEvidenceDigest: evidence})
	if e == msi.ErrUncertain || e == msi.ErrIntegrity {
		m.failed = true
	}
	return e
}

type CatalogueView struct {
	Version                 string         `json:"version"`
	Enabled                 bool           `json:"enabled"`
	ServerNow               int64          `json:"serverNow"`
	Revision                string         `json:"revision"`
	MaxEntries              int            `json:"maxEntries"`
	MaxRetainedPayloadBytes int64          `json:"maxRetainedPayloadBytes"`
	ReservedBytes           int64          `json:"reservedBytes"`
	Entries                 []ArtifactView `json:"entries"`
}

func (r *Registry) CatalogueView(ctx context.Context) (CatalogueView, error) {
	out := CatalogueView{Version: msi.CatalogueVersion, Revision: "0", MaxEntries: msi.MaxCatalogueEntries, MaxRetainedPayloadBytes: msi.MaxRetainedPayloadBytes, Entries: []ArtifactView{}}
	if !r.Catalogue() {
		return out, nil
	}
	out.ServerNow = r.artifact.now().Unix()
	store, ok := r.artifact.store.(msi.CatalogueStore)
	if !ok {
		return out, msi.ErrUnavailable
	}
	r.artifact.mu.Lock()
	if r.artifact.failed {
		r.artifact.mu.Unlock()
		return out, msi.ErrUncertain
	}
	record, e := store.ReadWindowsMSICatalogue(msi.WithFinalCheck(ctx, r.artifact.check), r.artifact.key)
	r.artifact.mu.Unlock()
	if e != nil {
		return out, e
	}
	if out.ServerNow < record.ClockFloor {
		return out, msi.ErrExpired
	}
	out.Enabled = true
	out.Revision = strconv.FormatUint(record.Revision, 10)
	out.ReservedBytes = record.ReservedBytes()
	for _, entry := range record.Entries {
		v, e := r.artifactViewRecord(ctx, entry)
		if e != nil {
			return out, e
		}
		out.Entries = append(out.Entries, v)
		out.ServerNow = max(out.ServerNow, v.ServerNow)
	}
	return out, msi.CheckFinal(ctx)
}
