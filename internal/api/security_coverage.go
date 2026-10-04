package api

import (
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/offlinecatalog"
	"localrmm/internal/operational"
	"net/http"
	"strings"
	"time"
)

type inventoryCoverage struct {
	Coverage          string     `json:"coverage"`
	Freshness         string     `json:"freshness"`
	ReportedItemCount *uint64    `json:"reportedItemCount"`
	InstalledCount    *uint64    `json:"installedCount"`
	ObservedCount     *uint64    `json:"observedCount"`
	CountExact        bool       `json:"countExact"`
	Truncated         bool       `json:"truncated"`
	CollectedAt       *time.Time `json:"collectedAt"`
	GenerationID      *string    `json:"generationId"`
	Scope             string     `json:"scope"`
	OriginAssurance   string     `json:"originAssurance"`
}
type catalogCoverage struct {
	Configured      bool    `json:"configured"`
	Revision        string  `json:"revision"`
	SHA256          *string `json:"sha256"`
	OriginAssurance string  `json:"originAssurance"`
	Freshness       string  `json:"freshness"`
}
type offeredCoverage struct {
	Coverage     string  `json:"coverage"`
	OfferedCount *uint64 `json:"offeredCount"`
	Reason       string  `json:"reason"`
}
type vulnerabilityCoverage struct {
	Coverage         string   `json:"coverage"`
	AffectedCVEs     *uint64  `json:"affectedCves"`
	ReviewCandidates *uint64  `json:"reviewCandidates"`
	ReasonCodes      []string `json:"reasonCodes"`
}
type securityCoverageView struct {
	SchemaVersion    string                `json:"schemaVersion"`
	DeviceID         string                `json:"deviceId"`
	ServerNow        time.Time             `json:"serverNow"`
	MaxAgeSeconds    int64                 `json:"maxAgeSeconds"`
	ReceivedAt       *time.Time            `json:"receivedAt"`
	CollectionStatus string                `json:"collectionStatus"`
	Inventory        inventoryCoverage     `json:"inventory"`
	Catalog          catalogCoverage       `json:"catalog"`
	OfferedUpdates   offeredCoverage       `json:"offeredUpdates"`
	Vulnerabilities  vulnerabilityCoverage `json:"vulnerabilities"`
}

// projectSecurityCoverage reports only facts present in the stored observation.
// No binary-name-to-source-package guess, OS-label parsing, vendor trust upgrade,
// vulnerability matching or offered-update decision is performed here.
func projectSecurityCoverage(source enrollmentstore.OperationalView, catalog offlinecatalog.View) securityCoverageView {
	v := securityCoverageView{SchemaVersion: "tracebolt.security-coverage.v1", DeviceID: source.DeviceID, ServerNow: source.ServerNow, MaxAgeSeconds: source.MaxAgeSeconds, ReceivedAt: source.ReceivedAt, CollectionStatus: source.Status,
		Inventory:       inventoryCoverage{Coverage: "unknown", Freshness: "unknown", Scope: "reported-installed-binary-packages", OriginAssurance: "unverified"},
		Catalog:         catalogCoverage{Configured: catalog.Catalog != nil, Revision: catalog.Revision, OriginAssurance: "unverified", Freshness: "unknown"},
		OfferedUpdates:  offeredCoverage{Coverage: "unknown", Reason: "native_update_adapter_unimplemented"},
		Vulnerabilities: vulnerabilityCoverage{Coverage: "unknown", ReasonCodes: []string{"advisory_snapshot_unavailable", "source_package_mapping_unavailable", "client_release_unverified", "installed_artifact_origin_unverified"}},
	}
	if catalog.Catalog != nil {
		digest := catalog.Catalog.SHA256
		v.Catalog.SHA256 = &digest
		v.Vulnerabilities.ReasonCodes[0] = "advisory_authority_unverified"
	}
	var section *operational.SoftwareSection
	retained := false
	if source.Snapshot != nil {
		candidate := source.Snapshot.Sections.Software
		if candidate.Meta.Quality == operational.Healthy || candidate.Meta.Quality == "stale" {
			section = &candidate
		}
	}
	if section == nil && source.LastGood.Software != nil && (source.LastGood.Software.Meta.Quality == operational.Healthy || source.LastGood.Software.Meta.Quality == "stale") {
		copy := *source.LastGood.Software
		section = &copy
		retained = true
	}
	if section == nil {
		return v
	}
	// Defensive view validation does not reinterpret an invalid section as empty.
	check := *section
	check.Meta.Quality = operational.Healthy
	if operational.ValidateSoftwareSection(check) != nil {
		return v
	}
	m := section.Meta
	n := uint64(len(section.Items))
	observed := m.ObservedCount
	at := m.ObservedAt
	generation := m.GenerationID
	v.Inventory.Coverage = "partial"
	v.Inventory.Freshness = "stale"
	v.Inventory.ReportedItemCount = &n
	v.Inventory.ObservedCount = &observed
	v.Inventory.CountExact = m.CountExact
	v.Inventory.Truncated = m.Truncated
	v.Inventory.CollectedAt = &at
	v.Inventory.GenerationID = &generation
	if m.Complete && m.CountExact && !m.Truncated && observed == n {
		v.Inventory.Coverage = "observed"
		total := n
		v.Inventory.InstalledCount = &total
	}
	if !retained && m.Quality == operational.Healthy && source.Status == "fresh" && source.ReceivedAt != nil && !source.ServerNow.Before(*source.ReceivedAt) && !source.ServerNow.Before(at) && source.ServerNow.Sub(at) <= time.Duration(source.MaxAgeSeconds)*time.Second && source.ServerNow.Sub(*source.ReceivedAt) <= time.Duration(source.MaxAgeSeconds)*time.Second {
		v.Inventory.Freshness = "fresh"
	}
	return v
}
func (s *Server) securityCoverage(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "security" || !validID(parts[3]) {
		fail(w, 404, "not_found", "Device not found.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
		return
	}
	s.mu.RLock()
	provider := s.lanOperational
	s.mu.RUnlock()
	catalog, _, now := s.catalogState()
	view := enrollmentstore.EmptyOperationalView(parts[3], now)
	if provider != nil {
		actual, e := provider(r.Context(), parts[3], now)
		if errors.Is(e, enrollmentstate.ErrNotFound) {
			fail(w, 404, "not_found", "Device not found.")
			return
		}
		if errors.Is(e, enrollmentstore.ErrOperationalBusy) || errors.Is(e, enrollmentstore.ErrBusy) {
			w.Header().Set("Retry-After", "2")
			fail(w, 429, "storage_busy", "Stored coverage is busy; retry shortly.")
			return
		}
		if e != nil {
			s.internal(w)
			return
		}
		view = actual
	} else {
		devices, e := s.devices()
		if e != nil {
			s.internal(w)
			return
		}
		found := false
		for _, d := range devices {
			if d.ID == parts[3] {
				found = true
				break
			}
		}
		if !found {
			fail(w, 404, "not_found", "Device not found.")
			return
		}
	}
	projected := projectSecurityCoverage(view, catalog.View(view.ServerNow))
	s.mu.RLock()
	packageProfile := s.aiCollectionProfile == enrollmentcrypto.CollectionProfilePackages
	s.mu.RUnlock()
	if packageProfile {
		projected.Vulnerabilities.ReasonCodes[1] = "source_package_mapping_not_assessed"
		projected.Vulnerabilities.ReasonCodes[2] = "client_release_not_assessed"
	}
	write(w, 200, projected)
}
