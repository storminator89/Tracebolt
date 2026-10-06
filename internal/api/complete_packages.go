package api

import (
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/linuxpackages"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type completeInventoryBinding struct {
	Sequence     string `json:"sequence"`
	GenerationID string `json:"generationId"`
	ManifestHash string `json:"manifestHash"`
}

func publicInventoryBinding(b enrollmentstore.InventoryBinding) completeInventoryBinding {
	return completeInventoryBinding{strconv.FormatUint(b.Sequence, 10), b.GenerationID, b.ManifestHash}
}

type completedInventoryMetadata struct {
	Binding       completeInventoryBinding `json:"binding"`
	Manifest      fullinventory.Manifest   `json:"manifest"`
	State         string                   `json:"state"`
	CompletedAt   time.Time                `json:"completedAt"`
	RetainedUntil time.Time                `json:"retainedUntil"`
}
type inventoryTransferMetadata struct {
	Binding        completeInventoryBinding `json:"binding"`
	State          string                   `json:"state"`
	DeclaredRows   uint64                   `json:"declaredRows"`
	AcceptedRows   uint64                   `json:"acceptedRows"`
	ExpectedChunks uint32                   `json:"expectedChunks"`
	AcceptedChunks uint32                   `json:"acceptedChunks"`
	CollectedAt    time.Time                `json:"collectedAt"`
	StartedAt      time.Time                `json:"startedAt"`
	ExpiresAt      time.Time                `json:"expiresAt"`
}
type inventoryFailureMetadata struct {
	Sequence     string    `json:"sequence"`
	GenerationID string    `json:"generationId"`
	AttemptedAt  time.Time `json:"attemptedAt"`
	ReceivedAt   time.Time `json:"receivedAt"`
	Reason       string    `json:"reason"`
}
type completePackageView struct {
	SchemaVersion     string                      `json:"schemaVersion"`
	DeviceID          string                      `json:"deviceId"`
	ServerNow         time.Time                   `json:"serverNow"`
	CollectionProfile string                      `json:"collectionProfile"`
	Status            string                      `json:"status"`
	Complete          *completedInventoryMetadata `json:"complete"`
	Transfer          *inventoryTransferMetadata  `json:"transfer"`
	Failure           *inventoryFailureMetadata   `json:"failure"`
}
type completePackagePage struct {
	SchemaVersion    string                     `json:"schemaVersion"`
	DeviceID         string                     `json:"deviceId"`
	ServerNow        time.Time                  `json:"serverNow"`
	Binding          completeInventoryBinding   `json:"binding"`
	CollectedAt      time.Time                  `json:"collectedAt"`
	CompletedAt      time.Time                  `json:"completedAt"`
	RetainedUntil    time.Time                  `json:"retainedUntil"`
	TotalRows        uint64                     `json:"totalRows"`
	Items            []linuxpackages.PackageRow `json:"items"`
	ScannedRows      int                        `json:"scannedRows"`
	Exhausted        bool                       `json:"exhausted"`
	SearchIncomplete bool                       `json:"searchIncomplete"`
	NextCursor       string                     `json:"nextCursor"`
	CursorExpiresAt  time.Time                  `json:"cursorExpiresAt"`
}

func completeView(in enrollmentstore.InventoryStatus) (completePackageView, error) {
	out := completePackageView{SchemaVersion: "tracebolt.complete-package-view.v1", DeviceID: in.DeviceID, ServerNow: in.ServerNow, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Status: "awaiting"}
	if in.Complete != nil {
		x := in.Complete
		hash, err := fullinventory.ManifestDigest(x.Manifest)
		if err != nil || in.CompleteBinding.Sequence == 0 || in.CompleteBinding.GenerationID != x.Manifest.GenerationID || in.CompleteBinding.ManifestHash != hash || (x.State != "complete" && x.State != "expired") {
			return completePackageView{}, enrollmentstore.ErrStorage
		}
		out.Status = "available"
		out.Complete = &completedInventoryMetadata{publicInventoryBinding(in.CompleteBinding), x.Manifest, x.State, x.CompletedAt, x.ExpiresAt}
	}
	if in.Transfer != nil {
		x := in.Transfer
		hash, err := fullinventory.ManifestDigest(x.Manifest)
		if err != nil || in.Sequence == 0 || (x.State != "pending" && x.State != "complete" && x.State != "expired" && x.State != "failed") {
			return completePackageView{}, enrollmentstore.ErrStorage
		}
		out.Transfer = &inventoryTransferMetadata{publicInventoryBinding(enrollmentstore.InventoryBinding{Sequence: in.Sequence, GenerationID: x.Manifest.GenerationID, ManifestHash: hash}), x.State, x.Manifest.ObservedCount, x.AcceptedRows, x.Manifest.ChunkCount, x.AcceptedChunks, x.Manifest.CollectedAt, x.StartedAt, x.ExpiresAt}
	}
	if in.Failure != nil {
		x := in.Failure
		out.Failure = &inventoryFailureMetadata{strconv.FormatUint(x.Failure.Sequence, 10), x.Failure.GenerationID, x.Failure.AttemptedAt, x.ReceivedAt, x.Failure.Reason}
	}
	return out, nil
}
func completePage(id string, now time.Time, in enrollmentstore.InventoryPageResult) completePackagePage {
	return completePackagePage{"tracebolt.complete-package-page.v1", id, now, publicInventoryBinding(in.Binding), in.Manifest.CollectedAt, in.CompletedAt, in.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL), in.TotalRows, in.Items, in.ScannedRows, in.Exhausted, in.SearchIncomplete, in.NextCursor, in.CursorExpiresAt}
}

// Complete inventory is operator-only. A read-only JSON POST keeps searches and
// opaque cursors out of URLs while preserving exact Host/Origin/session/CSRF
// rules and the existing global no-query path contract.
func (h *operatorHandler) completePackages(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	query := len(parts) == 7 && parts[6] == "query"
	if (len(parts) != 6 && !query) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "inventory" || parts[5] != "packages" {
		fail(w, 404, "not_found", "Device inventory is unavailable.")
		return
	}
	if (query && r.Method != "POST") || (!query && r.Method != "GET") {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.enrollment == nil || h.enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		if query {
			fail(w, 409, "inventory_not_configured", "Complete inventory is not configured.")
			return
		}
		devices, err := h.app.devices()
		if err != nil {
			h.app.internal(w)
			return
		}
		for _, d := range devices {
			if d.ID == parts[3] {
				write(w, 200, completePackageView{SchemaVersion: "tracebolt.complete-package-view.v1", DeviceID: d.ID, ServerNow: time.Now().UTC(), CollectionProfile: "", Status: "not_configured"})
				return
			}
		}
		fail(w, 404, "not_found", "Device inventory is unavailable.")
		return
	}
	if !query {
		now := h.enrollment.Now().UTC()
		view, err := h.enrollment.CompleteInventoryView(r.Context(), parts[3], now)
		if err != nil {
			completeInventoryError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		view, err = view.RecheckAt(h.enrollment.Now().UTC())
		if err != nil {
			completeInventoryError(w, err)
			return
		}
		dto, err := completeView(view)
		if err != nil {
			h.app.internal(w)
			return
		}
		write(w, 200, dto)
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	var input struct {
		GenerationID string `json:"generationId"`
		Cursor       string `json:"cursor"`
		Search       string `json:"search"`
		Limit        int    `json:"limit"`
	}
	if !readObject(w, r, 4096, []string{"generationId", "cursor", "search", "limit"}, &input) {
		return
	}
	if !enrollmentcrypto.ValidID(input.GenerationID, "sample_") || len(input.Cursor) > inventoryledger.MaxCursorBytes || len(input.Search) > inventoryledger.MaxSearchBytes || input.Limit < 1 || input.Limit > inventoryledger.MaxPageRows {
		fail(w, 400, "invalid_inventory_query", "The inventory query is invalid.")
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	// A body may arrive across cursor or retention expiry. Session authority and
	// the trusted retention clock are both reacquired after the complete body.
	now := h.enrollment.Now().UTC()
	page, err := h.enrollment.CompleteInventoryPage(r.Context(), parts[3], inventoryledger.PageRequest{GenerationID: input.GenerationID, Cursor: input.Cursor, Search: input.Search, Limit: input.Limit}, now)
	release()
	if err != nil {
		completeInventoryError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, completePage(parts[3], now, page))
}
func completeInventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device inventory is unavailable.")
	case errors.Is(err, enrollmentstore.ErrInventoryBusy), errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Stored inventory is busy; retry shortly.")
	case errors.Is(err, inventoryledger.ErrCursor), errors.Is(err, inventoryledger.ErrCursorExpired), errors.Is(err, inventoryledger.ErrExpired):
		fail(w, 409, "inventory_generation_expired", "Refresh the inventory before continuing.")
	case errors.Is(err, inventoryledger.ErrNotFound), errors.Is(err, enrollmentstate.ErrState), errors.Is(err, enrollmentstate.ErrExpired):
		fail(w, 409, "inventory_unavailable", "A current complete inventory is unavailable.")
	case errors.Is(err, inventoryledger.ErrInvalid), errors.Is(err, enrollmentstate.ErrInvalid):
		fail(w, 400, "invalid_inventory_query", "The inventory query is invalid.")
	default:
		fail(w, 503, "inventory_unavailable", "Stored inventory is unavailable.")
	}
}
