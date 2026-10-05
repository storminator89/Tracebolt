package api

import (
	"encoding/json"
	"errors"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewledger"
	"localrmm/internal/updategeneration"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type completedUpdateMetadata struct {
	Binding       completeInventoryBinding  `json:"binding"`
	Manifest      updategeneration.Manifest `json:"manifest"`
	State         string                    `json:"state"`
	CompletedAt   time.Time                 `json:"completedAt"`
	RetainedUntil time.Time                 `json:"retainedUntil"`
}
type completeUpdateView struct {
	SchemaVersion     string                     `json:"schemaVersion"`
	DeviceID          string                     `json:"deviceId"`
	ServerNow         time.Time                  `json:"serverNow"`
	CollectionProfile string                     `json:"collectionProfile"`
	Status            string                     `json:"status"`
	Complete          *completedUpdateMetadata   `json:"complete"`
	Transfer          *inventoryTransferMetadata `json:"transfer"`
	Failure           *inventoryFailureMetadata  `json:"failure"`
}
type completeUpdatePage struct {
	SchemaVersion    string                    `json:"schemaVersion"`
	DeviceID         string                    `json:"deviceId"`
	ServerNow        time.Time                 `json:"serverNow"`
	Binding          completeInventoryBinding  `json:"binding"`
	CollectedAt      time.Time                 `json:"collectedAt"`
	CompletedAt      time.Time                 `json:"completedAt"`
	RetainedUntil    time.Time                 `json:"retainedUntil"`
	TotalRows        uint64                    `json:"totalRows"`
	Items            []cachedupdates.Candidate `json:"items"`
	ScannedRows      int                       `json:"scannedRows"`
	Exhausted        bool                      `json:"exhausted"`
	SearchIncomplete bool                      `json:"searchIncomplete"`
	NextCursor       string                    `json:"nextCursor"`
	CursorExpiresAt  time.Time                 `json:"cursorExpiresAt"`
}

func completeUpdatesView(in enrollmentstore.CompleteUpdatesStatus) (completeUpdateView, error) {
	out := completeUpdateView{SchemaVersion: "tracebolt.complete-update-view.v1", DeviceID: in.DeviceID, ServerNow: in.ServerNow, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Status: "awaiting"}
	switch in.Status {
	case "", "awaiting", "available", "revoked", "unavailable", "not_configured":
	default:
		return completeUpdateView{}, enrollmentstore.ErrStorage
	}
	if in.Status != "" {
		out.Status = in.Status
	}
	if in.Status == "revoked" || in.Status == "not_configured" {
		if in.Complete != nil || in.Transfer != nil || in.Failure != nil {
			return completeUpdateView{}, enrollmentstore.ErrStorage
		}
		return out, nil
	}
	if in.Complete != nil {
		x := in.Complete
		hash, err := updategeneration.ManifestDigest(x.Manifest)
		if err != nil || in.CompleteBinding.Sequence == 0 || in.CompleteBinding.GenerationID != x.Manifest.GenerationID || in.CompleteBinding.ManifestHash != hash || (x.State != "complete" && x.State != "expired") {
			return completeUpdateView{}, enrollmentstore.ErrStorage
		}
		if x.State == "complete" {
			out.Status = "available"
		}
		out.Complete = &completedUpdateMetadata{publicInventoryBinding(in.CompleteBinding), x.Manifest, x.State, x.CompletedAt, x.ExpiresAt}
	}
	if in.Transfer != nil {
		x := in.Transfer
		hash, err := updategeneration.ManifestDigest(x.Manifest)
		if err != nil || in.Sequence == 0 || (x.State != "pending" && x.State != "complete" && x.State != "expired" && x.State != "failed") {
			return completeUpdateView{}, enrollmentstore.ErrStorage
		}
		out.Transfer = &inventoryTransferMetadata{publicInventoryBinding(enrollmentstore.InventoryBinding{Sequence: in.Sequence, GenerationID: x.Manifest.GenerationID, ManifestHash: hash}), x.State, uint64(x.Manifest.CandidateCount), x.AcceptedRows, x.Manifest.ChunkCount, x.AcceptedChunks, x.Manifest.CollectedAt, x.StartedAt, x.ExpiresAt}
	}
	if in.Failure != nil {
		x := in.Failure
		out.Failure = &inventoryFailureMetadata{strconv.FormatUint(x.Failure.Sequence, 10), x.Failure.GenerationID, x.Failure.AttemptedAt, x.ReceivedAt, x.Failure.Reason}
	}
	return out, nil
}
func completeUpdatesPage(id string, now time.Time, in enrollmentstore.CompleteUpdatesPageResult) completeUpdatePage {
	return completeUpdatePage{"tracebolt.complete-update-page.v1", id, now, publicInventoryBinding(in.Binding), in.Manifest.CollectedAt, in.CompletedAt, in.Manifest.CollectedAt.Add(inventoryledger.ObservationTTL), in.TotalRows, in.Items, in.ScannedRows, in.Exhausted, in.SearchIncomplete, in.NextCursor, in.CursorExpiresAt}
}

// Complete inventory is operator-only. A read-only JSON POST keeps searches and
// opaque cursors out of URLs while preserving exact Host/Origin/session/CSRF
// rules and the existing global no-query path contract.
func (h *operatorHandler) completeUpdates(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	query := len(parts) == 7 && parts[6] == "query"
	if (len(parts) != 6 && !query) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "inventory" || parts[5] != "complete-updates" {
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
				if !operatorStillActive(w, r) {
					return
				}
				write(w, 200, completeUpdateView{SchemaVersion: "tracebolt.complete-update-view.v1", DeviceID: d.ID, ServerNow: time.Now().UTC(), CollectionProfile: "", Status: "not_configured"})
				return
			}
		}
		fail(w, 404, "not_found", "Device inventory is unavailable.")
		return
	}
	if !query {
		now := h.enrollment.Now().UTC()
		view, err := h.enrollment.CompleteUpdatesView(r.Context(), parts[3], now)
		if err != nil {
			completeUpdatesError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		dto, err := completeUpdatesView(view)
		if err != nil {
			h.app.internal(w)
			return
		}
		h.writeCompleteUpdatesResponse(w, r, dto, 16384, view.ValidateAt)
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
	page, err := h.enrollment.CompleteUpdatesPage(r.Context(), parts[3], inventoryledger.PageRequest{GenerationID: input.GenerationID, Cursor: input.Cursor, Search: input.Search, Limit: input.Limit}, now)
	release()
	if err != nil {
		completeUpdatesError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	dto := completeUpdatesPage(parts[3], page.ServerNow, page)
	h.writeCompleteUpdatesResponse(w, r, dto, 256<<10, page.ValidateAt)
}

func completeUpdatesError(w http.ResponseWriter, err error) {
	if errors.Is(err, overviewledger.ErrExpired) || errors.Is(err, overviewledger.ErrCursor) || errors.Is(err, overviewledger.ErrCursorExpired) {
		fail(w, 409, "inventory_generation_expired", "Refresh the update inventory before continuing.")
		return
	}
	if errors.Is(err, enrollmentstore.ErrCompleteUpdatesNotConfigured) {
		fail(w, 409, "complete_updates_not_configured", "Complete update collection is not configured.")
		return
	}
	completeInventoryError(w, err)
}

// Marshal once; recheck current session and committed observation deadline before
// emitting those exact bounded bytes. Queries never trigger endpoint work.
func (h *operatorHandler) writeCompleteUpdatesResponse(w http.ResponseWriter, r *http.Request, value any, limit int, validate func(time.Time) error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw)+1 > limit {
		h.app.internal(w)
		return
	}
	raw = append(raw, '\n')
	if !operatorStillActive(w, r) {
		return
	}
	if validate != nil {
		if e = validate(h.enrollment.Now().UTC()); e != nil {
			completeUpdatesError(w, e)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
