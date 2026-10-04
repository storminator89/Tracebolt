package api

import (
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type completeOverviewBinding struct {
	Section      string `json:"section"`
	Sequence     string `json:"sequence"`
	GenerationID string `json:"generationId"`
	ManifestHash string `json:"manifestHash"`
}

func publicOverviewBinding(b enrollmentstore.OverviewBinding) completeOverviewBinding {
	return completeOverviewBinding{b.Section, strconv.FormatUint(b.Sequence, 10), b.GenerationID, b.ManifestHash}
}

type completedOverviewMetadata struct {
	Binding       completeOverviewBinding     `json:"binding"`
	Manifest      overviewgeneration.Manifest `json:"manifest"`
	State         string                      `json:"state"`
	CompletedAt   time.Time                   `json:"completedAt"`
	RetainedUntil time.Time                   `json:"retainedUntil"`
}
type overviewTransferMetadata struct {
	Binding        completeOverviewBinding     `json:"binding"`
	Manifest       overviewgeneration.Manifest `json:"manifest"`
	State          string                      `json:"state"`
	DeclaredRows   uint64                      `json:"declaredRows"`
	AcceptedRows   uint64                      `json:"acceptedRows"`
	ExpectedChunks uint32                      `json:"expectedChunks"`
	AcceptedChunks uint32                      `json:"acceptedChunks"`
	CollectedAt    time.Time                   `json:"collectedAt"`
	StartedAt      time.Time                   `json:"startedAt"`
	ExpiresAt      time.Time                   `json:"expiresAt"`
}
type overviewFailureMetadata struct {
	Sequence     string    `json:"sequence"`
	GenerationID string    `json:"generationId"`
	AttemptedAt  time.Time `json:"attemptedAt"`
	ReceivedAt   time.Time `json:"receivedAt"`
	Reason       string    `json:"reason"`
}
type completeOverviewSection struct {
	Status   string                     `json:"status"`
	Complete *completedOverviewMetadata `json:"complete"`
	Transfer *overviewTransferMetadata  `json:"transfer"`
	Failure  *overviewFailureMetadata   `json:"failure"`
}
type completeOverviewView struct {
	SchemaVersion     string                  `json:"schemaVersion"`
	DeviceID          string                  `json:"deviceId"`
	ServerNow         time.Time               `json:"serverNow"`
	CollectionProfile string                  `json:"collectionProfile"`
	Status            string                  `json:"status"`
	Processes         completeOverviewSection `json:"processes"`
	Volumes           completeOverviewSection `json:"volumes"`
}
type completeOverviewPage struct {
	SchemaVersion    string                      `json:"schemaVersion"`
	DeviceID         string                      `json:"deviceId"`
	ServerNow        time.Time                   `json:"serverNow"`
	Section          string                      `json:"section"`
	Binding          completeOverviewBinding     `json:"binding"`
	Manifest         overviewgeneration.Manifest `json:"manifest"`
	CollectedAt      time.Time                   `json:"collectedAt"`
	CompletedAt      time.Time                   `json:"completedAt"`
	RetainedUntil    time.Time                   `json:"retainedUntil"`
	TotalRows        uint64                      `json:"totalRows"`
	Items            []overviewgeneration.Row    `json:"items"`
	ScannedRows      int                         `json:"scannedRows"`
	Exhausted        bool                        `json:"exhausted"`
	SearchIncomplete bool                        `json:"searchIncomplete"`
	NextCursor       string                      `json:"nextCursor"`
	CursorExpiresAt  time.Time                   `json:"cursorExpiresAt"`
}

func overviewSection(section string, in enrollmentstore.OverviewSectionStatus) (completeOverviewSection, error) {
	out := completeOverviewSection{Status: "awaiting"}
	if in.Complete != nil {
		x := in.Complete
		hash, err := overviewgeneration.ManifestDigest(x.Manifest)
		if err != nil || x.Manifest.Section != section || in.CompleteBinding.Section != section || in.CompleteBinding.Sequence == 0 || in.CompleteBinding.GenerationID != x.Manifest.GenerationID || in.CompleteBinding.ManifestHash != hash || (x.State != "complete" && x.State != "expired") {
			return completeOverviewSection{}, enrollmentstore.ErrStorage
		}
		out.Status = "available"
		if x.State == "expired" {
			out.Status = "expired"
		}
		out.Complete = &completedOverviewMetadata{publicOverviewBinding(in.CompleteBinding), x.Manifest, x.State, x.CompletedAt, x.ExpiresAt}
	}
	if in.Transfer != nil {
		x := in.Transfer
		hash, err := overviewgeneration.ManifestDigest(x.Manifest)
		if err != nil || x.Manifest.Section != section || in.Sequence == 0 || (x.State != "pending" && x.State != "complete" && x.State != "expired" && x.State != "failed") {
			return completeOverviewSection{}, enrollmentstore.ErrStorage
		}
		out.Transfer = &overviewTransferMetadata{publicOverviewBinding(enrollmentstore.OverviewBinding{Section: section, Sequence: in.Sequence, GenerationID: x.Manifest.GenerationID, ManifestHash: hash}), x.Manifest, x.State, x.Manifest.ObservedCount, x.AcceptedRows, x.Manifest.ChunkCount, x.AcceptedChunks, x.Manifest.CollectedAt, x.StartedAt, x.ExpiresAt}
	}
	if in.Failure != nil {
		x := in.Failure
		if x.Failure.Section != section {
			return completeOverviewSection{}, enrollmentstore.ErrStorage
		}
		out.Failure = &overviewFailureMetadata{strconv.FormatUint(x.Failure.Sequence, 10), x.Failure.GenerationID, x.Failure.AttemptedAt, x.ReceivedAt, x.Failure.Reason}
	}
	return out, nil
}
func overviewView(in enrollmentstore.OverviewStatus) (completeOverviewView, error) {
	out := completeOverviewView{SchemaVersion: "tracebolt.complete-overview-view.v1", DeviceID: in.DeviceID, ServerNow: in.ServerNow, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Status: "awaiting"}
	var err error
	if out.Processes, err = overviewSection("processes", in.Processes); err != nil {
		return completeOverviewView{}, err
	}
	if out.Volumes, err = overviewSection("volumes", in.Volumes); err != nil {
		return completeOverviewView{}, err
	}
	if out.Processes.Status == "available" || out.Volumes.Status == "available" {
		out.Status = "available"
	} else if out.Processes.Status == "expired" || out.Volumes.Status == "expired" {
		out.Status = "expired"
	}
	return out, nil
}
func overviewPage(id, section string, now time.Time, in enrollmentstore.OverviewPageResult) completeOverviewPage {
	return completeOverviewPage{"tracebolt.complete-overview-page.v1", id, now, section, publicOverviewBinding(in.Binding), in.Manifest, in.Manifest.CollectedAt, in.CompletedAt, in.Manifest.CollectedAt.Add(overviewledger.ObservationTTL), in.TotalRows, in.Items, in.ScannedRows, in.Exhausted, in.SearchIncomplete, in.NextCursor, in.CursorExpiresAt}
}

// Complete overview is operator-only. A read-only JSON POST keeps searches and
// opaque cursors out of URLs while preserving exact Host/Origin/session/CSRF
// rules and the existing global no-query path contract. Each section retains
// its independent generation and original capture interval in the manifest.
func (h *operatorHandler) completeOverview(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	query := len(parts) == 7 && parts[6] == "query"
	if (len(parts) != 6 && !query) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "inventory" || parts[5] != "overview" {
		fail(w, 404, "not_found", "Device overview is unavailable.")
		return
	}
	if (query && r.Method != "POST") || (!query && r.Method != "GET") {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.enrollment == nil || h.enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete {
		if query {
			fail(w, 409, "overview_not_configured", "Complete overview is not configured.")
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
				h.writeOverviewResponse(w, r, completeOverviewView{SchemaVersion: "tracebolt.complete-overview-view.v1", DeviceID: d.ID, ServerNow: time.Now().UTC(), Status: "not_configured", Processes: completeOverviewSection{Status: "not_configured"}, Volumes: completeOverviewSection{Status: "not_configured"}}, nil)
				return
			}
		}
		fail(w, 404, "not_found", "Device overview is unavailable.")
		return
	}
	if !query {
		view, err := h.enrollment.CompleteOverviewView(r.Context(), parts[3], h.enrollment.Now().UTC())
		if err != nil {
			completeOverviewError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		dto, err := overviewView(view)
		if err != nil {
			h.app.internal(w)
			return
		}
		h.writeOverviewResponse(w, r, dto, view.ValidateAt)
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	input, ok := readOverviewQuery(w, r)
	if !ok {
		return
	}
	release, ok := beginOperatorMutation(w, r)
	if !ok {
		return
	}
	// A body may arrive across cursor or retention expiry. Session authority and
	// the trusted retention clock are both reacquired after the complete body.
	now := h.enrollment.Now().UTC()
	page, err := h.enrollment.CompleteOverviewPage(r.Context(), parts[3], input, now)
	release()
	if err != nil {
		completeOverviewError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	dto := overviewPage(parts[3], input.Section, page.ServerNow, page)
	h.writeOverviewResponse(w, r, dto, page.ValidateAt)
}

// Encode exactly once, then recheck the session and committed output deadline
// immediately before emitting those same bounded bytes. No second marshal may
// move an otherwise checked page across expiry before its first byte is written.
func (h *operatorHandler) writeOverviewResponse(w http.ResponseWriter, r *http.Request, value any, validate func(time.Time) error) {
	raw, err := json.Marshal(value)
	if err != nil {
		h.app.internal(w)
		return
	}
	if len(raw) > 256*1024-1 {
		fail(w, 409, "overview_page_limit", "Reduce the page size before continuing.")
		return
	}
	raw = append(raw, '\n')
	if !operatorStillActive(w, r) {
		return
	}
	if validate != nil {
		if err = validate(h.enrollment.Now().UTC()); err != nil {
			completeOverviewError(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func readOverviewQuery(w http.ResponseWriter, r *http.Request) (overviewledger.PageRequest, bool) {
	var input struct {
		Section      string `json:"section"`
		GenerationID string `json:"generationId"`
		Cursor       string `json:"cursor"`
		Search       string `json:"search"`
		Limit        int    `json:"limit"`
	}
	if !readObject(w, r, 4096, []string{"section", "generationId", "cursor", "search", "limit"}, &input) {
		return overviewledger.PageRequest{}, false
	}
	if (input.Section != "processes" && input.Section != "volumes") || !enrollmentcrypto.ValidID(input.GenerationID, "sample_") || len(input.Cursor) > overviewledger.MaxCursorBytes || len(input.Search) > overviewledger.MaxSearchBytes || input.Limit < 1 || input.Limit > overviewledger.MaxPageRows {
		fail(w, 400, "invalid_overview_query", "The overview query is invalid.")
		return overviewledger.PageRequest{}, false
	}
	return overviewledger.PageRequest{Section: input.Section, GenerationID: input.GenerationID, Cursor: input.Cursor, Search: input.Search, Limit: input.Limit}, true
}
func completeOverviewError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollmentstore.ErrOverviewNotConfigured):
		fail(w, 409, "overview_not_configured", "Complete overview is not configured.")
	case errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "not_found", "Device overview is unavailable.")
	case errors.Is(err, enrollmentstore.ErrOverviewBusy), errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "storage_busy", "Stored overview is busy; retry shortly.")
	case errors.Is(err, overviewledger.ErrQuota), errors.Is(err, inventoryledger.ErrQuota):
		fail(w, 409, "overview_resource_limit", "Stored overview exceeds the resource limit.")
	case errors.Is(err, overviewledger.ErrCursor), errors.Is(err, overviewledger.ErrCursorExpired), errors.Is(err, overviewledger.ErrExpired):
		fail(w, 409, "overview_generation_expired", "Refresh the overview before continuing.")
	case errors.Is(err, overviewledger.ErrNotFound), errors.Is(err, enrollmentstate.ErrState), errors.Is(err, enrollmentstate.ErrExpired), errors.Is(err, enrollmentstate.ErrProof):
		fail(w, 409, "overview_unavailable", "A current complete overview is unavailable.")
	case errors.Is(err, overviewledger.ErrInvalid), errors.Is(err, enrollmentstate.ErrInvalid):
		fail(w, 400, "invalid_overview_query", "The overview query is invalid.")
	default:
		fail(w, 503, "overview_unavailable", "Stored overview is unavailable.")
	}
}
