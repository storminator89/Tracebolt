package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type journalView struct {
	SchemaVersion string                                 `json:"schemaVersion"`
	DeviceID      string                                 `json:"deviceId"`
	ServerNow     time.Time                              `json:"serverNow"`
	Configured    bool                                   `json:"configured"`
	ExpectedFloor string                                 `json:"expectedFloor"`
	Request       *journalrequest.Status                 `json:"request"`
	LocalStatus   string                                 `json:"localStatus"`
	ContentStatus string                                 `json:"contentStatus"`
	Generation    *enrollmentstore.JournalGenerationView `json:"generation,omitempty"`
}

func (h *operatorHandler) journal(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "journal" {
		fail(w, 404, "not_found", "Journal view is unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
	}
	if action != "" && action != "create" && action != "cancel" && action != "query" {
		fail(w, 404, "not_found", "Journal action is unavailable.")
		return
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	configured := h.enrollment != nil && h.enrollment.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileComplete
	if !configured {
		if action != "" {
			fail(w, 409, "journal_not_configured", "On-demand journals require the complete profile and separate local consent.")
			return
		}
		devices, e := h.app.devices()
		if e != nil {
			h.app.internal(w)
			return
		}
		for _, d := range devices {
			if d.ID == parts[3] {
				if !operatorStillActive(w, r) {
					return
				}
				write(w, 200, journalView{SchemaVersion: "tracebolt.journal-view.v1", DeviceID: d.ID, ServerNow: time.Now().UTC(), ExpectedFloor: "0", LocalStatus: "unknown", ContentStatus: "unavailable"})
				return
			}
		}
		fail(w, 404, "not_found", "Journal view is unavailable.")
		return
	}
	if action == "" {
		h.writeJournalView(w, r, parts[3])
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	switch action {
	case "create":
		floor, q, generation, ok := readJournalCreate(w, r, h.enrollment.Now().UTC(), h.insecureHTTPTest)
		if !ok {
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		_, err := h.enrollment.CreateJournalRequestWithGeneration(r.Context(), parts[3], floor, q, generation, h.enrollment.Now().UTC())
		release()
		if err != nil {
			journalOperatorError(w, err)
			return
		}
		h.writeJournalView(w, r, parts[3])
	case "cancel":
		var in struct {
			Identity json.RawMessage `json:"identity"`
		}
		if !readObject(w, r, 4096, []string{"identity"}, &in) {
			return
		}
		var id journalrequest.Identity
		if !journalIdentity(in.Identity, &id) {
			fail(w, 400, "invalid_journal_request", "The request identity is invalid.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		err := h.enrollment.CancelJournalRequest(r.Context(), parts[3], id, h.enrollment.Now().UTC())
		release()
		if err != nil {
			journalOperatorError(w, err)
			return
		}
		h.writeJournalView(w, r, parts[3])
	case "query":
		var in struct {
			Identity       json.RawMessage `json:"identity"`
			SnapshotDigest string          `json:"snapshotDigest"`
			Search         string          `json:"search"`
			Offset         int             `json:"offset"`
			Limit          int             `json:"limit"`
		}
		if !readObject(w, r, 4096, []string{"identity", "snapshotDigest", "search", "offset", "limit"}, &in) {
			return
		}
		var id journalrequest.Identity
		if !journalIdentity(in.Identity, &id) {
			fail(w, 400, "invalid_journal_request", "The request identity is invalid.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		page, err := h.enrollment.JournalPage(r.Context(), parts[3], journalcache.PageRequest{Identity: id, SnapshotDigest: in.SnapshotDigest, Search: in.Search, Offset: in.Offset, Limit: in.Limit}, h.enrollment.Now().UTC())
		release()
		if err != nil {
			journalOperatorError(w, err)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		raw, err := json.Marshal(page)
		if err != nil || len(raw) > journalview.MaxPageBytes {
			fail(w, 503, "journal_unavailable", "Journal content is unavailable.")
			return
		}

		// Page preparation and encoding may cross expiry or a concurrent revoke.
		// Recheck the exact committed receipt after those steps and immediately
		// before emitting bytes, under the current trusted service clock.
		current, _, checkErr := h.enrollment.JournalStatus(r.Context(), parts[3], h.enrollment.Now().UTC())
		if checkErr != nil {
			clear(raw)
			journalOperatorError(w, checkErr)
			return
		}
		if current.State != journalrequest.Accepted || current.ContentStatus != "available" || current.Description.Identity != page.Identity || current.Receipt == nil || current.Receipt.ResultDigest != page.SnapshotDigest || !current.Description.ExpiresAt.Equal(page.ExpiresAt) {
			clear(raw)
			journalOperatorError(w, journalcache.ErrUnavailable)
			return
		}
		if !operatorStillActive(w, r) {
			clear(raw)
			return
		}
		if !h.enrollment.Now().UTC().Before(page.ExpiresAt) {
			clear(raw)
			_, _, _ = h.enrollment.JournalStatus(r.Context(), parts[3], h.enrollment.Now().UTC())
			journalOperatorError(w, journalrequest.ErrExpired)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
	}
}
func (h *operatorHandler) writeJournalView(w http.ResponseWriter, r *http.Request, device string) {
	now := h.enrollment.Now().UTC()
	s, local, err := h.enrollment.JournalStatus(r.Context(), device, now)
	v := journalView{SchemaVersion: "tracebolt.journal-view.v1", DeviceID: device, ServerNow: now, Configured: true, ExpectedFloor: "0", LocalStatus: local, ContentStatus: "unavailable"}
	if err != nil && !errors.Is(err, journalrequest.ErrNotFound) && !errors.Is(err, journalrequest.ErrNotReady) {
		journalOperatorError(w, err)
		return
	}
	if err == nil {
		v.Request = &s
		v.ExpectedFloor = strconv.FormatUint(s.Description.Identity.Sequence, 10)
		v.ContentStatus = s.ContentStatus
	}
	generation, generationErr := h.enrollment.JournalGenerationStatus(r.Context(), device, now)
	if generationErr != nil && !errors.Is(generationErr, journalrequest.ErrNotReady) {
		journalOperatorError(w, generationErr)
		return
	}
	if generation != nil {
		v.SchemaVersion = "tracebolt.journal-view.v2"
		v.Generation = generation
	}
	// Status and report reads independently recheck authority. A report racing
	// between them may cancel old work; never publish a hybrid active view.
	if v.Request != nil {
		d := v.Request.Description
		if d.SchemaVersion == journalrequest.SchemaVersionV2 && (generation == nil || d.PolicyGeneration.Revision > generation.PolicyGeneration.Revision || d.PolicyGeneration.Revision == generation.PolicyGeneration.Revision && d.PolicyGeneration != generation.PolicyGeneration) || generation != nil && (v.Request.State == journalrequest.Pending || v.Request.State == journalrequest.Claimed) && (d.SchemaVersion != journalrequest.SchemaVersionV2 || d.PolicyGeneration != generation.PolicyGeneration) {
			journalOperatorError(w, journalrequest.ErrConflict)
			return
		}
	}
	// The independent generation read can wait after the request read. Never
	// emit a live request or fresh generation after its original expiry.
	after := h.enrollment.Now().UTC()
	if after.Before(now) {
		after = now
	}
	if v.Request != nil && v.Request.State != journalrequest.Expired && !after.Before(v.Request.Description.ExpiresAt) {
		_, _, err := h.enrollment.JournalStatus(r.Context(), device, after)
		if err == nil {
			err = journalrequest.ErrExpired
		}
		journalOperatorError(w, err)
		return
	}
	if generation != nil && generation.Fresh && !after.Before(generation.ExpiresAt) {
		_, err := h.enrollment.JournalGenerationStatus(r.Context(), device, after)
		if err == nil {
			err = enrollmentstore.ErrJournalGenerationStale
		}
		journalOperatorError(w, err)
		return
	}
	v.ServerNow = after
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, v)
}
func journalOperatorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, journalrequest.ErrInvalid):
		fail(w, 400, "invalid_journal_request", "The journal query is invalid.")
	case errors.Is(err, journalrequest.ErrConflict), errors.Is(err, journalrequest.ErrConsumed):
		fail(w, 409, "journal_conflict", "The journal request changed. Refresh before continuing.")
	case errors.Is(err, journalrequest.ErrExpired), errors.Is(err, journalrequest.ErrCanceled), errors.Is(err, journalcache.ErrUnavailable):
		fail(w, 409, "journal_unavailable", "Captured journal content is expired, canceled or unavailable; it will not be recollected automatically.")
	case errors.Is(err, enrollmentstore.ErrJournalGenerationStale):
		fail(w, 409, "journal_generation_stale", "A fresh endpoint policy report is required. Refresh before an explicit new capture.")
	case errors.Is(err, journalrequest.ErrNotReady):
		fail(w, 409, "journal_not_ready", "A current system observation is required before creating a journal request.")
	case errors.Is(err, journalrequest.ErrNotFound), errors.Is(err, enrollmentstate.ErrNotFound):
		fail(w, 404, "journal_not_found", "Journal request is unavailable.")
	case errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrInventoryBusy), errors.Is(err, journalcache.ErrCapacity), errors.Is(err, journalcache.ErrBusy):
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "journal_busy", "The journal view is busy; retry shortly.")
	case errors.Is(err, enrollmentstate.ErrProof), errors.Is(err, enrollmentstate.ErrState), errors.Is(err, enrollmentstate.ErrExpired):
		fail(w, 409, "journal_unavailable", "Current device authority is unavailable.")
	default:
		fail(w, 503, "journal_unavailable", "Journal content is unavailable.")
	}
}

// Nested request objects retain exact singleton typed keys, including zero-valued
// priority and sequence fields; json.Unmarshal's duplicate/alias/null tolerance
// must not silently widen this explicitly acknowledged request.
func journalObject(raw []byte, keys []string, out any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != len(keys) {
		return false
	}
	if _, err = d.Token(); err != io.EOF {
		return false
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil
}
func journalIdentity(raw []byte, id *journalrequest.Identity) bool {
	if !journalObject(raw, []string{"id", "sequence", "queryDigest"}, id) || !journalwire.ValidIdentity(*id) {
		return false
	}
	var v map[string]json.RawMessage
	_ = json.Unmarshal(raw, &v)
	var seq string
	return json.Unmarshal(v["sequence"], &seq) == nil && seq == strconv.FormatUint(id.Sequence, 10)
}

func readJournalCreate(w http.ResponseWriter, r *http.Request, now time.Time, insecure bool) (uint64, journalview.Query, journalgeneration.Tuple, bool) {
	var in struct {
		ExpectedFloor            string          `json:"expectedFloor"`
		ExpectedPolicyGeneration json.RawMessage `json:"expectedPolicyGeneration"`
		Query                    json.RawMessage `json:"query"`
		AcknowledgeLogContent    bool            `json:"acknowledgeLogContent"`
		AcknowledgePlaintext     bool            `json:"acknowledgePlaintext"`
	}
	// Choose the explicitly versioned optional shape, then use the existing
	// singleton-key/null/unknown-field parser over the same bounded bytes.
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if readErr != nil {
		var maximum *http.MaxBytesError
		if errors.As(readErr, &maximum) {
			fail(w, 413, "body_too_large", "Request body exceeds this endpoint's byte limit.")
		} else {
			fail(w, 400, "invalid_journal_request", "The journal request body is invalid.")
		}
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		fail(w, 400, "invalid_journal_request", "The journal request body is invalid.")
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	keys := []string{"expectedFloor", "query", "acknowledgeLogContent", "acknowledgePlaintext"}
	if _, exists := fields["expectedPolicyGeneration"]; exists {
		keys = append(keys, "expectedPolicyGeneration")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if !readObject(w, r, 4096, keys, &in) {
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	floor, err := strconv.ParseUint(in.ExpectedFloor, 10, 64)
	var q journalview.Query
	if err != nil || strconv.FormatUint(floor, 10) != in.ExpectedFloor || !journalObject(in.Query, []string{"unit", "start", "end", "maxPriority"}, &q) || journalview.ValidateQuery(q, now) != nil {
		fail(w, 400, "invalid_journal_request", "Use one exact service, a past UTC time range up to one hour, and priority 0–7.")
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	if !in.AcknowledgeLogContent {
		fail(w, 400, "journal_acknowledgement_required", "Acknowledge that journal messages may contain credentials, personal data or other secrets despite best-effort masking.")
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	if insecure && !in.AcknowledgePlaintext {
		fail(w, 400, "journal_plaintext_acknowledgement_required", "Acknowledge that this HTTP test sends log content unencrypted without server authentication.")
		return 0, journalview.Query{}, journalgeneration.Tuple{}, false
	}
	var generation journalgeneration.Tuple
	if len(in.ExpectedPolicyGeneration) != 0 {
		var e error
		generation, e = journalgeneration.Decode(in.ExpectedPolicyGeneration)
		if e != nil {
			fail(w, 400, "invalid_journal_request", "The expected policy generation is invalid.")
			return 0, journalview.Query{}, journalgeneration.Tuple{}, false
		}
	}
	return floor, q, generation, true
}
