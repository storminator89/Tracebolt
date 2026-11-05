package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
)

const deviceNotesResponseBytes = 512 * 1024

// This floor shares the lifetime of Server.csrf, the process-random review
// signing key. Every successful view advances it before exposing serverNow;
// every write rechecks it under the original-identity lease before committing.
// A clock rollback therefore cannot reopen an expired review after a negative
// leased read. A new Server resets both floor and signing key, not one alone.
// This is a single-writer manager contract, not multi-process authorization.
type deviceNotesClock struct {
	mu    sync.Mutex
	floor time.Time
}

func (c *deviceNotesClock) observe(clock func() time.Time) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Sample inside this short mutex, never while holding it across I/O.
	at := clock().UTC()
	if at.IsZero() || at.Before(c.floor) {
		return time.Time{}, store.ErrDeviceNotesConflict
	}
	c.floor = at
	return at, nil
}

type deviceNoteReceipt struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	NoteID   string `json:"noteId"`
	Revision uint64 `json:"revision"`
}
type deviceNotesLimits struct {
	Notes      int `json:"notes"`
	Operations int `json:"operations"`
	TextBytes  int `json:"textBytes"`
}
type deviceNotesView struct {
	SchemaVersion string              `json:"schemaVersion"`
	DeviceID      string              `json:"deviceId"`
	Binding       string              `json:"binding"`
	IdentityKey   string              `json:"identityKey"`
	ServerNow     time.Time           `json:"serverNow"`
	ValidUntil    time.Time           `json:"validUntil"`
	Revision      uint64              `json:"revision"`
	CanWrite      bool                `json:"canWrite"`
	Notes         []store.DeviceNote  `json:"notes"`
	Operations    []deviceNoteReceipt `json:"operations"`
	Limits        deviceNotesLimits   `json:"limits"`
}
type deviceNotesInput struct {
	Binding          string    `json:"binding"`
	ValidUntil       time.Time `json:"validUntil"`
	ExpectedRevision uint64    `json:"expectedRevision"`
	OperationID      string    `json:"operationId"`
	Action           string    `json:"action"`
	NoteID           string    `json:"noteId"`
	Text             string    `json:"text"`
}

// Only this new private manager resource exposes authored notes. It is never
// joined into telemetry, Device/Overview, incidents, AI, bundles or exports.
func deviceNotesRoute(r *http.Request) (string, bool) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "handover-notes" || !enrollmentcrypto.ValidID(parts[3], "agent_") || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", false
	}
	return parts[3], true
}

// The opaque token deliberately hides the original identity hash and binds a
// deliberate write to the original authenticated session and review deadline.
// app.csrf is a process-random secret; LAN responses expose session CSRF only.
func (h *operatorHandler) deviceNotesBinding(manager, identity, session string, until time.Time) string {
	raw, _ := json.Marshal([]string{"tracebolt.device-notes.review.v1", manager, identity, session, until.UTC().Format(time.RFC3339Nano)})
	mac := hmac.New(sha256.New, []byte(h.app.csrf))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *operatorHandler) deviceNotesAPI(w http.ResponseWriter, r *http.Request) {
	id, valid := deviceNotesRoute(r)
	if !valid {
		fail(w, 404, "not_found", "Device notes are unavailable.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		fail(w, 405, "method_not_allowed", "Use GET or POST for device notes.")
		return
	}
	op, ok := operatorContext(r)
	if !ok || op.active == nil || !op.active() {
		fail(w, 401, "authentication_required", "An active operator session is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	mutation := r.Method == http.MethodPost
	var releaseMutation func()
	defer func() {
		if releaseMutation != nil {
			releaseMutation()
		}
	}()
	var input deviceNotesInput
	if mutation {
		if op.session.Named() {
			fail(w, 403, "operator_capability_required", "Only the shared administrator can save device notes.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) || !readObject(w, r, 16384, []string{"binding", "validUntil", "expectedRevision", "operationId", "action", "noteId", "text"}, &input) {
			return
		}
		validAction := input.Action == "add" && store.ValidDeviceNoteText(input.Text) && input.NoteID == "note_"+strings.TrimPrefix(input.OperationID, "noteop_") || (input.Action == "archive" || input.Action == "restore") && input.Text == ""
		if !validAction || !enrollmentcrypto.ValidHash(input.Binding) || !enrollmentcrypto.ValidID(input.OperationID, "noteop_") || !enrollmentcrypto.ValidID(input.NoteID, "note_") || input.ExpectedRevision >= store.MaxDeviceNoteOperations || input.ValidUntil.IsZero() {
			fail(w, 400, "invalid_device_note", "Use a valid note, operation and current review.")
			return
		}
		release, allowed := beginOperatorMutation(w, r)
		if !allowed {
			return
		}
		releaseMutation = release
	}

	sources := h.groupSources()
	manager, started, devices, err := fleetGroupAdmission(ctx, sources)
	if err != nil {
		fail(w, 503, "device_notes_unavailable", "Current device identity is unavailable.")
		return
	}
	device, found := devices[id]
	if !found || device.Platform != "windows" {
		fail(w, 404, "device_notes_unavailable", "Notes require a currently admitted Windows device identity.")
		return
	}
	// Reuse existing authority leases; no enrollment or collection contract is
	// changed. Other enrollment sources exclude a colliding ID through the same
	// operator-store transaction. Aliased stores fail before nesting any lease.
	var files []os.FileInfo
	windowsIndex := -1
	for i, source := range sources {
		provider, has := source.(customerEnrollmentLeaseIdentity)
		if !has {
			err = store.ErrDeviceNotesConflict
			break
		}
		file, e := provider.CustomerEnrollmentLeaseIdentity()
		if e != nil || file == nil {
			err = store.ErrDeviceNotesConflict
			break
		}
		for _, previous := range files {
			if os.SameFile(previous, file) {
				err = store.ErrDeviceNotesConflict
				break
			}
		}
		if err != nil {
			break
		}
		files = append(files, file)
		if source.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
			if windowsIndex != -1 {
				err = store.ErrDeviceNotesConflict
				break
			}
			windowsIndex = i
		}
	}
	if err != nil || windowsIndex < 0 {
		fail(w, 503, "device_notes_unavailable", "Device authority cannot be verified.")
		return
	}
	source := sources[windowsIndex]
	lease, hasLease := source.(windowsMonitoringAuthoritySource)
	rows, err := source.WindowsContactInputs(ctx, started)
	authority, authorityErr := windowsContactAuthority(rows, started)
	in, admitted := authority[id]
	if !hasLease || err != nil || authorityErr != nil || !admitted || !in.Authorized || monitoringIdentity(source.Binding(), in) != device.identity {
		fail(w, 503, "device_notes_unavailable", "Device authority changed. Refresh notes.")
		return
	}
	if mutation {
		expected := h.deviceNotesBinding(manager, device.identity, op.session.ID, input.ValidUntil)
		if !hmac.Equal([]byte(expected), []byte(input.Binding)) || !started.Before(input.ValidUntil) || input.ValidUntil.After(started.Add(60*time.Second)) || input.ValidUntil.After(op.session.ExpiresAt) || input.ValidUntil.After(in.AuthorityUntil) {
			fail(w, 409, "device_notes_rejected", "The notes review changed or expired. Refresh before saving.")
			return
		}
	}
	last := started
	var raw []byte
	accepted := false
	var viewUntil time.Time
	defer func() { clear(raw) }()
	var acquire func(int, []func(time.Time) error) error
	acquire = func(index int, guards []func(time.Time) error) error {
		if index < len(sources) {
			if index == windowsIndex {
				return lease.WithWindowsMonitoringAuthority(ctx, []windowscontact.Input{in}, func(guard func(time.Time) error) error { return acquire(index+1, append(guards, guard)) })
			}
			exclusion, ok := sources[index].(customerIdentityExclusionSource)
			if !ok {
				return store.ErrDeviceNotesConflict
			}
			return exclusion.WithCustomerIdentityExclusion(ctx, []string{id}, func(guard func(time.Time) error) error { return acquire(index+1, append(guards, guard)) })
		}
		guard := func() error {
			at, clockErr := h.app.deviceNotesClock.observe(source.Now)
			if clockErr != nil || ctx.Err() != nil || !op.active() || at.Before(last) || !contactReadTime(started, at) || !at.Before(in.AuthorityUntil) || !at.Before(op.session.ExpiresAt) || mutation && !at.Before(input.ValidUntil) {
				return store.ErrDeviceNotesConflict
			}
			last = at
			for _, check := range guards {
				if e := check(at); e != nil {
					return store.ErrDeviceNotesConflict
				}
			}
			current, now, e := customerManager(ctx, sources)
			if e != nil || current != manager || now.Before(last) || !contactReadTime(started, now) || !now.Before(in.AuthorityUntil) || !now.Before(op.session.ExpiresAt) || mutation && !now.Before(input.ValidUntil) || !op.active() || ctx.Err() != nil {
				return store.ErrDeviceNotesConflict
			}
			final, clockErr := h.app.deviceNotesClock.observe(source.Now)
			if clockErr != nil || final.Before(now) || !contactReadTime(started, final) || !final.Before(in.AuthorityUntil) || !final.Before(op.session.ExpiresAt) || mutation && !final.Before(input.ValidUntil) || !op.active() || ctx.Err() != nil {
				return store.ErrDeviceNotesConflict
			}
			last = final
			return nil
		}
		if e := guard(); e != nil {
			return e
		}
		var notebook store.DeviceNotes
		var e error
		if mutation {
			notebook, e = h.app.store.ApplyDeviceNote(ctx, manager, device.identity, id, input.OperationID, input.Action, input.NoteID, input.Text, input.ExpectedRevision, last, guard)
			accepted = e == nil
		} else {
			notebook, e = h.app.store.ReadDeviceNotes(ctx, manager, device.identity, id)
		}
		if e != nil {
			return e
		}
		if e = guard(); e != nil {
			return e
		}
		for _, note := range notebook.Notes {
			if last.Before(note.CreatedAt) || last.Before(note.ChangedAt) {
				return store.ErrDeviceNotesConflict
			}
		}
		until := last.Add(60 * time.Second)
		if in.AuthorityUntil.Before(until) {
			until = in.AuthorityUntil
		}
		if op.session.ExpiresAt.Before(until) {
			until = op.session.ExpiresAt
		}
		viewUntil = until
		// Public opaque correlation only, never authorization. This independent
		// domain stays stable across leaf renewal and manager process restarts.
		identityKey := fleetHash([]string{"tracebolt.device-notes.identity.v1", manager, device.identity})
		view := deviceNotesView{SchemaVersion: "tracebolt.device-notes.v1", DeviceID: id, Binding: h.deviceNotesBinding(manager, device.identity, op.session.ID, until), IdentityKey: identityKey, ServerNow: last, ValidUntil: until, Revision: notebook.Revision, CanWrite: !op.session.Named(), Notes: notebook.Notes, Operations: []deviceNoteReceipt{}, Limits: deviceNotesLimits{store.MaxDeviceNotes, store.MaxDeviceNoteOperations, store.MaxDeviceNoteTextBytes}}
		for _, operation := range notebook.Operations {
			view.Operations = append(view.Operations, deviceNoteReceipt{operation.ID, operation.Action, operation.NoteID, operation.Revision})
		}
		raw, e = json.Marshal(view)
		if e != nil || len(raw) >= deviceNotesResponseBytes-1 {
			return store.ErrDeviceNotesInvalid
		}
		raw = append(raw, '\n')
		if e = guard(); e != nil {
			return e
		}
		return nil
	}
	err = acquire(0, nil)
	// Mutation gates and enrollment transactions must not wait for a slow HTTP
	// reader. Revalidate the exact identity after releasing them and before output.
	if releaseMutation != nil {
		releaseMutation()
		releaseMutation = nil
	}
	if err != nil {
		status := 503
		code := "device_notes_unconfirmed"
		if mutation && !accepted && (errors.Is(err, store.ErrDeviceNotesConflict) || errors.Is(err, store.ErrDeviceNotesLimit)) {
			status = 409
			code = "device_notes_rejected"
		}
		fail(w, status, code, "Notes could not be confirmed. Check the saved result before another change.")
		return
	}
	currentManager, final, current, e := fleetGroupAdmission(ctx, sources)
	currentDevice, stillPresent := current[id]
	if e != nil || currentManager != manager || !stillPresent || currentDevice.Platform != "windows" || currentDevice.identity != device.identity || !currentDevice.expires.Equal(device.expires) || final.Before(last) || !contactReadTime(started, final) || !final.Before(viewUntil) || !final.Before(in.AuthorityUntil) || !final.Before(op.session.ExpiresAt) || !op.active() || ctx.Err() != nil {
		fail(w, 503, "device_notes_unconfirmed", "Notes could not be confirmed. Check the saved result before another change.")
		return
	}
	end, clockErr := h.app.deviceNotesClock.observe(source.Now)
	if clockErr != nil || end.Before(final) || !contactReadTime(started, end) || !end.Before(viewUntil) || !end.Before(in.AuthorityUntil) || !end.Before(op.session.ExpiresAt) || !op.active() || ctx.Err() != nil {
		fail(w, 503, "device_notes_unconfirmed", "Notes could not be confirmed. Check the saved result before another change.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
