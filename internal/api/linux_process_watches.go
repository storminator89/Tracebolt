package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/linuxprocesswatch"
	"localrmm/internal/store"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type linuxProcessWatchSource interface {
	WithLinuxProcessWatch(context.Context, string, []string, string, func(linuxprocesswatch.Input, func(time.Time) error) error) error
	Now() time.Time
}
type linuxProcessWatchMonitor struct {
	mu           sync.Mutex
	store        *store.Store
	source       linuxProcessWatchSource
	epoch        string
	deviceEpochs map[string]string
}

func newLinuxProcessWatchMonitor(db *store.Store, source linuxProcessWatchSource) (*linuxProcessWatchMonitor, error) {
	m := &linuxProcessWatchMonitor{store: db, source: source}
	return m, m.ensureEpoch()
}
func (m *linuxProcessWatchMonitor) ensureEpoch() error {
	if m.epoch != "" {
		return nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	m.epoch = hex.EncodeToString(raw[:])
	return nil
}

// A failed device source must not break unrelated devices' confirmation.
func (m *linuxProcessWatchMonitor) epochFor(id string) (string, error) {
	if err := m.ensureEpoch(); err != nil {
		return "", err
	}
	epoch, exists := m.deviceEpochs[id]
	if !exists {
		return m.epoch, nil
	}
	if epoch == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		epoch = hex.EncodeToString(raw[:])
		m.deviceEpochs[id] = epoch
	}
	return epoch, nil
}
func (m *linuxProcessWatchMonitor) invalidateDevice(id string) {
	if m.deviceEpochs == nil {
		m.deviceEpochs = map[string]string{}
	}
	m.deviceEpochs[id] = ""
}
func (m *linuxProcessWatchMonitor) invalidateAll() { m.epoch = ""; m.deviceEpochs = nil }

// Only previously opted-in device ledgers are evaluated. Source generations are
// already collected under the existing local complete-overview consent. A failed
// pass invalidates continuity and review tokens; it never recollects or backfills.
func (m *linuxProcessWatchMonitor) evaluate(ctx context.Context) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err = ctx.Err(); err != nil {
		m.invalidateAll()
		return err
	}
	if err = m.ensureEpoch(); err != nil {
		m.invalidateAll()
		return err
	}
	states, err := m.store.LinuxProcessWatchStates(ctx)
	if err != nil {
		m.invalidateAll()
		return err
	}
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// Reclaim expired terminal history before any unavailable/revoked source
	// can reject or occupy its lease. This pass lends no observation credit.
	for _, id := range ids {
		if err = m.store.PruneLinuxProcessWatchHistory(ctx, id, m.source.Now); err != nil {
			m.invalidateAll()
			return err
		}
	}
	var failures []error
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			m.invalidateAll()
			return err
		}

		if !states[id].Policy.Enabled {
			continue
		}

		epoch, e := m.epochFor(id)
		if e != nil {
			m.invalidateAll()
			return e
		}
		step, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = m.source.WithLinuxProcessWatch(step, id, states[id].Policy.Names, epoch, func(in linuxprocesswatch.Input, guard func(time.Time) error) error {
			_, _, e := m.store.UpdateLinuxProcessWatches(step, in, nil, nil, true, m.source.Now, guard)
			return e
		})
		cancel()
		if e != nil {
			m.invalidateDevice(id)
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}
func (h *operatorHandler) linuxProcessWatchesAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 5 && len(parts) != 6) || parts[1] != "api" || parts[2] != "devices" || !enrollmentcrypto.ValidID(parts[3], "agent_") || parts[4] != "linux-process-watches" {
		fail(w, 404, "not_found", "Linux process watches are unavailable.")
		return
	}
	action := ""
	if len(parts) == 6 {
		action = parts[5]
		if action != "policy" && action != "acknowledge" {
			fail(w, 404, "not_found", "Process watch action is unavailable.")
			return
		}
	}
	if action == "" && r.Method != "GET" || action != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_request", "Process watches do not accept query parameters.")
		return
	}
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authenticated operator is required.")
		return
	}
	can := !op.session.Named()
	m := h.app.linuxProcessWatches
	if m == nil {
		fail(w, 409, "process_watches_unavailable", "Process watches require existing Linux complete-overview observations.")
		return
	}
	var policy *linuxprocesswatch.ConfigureRequest
	var ack *linuxprocesswatch.AcknowledgeRequest
	if action != "" {
		if !can {
			fail(w, 403, "operator_capability_required", "Process watch administration is not granted.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		var valid bool
		policy, ack, valid = readLinuxProcessWatchCommand(w, r, action)
		if !valid {
			return
		}
		release, valid := beginOperatorMutation(w, r)
		if !valid {
			return
		}
		defer release()
	} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		fail(w, 400, "invalid_request", "Process watch reads do not accept a body.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if http.NewResponseController(w).SetWriteDeadline(time.Now().Add(7*time.Second)) != nil {
		fail(w, 503, "process_watches_unavailable", "Process watches are unavailable.")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	epoch, e := m.epochFor(parts[3])
	if e != nil {
		linuxProcessWatchError(w, e)
		return
	}
	state, e := m.store.LinuxProcessWatchState(ctx, parts[3])
	if e != nil {
		linuxProcessWatchError(w, e)
		return
	}
	names := state.Policy.Names
	if policy != nil {
		names = policy.Names
	}
	var raw []byte
	var view linuxprocesswatch.PublicView
	e = m.source.WithLinuxProcessWatch(ctx, parts[3], names, epoch, func(in linuxprocesswatch.Input, sourceGuard func(time.Time) error) error {
		guard := func(at time.Time) error {
			if ctx.Err() != nil || op.active == nil || !op.active() {
				return store.ErrLinuxProcessWatchSession
			}
			return sourceGuard(at)
		}
		current, at, err := m.store.UpdateLinuxProcessWatches(ctx, in, policy, ack, false, m.source.Now, guard)
		if err != nil {
			return err
		}
		fresh := m.source.Now().UTC()
		if fresh.Before(at) {
			return linuxprocesswatch.ErrClock
		}
		view = linuxprocesswatch.View(current, in, fresh, can)
		raw, err = json.Marshal(view)
		if err != nil || len(raw) > linuxprocesswatch.MaxBytes {
			return store.ErrLinuxProcessWatchUnavailable
		}
		return guard(fresh)
	})
	if e != nil {
		linuxProcessWatchError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	now := m.source.Now().UTC()
	if now.Before(view.ServerNow) || !now.Before(view.ValidUntil) {
		linuxProcessWatchError(w, linuxprocesswatch.ErrSource)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func readLinuxProcessWatchCommand(w http.ResponseWriter, r *http.Request, action string) (*linuxprocesswatch.ConfigureRequest, *linuxprocesswatch.AcknowledgeRequest, bool) {
	var input struct {
		RequestID             string   `json:"requestId"`
		ExpectedRevision      string   `json:"expectedRevision"`
		SourceToken           string   `json:"sourceToken"`
		Enabled               bool     `json:"enabled"`
		Names                 []string `json:"names"`
		ConsecutiveFailures   int      `json:"consecutiveFailures"`
		RetentionAcknowledged bool     `json:"retentionAcknowledged"`
		IncidentID            string   `json:"incidentId"`
	}
	fields := []string{"requestId", "expectedRevision", "sourceToken"}
	if action == "policy" {
		fields = append(fields, "enabled", "names", "consecutiveFailures", "retentionAcknowledged")
	} else {
		fields = append(fields, "incidentId")
	}
	if !readObject(w, r, 4096, fields, &input) {
		return nil, nil, false
	}
	invalid := func() (*linuxprocesswatch.ConfigureRequest, *linuxprocesswatch.AcknowledgeRequest, bool) {
		fail(w, 400, "invalid_process_watch", "Use exactly the reviewed process watch command fields.")
		return nil, nil, false
	}
	rev, err := strconv.ParseUint(input.ExpectedRevision, 10, 63)
	if err != nil || strconv.FormatUint(rev, 10) != input.ExpectedRevision || !enrollmentcrypto.ValidID(input.RequestID, "processrequest_") || !enrollmentcrypto.ValidID(input.SourceToken, "processsource_") {
		return invalid()
	}
	if action == "acknowledge" {
		if len(input.IncidentID) != len("processincident_")+16 || !strings.HasPrefix(input.IncidentID, "processincident_") {
			return invalid()
		}
		b, err := hex.DecodeString(strings.TrimPrefix(input.IncidentID, "processincident_"))
		if err != nil || hex.EncodeToString(b) != strings.TrimPrefix(input.IncidentID, "processincident_") {
			return invalid()
		}
		return nil, &linuxprocesswatch.AcknowledgeRequest{ExpectedRevision: rev, RequestID: input.RequestID, SourceToken: input.SourceToken, IncidentID: input.IncidentID}, true
	}
	if input.Names == nil || len(input.Names) > linuxprocesswatch.MaxRules {
		return invalid()
	}
	for i, name := range input.Names {
		if !linuxprocesswatch.ValidName(name) || i > 0 && input.Names[i-1] >= name {
			return invalid()
		}
	}
	if input.Enabled {
		if len(input.Names) == 0 || !input.RetentionAcknowledged || (input.ConsecutiveFailures != 2 && input.ConsecutiveFailures != 3) {
			return invalid()
		}
	} else if len(input.Names) != 0 || input.RetentionAcknowledged || input.ConsecutiveFailures != 0 {
		return invalid()
	}
	return &linuxprocesswatch.ConfigureRequest{ExpectedRevision: rev, RequestID: input.RequestID, SourceToken: input.SourceToken, Enabled: input.Enabled, Names: input.Names, ConsecutiveFailures: input.ConsecutiveFailures, RetentionAcknowledged: input.RetentionAcknowledged}, nil, true
}
func linuxProcessWatchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLinuxProcessWatchSession):
		fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
	case errors.Is(err, enrollmentstate.ErrNotFound), errors.Is(err, enrollmentstate.ErrProof), errors.Is(err, enrollmentstate.ErrExpired), errors.Is(err, enrollmentstate.ErrState):
		fail(w, 404, "not_found", "Linux process watches are unavailable for this device.")
	case errors.Is(err, linuxprocesswatch.ErrInvalid):
		fail(w, 400, "invalid_process_watch", "The process watch command is invalid.")
	case errors.Is(err, linuxprocesswatch.ErrConflict), errors.Is(err, linuxprocesswatch.ErrSource), errors.Is(err, linuxprocesswatch.ErrClock), errors.Is(err, linuxprocesswatch.ErrCapacity), errors.Is(err, enrollmentstore.ErrOverviewNotConfigured):
		fail(w, 409, "process_watches_changed", "Process watch state or source changed. Read saved state before another review.")
	case errors.Is(err, enrollmentstore.ErrBusy), errors.Is(err, enrollmentstore.ErrOverviewBusy), errors.Is(err, enrollmentstore.ErrOperationalBusy):
		fail(w, 429, "process_watches_busy", "Stored observations are busy. Read saved state before another review.")
	default:
		fail(w, 503, "process_watches_unavailable", "Process watches are unavailable; a write outcome may be uncertain. Read saved state and do not repeat the write.")
	}
}
