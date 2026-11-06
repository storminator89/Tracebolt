package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
)

const maintenanceSeriesPath = "/api/fleet/windows-maintenance-schedule/series"

type maintenanceSeriesTokenKey struct {
	once sync.Once
	key  [32]byte
	err  error
}
type maintenanceSeriesPlan struct {
	Session      string                                `json:"session"`
	OperationID  string                                `json:"operationId"`
	IssuedAt     time.Time                             `json:"issuedAt"`
	ExpiresAt    time.Time                             `json:"expiresAt"`
	Key          string                                `json:"key"`
	Revision     uint64                                `json:"revision"`
	Action       string                                `json:"action"`
	OccurrenceID uint64                                `json:"occurrenceId"`
	Intent       string                                `json:"intent"`
	Occurrences  []store.WindowsMaintenanceSeriesDates `json:"occurrences"`
}

func seriesSession(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}
func (h *operatorHandler) signMaintenanceSeries(p maintenanceSeriesPlan) (string, error) {
	h.maintenanceSeriesTokens.once.Do(func() { _, h.maintenanceSeriesTokens.err = rand.Read(h.maintenanceSeriesTokens.key[:]) })
	if h.maintenanceSeriesTokens.err != nil {
		return "", h.maintenanceSeriesTokens.err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, h.maintenanceSeriesTokens.key[:])
	mac.Write([]byte("tracebolt.windows-maintenance-series-review.v1\x00"))
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (h *operatorHandler) verifyMaintenanceSeries(token string) (maintenanceSeriesPlan, bool) {
	var p maintenanceSeriesPlan
	h.maintenanceSeriesTokens.once.Do(func() { _, h.maintenanceSeriesTokens.err = rand.Read(h.maintenanceSeriesTokens.key[:]) })
	if h.maintenanceSeriesTokens.err != nil {
		return p, false
	}
	if len(token) > 8192 {
		return p, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return p, false
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return p, false
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return p, false
	}
	mac := hmac.New(sha256.New, h.maintenanceSeriesTokens.key[:])
	mac.Write([]byte("tracebolt.windows-maintenance-series-review.v1\x00"))
	mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(raw, &p) != nil {
		return p, false
	}
	return p, true
}
func seriesOperationID(now time.Time) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return fmt.Sprintf("wms_%d_%s", now.UnixMilli(), hex.EncodeToString(b[:])), nil
}
func validSeriesOperationID(id string) bool {
	parts := strings.Split(id, "_")
	if len(parts) != 3 || parts[0] != "wms" || len(parts[1]) > 16 || len(parts[2]) != 32 {
		return false
	}
	n, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || n <= 0 || strconv.FormatInt(n, 10) != parts[1] {
		return false
	}
	raw, e := hex.DecodeString(parts[2])
	return e == nil && hex.EncodeToString(raw) == parts[2]
}
func seriesDates(w http.ResponseWriter, r *http.Request, raw []json.RawMessage) ([]store.WindowsMaintenanceSeriesDates, bool) {
	if len(raw) < 2 || len(raw) > 4 {
		fail(w, 400, "invalid_windows_maintenance", "Review exactly two through four weekly occurrences.")
		return nil, false
	}
	dates := make([]store.WindowsMaintenanceSeriesDates, 0, len(raw))
	for _, item := range raw {
		var d struct {
			StartsAt string `json:"startsAt"`
			EndsAt   string `json:"endsAt"`
		}
		nested := r.Clone(r.Context())
		nested.Body = io.NopCloser(bytes.NewReader(item))
		if !readObject(w, nested, 256, []string{"startsAt", "endsAt"}, &d) {
			return nil, false
		}
		start, e1 := time.Parse(time.RFC3339Nano, d.StartsAt)
		end, e2 := time.Parse(time.RFC3339Nano, d.EndsAt)
		if e1 != nil || e2 != nil || start.Location() != time.UTC || end.Location() != time.UTC || start.Format(time.RFC3339Nano) != d.StartsAt || end.Format(time.RFC3339Nano) != d.EndsAt {
			fail(w, 400, "invalid_windows_maintenance", "Choose exact canonical UTC occurrence dates.")
			return nil, false
		}
		if start.Year() < 1970 || end.Year() < 1970 || end.Sub(start) < time.Minute || end.Sub(start) > 24*time.Hour || len(dates) > 0 && (start.Sub(dates[len(dates)-1].StartsAt) != 7*24*time.Hour || end.Sub(dates[len(dates)-1].EndsAt) != 7*24*time.Hour) {
			fail(w, 400, "invalid_windows_maintenance", "Review equal one-minute through 24-hour windows exactly seven UTC days apart.")
			return nil, false
		}
		dates = append(dates, store.WindowsMaintenanceSeriesDates{StartsAt: start, EndsAt: end})
	}
	return dates, true
}

type windowsMaintenanceSeriesTargetView struct {
	Key                string                                     `json:"key"`
	DeviceID           string                                     `json:"deviceId"`
	Domain             string                                     `json:"domain"`
	Revision           uint64                                     `json:"revision"`
	ChangedAt          *time.Time                                 `json:"changedAt"`
	RetiredOccurrences uint64                                     `json:"retiredOccurrences"`
	RemainingSlots     int                                        `json:"remainingSlots"`
	ImmediateActive    bool                                       `json:"immediateActive"`
	LegacyReserved     bool                                       `json:"legacyReserved"`
	Occurrences        []store.WindowsMaintenanceSeriesOccurrence `json:"occurrences"`
}
type windowsMaintenanceSeriesView struct {
	SchemaVersion      string                               `json:"schemaVersion"`
	ServerNow          time.Time                            `json:"serverNow"`
	AuthorityExpiresAt time.Time                            `json:"authorityExpiresAt"`
	Targets            []windowsMaintenanceSeriesTargetView `json:"targets"`
}
type windowsMaintenanceSeriesReceiptView struct {
	SchemaVersion string    `json:"schemaVersion"`
	OperationID   string    `json:"operationId"`
	Key           string    `json:"key"`
	Action        string    `json:"action"`
	Revision      uint64    `json:"revision"`
	OccurrenceIDs []uint64  `json:"occurrenceIds"`
	CommittedAt   time.Time `json:"committedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

func seriesReceiptView(r store.WindowsMaintenanceSeriesReceipt) windowsMaintenanceSeriesReceiptView {
	return windowsMaintenanceSeriesReceiptView{"tracebolt.windows-maintenance-series-receipt.v1", r.OperationID, r.Target.Key(), r.Action, r.Revision, r.OccurrenceIDs, r.CommittedAt, r.ExpiresAt}
}
func projectWindowsMaintenanceSeries(states []store.WindowsMaintenanceSeriesState, legacy []store.WindowsMaintenanceScheduleState, immediate []store.WindowsMaintenanceState, authority map[string]windowscapacity.Input, now time.Time) (windowsMaintenanceSeriesView, error) {
	base, e := projectWindowsMaintenanceSchedules(legacy, immediate, authority, now)
	v := windowsMaintenanceSeriesView{SchemaVersion: "tracebolt.windows-maintenance-series.v1", ServerNow: now, AuthorityExpiresAt: base.AuthorityExpiresAt, Targets: []windowsMaintenanceSeriesTargetView{}}
	if e != nil {
		return v, e
	}
	byKey := map[string]store.WindowsMaintenanceSeriesState{}
	for _, s := range states {
		byKey[s.Target.Key()] = s
	}
	for _, b := range base.Targets {
		row := windowsMaintenanceSeriesTargetView{Key: b.Key, DeviceID: b.DeviceID, Domain: b.Domain, RemainingSlots: b.RemainingSlots, ImmediateActive: b.ImmediateActive, Occurrences: []store.WindowsMaintenanceSeriesOccurrence{}}
		for _, s := range legacy {
			if s.Target.DeviceID == b.DeviceID && s.Target.Key() == maintenanceTarget(authority[b.DeviceID], s.Target.Domain).Key() && (s.Target.Domain == "all" || b.Domain == "all" || b.Domain == s.Target.Domain) {
				for _, w := range s.Windows {
					if w.Pending(now) || w.Active(now) {
						row.LegacyReserved = true
					}
				}
			}
		}
		if s, ok := byKey[b.Key]; ok {
			if now.Before(s.ObservedAt) || now.Before(s.ChangedAt) {
				return v, store.ErrWindowsMaintenanceConflict
			}
			row.Revision = s.Revision
			row.ChangedAt = inboxStamp(s.ChangedAt)
			row.RetiredOccurrences = s.RetiredOccurrences
			row.RemainingSlots -= len(s.Occurrences)
			terminal := 0
			for i := len(s.Occurrences) - 1; i >= 0; i-- {
				o := s.Occurrences[i]
				if o.Pending(now) || o.Active(now) {
					row.Occurrences = append(row.Occurrences, o)
				} else if terminal < 4 {
					row.Occurrences = append(row.Occurrences, o)
					terminal++
				}
			}
		}
		if row.RemainingSlots < 0 {
			return v, store.ErrWindowsMaintenanceConflict
		}
		v.Targets = append(v.Targets, row)
	}
	return v, nil
}

type windowsMaintenanceSeriesReservation struct {
	Key            string `json:"key"`
	SeriesReserved bool   `json:"seriesReserved"`
	RemainingSlots int    `json:"remainingSlots"`
}
type windowsMaintenanceSeriesLegacyView struct {
	SchemaVersion string                                `json:"schemaVersion"`
	Legacy        windowsMaintenanceScheduleView        `json:"legacy"`
	Reservations  []windowsMaintenanceSeriesReservation `json:"reservations"`
}

// The legacy DTO remains byte-compatible. Series reservations and the combined
// retained-slot budget belong to this new envelope, never to the v1 window list.
func projectWindowsMaintenanceSeriesLegacy(legacy []store.WindowsMaintenanceScheduleState, series []store.WindowsMaintenanceSeriesState, immediate []store.WindowsMaintenanceState, authority map[string]windowscapacity.Input, now time.Time) (windowsMaintenanceSeriesLegacyView, error) {
	base, e := projectWindowsMaintenanceSchedules(legacy, immediate, authority, now)
	v := windowsMaintenanceSeriesLegacyView{SchemaVersion: "tracebolt.windows-maintenance-series-legacy.v1", Legacy: base, Reservations: []windowsMaintenanceSeriesReservation{}}
	if e != nil {
		return v, e
	}
	for _, row := range base.Targets {
		reservation := windowsMaintenanceSeriesReservation{Key: row.Key, RemainingSlots: row.RemainingSlots}
		for _, state := range series {
			in, ok := authority[state.Target.DeviceID]
			if !ok || !in.Authorized || maintenanceTarget(in, state.Target.Domain) != state.Target {
				continue
			}
			if now.Before(state.ObservedAt) || now.Before(state.ChangedAt) {
				return v, store.ErrWindowsMaintenanceConflict
			}
			if state.Target.Key() == row.Key {
				reservation.RemainingSlots -= len(state.Occurrences)
			}
			if state.Target.DeviceID != row.DeviceID || !(state.Target.Domain == "all" || row.Domain == "all" || state.Target.Domain == row.Domain) {
				continue
			}
			for _, occurrence := range state.Occurrences {
				if occurrence.Pending(now) || occurrence.Active(now) {
					reservation.SeriesReserved = true
				}
			}
		}
		if reservation.RemainingSlots < 0 {
			return v, store.ErrWindowsMaintenanceConflict
		}
		v.Reservations = append(v.Reservations, reservation)
	}
	return v, nil
}

func (h *operatorHandler) windowsMaintenanceSeriesAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	review := path == maintenanceSeriesPath+"/review" || path == maintenanceSeriesPath+"/cancel/review" || path == maintenanceSeriesPath+"/end/review"
	commit := path == maintenanceSeriesPath+"/commit"
	receiptRead := strings.HasPrefix(path, maintenanceSeriesPath+"/receipts/")
	mutation := review || commit
	legacyRead := path == maintenanceSeriesPath+"/legacy"
	if !legacyRead && path != maintenanceSeriesPath && !mutation && !receiptRead {
		fail(w, 404, "not_found", "Maintenance series is unavailable.")
		return
	}
	method := "GET"
	if mutation {
		method = "POST"
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_windows_maintenance", "Maintenance does not accept query parameters.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows maintenance is not configured.")
		return
	}
	operator, ok := operatorContext(r)
	if !ok {
		fail(w, 401, "authentication_required", "An authenticated operator is required.")
		return
	}
	var plan maintenanceSeriesPlan
	operationID := ""
	if mutation {
		if operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change planned maintenance.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if commit {
			var body struct {
				ReviewToken  string `json:"reviewToken"`
				OperationID  string `json:"operationId"`
				Acknowledged bool   `json:"acknowledged"`
			}
			if !readObject(w, r, 12288, []string{"reviewToken", "operationId", "acknowledged"}, &body) {
				return
			}
			var valid bool
			plan, valid = h.verifyMaintenanceSeries(body.ReviewToken)
			if !valid || !body.Acknowledged || body.OperationID != plan.OperationID || plan.Session != seriesSession(operator.session.ID) {
				fail(w, 409, "windows_maintenance_conflict", "The exact acknowledged review is no longer available. Read before reviewing again.")
				return
			}
		} else if path == maintenanceSeriesPath+"/review" {
			var body struct {
				Key         string            `json:"key"`
				Revision    uint64            `json:"revision"`
				Intent      string            `json:"intent"`
				Occurrences []json.RawMessage `json:"occurrences"`
			}
			if !readObject(w, r, 2048, []string{"key", "revision", "intent", "occurrences"}, &body) {
				return
			}
			dates, valid := seriesDates(w, r, body.Occurrences)
			if !valid {
				return
			}
			plan = maintenanceSeriesPlan{Key: body.Key, Revision: body.Revision, Intent: body.Intent, Occurrences: dates, Action: "create"}
		} else {
			var body struct {
				Key          string `json:"key"`
				Revision     uint64 `json:"revision"`
				OccurrenceID uint64 `json:"occurrenceId"`
			}
			if !readObject(w, r, 512, []string{"key", "revision", "occurrenceId"}, &body) {
				return
			}
			action := "cancel"
			if path == maintenanceSeriesPath+"/end/review" {
				action = "end"
			}
			if body.OccurrenceID < 1 || body.OccurrenceID > store.MaxWindowsMaintenanceRevision {
				fail(w, 400, "invalid_windows_maintenance", "Choose an exact retained occurrence.")
				return
			}
			plan = maintenanceSeriesPlan{Key: body.Key, Revision: body.Revision, OccurrenceID: body.OccurrenceID, Action: action}
		}
		if !enrollmentcrypto.ValidHash(plan.Key) || plan.Revision >= store.MaxWindowsMaintenanceRevision || plan.Action == "create" && !store.ValidWindowsMaintenanceIntent(plan.Intent) {
			fail(w, 400, "invalid_windows_maintenance", "Choose the exact current target, revision and maintenance purpose.")
			return
		}
		release, valid := beginOperatorMutation(w, r)
		if !valid {
			return
		}
		defer release()
	} else if receiptRead {
		operationID = strings.TrimPrefix(path, maintenanceSeriesPath+"/receipts/")
		if !validSeriesOperationID(operationID) {
			fail(w, 400, "invalid_windows_maintenance", "Choose the exact operation receipt.")
			return
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	inputs, err := m.source.WindowsCapacityInputs(r.Context(), started)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsCapacityAuthority(inputs, started)
	if err != nil {
		fail(w, 503, "windows_maintenance_unavailable", "Current Windows identity authority is unavailable.")
		return
	}
	lastChecked := started
	recheck := func() bool {
		if !operatorStillActive(w, r) {
			return false
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) || at.Before(lastChecked) {
			fail(w, 409, "windows_maintenance_conflict", "The time reference changed. Refresh maintenance.")
			return false
		}
		current, e := m.source.WindowsCapacityInputs(r.Context(), at)
		if e != nil {
			systemInventoryError(w, e)
			return false
		}
		latest, e := windowsCapacityAuthority(current, at)
		if e != nil || len(latest) != len(authority) {
			fail(w, 409, "windows_maintenance_conflict", "Windows authority changed. Refresh maintenance.")
			return false
		}
		for id, in := range authority {
			v, ok := latest[id]
			if !ok || v.Authorized != in.Authorized || in.Authorized && (v.InvitationID != in.InvitationID || v.CertificateHash != in.CertificateHash || !v.AuthorityUntil.Equal(in.AuthorityUntil)) {
				fail(w, 409, "windows_maintenance_conflict", "Windows authority changed. Refresh maintenance.")
				return false
			}
		}
		final := m.source.Now().UTC()
		if !contactReadTime(started, final) || final.Before(at) {
			fail(w, 409, "windows_maintenance_conflict", "The time reference changed. Refresh maintenance.")
			return false
		}
		for _, in := range latest {
			if in.Authorized && !final.Before(in.AuthorityUntil) {
				fail(w, 409, "windows_maintenance_conflict", "Windows authority expired. Refresh maintenance.")
				return false
			}
		}
		authority = latest
		lastChecked = final
		return operatorStillActive(w, r)
	}
	conflict := func(e error) bool {
		if e == nil {
			return false
		}
		if errors.Is(e, store.ErrWindowsMaintenanceConflict) {
			fail(w, 409, "windows_maintenance_conflict", "The revision, occurrences, time or authority changed. Read before reviewing again.")
		} else if errors.Is(e, store.ErrLimit) {
			fail(w, 409, "windows_maintenance_capacity", "The bounded maintenance metadata capacity is full.")
		} else {
			fail(w, 503, "windows_maintenance_unavailable", "The operation could not be confirmed. Read its receipt without repeating the write.")
		}
		return true
	}
	var response any
	deadline := started.Add(120 * time.Second)
	for _, in := range authority {
		if in.Authorized && in.AuthorityUntil.Before(deadline) {
			deadline = in.AuthorityUntil
		}
	}
	if operator.session.ExpiresAt.Before(deadline) {
		deadline = operator.session.ExpiresAt
	}
	if mutation {
		var target store.WindowsMaintenanceTarget
		var in windowscapacity.Input
		for _, current := range authority {
			if !current.Authorized {
				continue
			}
			for _, domain := range store.WindowsMaintenanceDomains() {
				candidate := maintenanceTarget(current, domain)
				if candidate.Key() == plan.Key {
					target, in = candidate, current
				}
			}
		}
		if !target.Valid() {
			fail(w, 409, "windows_maintenance_conflict", "The exact device identity or scope changed. Refresh maintenance.")
			return
		}
		if commit && (!validSeriesOperationID(plan.OperationID) || started.Before(plan.IssuedAt) || !started.Before(plan.ExpiresAt) || plan.ExpiresAt.After(plan.IssuedAt.Add(120*time.Second))) {
			fail(w, 409, "windows_maintenance_conflict", "The original review expired. Read its receipt before reviewing again.")
			return
		}
		if !recheck() {
			return
		}
		lease, valid := m.source.(windowsIncidentAuthoritySource)
		if !valid {
			fail(w, 503, "windows_maintenance_unavailable", "Current Windows authority cannot be locked.")
			return
		}
		var receipt store.WindowsMaintenanceSeriesReceipt
		err = lease.WithWindowsIncidentAuthority(r.Context(), in.Input, func(authorityGuard func(time.Time) error) error {
			guard := func(sampled, until time.Time) error {
				at := m.source.Now().UTC()
				op, live := operatorContext(r)
				if !live || op.active == nil || !op.active() || r.Context().Err() != nil || !contactReadTime(started, at) || at.Before(lastChecked) || at.Before(sampled) || !at.Before(in.AuthorityUntil) || !until.IsZero() && !at.Before(until) || commit && !at.Before(plan.ExpiresAt) {
					return store.ErrWindowsMaintenanceConflict
				}
				if e := authorityGuard(at); e != nil {
					return store.ErrWindowsMaintenanceConflict
				}
				final := m.source.Now().UTC()
				if !contactReadTime(started, final) || final.Before(at) || !final.Before(in.AuthorityUntil) || !until.IsZero() && !final.Before(until) || commit && !final.Before(plan.ExpiresAt) || !op.active() || r.Context().Err() != nil {
					return store.ErrWindowsMaintenanceConflict
				}
				lastChecked = final
				return nil
			}
			if e := guard(started, deadline); e != nil {
				return e
			}
			if commit {
				var e error
				dates, intent := plan.Occurrences, plan.Intent
				if plan.Action != "create" {
					dates, intent = nil, ""
				}
				receipt, e = m.store.ChangeWindowsMaintenanceSeries(r.Context(), target, plan.Revision, plan.Action, plan.OccurrenceID, dates, intent, plan.OperationID, plan.IssuedAt, plan.ExpiresAt, m.source.Now, guard)
				return e
			}
			if plan.Action != "create" {
				states, e := m.store.WindowsMaintenanceSeries(r.Context(), m.source.Now)
				if e != nil {
					return e
				}
				found := false
				for _, s := range states {
					if s.Target != target {
						continue
					}
					for _, o := range s.Occurrences {
						if o.ID == plan.OccurrenceID {
							plan.Intent = o.Intent
							plan.Occurrences = []store.WindowsMaintenanceSeriesDates{{StartsAt: o.StartsAt, EndsAt: o.EndsAt}}
							found = true
						}
					}
				}
				if !found {
					return store.ErrWindowsMaintenanceConflict
				}
			}
			dates, intent := plan.Occurrences, plan.Intent
			if plan.Action != "create" {
				dates, intent = nil, ""
			}
			if e := m.store.PreviewWindowsMaintenanceSeries(r.Context(), target, plan.Revision, plan.Action, plan.OccurrenceID, dates, intent, m.source.Now); e != nil {
				return e
			}
			return guard(started, deadline)
		})
		if conflict(err) {
			return
		}
		if commit {
			response = seriesReceiptView(receipt)
			if receipt.CommittedAt.After(lastChecked) {
				lastChecked = receipt.CommittedAt
			}
		} else {
			// Millisecond-issued identifiers can never be reused after bounded receipt retirement.
			plan.IssuedAt = started.Truncate(time.Millisecond)
			plan.ExpiresAt = deadline
			if max := plan.IssuedAt.Add(120 * time.Second); plan.ExpiresAt.After(max) {
				plan.ExpiresAt = max
			}
			plan.Session = seriesSession(operator.session.ID)
			plan.OperationID, err = seriesOperationID(plan.IssuedAt)
			if conflict(err) {
				return
			}
			token, e := h.signMaintenanceSeries(plan)
			if conflict(e) {
				return
			}
			response = struct {
				SchemaVersion string                                `json:"schemaVersion"`
				ReviewToken   string                                `json:"reviewToken"`
				OperationID   string                                `json:"operationId"`
				ExpiresAt     time.Time                             `json:"expiresAt"`
				Key           string                                `json:"key"`
				Revision      uint64                                `json:"revision"`
				Action        string                                `json:"action"`
				OccurrenceID  uint64                                `json:"occurrenceId"`
				Intent        string                                `json:"intent"`
				Occurrences   []store.WindowsMaintenanceSeriesDates `json:"occurrences"`
			}{"tracebolt.windows-maintenance-series-review.v1", token, plan.OperationID, plan.ExpiresAt, plan.Key, plan.Revision, plan.Action, plan.OccurrenceID, plan.Intent, plan.Occurrences}
			deadline = plan.ExpiresAt
		}
	} else if receiptRead {
		receipt, found, e := m.store.WindowsMaintenanceSeriesReceipt(r.Context(), operationID)
		if conflict(e) {
			return
		}
		if found {
			current, ok := authority[receipt.Target.DeviceID]
			if !ok || !current.Authorized || maintenanceTarget(current, receipt.Target.Domain) != receipt.Target {
				fail(w, 409, "windows_maintenance_conflict", "The receipt identity is no longer admitted.")
				return
			}
			response = seriesReceiptView(receipt)
		} else {
			response = struct {
				SchemaVersion string `json:"schemaVersion"`
				OperationID   string `json:"operationId"`
				Status        string `json:"status"`
			}{"tracebolt.windows-maintenance-series-unresolved.v1", operationID, "unresolved"}
		}
	} else {
		legacy, states, immediate, e := m.store.ReadWindowsMaintenancePlanning(r.Context(), m.source.Now)
		if conflict(e) {
			return
		}
		if !recheck() {
			return
		}
		now := m.source.Now().UTC()
		if legacyRead {
			view, e := projectWindowsMaintenanceSeriesLegacy(legacy, states, immediate, authority, now)
			if conflict(e) {
				return
			}
			response = view
			deadline = view.Legacy.AuthorityExpiresAt
		} else {
			view, e := projectWindowsMaintenanceSeries(states, legacy, immediate, authority, now)
			if conflict(e) {
				return
			}
			response = view
			deadline = view.AuthorityExpiresAt
		}
		lastChecked = now
	}
	if !recheck() {
		return
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw)+1 > 262144 {
		fail(w, 503, "windows_maintenance_unavailable", "Maintenance exceeds its bounded response.")
		return
	}
	defer clear(raw)
	final := m.source.Now().UTC()
	if !contactReadTime(started, final) || final.Before(lastChecked) || !final.Before(deadline) {
		fail(w, 409, "windows_maintenance_conflict", "The time reference or authority changed. Read before reviewing again.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
