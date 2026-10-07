package api

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/health"
	"localrmm/internal/store"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

const investigationPageSize = 50
const investigationResponseBytes = 2 * 1024 * 1024

type investigationCounts struct {
	Open      int `json:"open"`
	Recovered int `json:"recovered"`
	Closed    int `json:"closed"`
	All       int `json:"all"`
}
type journalAISummary struct {
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expiresAt"`
}
type investigationItem struct {
	JournalAI *journalAISummary     `json:"journalAI,omitempty"`
	DeviceID  string                `json:"deviceId"`
	Incident  health.Incident       `json:"incident"`
	Analysis  *store.HealthAnalysis `json:"analysis,omitempty"`
}
type investigationsView struct {
	SchemaVersion string              `json:"schemaVersion"`
	ServerNow     time.Time           `json:"serverNow"`
	Scope         string              `json:"scope"`
	Offset        int                 `json:"offset"`
	Total         int                 `json:"total"`
	Counts        investigationCounts `json:"counts"`
	Devices       []health.View       `json:"devices"`
	Items         []investigationItem `json:"items"`
}

func investigationScope(x health.Incident) string {
	if x.ResolvedAt == nil {
		return "open"
	}
	if x.ClosedReason == "recovered" {
		return "recovered"
	}
	return "closed"
}
func investigationAuthority(inputs []health.Input) (map[string]bool, bool) {
	allowed := map[string]bool{}
	for _, input := range inputs {
		if !input.Authorized {
			continue
		}
		if !enrollmentcrypto.ValidID(input.DeviceID, "agent_") || allowed[input.DeviceID] {
			return nil, false
		}
		allowed[input.DeviceID] = true
	}
	return allowed, len(allowed) <= 25
}

// Investigations are a read-only projection of durable health incidents. A GET
// never evaluates a check, creates a case, acknowledges, enqueues or collects.
// The demo case engine and its AI/note/status endpoints are deliberately separate.
func (h *operatorHandler) investigations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	query, err := parseInvestigationQuery(r)
	if err != nil {
		fail(w, 400, "invalid_query", "Choose a supported investigation scope and page.")
		return
	}
	scope, offset := query.scope, query.offset
	m := h.app.health
	if m == nil {
		fail(w, 409, "health_unavailable", "Investigations require activated Linux v3 health checks.")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, err := m.source.HealthInputs(r.Context(), map[string][]string{}, now)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	allowed, valid := investigationAuthority(inputs)
	if !valid {
		fail(w, 503, "health_unavailable", "Investigation data is unavailable.")
		return
	}
	states, err := m.store.HealthStates(r.Context())
	if err != nil {
		fail(w, 503, "health_unavailable", "Investigation history is unavailable.")
		return
	}
	view := investigationsView{SchemaVersion: "tracebolt.investigations.v1", ServerNow: now, Scope: scope, Offset: offset, Devices: []health.View{}, Items: []investigationItem{}}
	ids := make([]string, 0, len(allowed))
	for id := range allowed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items := []investigationItem{}
	for _, id := range ids {
		state, ok := states[id]
		if !ok {
			state = health.New()
		}
		current := state.View(id, now)
		current.Incidents = []health.Incident{}
		view.Devices = append(view.Devices, current)
		for _, incident := range state.Incidents {
			bucket := investigationScope(incident)
			switch bucket {
			case "open":
				view.Counts.Open++
			case "recovered":
				view.Counts.Recovered++
			case "closed":
				view.Counts.Closed++
			}
			view.Counts.All++
			if scope == "all" || scope == bucket {
				items = append(items, investigationItem{DeviceID: id, Incident: incident})
			}
		}
	}
	// Stable paging for a fixed snapshot. New incidents may move the next page;
	// every response rechecks authority and reports its own counts and timestamp.
	sort.Slice(items, func(i, j int) bool {
		if !items[i].Incident.OpenedAt.Equal(items[j].Incident.OpenedAt) {
			return items[i].Incident.OpenedAt.After(items[j].Incident.OpenedAt)
		}
		if items[i].DeviceID != items[j].DeviceID {
			return items[i].DeviceID < items[j].DeviceID
		}
		return items[i].Incident.ID < items[j].Incident.ID
	})
	view.Total = len(items)
	if offset < len(items) {
		end := offset + investigationPageSize
		if end > len(items) {
			end = len(items)
		}
		view.Items = items[offset:end]
	}
	// Attach only the current page's durable local findings. Reading never starts
	// inference. The same final enrollment recheck protects both data classes.
	journalByIncident := map[string]journalAISummary{}
	if h.app.journalAI != nil {
		attempts, err := m.store.JournalAIAttempts(r.Context())
		if err != nil {
			fail(w, 503, "health_unavailable", "Log analysis receipts are unavailable.")
			return
		}
		for _, attempt := range attempts {
			state := attempt.State
			if state == "completed" && attempt.ExpiresAt != nil && !now.Before(*attempt.ExpiresAt) {
				state = "expired"
			}
			journalByIncident[journalAIKey(attempt.DeviceID, attempt.IncidentID)] = journalAISummary{State: state, ExpiresAt: attempt.ExpiresAt}
		}
	}
	analysisByDevice := map[string]map[string]store.HealthAnalysis{}
	for i := range view.Items {
		item := &view.Items[i]
		if summary, ok := journalByIncident[journalAIKey(item.DeviceID, item.Incident.ID)]; ok {
			item.JournalAI = &summary
		}
		if _, ok := analysisByDevice[item.DeviceID]; !ok {
			findings, err := m.store.HealthAnalyses(r.Context(), item.DeviceID)
			if err != nil {
				fail(w, 503, "health_unavailable", "Analysis history is unavailable.")
				return
			}
			analysisByDevice[item.DeviceID] = findings
		}
		if finding, ok := analysisByDevice[item.DeviceID][item.Incident.ID]; ok {
			item.Analysis = &finding
		}
	}
	raw, err := json.Marshal(view)
	if err != nil || len(raw) >= investigationResponseBytes-1 {
		fail(w, 503, "health_unavailable", "Investigation response is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	// Revalidate enrolled authority after state reads and encoding, immediately
	// before releasing the same bounded bytes. Loss of any included device fails
	// the whole response; retained history never grants access after revocation.
	at := m.source.Now().UTC()
	if at.Before(now) || at.Sub(now) > 5*time.Second {
		fail(w, 503, "health_unavailable", "Investigation time reference changed.")
		return
	}
	currentInputs, err := m.source.HealthInputs(r.Context(), map[string][]string{}, at)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	currentAllowed, valid := investigationAuthority(currentInputs)
	if !valid {
		fail(w, 503, "health_unavailable", "Investigation authority is unavailable.")
		return
	}
	for _, id := range ids {
		if !currentAllowed[id] {
			fail(w, 409, "health_unavailable", "Investigation authority changed. Refresh this view.")
			return
		}
	}
	finished := m.source.Now().UTC()
	if finished.Before(at) || finished.Sub(now) > 5*time.Second {
		fail(w, 503, "health_unavailable", "Investigation time reference changed.")
		return
	}
	for _, input := range currentInputs {
		if allowed[input.DeviceID] && (input.AuthorityUntil.IsZero() || !finished.Before(input.AuthorityUntil)) {
			fail(w, 409, "health_unavailable", "Investigation authority expired. Refresh this view.")
			return
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

type investigationQuery struct {
	scope  string
	offset int
}

func parseInvestigationQuery(r *http.Request) (investigationQuery, error) {
	out := investigationQuery{scope: "open"}
	if len(r.URL.RawQuery) > 128 {
		return out, health.ErrInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return out, err
	}
	for key, value := range values {
		if len(value) != 1 {
			return out, health.ErrInvalid
		}
		switch key {
		case "scope":
			switch value[0] {
			case "open", "recovered", "closed", "all":
				out.scope = value[0]
			default:
				return out, health.ErrInvalid
			}
		case "offset":
			n, err := strconv.Atoi(value[0])
			if err != nil || n < 0 || n > 2500 || n%investigationPageSize != 0 || strconv.Itoa(n) != value[0] {
				return out, health.ErrInvalid
			}
			out.offset = n
		default:
			return out, health.ErrInvalid
		}
	}
	return out, nil
}
