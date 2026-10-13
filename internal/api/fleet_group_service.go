package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsservicehealth"
)

type fleetGroupServiceMember struct {
	Key      string                      `json:"key"`
	DeviceID string                      `json:"deviceId"`
	Name     string                      `json:"name"`
	Policy   windowsservicehealth.Policy `json:"policy"`
}
type fleetGroupServiceView struct {
	SchemaVersion        string                    `json:"schemaVersion"`
	ServerNow            time.Time                 `json:"serverNow"`
	AuthorityExpiresAt   time.Time                 `json:"authorityExpiresAt"`
	GroupID              string                    `json:"groupId"`
	GroupName            string                    `json:"groupName"`
	GroupRevision        uint64                    `json:"groupRevision"`
	ExcludedLinuxMembers int                       `json:"excludedLinuxMembers"`
	UnavailableMembers   int                       `json:"unavailableMembers"`
	Members              []fleetGroupServiceMember `json:"members"`
}
type fleetGroupServiceChoice struct {
	fleetGroupServiceMember
	Inventory *windowsservicehealth.Inventory `json:"inventory"`
}
type fleetGroupServiceChoiceView struct {
	SchemaVersion      string                  `json:"schemaVersion"`
	ServerNow          time.Time               `json:"serverNow"`
	AuthorityExpiresAt time.Time               `json:"authorityExpiresAt"`
	GroupID            string                  `json:"groupId"`
	GroupName          string                  `json:"groupName"`
	GroupRevision      uint64                  `json:"groupRevision"`
	Member             fleetGroupServiceChoice `json:"member"`
}

// Original membership is resolved server-side. A mutable device ID or name alone
// never joins a replacement identity to either the chooser or the policy write.
func projectFleetGroupService(read fleetGroupMaintenanceRead, authority map[string]windowscapacity.Input, states map[string]windowsservicehealth.State, now time.Time) (fleetGroupServiceView, map[string]windowscapacity.Input, error) {
	return projectFleetGroupServiceMode(read, authority, states, now, false)
}
func projectFleetGroupServiceMode(read fleetGroupMaintenanceRead, authority map[string]windowscapacity.Input, states map[string]windowsservicehealth.State, now time.Time, complete bool) (fleetGroupServiceView, map[string]windowscapacity.Input, error) {
	g := read.group
	v := fleetGroupServiceView{SchemaVersion: "tracebolt.fleet-group-service-checks.v1", ServerNow: now, AuthorityExpiresAt: now.Add(120 * time.Second), GroupID: g.ID, GroupName: g.Name, GroupRevision: g.Revision, Members: []fleetGroupServiceMember{}}
	if complete {
		v.SchemaVersion = "tracebolt.fleet-group-service-checks.v2"
	}
	selected := map[string]windowscapacity.Input{}
	seen := map[string]bool{}
	if len(g.Members) > store.MaxFleetGroupMembers || g.Manager != monitoringManager(read.binding) {
		return v, selected, store.ErrWindowsMaintenanceConflict
	}
	for _, member := range g.Members {
		if seen[member.DeviceID] {
			return v, selected, store.ErrWindowsMaintenanceConflict
		}
		seen[member.DeviceID] = true
		d, ok := read.devices[member.DeviceID]
		if !ok || d.identity != member.Identity {
			v.UnavailableMembers++
			continue
		}
		if !now.Before(d.expires) {
			return v, selected, store.ErrWindowsMaintenanceConflict
		}
		if d.expires.Before(v.AuthorityExpiresAt) {
			v.AuthorityExpiresAt = d.expires
		}
		if d.Platform == "linux" {
			v.ExcludedLinuxMembers++
			continue
		}
		in, ok := authority[member.DeviceID]
		if d.Platform != "windows" || !ok || !in.Authorized || member.Identity != monitoringIdentity(read.binding, in.Input) {
			v.UnavailableMembers++
			continue
		}
		if !now.Before(in.AuthorityUntil) {
			return v, selected, store.ErrWindowsMaintenanceConflict
		}
		if in.AuthorityUntil.Before(v.AuthorityExpiresAt) {
			v.AuthorityExpiresAt = in.AuthorityUntil
		}
		state := windowsservicehealth.New()
		if complete {
			state = windowsservicehealth.NewComplete()
		}
		if retained, ok := states[member.DeviceID]; ok {
			if (retained.SchemaVersion == windowsservicehealth.CompleteStateSchema) != complete || retained.InvitationID != in.InvitationID || retained.CertificateHash != in.CertificateHash {
				v.UnavailableMembers++
				continue
			}
			state = retained
		}
		key := maintenanceTarget(in, "service").Key()
		selected[key] = in
		v.Members = append(v.Members, fleetGroupServiceMember{key, in.DeviceID, d.Name, state.Policy})
	}
	if len(v.Members) > 25 {
		return v, selected, store.ErrWindowsMaintenanceConflict
	}
	sort.Slice(v.Members, func(i, j int) bool { return v.Members[i].DeviceID < v.Members[j].DeviceID })
	return v, selected, nil
}

func (h *operatorHandler) fleetGroupServiceAPI(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(r.URL.Path, "/")
	if (len(p) != 6 && len(p) != 7) || p[1] != "api" || p[2] != "fleet" || p[3] != "groups" || !enrollmentcrypto.ValidID(p[4], "group_") || (p[5] != "service-checks" && p[5] != "service-checks-complete") || len(p) == 7 && !enrollmentcrypto.ValidHash(p[6]) {
		fail(w, 404, "not_found", "Group service checks are unavailable.")
		return
	}
	complete := p[5] == "service-checks-complete"
	detail := len(p) == 7
	mutation := r.Method == http.MethodPost && detail
	if r.Method != http.MethodGet && !mutation {
		w.Header().Set("Allow", "GET")
		if detail {
			w.Header().Set("Allow", "GET, POST")
		}
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_group_service", "Query parameters are unsupported.")
		return
	}
	m := h.app.windowsCapacity
	if m == nil {
		fail(w, 404, "not_found", "Windows service checks are not configured.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	var body struct {
		GroupRevision    uint64                           `json:"groupRevision"`
		ExpectedRevision uint64                           `json:"expectedRevision"`
		Enabled          bool                             `json:"enabled"`
		Services         []string                         `json:"services"`
		Consent          bool                             `json:"consent"`
		Source           *windowsservicehealth.Provenance `json:"source"`
	}
	if mutation {
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		fields := []string{"groupRevision", "expectedRevision", "enabled", "services", "consent"}
		if complete {
			fields = append(fields, "source")
		}
		if !readObject(w, r, 32<<10, fields, &body) {
			return
		}
		if !body.Consent || body.GroupRevision < 1 || body.GroupRevision > store.MaxFleetGroupRevision || body.ExpectedRevision >= windowsservicehealth.MaxCounter {
			fail(w, 400, "invalid_group_service", "Review the exact settings and explicitly confirm them.")
			return
		}
		validateNames := windowsservicehealth.Services
		if complete {
			validateNames = windowsservicehealth.CompleteServices
		}
		if _, err := validateNames(body.Services); err != nil || body.Enabled && len(body.Services) == 0 {
			fail(w, 400, "invalid_group_service", "Choose up to eight exact reported service names.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.source.Now().UTC()
	var read *fleetGroupMaintenanceRead
	var view fleetGroupServiceView
	var selected map[string]windowscapacity.Input
	var expected windowscapacity.Input
	refresh := func() error {
		var err error
		read, err = h.readFleetGroupMaintenance(ctx, p[4], started)
		if err != nil {
			return err
		}
		states, err := m.store.WindowsServiceStates(ctx)
		if err != nil {
			return err
		}
		at := m.source.Now().UTC()
		if !contactReadTime(started, at) {
			return store.ErrWindowsMaintenanceConflict
		}
		sourceCtx := ctx
		if complete && detail && expected.DeviceID != "" {
			names := []string{}
			if state, ok := states[expected.DeviceID]; ok {
				names = state.Policy.Services
			}
			if mutation {
				names = body.Services
			}
			sourceCtx = windowsservicehealth.WithCompleteSelections(ctx, map[string][]string{expected.DeviceID: names})
		}
		rows, err := m.source.WindowsCapacityInputs(sourceCtx, at)
		if err != nil {
			return err
		}
		authority, err := windowsCapacityAuthority(rows, at)
		if err != nil {
			return err
		}
		now := m.source.Now().UTC()
		if !contactReadTime(started, now) || now.Before(at) {
			return store.ErrWindowsMaintenanceConflict
		}
		view, selected, err = projectFleetGroupServiceMode(*read, authority, states, now, complete)
		return err
	}
	if err := refresh(); err != nil {
		fleetGroupServiceError(w, err)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	if detail {
		var ok bool
		expected, ok = selected[p[6]]
		if !ok {
			fail(w, 409, "group_service_conflict", "The exact group member is unavailable.")
			return
		}
	}
	if complete && detail {
		if err := refresh(); err != nil {
			fleetGroupServiceError(w, err)
			return
		}
		current, ok := selected[p[6]]
		if !ok || current.InvitationID != expected.InvitationID || current.CertificateHash != expected.CertificateHash || !current.AuthorityUntil.Equal(expected.AuthorityUntil) || complete && current.CurrentLeaf != expected.CurrentLeaf {
			fleetGroupServiceError(w, store.ErrWindowsMaintenanceConflict)
			return
		}
		expected = current
	}
	if mutation {
		if body.GroupRevision != view.GroupRevision {
			fail(w, 409, "group_service_conflict", "Group membership changed. Review again.")
			return
		}
		selection := store.FleetGroupMaintenanceSelection{Manager: read.group.Manager, GroupID: p[4], GroupRevision: body.GroupRevision, Identity: monitoringIdentity(read.binding, expected.Input)}
		configure := func(guard func(time.Time) error) (windowsservicehealth.State, error) {
			return m.store.ConfigureFleetGroupService(ctx, selection, windowsservicehealth.Input{Input: expected.Input, Sample: expected.Services, Complete: complete, Selection: body.Source}, body.Enabled, body.Services, body.ExpectedRevision, m.source.Now, guard)
		}
		var err error
		if complete {
			_, err = h.withWindowsCompleteServicePolicyAuthority(r, expected, body.Source, started, configure)
		} else {
			_, err = h.withWindowsServicePolicyAuthority(r, expected, started, configure)
		}
		if err != nil {
			fleetGroupServiceError(w, err)
			return
		}
	}
	// A post-commit read failure remains uncertain to the caller; never replay.
	original := view
	if err := refresh(); err != nil {
		fleetGroupServiceError(w, err)
		return
	}
	if original.GroupRevision != view.GroupRevision || original.GroupName != view.GroupName {
		fail(w, 409, "group_service_conflict", "Group changed. Read the current settings without repeating the write.")
		return
	}
	if original.AuthorityExpiresAt.Before(view.AuthorityExpiresAt) {
		view.AuthorityExpiresAt = original.AuthorityExpiresAt
	}
	var response any = view
	if detail {
		current, ok := selected[p[6]]
		if !ok || current.InvitationID != expected.InvitationID || current.CertificateHash != expected.CertificateHash || !current.AuthorityUntil.Equal(expected.AuthorityUntil) || complete && current.CurrentLeaf != expected.CurrentLeaf {
			fail(w, 409, "group_service_conflict", "Device authority changed. Review again.")
			return
		}
		for _, member := range view.Members {
			if member.Key == p[6] {
				schema := "tracebolt.fleet-group-service-choice.v1"
				if complete {
					schema = "tracebolt.fleet-group-service-choice.v2"
				}
				inventory := (windowsservicehealth.Input{Input: current.Input, Sample: current.Services, Complete: complete}).Inventory(view.ServerNow)
				if complete && inventory != nil {
					rows := []windowsservicehealth.Choice{}
					for _, row := range inventory.Services {
						for _, name := range member.Policy.Services {
							if row.Name == name {
								rows = append(rows, row)
							}
						}
					}
					inventory.Services = rows
				}
				response = fleetGroupServiceChoiceView{SchemaVersion: schema, ServerNow: view.ServerNow, AuthorityExpiresAt: view.AuthorityExpiresAt, GroupID: view.GroupID, GroupName: view.GroupName, GroupRevision: view.GroupRevision, Member: fleetGroupServiceChoice{member, inventory}}
			}
		}
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw)+1 > 262144 {
		fail(w, 503, "group_service_unavailable", "Service settings exceed the bounded response.")
		return
	}
	defer clear(raw)
	final := m.source.Now().UTC()
	if !contactReadTime(started, final) || final.Before(view.ServerNow) || !final.Before(view.AuthorityExpiresAt) {
		fail(w, 409, "group_service_conflict", "Authority or time changed. Review again.")
		return
	}
	if complete && detail {
		if choice, ok := response.(fleetGroupServiceChoiceView); ok && choice.Member.Inventory != nil && (choice.Member.Inventory.Source == nil || !choice.Member.Inventory.Source.Fresh(final)) {
			fleetGroupServiceError(w, windowsservicehealth.ErrInvalid)
			return
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

func fleetGroupServiceError(w http.ResponseWriter, err error) {
	if errors.Is(err, errFleetMaintenanceGroupMissing) {
		fail(w, 404, "not_found", "Group no longer exists.")
	} else if errors.Is(err, store.ErrWindowsMaintenanceConflict) || errors.Is(err, windowsservicehealth.ErrInvalid) {
		fail(w, 409, "group_service_conflict", "Membership, service selection, policy or authority changed. Review again.")
	} else {
		fail(w, 503, "group_service_unavailable", "Service settings are unavailable. Read current settings before another review.")
	}
}
