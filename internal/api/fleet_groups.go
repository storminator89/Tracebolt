package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"net/http"
	"sort"
	"strings"
	"time"
)

type fleetGroupSource interface {
	Snapshots(context.Context) ([]enrollmentstate.Snapshot, error)
	Devices(context.Context, time.Time) ([]model.Device, error)
	WindowsContactInputs(context.Context, time.Time) ([]windowscontact.Input, error)
	Binding() enrollmentstate.Binding
	Now() time.Time
	IssuerValidity() (time.Time, time.Time, error)
}

type fleetEnrollmentSource struct{ *enrollmentservice.Service }

func (s fleetEnrollmentSource) IssuerValidity() (time.Time, time.Time, error) {
	c, err := x509.ParseCertificate(s.IssuerDER())
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return c.NotBefore, c.NotAfter, nil
}

type fleetGroupDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	identity string
	expires  time.Time
}
type fleetGroupView struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Revision           uint64   `json:"revision"`
	MemberIDs          []string `json:"memberIds"`
	UnavailableMembers int      `json:"unavailableMembers"`
}
type fleetGroupsView struct {
	SchemaVersion string             `json:"schemaVersion"`
	ServerNow     time.Time          `json:"serverNow"`
	Groups        []fleetGroupView   `json:"groups"`
	Devices       []fleetGroupDevice `json:"devices"`
}

func fleetHash(value any) string {
	raw, _ := json.Marshal(value)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func (h *operatorHandler) groupSources() []fleetGroupSource {
	if h.fleetGroupSources != nil {
		return h.fleetGroupSources
	}
	sources := []fleetGroupSource{}
	if h.enrollment != nil {
		sources = append(sources, fleetEnrollmentSource{h.enrollment})
	}
	if h.windowsEnrollment != nil && h.windowsEnrollment.enrollment != nil && h.windowsEnrollment.enrollment != h.enrollment {
		sources = append(sources, fleetEnrollmentSource{h.windowsEnrollment.enrollment})
	}
	return sources
}
func fleetGroupAdmission(ctx context.Context, sources []fleetGroupSource) (string, time.Time, map[string]fleetGroupDevice, error) {
	if len(sources) == 0 || len(sources) > 2 {
		return "", time.Time{}, nil, store.ErrFleetGroupInvalid
	}
	// Scope the group catalog to this manager and transport, while retaining each
	// member's complete original collection/profile and issued-identity binding.
	binding := sources[0].Binding()
	manager := fleetHash([]string{binding.InstanceID, binding.Origin, binding.Profile, binding.IssuerFingerprint})
	now := sources[0].Now().UTC()
	admitted := map[string]fleetGroupDevice{}
	seenIDs := map[string]bool{}
	for _, source := range sources {
		issuerStart, issuerEnd, issuerErr := source.IssuerValidity()
		if issuerErr != nil || now.Before(issuerStart) || !now.Before(issuerEnd) {
			return "", now, nil, store.ErrFleetGroupConflict
		}
		b := source.Binding()
		if b.InstanceID != binding.InstanceID || b.Origin != binding.Origin || b.Profile != binding.Profile || b.IssuerFingerprint != binding.IssuerFingerprint {
			return "", now, nil, store.ErrFleetGroupInvalid
		}
		snapshots, err := source.Snapshots(ctx)
		if err != nil {
			return "", now, nil, err
		}
		if len(snapshots) > 25 {
			return "", now, nil, store.ErrFleetGroupInvalid
		}
		devices, err := source.Devices(ctx, now)
		if err != nil {
			return "", now, nil, err
		}
		if len(devices) > 25 {
			return "", now, nil, store.ErrFleetGroupInvalid
		}
		current := map[string]model.Device{}
		for _, d := range devices {
			if _, duplicate := current[d.ID]; duplicate {
				return "", now, nil, store.ErrFleetGroupInvalid
			}
			current[d.ID] = d
		}
		windows := map[string]windowscontact.Input{}
		if b.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
			rows, e := source.WindowsContactInputs(ctx, now)
			if e != nil {
				return "", now, nil, e
			}
			windows, e = windowsContactAuthority(rows, now)
			if e != nil {
				return "", now, nil, e
			}
		}
		for _, snap := range snapshots {
			if id := snap.Approval.DeviceID; id != "" {
				if seenIDs[id] {
					return "", now, nil, store.ErrFleetGroupInvalid
				}
				seenIDs[id] = true
			}
			if snap.State != enrollmentstate.Activated || snap.Binding != b {
				continue
			}
			id := snap.Approval.DeviceID
			d, ok := current[id]
			if !ok || !enrollmentcrypto.ValidID(id, "agent_") || !enrollmentcrypto.ValidID(snap.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(snap.Issuance.CertificateHash) || d.AgentCertificate == nil || d.AgentCertificate.ExpiresAt == nil || !now.Before(*d.AgentCertificate.ExpiresAt) {
				continue
			}
			expires := *d.AgentCertificate.ExpiresAt
			if renewal := d.AgentCertificate.Renewal; renewal != nil && renewal.AuthorityExpiresAt.Before(expires) {
				expires = renewal.AuthorityExpiresAt
			}
			platform := snap.Platform
			if platform != "windows" && platform != "linux" {
				continue
			}
			if platform == "windows" {
				v, ok := windows[id]
				if !ok || !v.Authorized || v.InvitationID != snap.InvitationID || v.CertificateHash != snap.Issuance.CertificateHash {
					continue
				}
				expires = v.AuthorityUntil
			}
			if issuerEnd.Before(expires) {
				expires = issuerEnd
			}
			if !now.Before(expires) {
				continue
			}
			if _, duplicate := admitted[id]; duplicate {
				return "", now, nil, store.ErrFleetGroupInvalid
			}
			name := d.Name
			if name == "" || len(name) > 256 {
				name = id
			}
			admitted[id] = fleetGroupDevice{ID: id, Name: name, Platform: platform, identity: fleetHash(struct {
				Binding                    enrollmentstate.Binding
				Device, Invitation, Issued string
			}{b, id, snap.InvitationID, snap.Issuance.CertificateHash}), expires: expires}
		}
		if !contactReadTime(now, source.Now().UTC()) {
			return "", now, nil, store.ErrFleetGroupConflict
		}
	}
	return manager, now, admitted, nil
}
func projectFleetGroups(groups []store.FleetGroup, devices map[string]fleetGroupDevice, now time.Time) fleetGroupsView {
	view := fleetGroupsView{SchemaVersion: "tracebolt.fleet-groups.v1", ServerNow: now, Groups: []fleetGroupView{}, Devices: []fleetGroupDevice{}}
	for _, d := range devices {
		view.Devices = append(view.Devices, d)
	}
	sort.Slice(view.Devices, func(i, j int) bool { return view.Devices[i].ID < view.Devices[j].ID })
	for _, g := range groups {
		v := fleetGroupView{ID: g.ID, Name: g.Name, Revision: g.Revision, MemberIDs: []string{}}
		for _, member := range g.Members {
			if d, ok := devices[member.DeviceID]; ok && d.identity == member.Identity {
				v.MemberIDs = append(v.MemberIDs, member.DeviceID)
			} else {
				v.UnavailableMembers++
			}
		}
		view.Groups = append(view.Groups, v)
	}
	return view
}
func (h *operatorHandler) fleetGroupsAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	id := ""
	remove := false
	valid := r.URL.RawQuery == "" && !r.URL.ForceQuery && len(parts) >= 4 && parts[1] == "api" && parts[2] == "fleet" && parts[3] == "groups"
	if len(parts) == 5 || len(parts) == 6 {
		id = parts[4]
		valid = valid && enrollmentcrypto.ValidID(id, "group_")
		if len(parts) == 6 {
			remove = parts[5] == "delete"
			valid = valid && remove
		}
	} else {
		valid = valid && len(parts) == 4
	}
	if !valid {
		fail(w, 404, "not_found", "Fleet group route is unavailable.")
		return
	}
	mutation := r.Method == http.MethodPost
	if !mutation && (r.Method != http.MethodGet || remove) {
		fail(w, 405, "method_not_allowed", "Use GET or POST.")
		return
	}
	var input struct {
		Name              string   `json:"name"`
		MemberIDs         []string `json:"memberIds"`
		Expected          uint64   `json:"expectedRevision"`
		RemoveUnavailable bool     `json:"removeUnavailableMembers"`
	}
	if mutation {
		operator, ok := operatorContext(r)
		if !ok || operator.session.Named() {
			fail(w, 403, "operator_capability_required", "A shared administrator is required to change groups.")
			return
		}
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		keys := []string{"name", "memberIds", "expectedRevision"}
		if id != "" && !remove {
			keys = append(keys, "removeUnavailableMembers")
		}
		if remove {
			keys = []string{"expectedRevision"}
		}
		if !readObject(w, r, 8192, keys, &input) {
			return
		}
		if input.Expected >= store.MaxFleetGroupRevision || id == "" && input.Expected != 0 || !remove && (!store.ValidFleetGroupName(input.Name) || input.MemberIDs == nil || len(input.MemberIDs) > store.MaxFleetGroupMembers) {
			fail(w, 400, "invalid_body", "Choose a group name, bounded member list and current revision.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	sources := h.groupSources()
	manager, now, devices, err := fleetGroupAdmission(r.Context(), sources)
	if err != nil {
		fail(w, 503, "fleet_groups_unavailable", "Current group membership is unavailable.")
		return
	}
	groups, err := h.app.store.FleetGroups(r.Context(), manager)
	if err != nil {
		fail(w, 503, "fleet_groups_unavailable", "Groups are unavailable.")
		return
	}
	var selected *store.FleetGroup
	if id != "" {
		for i := range groups {
			if groups[i].ID == id {
				selected = &groups[i]
				break
			}
		}
		if selected == nil {
			fail(w, 404, "not_found", "Group no longer exists.")
			return
		}
	}
	if mutation {
		if id == "" {
			var raw [16]byte
			if _, err = rand.Read(raw[:]); err != nil {
				fail(w, 503, "fleet_groups_unavailable", "Group could not be created.")
				return
			}
			id = "group_" + hex.EncodeToString(raw[:])
		}
		if remove {
			input.Name = selected.Name
			input.MemberIDs = []string{}
		}
		members := []store.FleetGroupMember{}
		seen := map[string]bool{}
		for _, memberID := range input.MemberIDs {
			d, ok := devices[memberID]
			if !ok || seen[memberID] {
				fail(w, 409, "fleet_group_conflict", "Membership changed. Refresh the group.")
				return
			}
			seen[memberID] = true
			members = append(members, store.FleetGroupMember{DeviceID: memberID, Identity: d.identity})
		}
		// Re-read admission before mutation; removed/replaced identities cannot be
		// rebound by merely saving a retained display ID.
		_, _, latest, e := fleetGroupAdmission(r.Context(), sources)
		if e != nil {
			fail(w, 409, "fleet_group_conflict", "Membership changed. Refresh the group.")
			return
		}
		for _, m := range members {
			d, ok := latest[m.DeviceID]
			if !ok || d.identity != m.Identity {
				fail(w, 409, "fleet_group_conflict", "Membership changed. Refresh the group.")
				return
			}
		}
		// Unavailable identities were not displayed for review. Keep their exact
		// private bindings unless the operator explicitly reviewed their removal.
		if selected != nil && !remove && !input.RemoveUnavailable {
			for _, old := range selected.Members {
				initial, initialOK := devices[old.DeviceID]
				current, currentOK := latest[old.DeviceID]
				if !initialOK || initial.identity != old.Identity || !currentOK || current.identity != old.Identity {
					if seen[old.DeviceID] {
						fail(w, 409, "fleet_group_conflict", "Remove the unavailable membership explicitly before adding its replacement.")
						return
					}
					members = append(members, old)
				}
			}
			if len(members) > store.MaxFleetGroupMembers {
				fail(w, 409, "fleet_group_conflict", "The retained and selected members exceed the group limit.")
				return
			}
		}
		guard := func() error {
			operator, ok := operatorContext(r)
			if !ok || operator.active == nil || !operator.active() || r.Context().Err() != nil {
				return store.ErrFleetGroupConflict
			}
			for _, source := range sources {
				at := source.Now().UTC()
				if !contactReadTime(now, at) {
					return store.ErrFleetGroupConflict
				}
				for _, memberID := range input.MemberIDs {
					if !at.Before(latest[memberID].expires) {
						return store.ErrFleetGroupConflict
					}
				}
			}
			return nil
		}
		_, err = h.app.store.SaveFleetGroup(r.Context(), manager, id, input.Name, members, input.Expected, remove, guard)
		if err != nil {
			status := 503
			if errors.Is(err, store.ErrFleetGroupConflict) || errors.Is(err, store.ErrLimit) {
				status = 409
			}
			fail(w, status, "fleet_group_conflict", "Group save could not be confirmed. Refresh before another change.")
			return
		}
		manager, now, devices, err = fleetGroupAdmission(r.Context(), sources)
		if err != nil {
			fail(w, 503, "fleet_groups_unavailable", "Group save requires read-only reconciliation.")
			return
		}
		groups, err = h.app.store.FleetGroups(r.Context(), manager)
		if err != nil {
			fail(w, 503, "fleet_groups_unavailable", "Group save requires read-only reconciliation.")
			return
		}
	}
	if id != "" && !mutation {
		groups = []store.FleetGroup{*selected}
	}
	// Storage can wait. Obtain current admission again before projecting any
	// identity-bound membership or labels; reads never repair retained membership.
	_, releaseNow, currentDevices, releaseErr := fleetGroupAdmission(r.Context(), sources)
	if releaseErr != nil || !contactReadTime(now, releaseNow) {
		fail(w, 503, "fleet_groups_unavailable", "Current group membership is unavailable.")
		return
	}
	devices = currentDevices
	now = releaseNow
	view := projectFleetGroups(groups, devices, now)
	h.writeFleetIdentityBytes(w, r, view, 128*1024, func() error {
		for _, source := range sources {
			at := source.Now().UTC()
			if !contactReadTime(now, at) {
				return store.ErrFleetGroupConflict
			}
			for _, d := range devices {
				if !at.Before(d.expires) {
					return store.ErrFleetGroupConflict
				}
			}
		}
		return nil
	})
}
