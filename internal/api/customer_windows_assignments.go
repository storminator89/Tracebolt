package api

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"net/http"
	"os"
	"sort"
	"time"
)

type customerIdentityExclusionSource interface {
	WithCustomerIdentityExclusion(context.Context, []string, func(func(time.Time) error) error) error
}
type customerEnrollmentLeaseIdentity interface {
	CustomerEnrollmentLeaseIdentity() (os.FileInfo, error)
}

type customerWindowsDeviceView struct {
	DeviceID   string `json:"deviceId"`
	Identity   string `json:"identity"`
	CustomerID string `json:"customerId"`
}
type customerWindowsAssignmentsView struct {
	SchemaVersion          string                      `json:"schemaVersion"`
	ServerNow              time.Time                   `json:"serverNow"`
	ValidUntil             time.Time                   `json:"validUntil"`
	Customers              []customerView              `json:"customers"`
	Devices                []customerWindowsDeviceView `json:"devices"`
	UnavailableAssignments int                         `json:"unavailableAssignments"`
}

// This endpoint is only an organizational association of already activated,
// currently admitted Windows identities. It creates no enrollment authority.
func (h *operatorHandler) customerWindowsAssignmentsAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	op, ok := operatorContext(r)
	if !ok || op.session.Named() {
		fail(w, 403, "operator_capability_required", "A shared administrator is required.")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 404, "not_found", "Route unavailable.")
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Use GET or POST.")
		return
	}
	var input struct {
		CustomerID       string `json:"customerId"`
		CustomerRevision uint64 `json:"customerRevision"`
		DeviceID         string `json:"deviceId"`
		Identity         string `json:"identity"`
		Acknowledged     bool   `json:"acknowledged"`
	}
	var release func()
	if r.Method == "POST" {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readObject(w, r, 2048, []string{"customerId", "customerRevision", "deviceId", "identity", "acknowledged"}, &input) {
			return
		}
		if !input.Acknowledged || !enrollmentcrypto.ValidID(input.CustomerID, "customer_") || input.CustomerRevision < 1 || input.CustomerRevision > store.MaxFleetGroupRevision || !enrollmentcrypto.ValidID(input.DeviceID, "agent_") || !enrollmentcrypto.ValidHash(input.Identity) {
			fail(w, 400, "invalid_body", "Review the exact customer and identity.")
			return
		}
		var ok bool
		release, ok = beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
	}
	sources := h.groupSources()
	// Do not nest locks on aliased SQLite files, even if wrappers or paths differ.
	// Identity is checked for empty projections too; missing evidence fails closed.
	var files []os.FileInfo
	for _, s := range sources {
		identity, ok := s.(customerEnrollmentLeaseIdentity)
		if !ok {
			fail(w, 503, "customer_assignments_unavailable", "Enrollment source identity unavailable.")
			return
		}
		file, err := identity.CustomerEnrollmentLeaseIdentity()
		if err != nil || file == nil {
			fail(w, 503, "customer_assignments_unavailable", "Enrollment source identity unavailable.")
			return
		}
		for _, previous := range files {
			if os.SameFile(previous, file) {
				fail(w, 503, "customer_assignments_unavailable", "Enrollment sources overlap.")
				return
			}
		}
		files = append(files, file)
	}
	manager, started, err := customerManager(r.Context(), sources)
	if err != nil {
		fail(w, 503, "customer_assignments_unavailable", "Current manager unavailable.")
		return
	}
	admittedManager, _, devices, err := fleetGroupAdmission(r.Context(), sources)
	if err != nil || admittedManager != manager {
		fail(w, 503, "customer_assignments_unavailable", "Current identities unavailable.")
		return
	}
	var source fleetGroupSource
	windowIndex := -1
	for i, s := range sources {
		if s.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory {
			if source != nil {
				fail(w, 503, "customer_assignments_unavailable", "Ambiguous Windows authority.")
				return
			}
			source = s
			windowIndex = i
		}
	}
	lease, ok := source.(windowsMonitoringAuthoritySource)
	if source == nil || !ok {
		fail(w, 503, "customer_assignments_unavailable", "Windows authority unavailable.")
		return
	}
	rows, err := source.WindowsContactInputs(r.Context(), started)
	if err != nil {
		fail(w, 503, "customer_assignments_unavailable", "Windows identities unavailable.")
		return
	}
	authority, err := windowsContactAuthority(rows, started)
	if err != nil {
		fail(w, 503, "customer_assignments_unavailable", "Windows identities unavailable.")
		return
	}
	var ids []string
	for id, d := range devices {
		if d.Platform == "windows" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	selected := make([]windowscontact.Input, 0, len(ids))
	for _, id := range ids {
		in, found := authority[id]
		if !found || !in.Authorized || monitoringIdentity(source.Binding(), in) != devices[id].identity {
			fail(w, 503, "customer_assignments_unavailable", "Windows identities changed.")
			return
		}
		selected = append(selected, in)
	}
	if r.Method == "POST" {
		d, found := devices[input.DeviceID]
		if !found || d.Platform != "windows" || d.identity != input.Identity {
			fail(w, 409, "customer_assignment_conflict", "Device identity changed; refresh.")
			return
		}
	}
	view := customerWindowsAssignmentsView{SchemaVersion: "tracebolt.customer-windows-assignments.v1", Customers: []customerView{}, Devices: []customerWindowsDeviceView{}}
	lastGuard := started
	build := func(authorityGuard func(time.Time) error) error {
		guard := func() error {
			at := source.Now().UTC()
			current, now, e := customerManager(r.Context(), sources)
			p, ok := operatorContext(r)
			if e != nil || current != manager || now.Before(at) || !contactReadTime(started, now) || at.Before(lastGuard) || !contactReadTime(started, at) || !ok || p.active == nil || !p.active() || r.Context().Err() != nil {
				return store.ErrCustomerAssignmentConflict
			}
			lastGuard = now
			if authorityGuard != nil {
				return authorityGuard(at)
			}
			return nil
		}
		if err := guard(); err != nil {
			return err
		}
		if r.Method == "POST" {
			a := store.CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: input.CustomerID, CustomerRevision: input.CustomerRevision, DeviceID: input.DeviceID, Identity: input.Identity}
			if err := h.app.store.CreateCustomerWindowsAssignment(r.Context(), a, guard); err != nil {
				return err
			}
		}
		customers, e := h.app.store.Customers(r.Context(), manager)
		if e != nil {
			return e
		}
		assignments, e := h.app.store.CustomerWindowsAssignments(r.Context(), manager)
		if e != nil {
			return e
		}
		view.Customers = projectCustomers(customers).Customers
		visible := map[string]bool{}
		for _, id := range ids {
			d := devices[id]
			entry := customerWindowsDeviceView{DeviceID: id, Identity: d.identity}
			for _, a := range assignments {
				if a.Identity == d.identity && a.DeviceID == id {
					entry.CustomerID = a.CustomerID
					visible[a.Identity] = true
				}
			}
			view.Devices = append(view.Devices, entry)
		}
		for _, a := range assignments {
			if !visible[a.Identity] {
				view.UnavailableAssignments++
			}
		}
		if e = guard(); e != nil {
			return e
		}
		view.ServerNow = source.Now().UTC()
		if view.ServerNow.Before(lastGuard) || !contactReadTime(started, view.ServerNow) {
			return store.ErrCustomerAssignmentConflict
		}
		lastGuard = view.ServerNow
		view.ValidUntil = view.ServerNow.Add(30 * time.Second)
		for _, source := range sources {
			_, end, err := source.IssuerValidity()
			if err != nil || !view.ServerNow.Before(end) {
				return store.ErrCustomerAssignmentConflict
			}
			if end.Before(view.ValidUntil) {
				view.ValidUntil = end
			}
		}
		for _, in := range selected {
			if in.AuthorityUntil.Before(view.ValidUntil) {
				view.ValidUntil = in.AuthorityUntil
			}
		}
		if !view.ServerNow.Before(view.ValidUntil) {
			return store.ErrCustomerAssignmentConflict
		}
		return nil
	}
	if len(selected) > 0 {
		// Hold every source in stable groupSources order. The other sources deny
		// any colliding DeviceID for the entire operator-store commit.
		var acquire func(int, []func(time.Time) error) error
		acquire = func(index int, guards []func(time.Time) error) error {
			if index == len(sources) {
				return build(func(at time.Time) error {
					for _, guard := range guards {
						if e := guard(at); e != nil {
							return e
						}
					}
					return nil
				})
			}
			if index == windowIndex {
				return lease.WithWindowsMonitoringAuthority(r.Context(), selected, func(g func(time.Time) error) error { return acquire(index+1, append(guards, g)) })
			}
			exclusion, ok := sources[index].(customerIdentityExclusionSource)
			if !ok {
				return store.ErrCustomerAssignmentConflict
			}
			return exclusion.WithCustomerIdentityExclusion(r.Context(), ids, func(g func(time.Time) error) error { return acquire(index+1, append(guards, g)) })
		}
		err = acquire(0, nil)
	} else {
		err = build(nil)
	}
	if err != nil {
		if errors.Is(err, store.ErrCustomerAssignmentConflict) {
			fail(w, 409, "customer_assignment_conflict", "Assignment changed; refresh before deciding again.")
		} else {
			fail(w, 503, "customer_assignments_unavailable", "Assignment result could not be confirmed; refresh.")
		}
		return
	}
	if release != nil {
		release()
	}
	if !operatorStillActive(w, r) {
		return
	}
	end := source.Now().UTC()
	currentManager, managerNow, managerErr := customerManager(r.Context(), sources)
	if managerErr != nil || currentManager != manager || managerNow.Before(end) || !contactReadTime(started, managerNow) || end.Before(view.ServerNow) || !contactReadTime(started, end) || !end.Before(view.ValidUntil) {
		fail(w, 503, "customer_assignments_unavailable", "Read-only reconciliation required.")
		return
	}
	// Re-read the exact original identities and current authority just before
	// output. A failed check after POST is an uncertain committed result.
	if len(selected) > 0 {
		latestRows, e := source.WindowsContactInputs(r.Context(), end)
		if e != nil {
			fail(w, 503, "customer_assignments_unavailable", "Read-only reconciliation required.")
			return
		}
		latest, e := windowsContactAuthority(latestRows, end)
		if e != nil {
			fail(w, 503, "customer_assignments_unavailable", "Read-only reconciliation required.")
			return
		}
		for _, before := range selected {
			after, ok := latest[before.DeviceID]
			if !ok || !after.Authorized || after.InvitationID != before.InvitationID || after.CertificateHash != before.CertificateHash || !after.AuthorityUntil.Equal(before.AuthorityUntil) {
				fail(w, 503, "customer_assignments_unavailable", "Read-only reconciliation required.")
				return
			}
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	final := source.Now().UTC()
	if final.Before(managerNow) || final.Before(end) || !contactReadTime(started, final) || !final.Before(view.ValidUntil) {
		fail(w, 503, "customer_assignments_unavailable", "Read-only reconciliation required.")
		return
	}
	write(w, 200, view)
}
