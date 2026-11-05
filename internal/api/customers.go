package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
)

type customerView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision uint64 `json:"revision"`
}
type customersView struct {
	SchemaVersion string         `json:"schemaVersion"`
	Customers     []customerView `json:"customers"`
}

// This manager-bound catalog is organizational metadata only. It confers no
// tenant isolation, device membership, installer or enrollment authority.
func customerManager(ctx context.Context, sources []fleetGroupSource) (string, time.Time, error) {
	if len(sources) == 0 || len(sources) > 4 || ctx.Err() != nil {
		return "", time.Time{}, store.ErrCustomerInvalid
	}
	binding := sources[0].Binding()
	manager := monitoringManager(binding)
	now := sources[0].Now().UTC()
	last := now
	for _, source := range sources {
		b := source.Binding()
		if b.InstanceID != binding.InstanceID || b.Origin != binding.Origin || b.Profile != binding.Profile || b.IssuerFingerprint != binding.IssuerFingerprint {
			return "", now, store.ErrCustomerInvalid
		}
		start, end, err := source.IssuerValidity()
		at := source.Now().UTC()
		if err != nil || now.Before(start) || !now.Before(end) || at.Before(start) || !at.Before(end) || at.Before(last) || !contactReadTime(now, at) || ctx.Err() != nil {
			return "", now, store.ErrCustomerConflict
		}
		last = at
	}
	return manager, last, nil
}

func projectCustomers(items []store.Customer) customersView {
	result := customersView{SchemaVersion: "tracebolt.customers.v1", Customers: []customerView{}}
	for _, item := range items {
		result.Customers = append(result.Customers, customerView{item.ID, item.Name, item.Revision})
	}
	return result
}

// Customer reads are a separate explicit named grant, never implied by ordinary
// read or maintenance authority. Shared administration retains its old mapping.
// Release the short admission before source/store I/O: every response still
// rechecks the same immutable session's lifetime and current source authority.
func authorizeCustomerAccess(w http.ResponseWriter, r *http.Request) bool {
	op, ok := operatorContext(r)
	if !ok {
		fail(w, 403, "operator_capability_required", "An authorized operator is required for customer records.")
		return false
	}
	if !op.session.Named() {
		return true
	}
	if r.Method != http.MethodGet {
		fail(w, 403, "operator_capability_required", "This customer permission allows reads only.")
		return false
	}
	release, err := op.session.BeginCapability(r.Context(), operatorauth.ReadCustomers)
	if err != nil {
		if errors.Is(err, operatorauth.ErrUnauthenticated) {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
		} else {
			fail(w, 403, "operator_capability_required", "The customer-read permission is not granted.")
		}
		return false
	}
	release()
	return true
}

func (h *operatorHandler) customersAPI(w http.ResponseWriter, r *http.Request) {
	if !authorizeCustomerAccess(w, r) {
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	id := ""
	valid := r.URL.RawQuery == "" && !r.URL.ForceQuery && len(parts) >= 3 && parts[1] == "api" && parts[2] == "customers"
	if len(parts) == 4 {
		id = parts[3]
		valid = valid && enrollmentcrypto.ValidID(id, "customer_")
	} else {
		valid = valid && len(parts) == 3
	}
	if !valid {
		fail(w, 404, "not_found", "Customer route is unavailable.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost || r.Method == http.MethodGet && id != "" {
		fail(w, 405, "method_not_allowed", "Use GET for the catalog or POST to create or rename.")
		return
	}
	var input struct {
		Name     string `json:"name"`
		Expected uint64 `json:"expectedRevision"`
	}
	var releaseMutation func()
	if r.Method == http.MethodPost {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		if !readObject(w, r, 2048, []string{"name", "expectedRevision"}, &input) {
			return
		}
		if !store.ValidFleetGroupName(input.Name) || input.Expected >= store.MaxFleetGroupRevision || id == "" && input.Expected != 0 || id != "" && input.Expected == 0 {
			fail(w, 400, "invalid_body", "Choose a valid name and expected revision.")
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		releaseMutation = release
		defer releaseMutation()
	}
	sources := h.groupSources()
	manager, started, err := customerManager(r.Context(), sources)
	if err != nil {
		fail(w, 503, "customers_unavailable", "Customer catalog is unavailable.")
		return
	}
	items, err := h.app.store.Customers(r.Context(), manager)
	if err != nil {
		fail(w, 503, "customers_unavailable", "Customer catalog is unavailable.")
		return
	}
	if r.Method == http.MethodPost {
		if id == "" {
			var raw [16]byte
			if _, err = rand.Read(raw[:]); err != nil {
				fail(w, 503, "customers_unavailable", "Customer could not be created.")
				return
			}
			id = "customer_" + hex.EncodeToString(raw[:])
		}
		guard := func() error {
			op, ok := operatorContext(r)
			if !ok || op.active == nil || !op.active() || r.Context().Err() != nil {
				return store.ErrCustomerConflict
			}
			current, at, e := customerManager(r.Context(), sources)
			if e != nil || current != manager || !contactReadTime(started, at) {
				return store.ErrCustomerConflict
			}
			return nil
		}
		_, err = h.app.store.SaveCustomer(r.Context(), manager, id, input.Name, input.Expected, guard)
		// Release the session mutation lease before readback and response. A
		// failure after commit is an uncertain outcome, never a claimed rollback.
		releaseMutation()
		if err != nil {
			status := 503
			if errors.Is(err, store.ErrCustomerConflict) || errors.Is(err, store.ErrLimit) {
				status = 409
			}
			fail(w, status, "customer_conflict", "Customer save could not be confirmed. Refresh before another change.")
			return
		}
		items, err = h.app.store.Customers(r.Context(), manager)
		if err != nil {
			fail(w, 503, "customers_unavailable", "Customer save requires read-only reconciliation.")
			return
		}
	}
	if !operatorStillActive(w, r) {
		return
	}
	current, end, err := customerManager(r.Context(), sources)
	if err != nil || current != manager || !contactReadTime(started, end) {
		fail(w, 503, "customers_unavailable", "Customer catalog requires read-only reconciliation.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, projectCustomers(items))
}
