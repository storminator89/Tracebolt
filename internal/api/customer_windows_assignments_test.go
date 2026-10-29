package api

import (
	"context"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test process image is an inert FileInfo stand-in; API never opens it.
func (f *fixtureMonitoringSource) CustomerEnrollmentLeaseIdentity() (os.FileInfo, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return os.Stat(path)
}

type customerAliasSource struct {
	*fixtureMonitoringSource
	binding enrollmentstate.Binding
}

func (s *customerAliasSource) Binding() enrollmentstate.Binding { return s.binding }

type customerRollbackSource struct {
	*fixtureMonitoringSource
	clockReads, rollbackAt int
}

func (s *customerRollbackSource) Now() time.Time {
	s.clockReads++
	if s.clockReads == s.rollbackAt {
		return s.now.Add(-time.Second)
	}
	return s.now
}

func TestCustomerWindowsAssignmentsRejectClockRollback(t *testing.T) {
	for _, empty := range []bool{false, true} {
		for _, at := range []int{8, 12} {
			t.Run(fmt.Sprintf("empty=%v/read=%d", empty, at), func(t *testing.T) {
				o := newOperatorFixture(t, time.Hour)
				source := &customerRollbackSource{fixtureMonitoringSource: &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}, rollbackAt: at}
				if empty {
					source.snapshots = nil
					source.devices = nil
					source.inputs = nil
				}
				o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{source}
				o.login(t)
				r, _ := o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil)
				if r.StatusCode == 200 || source.clockReads < at {
					t.Fatal("clock rollback accepted", r.StatusCode, source.clockReads)
				}
			})
		}
	}
}

// A forward jump inside customerManager must become the next guard floor.
// The following read returns to the prior value, including for empty projections.
type customerScriptedClockSource struct {
	*fixtureMonitoringSource
	reads int
}

func (s *customerScriptedClockSource) Now() time.Time {
	s.reads++
	if s.reads == 7 {
		return s.now.Add(time.Second)
	}
	return s.now
}

func TestCustomerWindowsAssignmentsRejectRollbackAfterManagerClock(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			source := &customerScriptedClockSource{fixtureMonitoringSource: &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}}
			if empty {
				source.snapshots = nil
				source.devices = nil
				source.inputs = nil
			}
			o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{source}
			o.login(t)
			r, _ := o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil)
			if r.StatusCode == 200 || source.reads < 8 {
				t.Fatal("rollback after manager clock accepted", r.StatusCode, source.reads)
			}
		})
	}
}

type customerOtherSource struct {
	*fixtureFleetGroupSource
	file    os.FileInfo
	guards  int
	onGuard func(int)
}

type customerBlockedSource struct{ *customerOtherSource }

func (s *customerBlockedSource) WithCustomerIdentityExclusion(ctx context.Context, _ []string, _ func(func(time.Time) error) error) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestCustomerWindowsAssignmentsCancelWaitingForSource(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	windows := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	other := &customerOtherSource{fixtureFleetGroupSource: newFleetGroupSource()}
	other.now = windows.now
	other.binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	other.snapshots = nil
	other.devices = nil
	other.inputs = nil
	file := filepath.Join(t.TempDir(), "other-source")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	other.file, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{&customerBlockedSource{other}, windows}
	session, err := h.auth.Login(context.Background(), "127.0.0.1", operatorFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ctx = context.WithValue(ctx, operatorRequestKey{}, operatorRequest{session: session, origin: o.server.URL, active: func() bool { return true }})
	r := httptest.NewRequest("GET", o.server.URL+"/api/customer-windows-assignments", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	start := time.Now()
	h.customerWindowsAssignmentsAPI(w, r)
	if w.Code == 200 || time.Since(start) > 2*time.Second {
		t.Fatal("source wait was not bounded", w.Code, time.Since(start))
	}
}

func (s *customerOtherSource) CustomerEnrollmentLeaseIdentity() (os.FileInfo, error) {
	return s.file, nil
}
func (s *customerOtherSource) WithCustomerIdentityExclusion(ctx context.Context, ids []string, fn func(func(time.Time) error) error) error {
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	guard := func(min time.Time) error {
		s.guards++
		if s.onGuard != nil {
			s.onGuard(s.guards)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.now.Before(min) {
			return enrollmentstate.ErrConflict
		}
		for _, snapshot := range s.snapshots {
			if wanted[snapshot.Approval.DeviceID] {
				return enrollmentstate.ErrConflict
			}
		}
		return nil
	}
	if err := guard(s.now); err != nil {
		return err
	}
	return fn(guard)
}

func TestCustomerWindowsAssignmentsCrossSourceCollisionDuringCommit(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	windows := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	other := &customerOtherSource{fixtureFleetGroupSource: newFleetGroupSource()}
	other.now = windows.now
	other.binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	other.snapshots = nil
	other.devices = nil
	other.inputs = nil
	file := filepath.Join(t.TempDir(), "other-source")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	other.file, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{other, windows}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, login := o.login(t)
	id := windows.inputs[0].DeviceID
	other.onGuard = func(n int) {
		if n == 4 {
			other.snapshots = []enrollmentstate.Snapshot{{Approval: enrollmentstate.Approval{DeviceID: id}}}
		}
	}
	body := map[string]any{"customerId": customer, "customerRevision": 1, "deviceId": id, "identity": devices[id].identity, "acknowledged": true}
	r, _ := o.call(t, "POST", "/api/customer-windows-assignments", body, login["csrfToken"].(string), nil)
	if r.StatusCode == 200 || other.guards < 4 {
		t.Fatal("racing cross-source identity accepted", r.StatusCode, other.guards)
	}
	rows, err := o.app.store.CustomerWindowsAssignments(context.Background(), manager)
	if err != nil || len(rows) != 0 {
		t.Fatal("collision was committed", rows, err)
	}
}

func TestCustomerWindowsAssignmentsRejectAliasedStoresBeforeLeases(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprint("empty=", empty), func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
			if empty {
				source.snapshots = nil
				source.devices = nil
				source.inputs = nil
			}
			binding := source.binding
			binding.CollectionProfile = "basic-readonly-v1"
			alias := &customerAliasSource{fixtureMonitoringSource: source, binding: binding}
			o.server.Config.Handler.(*operatorHandler).fleetGroupSources = []fleetGroupSource{source, alias}
			o.login(t)
			r, _ := o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil)
			if r.StatusCode != 503 || source.leases != 0 {
				t.Fatal("aliased enrollment stores were not rejected before locks", r.StatusCode, source.leases)
			}
		})
	}
}

func TestCustomerWindowsAssignmentsExplicitIdentityAndSession(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	path := "/api/customer-windows-assignments"
	if r, _ := o.call(t, "GET", path, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous", r.StatusCode)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	server, e := time.Parse(time.RFC3339Nano, v["serverNow"].(string))
	if e != nil {
		t.Fatal(e)
	}
	deadline, e := time.Parse(time.RFC3339Nano, v["validUntil"].(string))
	if e != nil || !deadline.After(server) || deadline.After(server.Add(30*time.Second)) {
		t.Fatal("invalid view lifetime", server, deadline, e)
	}
	id := source.inputs[0].DeviceID
	d := devices[id]
	items := v["devices"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["identity"] != d.identity {
		t.Fatal(items)
	}
	body := map[string]any{"customerId": customer, "customerRevision": 1, "deviceId": id, "identity": d.identity, "acknowledged": false}
	if r, _ = o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 400 {
		t.Fatal("unchecked approval accepted", r.StatusCode)
	}
	body["acknowledged"] = true
	if r, _ = o.call(t, "POST", path, body, "", nil); r.StatusCode != 403 {
		t.Fatal("missing csrf accepted", r.StatusCode)
	}
	body["identity"] = strings.Repeat("f", 64)
	if r, _ = o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("wrong identity accepted", r.StatusCode)
	}
	body["identity"] = d.identity
	body["customerRevision"] = 2
	if r, _ = o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("stale customer accepted", r.StatusCode)
	}
	body["customerRevision"] = 1
	r, v = o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 200 || v["devices"].([]any)[0].(map[string]any)["customerId"] != customer {
		t.Fatal("save", r.StatusCode, v)
	}
	if r, _ = o.call(t, "POST", path, body, csrf, nil); r.StatusCode != 409 {
		t.Fatal("repeat accepted", r.StatusCode)
	}
	// Renewal changes the currently valid leaf deadline, not original identity.
	newExpiry := source.now.Add(2 * time.Hour)
	source.inputs[0].AuthorityUntil = newExpiry
	source.devices[0].AgentCertificate.ExpiresAt = &newExpiry
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["devices"].([]any)[0].(map[string]any)["customerId"] != customer {
		t.Fatal("renewal lost original identity", r.StatusCode, v)
	}
	// A new enrollment with the same mutable device ID must not inherit it.
	newInvite := "invite_" + strings.Repeat("5", 32)
	newCert := strings.Repeat("c", 64)
	source.inputs[0].InvitationID, source.inputs[0].CertificateHash = newInvite, newCert
	source.snapshots[0].InvitationID, source.snapshots[0].Issuance.CertificateHash = newInvite, newCert
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["devices"].([]any)[0].(map[string]any)["customerId"] != "" || v["unavailableAssignments"] != float64(1) {
		t.Fatal("new enrollment inherited old assignment", r.StatusCode, v)
	}
	source.inputs[0].Authorized = false
	source.snapshots[0].State = "revoked"
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || len(v["devices"].([]any)) != 0 || v["unavailableAssignments"] != float64(1) {
		t.Fatal("revoked association shown", r.StatusCode, v)
	}
}

func TestCustomerWindowsAssignmentHistoryAndIssuerLifetime(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, _, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 100; i++ {
		a := store.CustomerWindowsAssignment{Version: "tracebolt.customer-windows-assignment.v1", Manager: manager, CustomerID: customer, CustomerRevision: 1, DeviceID: fmt.Sprintf("agent_%032x", i), Identity: fmt.Sprintf("%064x", i)}
		if err = o.app.store.CreateCustomerWindowsAssignment(context.Background(), a, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	source.issuerEnd = source.now.Add(12 * time.Second)
	_, login := o.login(t)
	_ = login
	r, v := o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil)
	if r.StatusCode != 200 || v["unavailableAssignments"] != float64(100) {
		t.Fatal("historical bound", r.StatusCode, v)
	}
	until, e := time.Parse(time.RFC3339Nano, v["validUntil"].(string))
	if e != nil || !until.Equal(source.issuerEnd) {
		t.Fatal("issuer expiry not respected", until, e)
	}
	shorter := source.now.Add(8 * time.Second)
	source.inputs[0].AuthorityUntil = shorter
	source.devices[0].AgentCertificate.ExpiresAt = &shorter
	r, v = o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil)
	until, e = time.Parse(time.RFC3339Nano, v["validUntil"].(string))
	if r.StatusCode != 200 || e != nil || !until.Equal(shorter) {
		t.Fatal("device authority expiry not respected", r.StatusCode, until, e)
	}
	h.fleetGroupSources = []fleetGroupSource{source, source}
	if r, _ = o.call(t, "GET", "/api/customer-windows-assignments", nil, "", nil); r.StatusCode != 503 {
		t.Fatal("ambiguous IDs accepted", r.StatusCode)
	}
}

func TestCustomerWindowsAssignmentResponseLossRequiresReconciliation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	body := map[string]any{"customerId": customer, "customerRevision": 1, "deviceId": id, "identity": devices[id].identity, "acknowledged": true}
	// Authorization is lost after the store transaction commits. This is an
	// uncertain result, not evidence that the assignment rolled back.
	source.onGuard = func(n int) {
		if n == 5 {
			source.inputs[0].Authorized = false
		}
	}
	r, _ := o.call(t, "POST", "/api/customer-windows-assignments", body, csrf, nil)
	if r.StatusCode == 200 {
		t.Fatal("lost final authority was reported as success")
	}
	rows, err := o.app.store.CustomerWindowsAssignments(context.Background(), manager)
	if err != nil || len(rows) != 1 || rows[0].Identity != devices[id].identity {
		t.Fatal("committed outcome was lost", rows, err)
	}
}

func TestCustomerWindowsAssignmentAuthorityChangeRollsBack(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	source := &fixtureMonitoringSource{fixtureFleetGroupSource: newFleetGroupSource()}
	h := o.server.Config.Handler.(*operatorHandler)
	h.fleetGroupSources = []fleetGroupSource{source}
	manager, _, devices, err := fleetGroupAdmission(context.Background(), h.groupSources())
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("1", 32)
	if _, err = o.app.store.SaveCustomer(context.Background(), manager, customer, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	body := map[string]any{"customerId": customer, "customerRevision": 1, "deviceId": id, "identity": devices[id].identity, "acknowledged": true}
	source.onGuard = func(n int) {
		if n == 4 {
			source.inputs[0].Authorized = false
		}
	}
	r, _ := o.call(t, "POST", "/api/customer-windows-assignments", body, csrf, nil)
	if r.StatusCode == 200 {
		t.Fatal("authority change accepted")
	}
	rows, err := o.app.store.CustomerWindowsAssignments(context.Background(), manager)
	if err != nil || len(rows) != 0 {
		t.Fatal("authority change persisted", rows, err)
	}
}
