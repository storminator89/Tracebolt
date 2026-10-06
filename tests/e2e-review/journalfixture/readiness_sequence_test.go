package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/completeoverview"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
)

func readinessPtr[T any](v T) *T { return &v }

// These typed synthetic builders follow the existing v3fixture, overviewfixture
// and endpointfixture production write paths. There are no collectors or native
// helpers; the authenticated enrollment and operator session are shared with the
// journal handler contract fixture, rather than replacing trust with a mock.
func readinessPackages(f *fixture) error {
	identity, at := f.devices["alpha"], f.now()
	generation, err := inventorywire.GenerationID(identity.Approval.DeviceID, 1)
	if err != nil {
		return err
	}
	rows := make([]linuxpackages.PackageRow, 12)
	for i := range rows {
		rows[i] = linuxpackages.PackageRow{Name: fmt.Sprintf("invented-package-%03d", i), Version: "1.0-1", Architecture: "amd64", SourcePackage: fmt.Sprintf("invented-source-%03d", i), SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}
	}
	ctx := context.Background()
	manifest, chunks, err := fullinventory.Build(ctx, fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Rows: rows, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}}, nil)
	if err != nil {
		return err
	}
	digest, err := fullinventory.ManifestDigest(manifest)
	if err != nil {
		return err
	}
	binding := enrollmentstore.InventoryBinding{Sequence: 1, GenerationID: generation, ManifestHash: digest}
	if _, err = f.store.InventoryBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); err != nil {
		return err
	}
	for _, chunk := range chunks {
		if _, err = f.store.InventoryAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, at); err != nil {
			return err
		}
	}
	_, err = f.store.InventoryFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at)
	return err
}

func readinessOverview(f *fixture, section string) error {
	identity, at := f.devices["alpha"], f.now()
	generation, err := overviewwire.GenerationID(identity.Approval.DeviceID, section, 1)
	if err != nil {
		return err
	}
	snapshot := completeoverview.Empty(generation, at.Add(-time.Millisecond), completeoverview.ReasonNotCollected)
	snapshot.CaptureFinishedAt = at
	meta := completeoverview.SectionMeta{GenerationID: generation, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: readinessPtr(uint64(1)), CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: 1}}
	if section == "processes" {
		snapshot.Processes = completeoverview.ProcessSection{Meta: meta, Items: []completeoverview.Process{{PID: 42, ParentPID: readinessPtr(uint32(1)), Name: readinessPtr("invented-worker"), State: readinessPtr("sleeping"), RSSBytes: readinessPtr(uint64(4096)), CPUTimeSeconds: readinessPtr(float64(1)), Threads: readinessPtr(uint32(1)), Observation: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}}}}
	} else {
		snapshot.Volumes = completeoverview.VolumeSection{Meta: meta, Items: []completeoverview.Volume{{ID: "mount_1", MountPoint: "/synthetic/mount", Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_42_1", CapacityScope: "agent-mount-namespace", TotalBytes: readinessPtr(uint64(1048576)), AvailableBytes: readinessPtr(uint64(786432)), UsedPercent: readinessPtr(float64(25)), Measurement: completeoverview.Observation{Status: completeoverview.Observed, Reason: completeoverview.ReasonNone}}}}
	}
	ctx := context.Background()
	manifest, chunks, err := overviewgeneration.Build(ctx, snapshot, section, generation, nil)
	if err != nil {
		return err
	}
	digest, err := overviewgeneration.ManifestDigest(manifest)
	if err != nil {
		return err
	}
	binding := enrollmentstore.OverviewBinding{Section: section, Sequence: 1, GenerationID: generation, ManifestHash: digest}
	if _, err = f.store.OverviewBegin(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, manifest, at); err != nil {
		return err
	}
	for _, chunk := range chunks {
		if _, err = f.store.OverviewAppend(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, chunk, at); err != nil {
			return err
		}
	}
	_, err = f.store.OverviewFinalize(ctx, identity.InvitationID, identity.Issuance.CertificateHash, binding, at)
	return err
}

func readinessSystemFrame(f *fixture, sequence uint64) ([]byte, time.Time, error) {
	at := f.now()
	generation, err := systemwire.GenerationID(f.devices["alpha"].Approval.DeviceID, sequence)
	if err != nil {
		return nil, at, err
	}
	snapshot := systeminventory.Empty(generation, at, systeminventory.ReasonNotCollected)
	meta := func(n int) systeminventory.SectionMeta {
		return systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: readinessPtr(uint64(n)), CountExact: true}
	}
	snapshot.Services = systeminventory.ServiceSection{Meta: meta(1), Items: []systeminventory.Service{{Name: "invented.service", Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}}}}
	sockets := make([]systeminventory.Socket, 205)
	for i := range sockets {
		sockets[i] = systeminventory.Socket{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: uint16(10000 + i)}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{{PID: uint32(42 + i), ProcessName: readinessPtr("invented-worker"), NameReason: systeminventory.ReasonNone}}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionObserved, Reason: systeminventory.ReasonNone}}
	}
	snapshot.Sockets = systeminventory.SocketSection{Meta: meta(len(sockets)), Items: sockets}
	endpoint := endpointidentity.Empty(generation, at, endpointidentity.ReasonNotCollected)
	endpoint.ReportedHostname = endpointidentity.Hostname{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, Value: readinessPtr("invented-readiness-host")}
	endpoint.Interfaces = endpointidentity.InterfaceSection{Meta: endpointidentity.SectionMeta{Coverage: endpointidentity.Complete, Reason: endpointidentity.ReasonNone, ObservedCount: readinessPtr(uint32(0)), CountExact: true}, Items: []endpointidentity.Interface{}}
	provenance := systeminventory.SocketOwnerProvenance{SchemaVersion: systeminventory.SocketOwnerSourceVersion, Scope: systeminventory.SocketOwnerSourceScope, GrantEpoch: strings.Repeat("1", 64), PolicyDigest: strings.Repeat("2", 64), AuthorityRevision: strings.Repeat("3", 64), ContextID: strings.Repeat("4", 64), StartedAt: at, FinishedAt: at}
	raw, err := systemwire.EncodeSocketOwners(sequence, snapshot, provenance, &endpoint, nil)
	return raw, at, err
}

// One complete operator workflow uses the real one-second manager maintenance
// loop, real temp SQLite transactions, real typed startup observations, and the
// exact native packages -> System -> overview -> endpoint -> journal read order.
// The external SQLite transaction is only a barrier: release follows 40 ms of
// verified contention, far below the unchanged 750 ms admission/5 s SQL budgets.
// Every HTTP request (including all POSTs) is made exactly once, never retried.
func TestReadAdminFullReadinessSequenceDuringMaintenance(t *testing.T) {
	client := newJournalHandlerFixture(t)
	client.login()
	ctx := context.Background()
	f, state := client.f, client.state
	alpha := f.devices["alpha"]
	base := "/api/devices/" + alpha.Approval.DeviceID
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(state.InitializeOverview(ctx))

	maintenanceCtx, cancelMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan error, 1)
	var warnings atomic.Int32
	go func() {
		maintenanceDone <- f.service.RunInventoryMaintenance(maintenanceCtx, func() { warnings.Add(1) })
	}()
	t.Cleanup(func() {
		cancelMaintenance()
		select {
		case err := <-maintenanceDone:
			if err != nil {
				t.Errorf("maintenance stop: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("maintenance failed to stop")
		}
	})
	// Production startup flows execute with the manager maintenance loop running.
	check(readinessPackages(f))
	check(readinessOverview(f, "processes"))
	check(readinessOverview(f, "volumes"))
	raw, at, err := readinessSystemFrame(f, 1)
	check(err)
	_, err = state.SaveSystemObservation(ctx, alpha.InvitationID, alpha.Issuance.CertificateHash, raw, at)
	check(err)
	policy := sha256.Sum256([]byte("invented-journal-browser-policy:alpha"))
	tuple := journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + hex.EncodeToString(policy[:])}
	_, err = state.AcceptJournalGeneration(ctx, alpha.InvitationID, alpha.Issuance.CertificateHash, journalgeneration.Report{SchemaVersion: journalgeneration.ReportVersionV2, Tuple: tuple, Sequence: 1, ObservedAt: f.now(), PolicyEnabled: true, ServiceAuthorization: journalgeneration.AllSystemServices, AllowedUnits: []string{}}, f.now())
	check(err)
	blocker, err := sql.Open("sqlite", client.dbPath)
	check(err)
	defer blocker.Close()
	conn, err := blocker.Conn(ctx)
	check(err)
	defer conn.Close()
	defer conn.ExecContext(ctx, "ROLLBACK")
	heldReads := 0
	duringMaintenance := func(method, route string, body, out any) bool {
		t.Helper()
		_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		check(err)
		// Invalid empty frames stop before touching SQL. ErrInventoryBusy is positive
		// evidence that the actual timer loop has taken the shared inventory slot and
		// is blocked in BEGIN, not an assumed sleep or a fake store response.
		until := time.Now().Add(3 * time.Second)
		for {
			_, err := state.SaveSystemObservation(ctx, "", "", nil, f.now())
			if errors.Is(err, enrollmentstore.ErrInventoryBusy) {
				break
			}
			if !errors.Is(err, enrollmentstate.ErrInvalid) {
				t.Fatalf("admission probe: %v", err)
			}
			if time.Now().After(until) {
				t.Fatal("production one-second maintenance never acquired admission")
			}
			time.Sleep(time.Millisecond)
		}
		heldReads++
		response := make(chan *httptest.ResponseRecorder, 1)
		started := time.Now()
		go func() { response <- client.call(method, base+route, body) }()
		var w *httptest.ResponseRecorder
		select {
		case w = <-response:
			t.Errorf("%s %s returned HTTP %d before real maintenance/SQLite hold released: %s", method, route, w.Code, w.Body.String())
		case <-time.After(40 * time.Millisecond):
		}
		_, err = conn.ExecContext(ctx, "ROLLBACK")
		check(err)
		if w == nil {
			select {
			case w = <-response:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s %s did not resume", method, route)
			}
		}
		// An old fail-fast response can precede the maintenance COMMIT. Wait for
		// that observed tick to relinquish its slot before the next independent
		// request; this is fixture synchronization, never an HTTP POST retry.
		for until := time.Now().Add(5 * time.Second); ; {
			_, probeErr := state.SaveSystemObservation(ctx, "", "", nil, f.now())
			if errors.Is(probeErr, enrollmentstate.ErrInvalid) {
				break
			}
			if !errors.Is(probeErr, enrollmentstore.ErrInventoryBusy) || time.Now().After(until) {
				t.Fatalf("maintenance did not release admission: %v", probeErr)
			}
			time.Sleep(time.Millisecond)
		}
		if w.Code != 200 {
			t.Errorf("%s %s HTTP %d after %.0f ms; one-shot request was not retried", method, route, w.Code, float64(time.Since(started).Microseconds())/1000)
			return false
		}
		client.decode(w, 200, out)
		t.Logf("%s %s HTTP 200 after %.0f ms through production timer/SQLite contention", method, route, float64(time.Since(started).Microseconds())/1000)
		return true
	}
	var packages struct {
		DeviceID string
		Complete *struct {
			State    string
			Manifest fullinventory.Manifest
		}
	}
	var system enrollmentstore.SystemView
	var overview struct {
		DeviceID           string
		Processes, Volumes struct{ Complete *struct{ State string } }
	}
	var endpoint enrollmentstore.EndpointIdentityView
	type journalView struct {
		SchemaVersion, DeviceID, ContentStatus, ExpectedFloor string
		Configured                                            bool
		Generation                                            *enrollmentstore.JournalGenerationView
		Request                                               *journalrequest.Status
	}
	var journal journalView
	// Keep this ordering visibly identical to readAdminWaitViews, including reads
	// that already had fair admission before this regression was repaired.
	if duringMaintenance("GET", "/inventory/packages", nil, &packages) && (packages.DeviceID != alpha.Approval.DeviceID || packages.Complete == nil || packages.Complete.State != "complete") {
		t.Fatal("package readiness binding")
	}
	if duringMaintenance("GET", "/inventory/system", nil, &system) && (system.DeviceID != alpha.Approval.DeviceID || system.Latest == nil || system.Status != "fresh") {
		t.Fatal("System readiness binding")
	}
	if duringMaintenance("GET", "/inventory/overview", nil, &overview) && (overview.DeviceID != alpha.Approval.DeviceID || overview.Processes.Complete == nil || overview.Volumes.Complete == nil || overview.Processes.Complete.State != "complete" || overview.Volumes.Complete.State != "complete") {
		t.Fatal("overview readiness binding")
	}
	if duringMaintenance("GET", "/inventory/endpoint-identity", nil, &endpoint) && (endpoint.DeviceID != alpha.Approval.DeviceID || endpoint.Status != "fresh" || endpoint.Latest == nil) {
		t.Fatal("endpoint readiness binding")
	}
	if duringMaintenance("GET", "/journal", nil, &journal) && (journal.DeviceID != alpha.Approval.DeviceID || !journal.Configured || journal.Generation == nil || !journal.Generation.Fresh || journal.Generation.PolicyGeneration != tuple || journal.Request != nil) {
		t.Fatal("journal readiness binding")
	}

	// A live synthetic endpoint startup/refresh write shares that same admission.
	// Block at the existing test context's post-admission/pre-transaction boundary.
	raw, at, err = readinessSystemFrame(f, 2)
	check(err)
	held := &journalAdmissionContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	writeDone := make(chan error, 1)
	writeReleased := false
	defer func() {
		if !writeReleased {
			close(held.release)
		}
	}()
	go func() {
		_, err := state.SaveSystemObservation(held, alpha.InvitationID, alpha.Issuance.CertificateHash, raw, at)
		writeDone <- err
	}()
	select {
	case <-held.entered:
	case err := <-writeDone:
		t.Fatalf("startup writer did not acquire admission: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup writer did not enter")
	}
	refreshed := make(chan *httptest.ResponseRecorder, 1)
	go func() { refreshed <- client.call("GET", base+"/inventory/system", nil) }()
	var refreshResponse *httptest.ResponseRecorder
	select {
	case refreshResponse = <-refreshed:
		t.Errorf("System refresh returned early: %d", refreshResponse.Code)
	case <-time.After(40 * time.Millisecond):
	}
	close(held.release)
	writeReleased = true
	check(<-writeDone)
	if refreshResponse == nil {
		select {
		case refreshResponse = <-refreshed:
		case <-time.After(5 * time.Second):
			t.Fatal("System refresh did not resume")
		}
	}
	client.decode(refreshResponse, 200, &system)
	if system.Sequence == nil || *system.Sequence != 2 || system.Latest == nil || system.Latest.SocketOwnerProvenance == nil {
		t.Fatal("refreshed System lost sequence or provenance")
	}
	var refreshedEndpoint enrollmentstore.EndpointIdentityView
	client.decode(client.call("GET", base+"/inventory/endpoint-identity", nil), 200, &refreshedEndpoint)
	if refreshedEndpoint.Sequence == nil || *refreshedEndpoint.Sequence != 2 || refreshedEndpoint.Latest == nil {
		t.Fatal("endpoint refresh lost original generation")
	}
	input := enrollmentstore.SystemPageRequest{Section: "sockets", GenerationID: system.Latest.GenerationID, Limit: 100, Filter: "all"}
	var firstPage, secondPage, finalPage enrollmentstore.SystemPageResult
	if duringMaintenance("POST", "/inventory/system/query", input, &firstPage) {
		if len(firstPage.Sockets) != 100 || firstPage.Exhausted || firstPage.NextCursor == "" || firstPage.SocketOwnerProvenance == nil || !reflect.DeepEqual(firstPage.SocketOwnerProvenance, system.Latest.SocketOwnerProvenance) {
			t.Fatal("socket first page lost rows, cursor or original provenance")
		}
		input.Cursor = firstPage.NextCursor
		if duringMaintenance("POST", "/inventory/system/query", input, &secondPage) {
			if len(secondPage.Sockets) != 100 || secondPage.Exhausted || secondPage.NextCursor == "" || secondPage.CursorExpiresAt == nil || firstPage.CursorExpiresAt == nil || !secondPage.CursorExpiresAt.Equal(*firstPage.CursorExpiresAt) || !reflect.DeepEqual(secondPage.SocketOwnerProvenance, firstPage.SocketOwnerProvenance) {
				t.Fatal("socket continuation changed rows, cursor expiry or provenance")
			}
			input.Cursor = secondPage.NextCursor
			if duringMaintenance("POST", "/inventory/system/query", input, &finalPage) {
				if len(finalPage.Sockets) != 5 || !finalPage.Exhausted || finalPage.NextCursor != "" || finalPage.CursorExpiresAt != nil || !reflect.DeepEqual(finalPage.SocketOwnerProvenance, firstPage.SocketOwnerProvenance) {
					t.Fatal("socket final page changed original provenance or exhaustion")
				}
			}
		}
	}
	// Generation-bound create, status and exact-request content query retain their
	// existing POST behavior. No added POST retry conceals an admission failure.
	at = f.now().Truncate(time.Microsecond)
	query := journalview.Query{Unit: "invented.service", Start: at.Add(-time.Minute), End: at, MaxPriority: 7}
	create := map[string]any{"expectedFloor": "0", "expectedPolicyGeneration": tuple, "query": query, "acknowledgeLogContent": true, "acknowledgePlaintext": true}
	var created journalView
	client.decode(client.call("POST", base+"/journal/create", create), 200, &created)
	if created.Request == nil || created.Request.State != journalrequest.Pending || created.Request.Description.PolicyGeneration != tuple {
		t.Fatal("generation-bound journal create")
	}
	_, err = f.deliver("alpha", "complete")
	check(err)
	var accepted journalView
	if duringMaintenance("GET", "/journal", nil, &accepted) {
		if accepted.Request == nil || accepted.Request.Receipt == nil || accepted.Request.State != journalrequest.Accepted || accepted.ContentStatus != "available" || !reflect.DeepEqual(accepted.Request.Description, created.Request.Description) {
			t.Fatal("journal status lost exact request, original expiry or receipt")
		}
		var page journalcache.Page
		client.decode(client.call("POST", base+"/journal/query", map[string]any{"identity": accepted.Request.Description.Identity, "snapshotDigest": accepted.Request.Receipt.ResultDigest, "search": "Needle[.*]", "offset": 0, "limit": 100}), 200, &page)
		if page.DeviceID != alpha.Approval.DeviceID || page.Query != query || len(page.Rows) != 3 || page.Identity != accepted.Request.Description.Identity {
			t.Fatal("journal exact-request page changed")
		}
	}
	if heldReads < 7 || warnings.Load() != 0 {
		t.Fatalf("maintenance evidence: held reads=%d warnings=%d", heldReads, warnings.Load())
	}
	if !t.Failed() {
		t.Log("complete native-order authenticated readiness, synthetic concurrent startup refresh, generation-bound socket paging, journal create/status/query; no listener, collectors, systemd, native helper, network, or POST retries")
	}
}
