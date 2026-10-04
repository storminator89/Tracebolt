//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"localrmm/internal/agentidentity"
	"localrmm/internal/agentloop"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/systeminventory"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is an explicitly authorized, nonprivileged, read-only OS-source gate.
// Default tests stop before builds, listeners, enrollment or source collection.
// All credentials and observations stay in owned ephemeral state and loopback
// traffic. Only fixed status/count metadata leaves the test. This proves a
// process restart, not an installed service, account setup or operating-system
// reboot. Claim and pending continuation use the production enrollment library;
// manager and reporting use actual binaries built offline from this tree.
func TestCompleteMVPPendingApprovalNativeRestart(t *testing.T) {
	enabled, positive, endpointIdentity, err := completeMVPEndpointGateSelection(os.Getenv("TRACEBOLT_COMPLETE_RUNTIME_TEST"), os.Getenv("TRACEBOLT_COMPLETE_UBUNTU2404_TEST"), os.Getenv("TRACEBOLT_ENDPOINT_IDENTITY_RUNTIME_TEST"), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("explicit complete read-only runtime gate is not enabled")
	}
	// Match the production consent CLI guard before builds, listeners or state.
	// The hosted runner must already have a group-clean nonprivileged identity.
	if endpointIdentity && !agentidentity.Validate(completeMVPEndpointServiceIdentity()) {
		t.Fatal("complete_endpoint_requires_group_clean_service_identity")
	}
	checked := 0
	var inspect func(*testing.T, completeMVPObservation)
	if positive {
		inspect = func(t *testing.T, observed completeMVPObservation) {
			t.Helper()
			evidence, err := completeMVPUbuntu2404Evidence(observed.packages, observed.system)
			if err != nil {
				t.Fatal(err)
			}
			checked++
			t.Log(evidence)
		}
	}
	gate, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	binaries := map[string]string{}
	for _, name := range []string{"lan-manager", "lan-agent"} {
		path := filepath.Join(t.TempDir(), name)
		buildContext, cancelBuild := context.WithTimeout(gate, 2*time.Minute)
		build := packageGateCommand(buildContext, "go", "build", "-buildvcs=false", "-o", path, "../"+name)
		build.Env = packageGateOfflineEnvironment()
		err := build.Run()
		cancelBuild()
		if err != nil {
			t.Fatal("complete native fixture build failed", name)
		}
		binaries[name] = path
	}
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			completeMVPProfile(t, gate, profile, binaries, inspect, endpointIdentity)
		})
	}
	if positive && checked != 4 {
		t.Fatal("complete_positive_requires_four_delivered_samples")
	}
}

type completeMVPPackageView struct {
	SchemaVersion, DeviceID, CollectionProfile, Status string
	Complete                                           *struct {
		Binding                    struct{ Sequence, GenerationID, ManifestHash string }
		Manifest                   fullinventory.Manifest
		State                      string
		CompletedAt, RetainedUntil time.Time
	}
	Transfer *struct {
		Binding                        struct{ Sequence, GenerationID, ManifestHash string }
		State                          string
		DeclaredRows, AcceptedRows     uint64
		ExpectedChunks, AcceptedChunks uint32
	}
	Failure *struct {
		Sequence, GenerationID, Reason string
		AttemptedAt, ReceivedAt        time.Time
	}
}

type completeMVPObservation struct {
	metricSequence, systemSequence uint64
	metricAt, systemAt             time.Time
	packages                       completeMVPPackageView
	system                         enrollmentstore.SystemView
}

func completeMVPProfile(t *testing.T, gate context.Context, profile string, binaries map[string]string, inspect func(*testing.T, completeMVPObservation), endpointIdentity bool) {
	t.Helper()
	run, cancel := context.WithTimeout(gate, 2*time.Minute)
	defer cancel()
	m, enrolled, enrollmentPath := guidedFixture(t, profile)
	raw, err := os.ReadFile(enrollmentPath)
	var ec enrollmentconfig.Config
	if err != nil || json.Unmarshal(raw, &ec) != nil {
		t.Fatal("complete enrollment fixture configuration")
	}
	ec.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	raw, _ = json.Marshal(ec)
	if os.WriteFile(enrollmentPath, raw, 0600) != nil {
		t.Fatal("complete enrollment fixture profile write")
	}
	enrolled, err = enrollmentconfig.Load(enrollmentPath, m, time.Now().UTC())
	if err != nil {
		t.Fatal("complete enrollment fixture profile load")
	}
	configPath := filepath.Join(t.TempDir(), "lan.json")
	raw, _ = json.Marshal(m.Config)
	if os.WriteFile(configPath, raw, 0600) != nil {
		t.Fatal("complete manager fixture configuration")
	}
	manager := packageGateCommand(run, binaries["lan-manager"], "--lan-config", configPath, "--enrollment-config", enrollmentPath)
	if manager.Start() != nil {
		t.Fatal("complete native manager start")
	}
	managerDone := make(chan error, 1)
	go func() { managerDone <- manager.Wait() }()
	defer stopPackageGateProcess(t, manager, managerDone)
	roots := x509.NewCertPool()
	if profile == lanconfig.TLS && !roots.AppendCertsFromPEM([]byte(enrolled.ServerCAPEM())) {
		t.Fatal("complete operator explicit root")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	operator := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		response, e := operator.Get(m.Config.OperatorOrigin + "/api/auth/session")
		if e == nil {
			response.Body.Close()
			ready = response.StatusCode == http.StatusOK
			if ready {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("complete native manager readiness")
	}
	call := func(path string, body any, csrf string) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, _ := http.NewRequestWithContext(run, http.MethodPost, m.Config.OperatorOrigin+path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", m.Config.OperatorOrigin)
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, e := operator.Do(request)
		if e != nil {
			t.Fatal("complete operator request")
		}
		defer response.Body.Close()
		bodyBytes, e := io.ReadAll(io.LimitReader(response.Body, 192<<10))
		if e != nil {
			t.Fatal("complete operator response")
		}
		return response.StatusCode, bodyBytes
	}
	get := func(path string, out any) {
		t.Helper()
		request, _ := http.NewRequestWithContext(run, http.MethodGet, m.Config.OperatorOrigin+path, nil)
		response, e := operator.Do(request)
		if e != nil {
			t.Fatal("complete operator read")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 192<<10)).Decode(out) != nil {
			t.Fatal("complete operator read contract")
		}
	}
	status, body := call("/api/auth/login", map[string]string{"password": "fixture-password-only"}, "")
	var session struct{ CSRFToken string }
	if status != http.StatusOK || json.Unmarshal(body, &session) != nil || session.CSRFToken == "" {
		t.Fatal("complete operator login")
	}
	var offered struct {
		CollectionProfile, CollectionPrivacy string
		Items                                []enrollmentstate.Snapshot
	}
	get("/api/enrollment", &offered)
	if offered.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || offered.CollectionPrivacy != "complete_system_inventory_metadata_may_be_sensitive" || len(offered.Items) != 0 {
		t.Fatal("complete fresh-profile acknowledgement advertisement")
	}
	status, _ = call("/api/enrollment/invitations", map[string]any{"requestId": "request_" + strings.Repeat("7", 32), "platform": "linux"}, session.CSRFToken)
	if status != http.StatusBadRequest {
		t.Fatal("complete invitation admitted without acknowledgement")
	}
	status, body = call("/api/enrollment/invitations", map[string]any{"requestId": "request_" + strings.Repeat("8", 32), "platform": "linux", "collectionAcknowledged": true}, session.CSRFToken)
	var created struct {
		Snapshot                          enrollmentstate.Snapshot
		InvitationSecret, BootstrapSHA256 string
		Bootstrap                         api.EnrollmentBootstrap
	}
	if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || len(created.InvitationSecret) != 43 {
		t.Fatal("complete invitation creation")
	}
	clear(body)
	// Obtain the exact public bytes through the restricted production transport,
	// using the explicit root and digest supplied by the authenticated API.
	publicClient, err := lanclient.NewPublicBootstrapHTTPClient(created.Bootstrap.EnrollmentOrigin, profile, []byte(created.Bootstrap.ServerCAPEM), created.Bootstrap.InvitationID)
	if err != nil {
		t.Fatal("complete public bootstrap transport")
	}
	defer publicClient.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(run, http.MethodGet, created.Bootstrap.EnrollmentOrigin+lanclient.PublicBootstrapPathPrefix+created.Bootstrap.InvitationID, nil)
	response, err := publicClient.Do(request)
	if err != nil {
		t.Fatal("complete public bootstrap fetch")
	}
	public, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	response.Body.Close()
	digest := sha256.Sum256(public)
	if readErr != nil || response.StatusCode != http.StatusOK || hex.EncodeToString(digest[:]) != created.BootstrapSHA256 || bytes.Contains(public, []byte(created.InvitationSecret)) {
		t.Fatal("complete exact public bootstrap digest")
	}
	bootstrap, err := enrollmentclient.ParseBootstrap(public)
	wantBootstrap, _ := json.Marshal(created.Bootstrap)
	var exact enrollmentclient.Bootstrap
	if err != nil || json.Unmarshal(wantBootstrap, &exact) != nil || !reflect.DeepEqual(bootstrap, exact) {
		t.Fatal("complete public bootstrap changed")
	}
	stateDir := filepath.Join(t.TempDir(), "endpoint")
	var displayed enrollmentclient.TrustDisplay
	secretCalls := 0
	claim, err := enrollmentclient.Run(run, bootstrap, enrollmentclient.Options{
		ClaimOnly: true, StateDirectory: stateDir, InsecureHTTPAcknowledged: profile == lanconfig.HTTPTest,
		PollInterval: 2 * time.Second, Timeout: 30 * time.Second,
		Display: func(d enrollmentclient.TrustDisplay) error { displayed = d; return nil },
		Secret:  func(context.Context) ([]byte, error) { secretCalls++; return []byte(created.InvitationSecret), nil },
	})
	created.InvitationSecret = ""
	if err != nil || !claim.Pending || secretCalls != 1 || claim.ConfigPath != "" || claim.KeyFingerprint != displayed.KeyFingerprint || claim.ComparisonCode != displayed.ComparisonCode || claim.ServerAuthenticated != (profile == lanconfig.TLS) {
		t.Fatal("complete committed pending claim")
	}
	var pending struct{ Items []enrollmentstate.Snapshot }
	get("/api/enrollment", &pending)
	if len(pending.Items) != 1 || pending.Items[0].State != enrollmentstate.ClaimedPending || pending.Items[0].Claim.KeyFingerprint != displayed.KeyFingerprint || pending.Items[0].Claim.ComparisonCode != displayed.ComparisonCode {
		t.Fatal("complete pending public comparison")
	}
	committed := pending.Items[0]
	phase := make(chan struct{}, 1)
	type resumeResult struct {
		result enrollmentclient.Result
		err    error
	}
	resumed := make(chan resumeResult, 1)
	resumeContext, cancelResume := context.WithCancel(run)
	defer cancelResume()
	go func() {
		result, e := enrollmentclient.ResumeService(resumeContext, bootstrap, stateDir, profile == lanconfig.HTTPTest, func(p enrollmentclient.Progress) error {
			if p.Phase == "pending_approval" {
				select {
				case phase <- struct{}{}:
				default:
				}
			}
			return nil
		})
		resumed <- resumeResult{result, e}
	}()
	select {
	case <-phase:
	case <-resumed:
		t.Fatal("complete pending resume returned before approval")
	case <-time.After(10 * time.Second):
		t.Fatal("complete pending resume did not poll")
	}
	// Successful pending polling must not publish a sender or its source ledgers.
	for _, name := range []string{"agent.json", "ready.json", "telemetry"} {
		if _, e := os.Lstat(filepath.Join(stateDir, name)); !os.IsNotExist(e) {
			t.Fatal("complete collection handoff existed before approval")
		}
	}
	var before struct{ Items []model.Device }
	get("/api/devices", &before)
	if len(before.Items) != 0 {
		t.Fatal("complete pending claim fabricated a device observation")
	}
	status, _ = call("/api/enrollment/"+committed.InvitationID+"/approve", map[string]any{"requestId": "request_" + strings.Repeat("9", 32), "expectedRevision": committed.Revision, "expectedKeyFingerprint": displayed.KeyFingerprint}, session.CSRFToken)
	if status != http.StatusOK {
		t.Fatal("complete administrator approval")
	}
	var activated enrollmentclient.Result
	select {
	case result := <-resumed:
		if result.err != nil {
			t.Fatal("complete activation and sender handoff")
		}
		activated = result.result
	case <-time.After(25 * time.Second):
		t.Fatal("complete activation deadline")
	}
	cancelResume()
	c := activated.Config
	if activated.Pending || activated.KeyFingerprint != claim.KeyFingerprint || activated.ComparisonCode != claim.ComparisonCode || activated.ServerAuthenticated != (profile == lanconfig.TLS) || c.SchemaVersion != lanclient.CompleteConfigVersion || c.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || lanclient.ValidateGuidedHandoff(activated.ConfigPath) != nil {
		t.Fatal("complete activated bound v5 handoff")
	}
	for _, suffix := range []string{"state.json", "inventory/ledger.json", "system/system-state.json"} {
		if _, e := os.Stat(filepath.Join(c.StateDirectory, suffix)); e != nil {
			t.Fatal("complete handoff lacks a sequence domain")
		}
	}
	if completeMVPCounters(t, c.StateDirectory) != [3]uint64{} {
		t.Fatal("complete fresh handoff did not start with three unused domains")
	}
	identityBefore := completeMVPIdentity(t, stateDir)
	if endpointIdentity {
		completeMVPEndpointNotCollected(t, get, c.AgentID)
		completeMVPEndpointConsent(t, run, binaries["lan-agent"], activated.ConfigPath, stateDir, c.StateDirectory, "preview", false)
		completeMVPEndpointConsent(t, run, binaries["lan-agent"], activated.ConfigPath, stateDir, c.StateDirectory, "enable", true)
		completeMVPEndpointNotCollected(t, get, c.AgentID)
		if completeMVPCounters(t, c.StateDirectory) != [3]uint64{} {
			t.Fatal("complete_endpoint_consent_collected_before_sender")
		}
	}
	start := func() (*exec.Cmd, <-chan error, <-chan agentloop.Event) {
		sender := packageGateCommand(run, binaries["lan-agent"], "--config", activated.ConfigPath, "--foreground", "--interval", "15s")
		stream, e := sender.StdoutPipe()
		if e != nil || sender.Start() != nil {
			t.Fatal("complete native sender start")
		}
		done := make(chan error, 1)
		go func() { done <- sender.Wait() }()
		events := make(chan agentloop.Event, 8)
		go func() {
			defer close(events)
			scan := bufio.NewScanner(io.LimitReader(stream, 64<<10))
			scan.Buffer(make([]byte, 4096), 4096)
			for scan.Scan() {
				var line struct {
					SchemaVersion string
					Event         agentloop.Event
				}
				if json.Unmarshal(scan.Bytes(), &line) != nil || line.SchemaVersion != "tracebolt.agent-loop.v1" {
					return
				}
				if line.Event.Phase == agentloop.Finished {
					select {
					case events <- line.Event:
					case <-run.Done():
						return
					}
				}
			}
		}()
		return sender, done, events
	}
	sender, done, events := start()
	stopped := false
	defer func() {
		if !stopped {
			stopPackageGateProcess(t, sender, done)
		}
	}()
	var first completeMVPObservation
	for {
		event := completeMVPNext(t, run, events)
		first = completeMVPRead(t, get, c.AgentID, event, first)
		if first.packages.Complete != nil || first.packages.Failure != nil {
			break
		}
	}
	if inspect != nil {
		inspect(t, first)
	}
	var firstEndpoint enrollmentstore.EndpointIdentityView
	if endpointIdentity {
		firstEndpoint = completeMVPEndpointRead(t, get, first.system, "first")
	}
	stopPackageGateProcess(t, sender, done)
	stopped = true
	if lanclient.ValidateGuidedHandoff(activated.ConfigPath) != nil || completeMVPIdentity(t, stateDir) != identityBefore {
		t.Fatal("complete first process changed enrollment identity")
	}
	firstCounters := completeMVPCounters(t, c.StateDirectory)
	if firstCounters[0] != first.metricSequence || firstCounters[1] != first.systemSequence || firstCounters[2] == 0 {
		t.Fatal("complete first process counters not durable")
	}
	sender, done, events = start()
	stopped = false
	second := completeMVPRead(t, get, c.AgentID, completeMVPNext(t, run, events), first)
	if inspect != nil {
		inspect(t, second)
	}
	var secondEndpoint enrollmentstore.EndpointIdentityView
	if endpointIdentity {
		secondEndpoint = completeMVPEndpointRead(t, get, second.system, "restart")
		if err := completeMVPEndpointAdvanced(firstEndpoint, secondEndpoint); err != nil {
			t.Fatal(err)
		}
	}
	if second.metricSequence != first.metricSequence+1 || second.systemSequence != first.systemSequence+1 || !second.metricAt.After(first.metricAt) || !second.systemAt.After(first.systemAt) {
		t.Fatal("complete restart did not advance original metric and system domains")
	}
	stopPackageGateProcess(t, sender, done)
	stopped = true
	secondCounters := completeMVPCounters(t, c.StateDirectory)
	if secondCounters[0] != second.metricSequence || secondCounters[1] != second.systemSequence || secondCounters[2] != firstCounters[2] || !reflect.DeepEqual(second.packages, first.packages) || completeMVPIdentity(t, stateDir) != identityBefore || lanclient.ValidateGuidedHandoff(activated.ConfigPath) != nil {
		t.Fatal("complete restart changed identity or recaptured the package generation")
	}
	if endpointIdentity {
		// Administration is performed only after the sender has stopped. It does
		// not assert remote disablement: the last delivered metadata must age.
		completeMVPEndpointConsent(t, run, binaries["lan-agent"], activated.ConfigPath, stateDir, c.StateDirectory, "disable", false)
		sender, done, events = start()
		stopped = false
		ordinary := completeMVPRead(t, get, c.AgentID, completeMVPNext(t, run, events), second)
		if _, err := completeMVPUbuntu2404Evidence(ordinary.packages, ordinary.system); err != nil {
			t.Fatal(err)
		}
		var retained enrollmentstore.EndpointIdentityView
		get("/api/devices/"+c.AgentID+"/inventory/endpoint-identity", &retained)
		if err := completeMVPEndpointRetained(secondEndpoint, retained, ordinary.system); err != nil {
			t.Fatal(err)
		}
		stopPackageGateProcess(t, sender, done)
		stopped = true
		ordinaryCounters := completeMVPCounters(t, c.StateDirectory)
		if ordinaryCounters[0] != ordinary.metricSequence || ordinaryCounters[1] != ordinary.systemSequence || ordinaryCounters[2] != secondCounters[2] || !reflect.DeepEqual(ordinary.packages, second.packages) || completeMVPIdentity(t, stateDir) != identityBefore || lanclient.ValidateGuidedHandoff(activated.ConfigPath) != nil {
			t.Fatal("complete_endpoint_disabled_restart_changed_identity_or_package_domain")
		}
		t.Log("endpoint identity retained: stage=disabled_restart ordinary=advanced endpoint=original_age sequence=unchanged receipt=unchanged expiry=unchanged payload=unchanged")
	}
	get("/api/enrollment", &pending)
	if len(pending.Items) != 1 || pending.Items[0].State != enrollmentstate.Activated || pending.Items[0].InvitationID != committed.InvitationID || pending.Items[0].Claim.KeyFingerprint != claim.KeyFingerprint || pending.Items[0].Approval.DeviceID != c.AgentID {
		t.Fatal("complete restart created or replaced enrollment")
	}
	t.Log("PASS: fresh complete profile; exact public bootstrap digest; committed pending claim without sender state; explicit approval; activated three-domain handoff; actual native reports; one process restart preserved identity and counters; no installed-service or reboot claim")
}

func completeMVPNext(t *testing.T, ctx context.Context, events <-chan agentloop.Event) agentloop.Event {
	t.Helper()
	select {
	case event, ok := <-events:
		if !ok || event.Outcome != agentloop.Success || event.Metadata.Sequence == 0 || event.Metadata.SystemStatus != "acknowledged" || event.Metadata.SystemSequence == 0 {
			t.Fatal("complete native report not acknowledged")
		}
		switch event.Metadata.InventoryStatus {
		case "acknowledged", "failure_acknowledged", "not_due", "pending_retained":
		default:
			t.Fatal("complete native package status contract")
		}
		return event
	case <-ctx.Done():
		t.Fatal("complete native report deadline")
	}
	return agentloop.Event{}
}

func completeMVPRead(t *testing.T, get func(string, any), device string, event agentloop.Event, previous completeMVPObservation) completeMVPObservation {
	t.Helper()
	var devices struct{ Items []model.Device }
	get("/api/devices", &devices)
	if len(devices.Items) != 1 || devices.Items[0].ID != device || devices.Items[0].Source != "lan" || devices.Items[0].Synthetic || devices.Items[0].LastSeen.IsZero() {
		t.Fatal("complete actual device observation missing")
	}
	var metrics enrollmentstore.OperationalView
	get("/api/devices/"+device+"/operational", &metrics)
	if metrics.SchemaVersion != "tracebolt.operational-view.v1" || metrics.DeviceID != device || metrics.Status != "fresh" || metrics.ReceivedAt == nil || metrics.Snapshot == nil || metrics.Sequence == nil || *metrics.Sequence != event.Metadata.Sequence || operational.Validate(*metrics.Snapshot) != nil || metrics.Assessments.Updates.Quality != "unknown" || metrics.Assessments.Vulnerabilities.Quality != "unknown" {
		t.Fatal("complete operational provenance or fabricated assessment")
	}
	var system enrollmentstore.SystemView
	get("/api/devices/"+device+"/inventory/system", &system)
	if system.SchemaVersion != "tracebolt.system-inventory-view.v1" || system.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || system.DeviceID != device || system.Status != "fresh" || system.Sequence == nil || *system.Sequence != event.Metadata.SystemSequence || system.Latest == nil || system.ReceivedAt == nil || system.Latest.CollectedAt.IsZero() {
		t.Fatal("complete system metadata unavailable")
	}
	if event.Metadata.Sequence != previous.metricSequence+1 || event.Metadata.SystemSequence != previous.systemSequence+1 || !metrics.Snapshot.CollectedAt.After(previous.metricAt) || !system.Latest.CollectedAt.After(previous.systemAt) {
		t.Fatal("complete acknowledged report did not advance source times and domains")
	}
	for _, section := range []struct {
		meta systeminventory.SectionMeta
		last *enrollmentstore.SystemSectionSummary
	}{{system.Latest.Services, system.LastComplete.Services}, {system.Latest.Sockets, system.LastComplete.Sockets}} {
		count := 0
		if section.meta.ObservedCount != nil {
			count = int(*section.meta.ObservedCount)
		}
		if systeminventory.ValidateSectionMeta(section.meta, count) != nil || section.meta.GenerationID != system.Latest.GenerationID || !section.meta.ObservedAt.Equal(system.Latest.CollectedAt) {
			t.Fatal("complete system source metadata invalid")
		}
		if section.meta.Coverage == systeminventory.Failed && (section.meta.ObservedCount != nil || section.meta.CountExact) {
			t.Fatal("complete unavailable source fabricated zero")
		}
		if section.meta.Coverage == systeminventory.Complete && (section.last == nil || section.last.Sequence != *system.Sequence || !reflect.DeepEqual(section.last.Meta, section.meta)) {
			t.Fatal("complete source last-complete metadata missing")
		}
		if section.last != nil && (section.last.Meta.Coverage != systeminventory.Complete || section.last.Sequence > *system.Sequence || section.last.Meta.ObservedAt.After(system.Latest.CollectedAt)) {
			t.Fatal("complete last-complete metadata invalid")
		}
	}
	var packages completeMVPPackageView
	get("/api/devices/"+device+"/inventory/packages", &packages)
	if packages.SchemaVersion != "tracebolt.complete-package-view.v1" || packages.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || packages.DeviceID != device {
		t.Fatal("complete package metadata unavailable")
	}
	if packages.Complete != nil {
		c := packages.Complete
		digest, e := fullinventory.ManifestDigest(c.Manifest)
		if e != nil || c.State != "complete" || packages.Status != "available" || c.Binding.ManifestHash != digest || c.Binding.GenerationID != c.Manifest.GenerationID || c.CompletedAt.IsZero() || !c.RetainedUntil.After(c.CompletedAt) || packages.Failure != nil || packages.Transfer == nil || packages.Transfer.State != "complete" || packages.Transfer.AcceptedRows != c.Manifest.ObservedCount || packages.Transfer.AcceptedChunks != c.Manifest.ChunkCount {
			t.Fatal("complete manifest was not atomically completed")
		}
	}
	if packages.Failure != nil {
		if packages.Complete != nil || packages.Status != "awaiting" || packages.Failure.AttemptedAt.IsZero() || packages.Failure.ReceivedAt.IsZero() {
			t.Fatal("complete failed package source fabricated completion")
		}
		switch packages.Failure.Reason {
		case "source_missing", "source_invalid", "source_changed", "resource_limit", "collection_failed":
		default:
			t.Fatal("complete package failure not fixed metadata")
		}
	}
	switch event.Metadata.InventoryStatus {
	case "acknowledged":
		if packages.Complete == nil || packages.Complete.Binding.Sequence != strconv.FormatUint(event.Metadata.InventorySequence, 10) {
			t.Fatal("complete package acknowledgement not visible")
		}
	case "failure_acknowledged":
		if packages.Failure == nil || packages.Failure.Sequence != strconv.FormatUint(event.Metadata.InventorySequence, 10) {
			t.Fatal("complete package failure acknowledgement not visible")
		}
	case "not_due":
		if previous.packages.Complete == nil && previous.packages.Failure == nil {
			t.Fatal("complete package not-due without prior outcome")
		}
	case "pending_retained":
		if event.Metadata.InventorySequence == 0 || packages.Complete != nil || packages.Failure != nil {
			t.Fatal("complete package pending status contradicted by view")
		}
	}
	t.Logf("native report: sequence=%d systemSequence=%d packageStatus=%s servicesCoverage=%s servicesReason=%s socketsCoverage=%s socketsReason=%s", event.Metadata.Sequence, event.Metadata.SystemSequence, event.Metadata.InventoryStatus, system.Latest.Services.Coverage, system.Latest.Services.Reason, system.Latest.Sockets.Coverage, system.Latest.Sockets.Reason)
	if packages.Complete != nil {
		t.Logf("native complete package generation: observedRows=%d installedRows=%d chunks=%d", packages.Complete.Manifest.ObservedCount, packages.Complete.Manifest.InstalledCount, packages.Complete.Manifest.ChunkCount)
	}
	if packages.Failure != nil {
		t.Logf("native complete package attempt: failure=%s; no complete package count claimed", packages.Failure.Reason)
	}
	return completeMVPObservation{event.Metadata.Sequence, event.Metadata.SystemSequence, metrics.Snapshot.CollectedAt, system.Latest.CollectedAt, packages, system}
}

// Hash only ephemeral enrollment artifacts; never print keys, raw ledgers or
// observations. The sender's own three ledgers remain independently validated.
func completeMVPIdentity(t *testing.T, state string) [sha256.Size]byte {
	t.Helper()
	h := sha256.New()
	for _, name := range []string{"ledger.json", "agent.json", "agent-key.pem", "agent-cert.pem", "ready.json", "service-enrollment.json"} {
		raw, e := os.ReadFile(filepath.Join(state, name))
		if e != nil {
			t.Fatal("complete identity artifact unavailable")
		}
		h.Write(raw)
		clear(raw)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func completeMVPCounters(t *testing.T, state string) [3]uint64 {
	t.Helper()
	var counters [3]uint64
	for n, name := range []string{"state.json", "system/system-state.json", "inventory/ledger.json"} {
		raw, e := os.ReadFile(filepath.Join(state, name))
		var v struct{ LastSequence, Floor uint64 }
		if e != nil || json.Unmarshal(raw, &v) != nil {
			t.Fatal("complete sequence ledger unavailable")
		}
		clear(raw)
		counters[n] = v.LastSequence
		if n == 2 {
			counters[n] = v.Floor
		}
	}
	return counters
}
