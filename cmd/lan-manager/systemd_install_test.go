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
	"errors"
	"io"
	"localrmm/internal/agentinstall"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in test changes real accounts, fixed paths and systemd ONLY inside
// the separately approved fresh hosted VM. All ordinary test runs skip before
// creating files, credentials, accounts, processes or network listeners.
func TestApprovedDisposableSystemdInstallation(t *testing.T) {
	if os.Getenv("TRACEBOLT_APPROVED_SYSTEMD_TEST") != "1" {
		t.Skip("actual systemd installation not enabled; no privileged acceptance claimed")
	}
	runApprovedSystemdInstallation(t, lanconfig.TLS, enrollmentcrypto.CollectionProfile)
}

// The managed gate is separate from the original basic acceptance. Enabling it
// requires both explicit opt-ins and the same freshly approved hosted VM. Never
// run both gates on one machine: each requires a fresh fixed-path installation.
func TestApprovedManagedDisposableSystemdInstallation(t *testing.T) {
	value := os.Getenv("TRACEBOLT_APPROVED_MANAGED_SYSTEMD_TEST")
	if value == "" {
		t.Skip("managed systemd installation is not enabled; no privileged acceptance claimed")
	}
	if value != "1" || os.Getenv("TRACEBOLT_APPROVED_SYSTEMD_TEST") != "1" {
		t.Fatal("managed systemd acceptance requires both explicit opt-ins")
	}
	runApprovedSystemdInstallation(t, lanconfig.HTTPTest, enrollmentcrypto.CollectionProfilePackages)
}

func runApprovedSystemdInstallation(t *testing.T, profile, collectionProfile string) {
	runApprovedSystemdInstallationMode(t, profile, collectionProfile, nil)
}

func runApprovedSystemdInstallationMode(t *testing.T, profile, collectionProfile string, readAdmin *readAdminNativeOptions) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Linux" {
		t.Fatal("explicit gate requires the approved fresh root Linux hosted runner")
	}
	pid1, e := os.ReadFile("/proc/1/comm")
	if e != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("running systemd is required")
	}
	if _, e = os.Stat("/sys/fs/cgroup/cgroup.controllers"); e != nil {
		t.Fatal("cgroup v2 required")
	}
	for _, path := range []string{agentinstall.InstallDirectory, agentinstall.StateDirectory, "/etc/tracebolt-agent", "/var/lib/tracebolt-agent-installer", agentinstall.UnitPath} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("runner is not a fresh installation target")
		}
	}
	if _, e = user.Lookup(agentinstall.Account); e == nil {
		t.Fatal("test account already exists")
	} else {
		var unknown user.UnknownUserError
		if !errors.As(e, &unknown) {
			t.Fatal("test account lookup failed")
		}
	}
	if _, e = user.LookupGroup(agentinstall.Account); e == nil {
		t.Fatal("test group already exists")
	} else {
		var unknown user.UnknownGroupError
		if !errors.As(e, &unknown) {
			t.Fatal("test group lookup failed")
		}
	}
	if readAdmin != nil {
		readAdminFreshHost(t)
	}
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Fatal("private PTY helper required")
	}
	dir := os.Getenv("TRACEBOLT_SYSTEMD_BINARY_DIRECTORY")
	sourceArchive := os.Getenv("TRACEBOLT_SYSTEMD_SOURCE_ARCHIVE")
	if !filepath.IsAbs(dir) || !filepath.IsAbs(sourceArchive) {
		t.Fatal("explicit prebuilt artifact paths required")
	}
	binaries := map[string]string{}
	roles := []string{"agent-service", "lan-manager", "enroll-agent", "lan-agent"}
	if readAdmin != nil {
		roles = append(roles, "socket-owner-reader")
	} else {
		roles = append(roles, "enroll-agent-upgrade", "lan-agent-upgrade")
	}
	for _, name := range roles {
		p := filepath.Join(dir, name)
		i, e := os.Lstat(p)
		if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 {
			t.Fatal("selected native artifact unavailable")
		}
		binaries[name] = p
	}
	if readAdmin == nil && (systemdHash(t, binaries["lan-agent"]) == systemdHash(t, binaries["lan-agent-upgrade"]) || systemdHash(t, binaries["enroll-agent"]) == systemdHash(t, binaries["enroll-agent-upgrade"])) {
		t.Fatal("upgrade artifacts must have different selected bytes")
	}
	_ = systemdHash(t, sourceArchive)
	stage := "preflight"
	resultPath := os.Getenv("TRACEBOLT_SYSTEMD_RESULT_FILE")
	if !filepath.IsAbs(resultPath) || filepath.Clean(resultPath) != resultPath {
		t.Fatal("explicit sanitized result path required")
	}
	t.Cleanup(func() {
		status := "pass"
		if t.Failed() {
			status = "fail"
		}
		result := map[string]any{"schemaVersion": "tracebolt.systemd-acceptance.v1", "status": status, "stage": stage, "osRebootTested": false, "profile": profile, "telemetryExported": false}
		if collectionProfile == enrollmentcrypto.CollectionProfilePackages {
			result["schemaVersion"] = "tracebolt.managed-systemd-acceptance.v1"
			result["collectionProfile"] = collectionProfile
		}
		if readAdmin != nil {
			result["schemaVersion"] = "tracebolt.read-admin-systemd-acceptance.v2"
			result["readProfile"] = "tracebolt.linux-read-admin.v2"
			result["sourceCommit"] = readAdmin.source
			result["ptraceRiskAcknowledged"] = true
			result["socketNativeChecks"] = readAdmin.checks
			result["initialProbe"] = readAdmin.probeDiagnostic()
			result["setupFailure"] = readAdmin.setupDiagnostic()
			result["collectionProfile"] = collectionProfile
			result["scenario"] = readAdmin.scenario
			if readAdmin.upgrade {
				result["upgradeNativeChecks"] = readAdmin.upgradeChecks
			}
		}
		raw, _ := json.Marshal(result)
		f, e := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			t.Error("sanitized result creation failed")
			return
		}
		defer f.Close()
		if _, e = f.Write(append(raw, '\n')); e != nil || f.Sync() != nil {
			t.Error("sanitized result write failed")
		}
	})
	profileArguments := func(arguments []string) []string {
		if profile == lanconfig.HTTPTest {
			return append(arguments, "--insecure-http-test")
		}
		return arguments
	}
	if readAdmin != nil {
		stage = "read_admin_fixture_opt"
		readAdminPrepareDisposableOpt(t)
	}
	var readAdminCommand *readAdminNativeCommand
	t.Cleanup(func() {
		if readAdmin != nil && !readAdminStopOwnedHelper(t, readAdminCommand) {
			return
		}
		if _, e := os.Lstat(agentinstall.ManifestPath); e == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaries["agent-service"], profileArguments([]string{"--action", "uninstall", "--apply"})...)
			cmd.Env = systemdCleanEnvironment()
			var cleanupErr error
			if readAdmin != nil {
				cleanupErr = readAdminRunLifecycle(t, cmd, "uninstall_cleanup")
			} else {
				cleanupErr = cmd.Run()
			}
			if cleanupErr != nil {
				t.Error("owned service cleanup incomplete; discard this VM without exporting state")
			}
		}
	})
	m, enrolled, enrollmentPath := guidedFixture(t, profile)
	if collectionProfile != enrollmentcrypto.CollectionProfile {
		raw, err := os.ReadFile(enrollmentPath)
		var configured enrollmentconfig.Config
		if err != nil || json.Unmarshal(raw, &configured) != nil {
			t.Fatal("managed fixture configuration")
		}
		configured.CollectionProfile = collectionProfile
		raw, err = json.Marshal(configured)
		if err != nil || os.WriteFile(enrollmentPath, raw, 0600) != nil {
			t.Fatal("managed fixture configuration write")
		}
		enrolled, err = enrollmentconfig.Load(enrollmentPath, m, time.Now().UTC())
		if err != nil {
			t.Fatal("managed fixture configuration load")
		}
	}
	configPath := filepath.Join(t.TempDir(), "lan.json")
	config, _ := json.Marshal(m.Config)
	if os.WriteFile(configPath, config, 0600) != nil {
		t.Fatal("runtime config fixture")
	}
	stage = "manager_start"
	manager := exec.Command(binaries["lan-manager"], "--lan-config", configPath, "--enrollment-config", enrollmentPath)
	if manager.Start() != nil {
		t.Fatal("native manager start")
	}
	managerDone := make(chan error, 1)
	go func() { managerDone <- manager.Wait() }()
	defer stopFixtureProcess(t, manager, managerDone)
	roots := x509.NewCertPool()
	if profile == lanconfig.TLS && !roots.AppendCertsFromPEM([]byte(enrolled.ServerCAPEM())) {
		t.Fatal("explicit operator root")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	operator := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(8 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, e := operator.Get(m.Config.OperatorOrigin + "/api/auth/session")
		if e == nil {
			response.Body.Close()
			ready = response.StatusCode == 200
			if ready {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("guided runtime not ready")
	}
	// Sequential read-admin subtests rebind operator assertions to their own T.
	// Restore even after FailNow; a child must never call its parent's Fatal.
	operatorTest := t
	bindOperatorTest := func(current *testing.T) func() {
		previous := operatorTest
		operatorTest = current
		return func() { operatorTest = previous }
	}
	call := func(path string, body any, csrf string) (int, []byte) {
		raw, _ := json.Marshal(body)
		defer clear(raw)
		status, response, diagnostic := readAdminOperatorRequest(context.Background(), operator, m.Config.OperatorOrigin, path, http.MethodPost, raw, csrf, completeMVPOperatorWait)
		diagnostic.log(operatorTest)
		if diagnostic.failure != "" && diagnostic.failure != "status" {
			operatorTest.Fatal("operator fixture contract")
		}
		return status, response
	}
	get := func(path string, out any) {
		status, raw, diagnostic := readAdminOperatorRequest(context.Background(), operator, m.Config.OperatorOrigin, path, http.MethodGet, nil, "", completeMVPOperatorWait)
		defer clear(raw)
		if diagnostic.failure == "" {
			if status != 200 {
				diagnostic.failure = "status"
			} else {
				diagnostic = readAdminOperatorDecode(raw, out, diagnostic)
			}
		}
		diagnostic.log(operatorTest)
		if diagnostic.failure != "" {
			operatorTest.Fatal("operator fixture contract")
		}
	}
	stage = "operator_login"
	status, body := call("/api/auth/login", map[string]string{"password": "fixture-password-only"}, "")
	var session struct{ CSRFToken string }
	if status != 200 || json.Unmarshal(body, &session) != nil || session.CSRFToken == "" {
		t.Fatal("operator fixture login")
	}
	query := func(path string, input, output any) {
		status, raw := call(path, input, session.CSRFToken)
		defer clear(raw)
		if status != 200 {
			operatorTest.Fatal("operator fixture contract")
		}
		diagnostic := readAdminOperatorDecode(raw, output, readAdminOperatorDiagnostic{method: "post", resource: readAdminOperatorResource(path), status: "http_200", code: "none"})
		diagnostic.log(operatorTest)
		if diagnostic.failure != "" {
			operatorTest.Fatal("operator fixture contract")
		}
	}
	invitation := map[string]any{"requestId": "request_" + strings.Repeat("8", 32), "platform": "linux"}
	if collectionProfile != enrollmentcrypto.CollectionProfile {
		invitation["collectionAcknowledged"] = true
	}
	status, body = call("/api/enrollment/invitations", invitation, session.CSRFToken)
	var created struct {
		Snapshot         enrollmentstate.Snapshot `json:"snapshot"`
		InvitationSecret string                   `json:"invitationSecret"`
		Bootstrap        api.EnrollmentBootstrap  `json:"bootstrap"`
		BootstrapSHA256  string                   `json:"bootstrapSHA256"`
	}
	if status != 201 || json.Unmarshal(body, &created) != nil || len(created.InvitationSecret) != 43 {
		t.Fatal("invitation fixture failed")
	}
	bootstrapPath := filepath.Join(t.TempDir(), "bootstrap.json")
	raw, _ := json.Marshal(created.Bootstrap)
	if bytes.Contains(raw, []byte(created.InvitationSecret)) || os.WriteFile(bootstrapPath, raw, 0600) != nil {
		t.Fatal("public bootstrap fixture")
	}
	stateDir := agentinstall.EnrollmentDirectory
	stage = "install_enroll"
	args := []string{binaries["agent-service"], "--action", "install", "--apply", "--agent-binary", binaries["lan-agent"], "--agent-sha256", systemdHash(t, binaries["lan-agent"]), "--enroll-binary", binaries["enroll-agent"], "--enroll-sha256", systemdHash(t, binaries["enroll-agent"]), "--source-archive", sourceArchive, "--source-sha256", systemdHash(t, sourceArchive), "--bootstrap", bootstrapPath, "--bootstrap-sha256", systemdHash(t, bootstrapPath)}
	args = profileArguments(args)
	script := enrollmentPTY
	if readAdmin != nil {
		readAdminCommand = prepareReadAdminNativeCommand(t, python, binaries, sourceArchive, profile, created.Bootstrap, created.BootstrapSHA256, readAdmin)
		if readAdmin.upgrade {
			replacement := readAdminCommand
			prior, priorArchive := readAdminPriorArtifacts(t)
			readAdminCommand = prepareReadAdminNativeCommandSource(t, python, prior, priorArchive, profile, created.Bootstrap, created.BootstrapSHA256, readAdmin, readAdminPriorSource)
			readAdminCommand.replacement = replacement
		}
		stage = "read_admin_cancel"
		readAdminCancelBeforeInstall(t, readAdminCommand)
		stage = "install_enroll"
		args, script = readAdminCommand.args(false), readAdminPTY
	}
	inputFields := map[string]any{"args": args, "secret": created.InvitationSecret}
	if readAdminCommand != nil {
		inputFields = readAdminPTYInput(args, created.InvitationSecret, readAdminCommand.approval(), false)
	}
	input, _ := json.Marshal(inputFields)
	defer clear(input)
	enrollment := exec.Command(python, "-c", script)
	if readAdminCommand != nil {
		enrollment = exec.Command(python, "-I", "-c", script)
		enrollment.Env = readAdminCommand.environment()
	}
	enrollment.Stdin = bytes.NewReader(input)
	stdout, e := enrollment.StdoutPipe()
	if e != nil || enrollment.Start() != nil {
		t.Fatal("native PTY fixture start")
	}
	events := make(chan ptyEvent, 4)
	go func() {
		defer close(events)
		scan := bufio.NewScanner(io.LimitReader(stdout, 8192))
		for scan.Scan() {
			var event ptyEvent
			if json.Unmarshal(scan.Bytes(), &event) != nil {
				return
			}
			events <- event
		}
	}()
	enrollmentDone := make(chan error, 1)
	go func() { enrollmentDone <- enrollment.Wait() }()
	enrollmentWaited := false
	defer func() {
		if !enrollmentWaited {
			_ = enrollment.Process.Signal(os.Interrupt)
			select {
			case <-enrollmentDone:
			case <-time.After(8 * time.Second):
				enrollment.Process.Kill()
				<-enrollmentDone
			}
		}
	}()
	var prompt ptyEvent
	select {
	case prompt = <-events:
	case <-time.After(30 * time.Second):
		t.Fatal("native hidden prompt timeout")
	}
	if readAdmin != nil && prompt.Phase == "exit" {
		readAdmin.observeSetup(prompt)
	}
	if prompt.Phase == "exit" {
		stage = systemdInstallerStage(prompt.InstallerStage)
	}
	if prompt.Phase != "prompt" || !prompt.EchoDisabled || len(prompt.Fingerprint) != 64 || len(prompt.Comparison) != 32 {
		t.Fatal("native trust display or hidden prompt failed")
	}
	if readAdmin != nil && prompt.ScopeApprovals != 1 {
		t.Fatal("read-admin requires exactly one combined local approval")
	}
	var pending enrollmentstate.Snapshot
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var view struct{ Items []enrollmentstate.Snapshot }
		get("/api/enrollment", &view)
		if len(view.Items) == 1 && view.Items[0].State == enrollmentstate.ClaimedPending {
			pending = view.Items[0]
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if pending.State != enrollmentstate.ClaimedPending || pending.Claim.KeyFingerprint != prompt.Fingerprint || pending.Claim.ComparisonCode != prompt.Comparison {
		t.Fatal("local comparison does not match pending claim")
	}
	if readAdmin != nil {
		readAdminBeforeDeviceApproval(t, get)
		if readAdmin.scenario == "cancel-enrollment" {
			stage = "read_admin_retained"
			before := readAdminEnrollmentIdentity(t)
			if enrollment.Process.Signal(os.Interrupt) != nil {
				t.Fatal("read-admin cancellation signal failed")
			}
			var canceled ptyEvent
			select {
			case canceled = <-events:
			case <-time.After(45 * time.Second):
				t.Fatal("read-admin graceful cancellation timeout")
			}
			enrollmentWaited = true
			<-enrollmentDone
			readAdmin.observeSetup(canceled)
			readAdminCanceledEnrollment(t, canceled, before)
			stage = "complete"
			return
		}
	}
	stage = "approval"
	status, _ = call("/api/enrollment/"+pending.InvitationID+"/approve", map[string]any{"requestId": "request_" + strings.Repeat("9", 32), "expectedRevision": pending.Revision, "expectedKeyFingerprint": prompt.Fingerprint}, session.CSRFToken)
	if status != 200 {
		t.Fatal("native fixture approval")
	}
	var outcome ptyEvent
	completionWait := 30 * time.Second
	if readAdmin != nil {
		completionWait = 240 * time.Second
	}
	select {
	case outcome = <-events:
	case <-time.After(completionWait):
		t.Fatal("installer completion timeout")
	}
	if readAdmin != nil {
		readAdmin.observeSetup(outcome)
	}
	if readAdmin != nil && readAdmin.scenario == "retained-journal" {
		enrollmentWaited = true
		<-enrollmentDone
		stage = "read_admin_retained"
		readAdminRetainedJournal(t, readAdminCommand, outcome)
		stage = "complete"
		return
	}
	if outcome.ExitCode != 0 {
		stage = systemdInstallerStage(outcome.InstallerStage)
	}
	if outcome.Phase != "exit" || outcome.ExitCode != 0 || outcome.SecretEcho || !outcome.Ready || outcome.HTTPWarning != (profile == lanconfig.HTTPTest) {
		t.Fatal("native enrollment or private terminal boundary failed")
	}
	enrollmentWaited = true
	if e := <-enrollmentDone; e != nil {
		t.Fatal("PTY helper failed")
	}
	if readAdmin != nil {
		if !outcome.ReadAdminComplete || !outcome.ReadAdminPhasesComplete || outcome.ScopeApprovals != 1 {
			t.Fatal("read-admin combined configuration not confirmed")
		}
		stage = "initial_reports"
		readAdminCompleteAndRepeat(t, readAdminCommand, get, query, &stage, bindOperatorTest)
		stage = "complete"
		return
	}
	managedSequence := uint64(0)
	managedGeneration := ""
	var managedCollectedAt time.Time
	checkManagedObservation := func(after time.Time) {
		if collectionProfile != enrollmentcrypto.CollectionProfilePackages {
			return
		}
		var devices struct{ Items []model.Device }
		get("/api/devices", &devices)
		if len(devices.Items) != 1 {
			t.Fatal("managed service identity is unavailable")
		}
		deadline := time.Now().Add(75 * time.Second)
		for time.Now().Before(deadline) {
			var packages enrollmentstore.PackageView
			var operations enrollmentstore.OperationalView
			get("/api/devices/"+devices.Items[0].ID+"/packages", &packages)
			get("/api/devices/"+devices.Items[0].ID+"/operational", &operations)
			if operations.Sequence != nil && systemdManagedObservationAdvanced(packages, managedSequence, managedGeneration, managedCollectedAt, after) && *packages.Sequence == *operations.Sequence {
				if _, err := packageUbuntu2404PositiveEvidence(packages, operations); err != nil {
					t.Fatal("managed service requires positive bounded Ubuntu package and operational observations")
				}
				managedSequence = *packages.Sequence
				managedGeneration = packages.Snapshot.GenerationID
				managedCollectedAt = packages.Snapshot.CollectedAt
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("managed service observation readback did not advance consistently")
	}
	stage = "initial_reports"
	installationCompletedAt := time.Now().UTC()
	first := systemdWaitObservation(t, get, time.Time{})
	checkManagedObservation(installationCompletedAt)
	second := systemdWaitObservation(t, get, first)
	checkManagedObservation(installationCompletedAt)
	if !second.After(first) {
		t.Fatal("service did not send two distinct observations")
	}
	expectedIdentity := map[string]string{}
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "agent.json", "ready.json"} {
		p := filepath.Join(stateDir, name)
		expectedIdentity[name] = systemdHash(t, p)
		i, e := os.Stat(p)
		if e != nil || i.Mode().Perm()&0077 != 0 {
			t.Fatal("private handoff permissions")
		}
	}
	checkIdentity := func() {
		for name, hash := range expectedIdentity {
			if systemdHash(t, filepath.Join(stateDir, name)) != hash {
				t.Fatal("identity changed across service operation")
			}
		}
	}
	account, e := user.Lookup(agentinstall.Account)
	if e != nil {
		t.Fatal("dedicated account missing")
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if uid <= 0 || gid <= 0 {
		t.Fatal("service account is privileged")
	}
	systemdCheckProcessIdentity(t, uid, gid)
	sequence := systemdSequence(t, stateDir)
	if sequence < 2 {
		t.Fatal("durable sequence did not advance")
	}
	invoke := func(arguments ...string) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binaries["agent-service"], profileArguments(arguments)...)
		cmd.Env = systemdCleanEnvironment()
		if cmd.Run() != nil {
			t.Fatal("real installer lifecycle operation failed")
		}
	}
	stage = "restart"
	invoke("--action", "restart", "--apply")
	restartCompletedAt := time.Now().UTC()
	third := systemdWaitObservation(t, get, second)
	checkManagedObservation(restartCompletedAt)
	checkIdentity()
	if n := systemdSequence(t, stateDir); n <= sequence {
		t.Fatal("restart reset or failed sequence")
	} else {
		sequence = n
	}
	stage = "upgrade"
	invoke("--action", "upgrade", "--apply", "--agent-binary", binaries["lan-agent-upgrade"], "--agent-sha256", systemdHash(t, binaries["lan-agent-upgrade"]), "--enroll-binary", binaries["enroll-agent-upgrade"], "--enroll-sha256", systemdHash(t, binaries["enroll-agent-upgrade"]), "--source-archive", sourceArchive, "--source-sha256", systemdHash(t, sourceArchive))
	upgradeCompletedAt := time.Now().UTC()
	_ = systemdWaitObservation(t, get, third)
	checkManagedObservation(upgradeCompletedAt)
	checkIdentity()
	systemdCheckProcessIdentity(t, uid, gid)
	if systemdSequence(t, stateDir) <= sequence {
		t.Fatal("upgrade reset or failed sequence")
	}
	stage = "uninstall"
	invoke("--action", "uninstall", "--apply")
	checkIdentity()
	before := systemdHash(t, filepath.Join(stateDir, "telemetry", "state.json"))
	for _, p := range []string{agentinstall.UnitPath, agentinstall.AgentPath, agentinstall.EnrollPath, agentinstall.ManifestPath} {
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("owned installation file survived uninstall")
		}
	}
	if _, e = user.Lookup(agentinstall.Account); e != nil {
		t.Fatal("uninstall deleted retained account")
	}
	stage = "uninstall"
	invoke("--action", "uninstall", "--apply")
	checkIdentity()
	if systemdHash(t, filepath.Join(stateDir, "telemetry", "state.json")) != before {
		t.Fatal("repeated uninstall changed counter")
	}
	stage = "complete"
	t.Log("PASS: real systemd installation, hidden enrollment, numeric service identity, repeated Linux reports, restart, verified artifact upgrade, uninstall and retained identity; no OS reboot tested")
}
func systemdCleanEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/"}
}
func systemdHash(t *testing.T, p string) string {
	t.Helper()
	f, e := os.Open(p)
	if e != nil {
		t.Fatal("fixture artifact unavailable")
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 256<<20+1))
	if e != nil || n == 0 || n > 256<<20 {
		t.Fatal("fixture artifact bounds")
	}
	return hex.EncodeToString(h.Sum(nil))
}
func systemdSequence(t *testing.T, state string) uint64 {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(state, "telemetry", "state.json"))
	if e != nil {
		t.Fatal("sender ledger missing")
	}
	var record struct {
		LastSequence uint64 `json:"lastSequence"`
	}
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("sender ledger invalid")
	}
	clear(raw)
	return record.LastSequence
}
func systemdWaitObservation(t *testing.T, get func(string, any), after time.Time) time.Time {
	t.Helper()
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		var view struct{ Items []model.Device }
		get("/api/devices", &view)
		if len(view.Items) == 1 && view.Items[0].Source == "lan" && !view.Items[0].Synthetic && view.Items[0].Platform == "linux" && view.Items[0].LastSeen.After(after) {
			return view.Items[0].LastSeen
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("actual service observation deadline")
	return time.Time{}
}
func systemdCheckProcessIdentity(t *testing.T, uid, gid int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", agentinstall.UnitName, "--property=MainPID", "--value")
	cmd.Env = systemdCleanEnvironment()
	raw, e := cmd.Output()
	if e != nil || len(raw) > 64 {
		t.Fatal("service PID unavailable")
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil || pid <= 0 {
		t.Fatal("service inactive")
	}
	raw, e = os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if e != nil || len(raw) > 16384 {
		t.Fatal("service credential status unavailable")
	}
	found := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Uid:" || fields[0] == "Gid:" {
			want := uid
			if fields[0] == "Gid:" {
				want = gid
			}
			if len(fields) != 5 {
				t.Fatal("credential shape")
			}
			for _, v := range fields[1:] {
				if v != strconv.Itoa(want) {
					t.Fatal("service retained another real/effective/saved identity")
				}
			}
			found++
		}
		if fields[0] == "Groups:" {
			for _, v := range fields[1:] {
				if v != strconv.Itoa(gid) {
					t.Fatal("service retained extra supplementary groups")
				}
			}
			found++
		}
	}
	if found != 3 {
		t.Fatal("service credential fields missing")
	}
}

func systemdInstallerStage(raw string) string {
	switch raw {
	case "preflight_inspect", "preflight_systemd", "preflight_terminal", "preflight_systemctl_tool", "preflight_useradd_tool", "preflight_nologin_tool", "preflight_opt_directory", "preflight_etc_directory", "preflight_state_directory", "preflight_unit_directory", "preflight_unit_status", "preflight_account", "preflight_installation_state", "preflight_ownership_state", "preflight_fresh_paths", "preflight_bootstrap", "preflight_complete_profile", "preflight_artifacts", "preflight_plan", "preflight_begin", "preflight_reinspect", "preflight_replan", "preflight_unit_command", "preflight_unit_members", "preflight_unit_pid", "preflight_unit_absence", "preflight_manifest_absence", "preflight_begin_request", "preflight_begin_control", "preflight_begin_lock", "preflight_begin_journal", "preflight_begin_entropy", "preflight_begin_ownership", "preflight_begin_unit", "preflight_begin_artifacts", "preflight_begin_bootstrap", "preflight_begin_save":
		return "installer_" + raw
	case "preflight":
		return "installer_preflight"
	case "prepare_account_and_paths":
		return "installer_prepare"
	case "stage_verified_artifacts":
		return "installer_stage"
	case "enroll_as_dedicated_account":
		return "installer_enroll"
	case "validate_existing_guided_state":
		return "installer_validate"
	case "publish_owned_binaries_and_unit":
		return "installer_publish"
	case "start_owned_service":
		return "installer_start"
	case "commit":
		return "installer_commit"
	default:
		return "install_enroll"
	}
}
func TestSystemdDiagnosticStageAllowlist(t *testing.T) {
	for _, raw := range []string{"", "private-token-or-log", "unexpected/path"} {
		if systemdInstallerStage(raw) != "install_enroll" {
			t.Fatal("unrecognized diagnostic leaked")
		}
	}
	if systemdInstallerStage("enroll_as_dedicated_account") != "installer_enroll" {
		t.Fatal("fixed installer stage unavailable")
	}
}

// Positive sequence alone is insufficient: a post-operation report must carry a
// new collection generation and collection time after the completed action.
func systemdManagedObservationAdvanced(view enrollmentstore.PackageView, sequence uint64, generation string, collectedAt, after time.Time) bool {
	return view.Sequence != nil && *view.Sequence > sequence && view.Snapshot != nil &&
		view.Snapshot.GenerationID != "" && view.Snapshot.GenerationID != generation &&
		view.Snapshot.CollectedAt.After(collectedAt) && view.Snapshot.CollectedAt.After(after)
}

func TestManagedServiceObservationRequiresPostActionCollection(t *testing.T) {
	view, _ := packagePositiveFixture()
	boundary := view.Snapshot.CollectedAt.Add(-time.Second)
	prior := view.Snapshot.CollectedAt.Add(-2 * time.Second)
	sequence := *view.Sequence - 1
	if !systemdManagedObservationAdvanced(view, sequence, "different_generation", prior, boundary) {
		t.Fatal("fresh independent collection rejected")
	}
	if systemdManagedObservationAdvanced(view, *view.Sequence, "different_generation", prior, boundary) ||
		systemdManagedObservationAdvanced(view, sequence, view.Snapshot.GenerationID, prior, boundary) ||
		systemdManagedObservationAdvanced(view, sequence, "different_generation", view.Snapshot.CollectedAt, boundary) ||
		systemdManagedObservationAdvanced(view, sequence, "different_generation", prior, view.Snapshot.CollectedAt) ||
		systemdManagedObservationAdvanced(view, sequence, "different_generation", prior, view.Snapshot.CollectedAt.Add(time.Second)) {
		t.Fatal("old sequence, generation or pre-operation collection accepted")
	}
	view.Snapshot = nil
	if systemdManagedObservationAdvanced(view, sequence, "", prior, boundary) {
		t.Fatal("missing collection accepted")
	}
}
