//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/agentinstall"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/lanconfig"
	"localrmm/internal/model"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Only the explicitly approved fresh hosted-VM test calls the effectful helper.
// Ordinary tests exercise this metadata decision without reading the host.
func readAdminOptFixtureMode(mode uint32, uid, gid uint32) (bool, error) {
	if uid != 0 || gid != 0 || mode != unix.S_IFDIR|0755 && mode != unix.S_IFDIR|0777 {
		return false, errors.New("unsupported disposable opt fixture")
	}
	return mode == unix.S_IFDIR|0777, nil
}

func readAdminPrepareDisposableOpt(t *testing.T) {
	t.Helper()
	// GitHub's image deliberately makes /opt world-writable. Tighten only this
	// known root-owned top inode, never its children or production installer rules.
	fd, err := unix.Open("/opt", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("disposable opt fixture open rejected")
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		t.Fatal("disposable opt fixture metadata unavailable")
	}
	change, err := readAdminOptFixtureMode(before.Mode, before.Uid, before.Gid)
	if err != nil {
		t.Fatal("disposable opt fixture is not the approved root-owned directory shape")
	}
	if change && unix.Fchmod(fd, 0755) != nil {
		t.Fatal("disposable opt fixture preparation failed")
	}
	var after, current unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Lstat("/opt", &current) != nil ||
		after.Dev != before.Dev || after.Ino != before.Ino || current.Dev != after.Dev || current.Ino != after.Ino ||
		after.Mode != unix.S_IFDIR|0755 || current.Mode != after.Mode ||
		after.Uid != 0 || after.Gid != 0 || current.Uid != 0 || current.Gid != 0 {
		t.Fatal("disposable opt fixture readback failed")
	}
}

func TestReadAdminOptFixturePreparationIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		mode, uid, gid uint32
		change, valid  bool
	}{
		{unix.S_IFDIR | 0777, 0, 0, true, true},
		{unix.S_IFDIR | 0755, 0, 0, false, true},
		{unix.S_IFDIR | 0775, 0, 0, false, false},
		{unix.S_IFDIR | 01777, 0, 0, false, false},
		{unix.S_IFDIR | 0777, 1001, 0, false, false},
		{unix.S_IFDIR | 0777, 0, 1001, false, false},
		{unix.S_IFLNK | 0777, 0, 0, false, false},
		{unix.S_IFREG | 0777, 0, 0, false, false},
	} {
		change, err := readAdminOptFixtureMode(tc.mode, tc.uid, tc.gid)
		if (err == nil) != tc.valid || change != tc.change {
			t.Fatal("disposable directory fixture policy changed")
		}
	}
}

type readAdminNativeChecks struct {
	InstalledServiceOwners bool `json:"installedServiceOwners"`
	V4Provenance           bool `json:"v4Provenance"`
	RevocationCompleted    bool `json:"revocationCompleted"`
	RevokedNoAuthority     bool `json:"revokedNoAuthority"`
	JournalContent         bool `json:"journalContent"`
	ServiceRestartOnline   bool `json:"serviceRestartOnline"`
}
type readAdminNativeOptions struct {
	profile, scenario, source string
	checks                    readAdminNativeChecks
	initialProbe              readAdminProbeDiagnostic
}

// Closed diagnostic only: never copy private transcript, command, path or error text.
type readAdminProbeDiagnostic struct {
	Failure         string `json:"failure"`
	ChildExit       string `json:"childExit"`
	ScopePromptSeen bool   `json:"scopePromptSeen"`
}

func readAdminProbeReason(value string) string {
	switch value {
	case "not_attempted", "none", "driver-execution-failed", "driver-output-invalid", "unexpected-cancellation-result", "acceptance-gate-rejected", "acceptance-launcher-rejected", "acceptance-driver-rejected", "acceptance-deadline-exceeded", "acceptance-capture-exceeded", "read-admin-result-unavailable", "read-admin-result-invalid", "read-admin-phase-incomplete", "existing-installation-use-upgrade-or-recovery", "existing-journal-state-retained", "supported-linux-amd64-kernel", "systemd-pid1-required", "cgroup-v2-required", "platform-file", "platform-read-limit", "local-account-database", "local-nss-only", "existing-socket-owner-account", "alternate-unit-fragment", "unit-dropin", "existing-socket-owner-state", "fixed-command-failed", "systemd-unit-inspection-command-failed", "systemd-status-members", "preexisting-loaded-unit", "protected-directory", "protected-file", "changed-protected-file", "command-timeout", "command-output-limit", "acceptance-launcher-input", "acceptance-launcher-config", "acceptance-launcher-artifacts", "acceptance-launcher-source-loader", "acceptance-launcher-arguments", "acceptance-launcher-terminal", "acceptance-launcher-host", "acceptance-launcher-components", "acceptance-launcher-workflow":
		return value
	default:
		return "read-admin-phase-incomplete"
	}
}
func (o *readAdminNativeOptions) probeDiagnostic() readAdminProbeDiagnostic {
	if o.initialProbe.Failure == "" {
		return readAdminProbeDiagnostic{"not_attempted", "not_observed", false}
	}
	d := o.initialProbe
	d.Failure = readAdminProbeReason(d.Failure)
	if d.ChildExit != "zero" && d.ChildExit != "nonzero" {
		d.ChildExit = "not_observed"
	}
	return d
}
func readAdminProbeEventDiagnostic(event ptyEvent) readAdminProbeDiagnostic {
	reason := event.ReadAdminFailure
	if reason == "" {
		reason = "unexpected-cancellation-result"
		if event.ExitCode == 0 && event.ReadAdminCanceled && !event.ReadAdminComplete && event.ScopeApprovals == 1 {
			reason = "none"
		}
	}
	exit := "nonzero"
	if event.ExitCode == 0 {
		exit = "zero"
	}
	return readAdminProbeDiagnostic{readAdminProbeReason(reason), exit, event.ScopeApprovals == 1}
}

// Pure gate: ordinary tests skip before filesystem, identity, credential,
// listener, collector or service work. A selected but invalid gate fails.
func readAdminNativeSelection(base, approval, profile, scenario, source, actions, runner, runnerOS, readProfile, ptraceApproval, reviewedSource string, euid int) (*readAdminNativeOptions, error) {
	if approval == "" {
		return nil, nil
	}
	if approval != "1" || base != "1" || actions != "true" || runner != "github-hosted" || runnerOS != "Linux" || euid != 0 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		return nil, errors.New("read_admin_invalid_explicit_host_gate")
	}
	if readProfile != "tracebolt.linux-read-admin.v2" || ptraceApproval != "true" || reviewedSource != source {
		return nil, errors.New("read_admin_fresh_v2_scope_and_reviewed_source_required")
	}
	if profile != lanconfig.TLS && profile != lanconfig.HTTPTest {
		return nil, errors.New("read_admin_explicit_transport_required")
	}
	if scenario != "complete" && scenario != "cancel-enrollment" && scenario != "retained-journal" {
		return nil, errors.New("read_admin_explicit_scenario_required")
	}
	return &readAdminNativeOptions{profile: profile, scenario: scenario, source: source}, nil
}

func TestApprovedReadAdminDisposableSystemdInstallation(t *testing.T) {
	options, err := readAdminNativeSelection(os.Getenv("TRACEBOLT_APPROVED_SYSTEMD_TEST"), os.Getenv("TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST"), os.Getenv("TRACEBOLT_READ_ADMIN_TRANSPORT"), os.Getenv("TRACEBOLT_READ_ADMIN_SCENARIO"), os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_ACTIONS"), os.Getenv("RUNNER_ENVIRONMENT"), os.Getenv("RUNNER_OS"), os.Getenv("TRACEBOLT_READ_ADMIN_PROFILE"), os.Getenv("TRACEBOLT_APPROVED_READ_ADMIN_PTRACE"), os.Getenv("TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE"), os.Geteuid())
	if err != nil {
		t.Fatal("invalid explicit read-admin acceptance gate; no host work started")
	}
	if options == nil {
		t.Skip("read-admin privileged acceptance not enabled; no native acceptance claimed")
	}
	runApprovedSystemdInstallationMode(t, options.profile, enrollmentcrypto.CollectionProfileComplete, options)
}

func TestReadAdminNativeSelection(t *testing.T) {
	valid := []string{"1", "1", "tls", "complete", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "true", "github-hosted", "Linux", "tracebolt.linux-read-admin.v2", "true", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	selectGate := func(v []string, uid int) (*readAdminNativeOptions, error) {
		return readAdminNativeSelection(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], uid)
	}
	off := append([]string{}, valid...)
	off[1] = ""
	for _, uid := range []int{0, 1000} {
		if got, err := selectGate(off, uid); got != nil || err != nil {
			t.Fatal("default gate performed work")
		}
	}
	for _, profile := range []string{"tls", "http-test"} {
		for _, scenario := range []string{"complete", "cancel-enrollment", "retained-journal"} {
			v := append([]string{}, valid...)
			v[2], v[3] = profile, scenario
			if got, err := selectGate(v, 0); err != nil || got.profile != profile || got.scenario != scenario {
				t.Fatal("explicit selection rejected")
			}
		}
	}
	for index := range valid {
		v := append([]string{}, valid...)
		v[index] = "invalid"
		if _, err := selectGate(v, 0); err == nil {
			t.Fatal("invalid opt-in accepted")
		}
	}
	if _, err := selectGate(valid, 1000); err == nil {
		t.Fatal("nonroot enabled gate silently accepted")
	}
}

func readAdminNoSocketAuthority(t *testing.T) {
	t.Helper()
	for _, path := range []string{
		"/opt/tracebolt-agent/socket-owner-reader", "/run/tracebolt-socket-owner-reader",
		"/etc/tracebolt/socket-owner-policy.json", "/etc/tracebolt/socket-owner-deployment.json",
		"/etc/systemd/system/tracebolt-socket-owner-reader.service", "/etc/systemd/system/tracebolt-socket-owner-reader.socket",
		"/etc/systemd/system/tracebolt-socket-owner-reader.service.d", "/etc/systemd/system/tracebolt-socket-owner-reader.socket.d",
		"/etc/systemd/system/sockets.target.wants/tracebolt-socket-owner-reader.socket",
		"/var/lib/tracebolt-agent-installer/socket-owner-install-complete.json",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("socket authority predates fresh device approval")
		}
	}
	if _, err := user.Lookup("tracebolt-socket-owner-reader"); err == nil {
		t.Fatal("socket helper account predates approval")
	} else {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			t.Fatal("socket helper account lookup uncertain")
		}
	}
	if _, err := user.LookupGroup("tracebolt-socket-owner-reader"); err == nil {
		t.Fatal("socket helper group predates approval")
	} else {
		var unknown user.UnknownGroupError
		if !errors.As(err, &unknown) {
			t.Fatal("socket helper group lookup uncertain")
		}
	}
}

func readAdminFreshHost(t *testing.T) {
	t.Helper()
	readAdminNoSocketAuthority(t)
	for _, path := range []string{agentinstall.InstallDirectory, agentinstall.StateDirectory, "/etc/tracebolt-agent", "/var/lib/tracebolt-agent-installer", agentinstall.UnitPath,
		"/etc/tracebolt", "/run/tracebolt-journal-reader", "/etc/systemd/system/tracebolt-journal-reader.service", "/etc/systemd/system/tracebolt-journal-reader.socket",
		"/etc/systemd/system/tracebolt-journal-reader.service.d", "/etc/systemd/system/tracebolt-journal-reader.socket.d", "/etc/systemd/system/sockets.target.wants/tracebolt-journal-reader.socket"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("read-admin target is not fresh; preserve existing state")
		}
	}
	for _, name := range []string{agentinstall.Account, "tracebolt-journal-reader"} {
		if _, err := user.Lookup(name); err == nil {
			t.Fatal("read-admin account already exists")
		} else {
			var unknown user.UnknownUserError
			if !errors.As(err, &unknown) {
				t.Fatal("read-admin account lookup uncertain")
			}
		}
		if _, err := user.LookupGroup(name); err == nil {
			t.Fatal("read-admin group already exists")
		} else {
			var unknown user.UnknownGroupError
			if !errors.As(err, &unknown) {
				t.Fatal("read-admin group lookup uncertain")
			}
		}
	}
}

const readAdminFixtureVersion = "v0.0.0-read-admin-acceptance"

type readAdminNativeCommand struct {
	python      string
	configs     map[bool]string
	options     *readAdminNativeOptions
	maintenance map[string]string
}

func (c *readAdminNativeCommand) args(resume bool) []string {
	return []string{c.python, "-I", "-c", readAdminLauncher, c.configs[resume]}
}
func (c *readAdminNativeCommand) approval() string {
	if c.options.profile == lanconfig.HTTPTest {
		return "INSTALL READ ADMIN OVER HTTP"
	}
	return "INSTALL READ ADMIN"
}
func (c *readAdminNativeCommand) environment() []string {
	return append(systemdCleanEnvironment(), "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "RUNNER_OS=Linux", "GITHUB_SHA="+c.options.source,
		"TRACEBOLT_APPROVED_SYSTEMD_TEST=1", "TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST=1", "TRACEBOLT_READ_ADMIN_PROFILE=tracebolt.linux-read-admin.v2", "TRACEBOLT_APPROVED_READ_ADMIN_PTRACE=true", "TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE="+c.options.source, "TRACEBOLT_READ_ADMIN_TRANSPORT="+c.options.profile, "TRACEBOLT_READ_ADMIN_SCENARIO="+c.options.scenario)
}

func prepareReadAdminNativeCommand(t *testing.T, python string, binaries map[string]string, archive, profile string, bootstrap api.EnrollmentBootstrap, bootstrapHash string, options *readAdminNativeOptions) *readAdminNativeCommand {
	t.Helper()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(bootstrapHash) || bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfileComplete || bootstrap.Profile != profile {
		t.Fatal("read-admin public bootstrap scope is invalid")
	}
	// Match the production helper's fixed verified-release staging contract.
	// Keep this owned private staging evidence until the disposable VM is gone.
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("private source staging entropy unavailable")
	}
	stage := fmt.Sprintf("/tmp/tracebolt-release-%x", nonce)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal("fresh private source staging unavailable")
	}
	assets := map[string]any{}
	copyArtifact := func(src, name string, mode os.FileMode) {
		expected := systemdHash(t, src)
		in, err := os.Open(src)
		if err != nil {
			t.Fatal("read-admin selected artifact unavailable")
		}
		defer in.Close()
		output := filepath.Join(stage, name)
		out, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("read-admin artifact staging failed")
		}
		n, err := io.Copy(out, io.LimitReader(in, (256<<20)+1))
		if err != nil || n <= 0 || n > 256<<20 || out.Sync() != nil || out.Close() != nil || systemdHash(t, output) != expected || os.Chmod(output, mode) != nil {
			t.Fatal("read-admin selected bytes changed while staging")
		}
		assets[name] = map[string]any{"size": n, "sha256": expected}
	}
	for _, role := range []string{"agent-service", "enroll-agent", "lan-agent", "socket-owner-reader"} {
		copyArtifact(binaries[role], "tracebolt-"+readAdminFixtureVersion+"-linux-amd64-"+role, 0500)
	}
	copyArtifact(archive, "tracebolt-"+readAdminFixtureVersion+"-source.tar", 0600)
	manifest := map[string]any{"version": readAdminFixtureVersion, "sourceCommit": options.source, "assets": assets}
	arguments := []string{"--action", "install", "--apply", "--read-admin", "--read-admin-agent-origin", bootstrap.AgentOrigin, "--manager-origin", bootstrap.EnrollmentOrigin, "--invitation-id", bootstrap.InvitationID, "--bootstrap-sha256", bootstrapHash}
	if profile == lanconfig.HTTPTest {
		arguments = append(arguments, "--insecure-http-test")
	} else {
		arguments = append(arguments, "--server-ca-base64", base64.StdEncoding.EncodeToString([]byte(bootstrap.ServerCAPEM)))
	}
	command := &readAdminNativeCommand{python: python, configs: map[bool]string{}, maintenance: map[string]string{}, options: options}
	for _, resume := range []bool{false, true} {
		selected := append([]string{}, arguments...)
		if resume {
			selected = append(selected, "--resume-read-admin")
		}
		raw, err := json.Marshal(map[string]any{"directory": stage, "manifest": manifest, "arguments": selected, "scenario": options.scenario, "operation": "install"})
		if err != nil {
			t.Fatal("read-admin public fixture encoding")
		}
		name := filepath.Join(stage, fmt.Sprintf("configuration-%t.json", resume))
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("read-admin fixture config creation")
		}
		if _, err = f.Write(raw); err != nil || f.Sync() != nil || f.Close() != nil {
			t.Fatal("read-admin fixture config write")
		}
		command.configs[resume] = name
	}
	for _, operation := range []string{"inspect-socket", "revoke-socket", "cleanup"} {
		raw, err := json.Marshal(map[string]any{"directory": stage, "manifest": manifest, "arguments": arguments, "scenario": options.scenario, "operation": operation})
		if err != nil {
			t.Fatal("maintenance fixture encoding")
		}
		name := filepath.Join(stage, operation+".json")
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("maintenance fixture config creation")
		}
		if _, err = f.Write(raw); err != nil || f.Sync() != nil || f.Close() != nil {
			t.Fatal("maintenance fixture config write")
		}
		command.maintenance[operation] = name
	}
	return command
}

func readAdminPTYInput(args []string, secret, approval string, cancel bool) map[string]any {
	return map[string]any{"args": args, "secret": secret, "approval": approval, "cancelApproval": cancel}
}

func TestReadAdminPTYInput(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		value := readAdminPTYInput([]string{"/usr/bin/python3", "-I", "-c", "inert fixture"}, "", "INSTALL READ ADMIN", cancel)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal("public fixture encoding failed")
		}
		var decoded map[string]any
		if json.Unmarshal(raw, &decoded) != nil || len(decoded) != 4 || decoded["cancelApproval"] != cancel || decoded["approval"] != "INSTALL READ ADMIN" || decoded["secret"] != "" {
			t.Fatal("PTY input omitted required cancellation field")
		}
		if _, ok := decoded["args"]; !ok {
			t.Fatal("PTY input omitted command")
		}
	}
}

func readAdminProbe(t *testing.T, c *readAdminNativeCommand, resume, cancel bool) ptyEvent {
	t.Helper()
	raw, _ := json.Marshal(readAdminPTYInput(c.args(resume), "", c.approval(), cancel))
	defer clear(raw)
	cmd := exec.Command(c.python, "-I", "-c", readAdminPTY)
	cmd.Env = c.environment()
	cmd.Stdin = bytes.NewReader(raw)
	if cancel {
		c.options.initialProbe = readAdminProbeDiagnostic{"driver-execution-failed", "not_observed", false}
	}
	output, err := cmd.Output()
	defer clear(output)
	if len(output) > 8192 {
		if cancel {
			c.options.initialProbe.Failure = "driver-output-invalid"
		}
		t.Fatal("read-admin bounded PTY probe failed")
	}
	var event ptyEvent
	if json.Unmarshal(bytes.TrimSpace(output), &event) != nil || event.Phase != "exit" || event.SecretEcho {
		if cancel && !(err != nil && len(output) == 0) {
			c.options.initialProbe.Failure = "driver-output-invalid"
		}
		t.Fatal("read-admin probe produced unexpected prompt or data")
	}
	if cancel {
		c.options.initialProbe = readAdminProbeEventDiagnostic(event)
	}
	if err != nil {
		if cancel && c.options.initialProbe.Failure == "none" {
			c.options.initialProbe.Failure = "driver-execution-failed"
		}
		t.Fatal("read-admin bounded PTY probe failed")
	}
	return event
}

func readAdminCancelBeforeInstall(t *testing.T, c *readAdminNativeCommand) {
	t.Helper()
	event := readAdminProbe(t, c, false, true)
	if event.ExitCode != 0 || !event.ReadAdminCanceled || event.ReadAdminComplete || event.ScopeApprovals != 1 {
		t.Fatal("read-admin cancellation did not precede host changes")
	}
	readAdminFreshHost(t)
}

func readAdminBeforeDeviceApproval(t *testing.T, get func(string, any)) {
	t.Helper()
	readAdminNoSocketAuthority(t)
	var devices struct{ Items []model.Device }
	get("/api/devices", &devices)
	if len(devices.Items) != 0 {
		t.Fatal("read-admin sent observations before explicit device approval")
	}
	for _, path := range []string{agentinstall.UnitPath, "/etc/tracebolt", "/var/lib/tracebolt-agent-installer/read-admin-intent.json"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("read-admin privileged follow-on preceded device approval")
		}
	}
}

func readAdminEnrollmentIdentity(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(agentinstall.EnrollmentDirectory, "ledger.json"))
	if err != nil || len(raw) > 65536 {
		t.Fatal("retained enrollment fixture missing")
	}
	defer clear(raw)
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("retained enrollment fixture invalid")
	}
	defer func() {
		for _, raw := range value {
			clear(raw)
		}
	}()
	selected := map[string]json.RawMessage{}
	for _, key := range []string{"bootstrap", "seed", "csr", "claimId"} {
		if len(value[key]) == 0 {
			t.Fatal("retained enrollment identity missing")
		}
		selected[key] = value[key]
	}
	stable, err := json.Marshal(selected)
	if err != nil {
		t.Fatal("retained identity comparison failed")
	}
	defer clear(stable)
	return fmt.Sprintf("%x", sha256.Sum256(stable))
}

func readAdminCanceledEnrollment(t *testing.T, event ptyEvent, before string) {
	t.Helper()
	readAdminNoSocketAuthority(t)
	if event.Phase != "exit" || event.ExitCode == 0 || event.SecretEcho || event.ReadAdminComplete || event.ScopeApprovals != 1 || !event.InstallerRolledBack || !event.InstallerIdentityRetained || readAdminEnrollmentIdentity(t) != before {
		t.Fatal("graceful read-admin enrollment cancellation did not retain identity")
	}
	if account, err := user.Lookup(agentinstall.Account); err != nil || account.Uid == "0" {
		t.Fatal("canceled installation lost its retained nonroot account")
	}
	for _, path := range []string{agentinstall.UnitPath, "/etc/tracebolt", "/var/lib/tracebolt-agent-installer/read-admin-intent.json"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("canceled enrollment published follow-on authority")
		}
	}
}

func readAdminIdentitySnapshot(t *testing.T) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	for _, name := range []string{"agent-key.pem", "agent-cert.pem", "agent.json", "ready.json"} {
		path := filepath.Join(agentinstall.EnrollmentDirectory, name)
		snapshot[path] = systemdHash(t, path)
	}
	for _, name := range []string{"read-admin-intent.json", "read-admin-inventory.started.json", "read-admin-inventory.complete.json", "read-admin-journal.started.json"} {
		path := "/var/lib/tracebolt-agent-installer/" + name
		snapshot[path] = systemdHash(t, path)
	}
	return snapshot
}

func readAdminRetainedJournal(t *testing.T, c *readAdminNativeCommand, event ptyEvent) {
	t.Helper()
	if event.Phase != "exit" || event.ExitCode == 0 || event.SecretEcho || event.ReadAdminComplete || event.ScopeApprovals != 1 || event.ReadAdminFailure != "acceptance-injected-before-journal" {
		t.Fatal("read-admin test interruption not confirmed")
	}
	before := readAdminIdentitySnapshot(t)
	for _, path := range []string{"/etc/tracebolt", "/var/lib/tracebolt-agent-installer/read-admin-journal.complete.json"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("interrupted journal step created or completed authority")
		}
	}
	replay := readAdminProbe(t, c, true, false)
	if replay.ExitCode == 0 || replay.ReadAdminComplete || replay.ScopeApprovals != 1 || replay.ReadAdminFailure != "uncertain-journal-phase-retained" || !reflect.DeepEqual(before, readAdminIdentitySnapshot(t)) {
		t.Fatal("uncertain read-admin phase replayed or changed retained identity")
	}
	account, err := user.Lookup(agentinstall.Account)
	if err != nil {
		t.Fatal("retained agent missing")
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	systemdCheckProcessIdentity(t, uid, gid)
}

func readAdminCompleteAndRepeat(t *testing.T, c *readAdminNativeCommand, get func(string, any), query func(string, any, any), stage *string) {
	t.Helper()
	before := readAdminIdentitySnapshot(t)
	completePath := "/var/lib/tracebolt-agent-installer/read-admin-journal.complete.json"
	completeHash := systemdHash(t, completePath)
	protected := readAdminAuthoritySnapshot(t)
	sequence := systemdSequence(t, agentinstall.EnrollmentDirectory)
	first := systemdWaitObservation(t, get, time.Time{})
	_ = systemdWaitObservation(t, get, first)
	*stage = "read_admin_readiness"
	readAdminWaitViews(t, get)
	account, err := user.Lookup(agentinstall.Account)
	if err != nil {
		t.Fatal("read-admin dedicated agent missing")
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	systemdCheckProcessIdentity(t, uid, gid)
	if !reflect.DeepEqual(before, readAdminIdentitySnapshot(t)) || systemdHash(t, completePath) != completeHash || !reflect.DeepEqual(protected, readAdminAuthoritySnapshot(t)) || systemdSequence(t, agentinstall.EnrollmentDirectory) < sequence {
		t.Fatal("fresh read-admin identity or authority changed while observing")
	}
	readAdminSocketOwnersAndRevoke(t, c, get, query, stage)

}

type readAdminJournalView struct {
	SchemaVersion, DeviceID string
	Configured              bool
	Generation              *enrollmentstore.JournalGenerationView
}

func readAdminJournalReady(view readAdminJournalView, device string, expected journalgeneration.Tuple) bool {
	generation := view.Generation
	return view.SchemaVersion == "tracebolt.journal-view.v2" && view.DeviceID == device && view.Configured &&
		journalgeneration.Validate(expected) == nil && generation != nil && generation.SchemaVersion == "tracebolt.journal-generation-view.v2" &&
		generation.Fresh && generation.PolicyGeneration == expected && generation.Sequence > 0 &&
		!generation.ObservedAt.IsZero() && !generation.ReceivedAt.IsZero() && generation.PolicyEnabled != nil && *generation.PolicyEnabled &&
		generation.ServiceAuthorization == journalgeneration.AllSystemServices && generation.AllowedUnits != nil && len(*generation.AllowedUnits) == 0
}

func TestReadAdminJournalReady(t *testing.T) {
	enabled := true
	units := []string{}
	expected := journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("1", 64), PolicyDigest: "sha256:" + strings.Repeat("2", 64)}
	generation := enrollmentstore.JournalGenerationView{SchemaVersion: "tracebolt.journal-generation-view.v2", PolicyGeneration: expected,
		Sequence: 1, ObservedAt: time.Unix(1000, 0).UTC(), ReceivedAt: time.Unix(1001, 0).UTC(), Fresh: true, PolicyEnabled: &enabled,
		ServiceAuthorization: journalgeneration.AllSystemServices, AllowedUnits: &units}
	view := readAdminJournalView{SchemaVersion: "tracebolt.journal-view.v2", DeviceID: "agent_" + strings.Repeat("a", 32), Configured: true, Generation: &generation}
	if !readAdminJournalReady(view, view.DeviceID, expected) {
		t.Fatal("generation-bearing v2 journal view rejected")
	}
	legacy := view
	legacy.SchemaVersion = "tracebolt.journal-view.v1"
	if readAdminJournalReady(legacy, view.DeviceID, expected) {
		t.Fatal("legacy journal view accepted as broad generation readiness")
	}
	missing := view
	missing.Generation = nil
	if readAdminJournalReady(missing, view.DeviceID, expected) {
		t.Fatal("missing journal generation accepted")
	}
	wrong := expected
	wrong.Generation = strings.Repeat("3", 64)
	if readAdminJournalReady(view, view.DeviceID, wrong) || readAdminJournalReady(view, "agent_other", expected) {
		t.Fatal("unbound generation accepted")
	}
	generation.Fresh = false
	if readAdminJournalReady(view, view.DeviceID, expected) {
		t.Fatal("stale journal report accepted")
	}
	generation.Fresh = true
	enabled = false
	if readAdminJournalReady(view, view.DeviceID, expected) {
		t.Fatal("disabled journal policy accepted")
	}
}

func readAdminWaitViews(t *testing.T, get func(string, any)) {
	t.Helper()
	var devices struct{ Items []model.Device }
	get("/api/devices", &devices)
	if len(devices.Items) != 1 {
		t.Fatal("read-admin approved device unavailable")
	}
	device := devices.Items[0].ID
	expectedGeneration := readAdminExpectedGeneration(t)
	until := time.Now().Add(120 * time.Second)
	for time.Now().Before(until) {
		var packages completeMVPPackageView
		var system enrollmentstore.SystemView
		var overview completeMVPOverviewView
		var endpoint enrollmentstore.EndpointIdentityView
		var journal readAdminJournalView
		get("/api/devices/"+device+"/inventory/packages", &packages)
		get("/api/devices/"+device+"/inventory/system", &system)
		get("/api/devices/"+device+"/inventory/overview", &overview)
		get("/api/devices/"+device+"/inventory/endpoint-identity", &endpoint)
		get("/api/devices/"+device+"/journal", &journal)
		_, positive := completeMVPUbuntu2404Evidence(packages, system)
		if positive == nil && overview.DeviceID == device && overview.Processes.Complete != nil && overview.Volumes.Complete != nil && overview.Processes.Complete.State == "complete" && overview.Volumes.Complete.State == "complete" && endpoint.DeviceID == device && endpoint.Status == "fresh" && endpoint.Latest != nil && readAdminJournalReady(journal, device, expectedGeneration) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("read-admin received v3 inventory or broad-journal readiness deadline; no log content queried")
}

func readAdminAuthoritySnapshot(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, path := range []string{
		"/etc/tracebolt/journal-content-policy.json", "/etc/tracebolt/journal-client-policy.json",
		"/etc/tracebolt/journal-helper.json", "/etc/tracebolt/journal-client-helper.json", "/etc/tracebolt/journal-activation.json",
		agentinstall.EnrollmentDirectory + "/telemetry/complete-overview-consent.json",
		agentinstall.EnrollmentDirectory + "/telemetry/complete-cached-updates-consent.json",
		agentinstall.EnrollmentDirectory + "/telemetry/endpoint-identity-consent.json",
	} {
		result[path] = systemdHash(t, path)
	}
	return result
}

func readAdminExpectedGeneration(t *testing.T) journalgeneration.Tuple {
	t.Helper()
	file, err := os.Open("/etc/tracebolt/journal-activation.json")
	if err != nil {
		t.Fatal("read-admin committed journal authority unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		t.Fatal("read-admin journal authority bounds")
	}
	var activation struct {
		SchemaVersion, Phase string
		PolicyGeneration     journalgeneration.Tuple
	}
	if json.Unmarshal(raw, &activation) != nil || activation.SchemaVersion != "tracebolt.journal-activation.v1" || activation.Phase != "committed" || journalgeneration.Validate(activation.PolicyGeneration) != nil || activation.PolicyGeneration.Revision != 1 {
		t.Fatal("read-admin journal authority not fresh committed v3")
	}
	return activation.PolicyGeneration
}

func readAdminStopOwnedHelper(t *testing.T, c *readAdminNativeCommand) bool {
	t.Helper()
	if c == nil {
		return true
	}
	var result readAdminSocketNativeResult
	if !readAdminNativeMaintenance(t, c, "cleanup", &result) || !result.CleanupConfirmed {
		t.Error("owned helper containment unconfirmed; preserve state and discard VM")
		return false
	}
	return true
}

func TestReadAdminInitialProbeDiagnosticIsClosed(t *testing.T) {
	raw := "private-token-or-output"
	event := ptyEvent{Phase: "exit", ExitCode: 1, ReadAdminFailure: raw, ScopeApprovals: 99, Fingerprint: raw, Comparison: raw}
	got := readAdminProbeEventDiagnostic(event)
	if got != (readAdminProbeDiagnostic{"read-admin-phase-incomplete", "nonzero", false}) {
		t.Fatal("unbounded event exported")
	}
	event.ReadAdminFailure = "systemd-status-members"
	if got := readAdminProbeEventDiagnostic(event); got.Failure != "systemd-status-members" {
		t.Fatal("fixed preflight reason lost")
	}
	event = ptyEvent{Phase: "exit", ExitCode: 0, ReadAdminCanceled: true, ScopeApprovals: 1}
	if got := readAdminProbeEventDiagnostic(event); got != (readAdminProbeDiagnostic{"none", "zero", true}) {
		t.Fatal("valid cancellation diagnostic")
	}
	o := &readAdminNativeOptions{}
	if o.probeDiagnostic() != (readAdminProbeDiagnostic{"not_attempted", "not_observed", false}) {
		t.Fatal("unset probe")
	}
	o.initialProbe = readAdminProbeDiagnostic{raw, raw, false}
	b, _ := json.Marshal(o.probeDiagnostic())
	if bytes.Contains(b, []byte(raw)) {
		t.Fatal("arbitrary output exported")
	}
}
