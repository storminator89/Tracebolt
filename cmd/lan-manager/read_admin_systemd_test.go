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

// Frozen source-literal vocabulary; never accept a pattern or arbitrary error text.
const readAdminSetupFailureCodes = `abort-abandoned-generation
abort-archive-members
abort-archive-metadata
abort-archived-activation
abort-legacy-authority
abort-original-activation
abort-original-backup
abort-original-broad-scope
abort-original-exact-scope
abort-original-operation
abort-original-preview
abort-original-transaction
abort-receipt-contract
absolute-protected-path
acceptance-capture-exceeded
acceptance-deadline-exceeded
acceptance-driver-rejected
acceptance-gate-rejected
acceptance-injected-before-journal
acceptance-launcher-arguments
acceptance-launcher-artifacts
acceptance-launcher-components
acceptance-launcher-config
acceptance-launcher-host
acceptance-launcher-input
acceptance-launcher-rejected
acceptance-launcher-source-loader
acceptance-launcher-terminal
acceptance-launcher-workflow
account-membership
activation-appeared
activation-commit-changed
activation-migration-mismatch
activation-stage-present
active-socket-missing
addition-already-authorized
agent-changed-after-stop
agent-changed-before-activation
agent-config-changed
agent-directory-changed
agent-executable-template
agent-not-confirmed-stopped
agent-restart-blocked-retain-state
agent-restart-command-failed
agent-restart-ownership
agent-restart-status
agent-resume-failed
agent-resume-not-confirmed
agent-stop-command-failed
agent-stop-failed
agent-upgrade-required
all-system-services-already-authorized
alternate-unit-fragment
approved-installation-changed
archive-already-exists
archive-metadata
archive-readback
archive-revision
archive-source-metadata
artifact-hashes
asymmetric-declaration-copies
backup-verification
bound-declarations
bounded-json
bounded-offline-policy
broad-journal-not-ready
canonical-policy
cgroup-event-limit
cgroup-v2-required
changed-protected-file
command-output-limit
command-timeout
committed-activation-changed
committed-activation-mismatch
compatibility-changed
completion-readback
configuration-directory
consent-disclosure-contract
consent-enable-failed
consent-identity-changed
consent-preview-failed
consent-result-contract
content-acknowledgement-required
create-parent-changed
create-parent-replaced
created-artifact-changed
created-artifact-readback
dedicated-account
deployment-members
deployment-migration-required
disable-original-policy
disable-policy-changed
disabled-policy-unconfirmed
disabled-private-identity-changed
disabled-private-readback
disabled-root-policy-readback
driver-execution-failed
driver-output-invalid
duplicate-json-member
enable-link-changed
enable-link-metadata
enable-not-confirmed
enable-readback-disabled
enablement-link-changed
enablement-link-metadata
existing-activated-v3-config
existing-deployment
existing-helper-account
existing-helper-path
existing-installation-use-upgrade-or-recovery
existing-journal-group
existing-journal-state-retained
existing-policy
existing-policy-disabled-separate-enable-required
existing-read-admin-intent
existing-revoke-evidence
existing-socket-owner-account
existing-socket-owner-state
existing-state-domain
existing-systemd-journal-group
existing-transaction-target
explicit-service-allowlist
explicit-service-profile
fail-stop-parent-intent
file-write
fixed-activation-commit
fixed-agent-unit
fixed-amendment-command
fixed-artifact-changed
fixed-artifact-metadata
fixed-artifact-write
fixed-backup-file
fixed-cgroup-changed
fixed-cgroup-not-drained
fixed-command
fixed-command-failed
fixed-command-stage
fixed-consent-mode
fixed-control-group
fixed-create-directory
fixed-create-file
fixed-create-metadata
fixed-directory-list
fixed-drain-unit
fixed-enable-link
fixed-enablement-link
fixed-file-changed
fixed-file-metadata
fixed-helper-template
fixed-inventory-command
fixed-launcher-path
fixed-offline-failure-stage
fixed-offline-mode
fixed-phase
fixed-platform-path
fixed-policy-disable
fixed-public-source
fixed-receipt
fixed-replacement
fixed-root-command
fixed-socket-command
fixed-source-create
fixed-source-path
fixed-transaction-directory
fixed-unit
foreign-helper-systemd-unit
fresh-generation
fresh-grant-epoch-or-identity
fresh-read-admin-only
helper-account-changed
helper-account-command-failed
helper-enablement
helper-identity
helper-numeric-identity
helper-socket-start-command-failed
helper-source-changed
helper-source-changed-after-copy
helper-source-metadata
helper-source-private-parent
helper-source-root
helper-source-temporary-parent
immutable-source-pins
immutable-source-revision
inactive-new-helper
initialized-identity-changed
initialized-policy-generation
install-or-device-approval-incomplete
installation-changed
installation-changed-after-inventory
installation-changed-after-journal
installation-changed-after-socket
installation-changed-after-stop
installed-agent-capabilities-unavailable
installed-agent-changed
installed-agent-upgrade-required
installed-artifact-changed
installed-helper-artifact
installed-manifest
installed-owner-record
installed-release-or-bootstrap-changed
installed-socket-cli-incompatible
installed-unit-template-changed
installer-lock-changed
interrupted
invalid-json
invalid-json-number
inventory-account-membership
inventory-activation-commit-changed
inventory-agent-changed-after-stop
inventory-agent-changed-before-activation
inventory-agent-config-changed
inventory-agent-directory-changed
inventory-agent-not-confirmed-stopped
inventory-agent-restart-blocked-retain-state
inventory-agent-restart-command-failed
inventory-agent-restart-ownership
inventory-agent-restart-status
inventory-agent-resume-failed
inventory-agent-resume-not-confirmed
inventory-agent-stop-command-failed
inventory-agent-stop-failed
inventory-ambiguous-apt-consent
inventory-ambiguous-identity-consent
inventory-ambiguous-overview-consent
inventory-approved-installation-changed
inventory-bounded-json
inventory-changed-protected-file
inventory-command-output-limit
inventory-command-timeout
inventory-committed-activation-changed
inventory-consent-disclosure-contract
inventory-consent-enable-failed
inventory-consent-identity-changed
inventory-consent-preview-failed
inventory-consent-result-contract
inventory-content-acknowledgement-required
inventory-created-artifact-changed
inventory-dedicated-account
inventory-duplicate-json-member
inventory-enable-not-confirmed
inventory-enable-readback-disabled
inventory-existing-activated-v3-config
inventory-existing-helper-account
inventory-existing-helper-path
inventory-existing-state-domain
inventory-existing-systemd-journal-group
inventory-explicit-service-allowlist
inventory-explicit-service-profile
inventory-file-write
inventory-fixed-activation-commit
inventory-fixed-agent-unit
inventory-fixed-command
inventory-fixed-command-stage
inventory-fixed-consent-mode
inventory-fixed-create-directory
inventory-fixed-create-file
inventory-fixed-inventory-command
inventory-fixed-public-source
inventory-fixed-unit
inventory-foreign-helper-systemd-unit
inventory-helper-account-command-failed
inventory-helper-numeric-identity
inventory-helper-socket-start-command-failed
inventory-immutable-source-pins
inventory-inactive-new-helper
inventory-initialized-policy-generation
inventory-installation-changed-after-stop
inventory-installed-agent-capabilities-unavailable
inventory-installed-agent-upgrade-required
inventory-installed-manifest
inventory-installed-owner-record
inventory-installer-lock-changed
inventory-interrupted
inventory-invalid-json
inventory-invalid-json-number
inventory-inventory-command-output-limit
inventory-inventory-command-timeout
inventory-inventory-operation-failed
inventory-journal-group-identity
inventory-json-members
inventory-local-account-database
inventory-local-nss-only
inventory-local-operation-failed
inventory-local-root-linux-required
inventory-local-root-terminal-required
inventory-missing-apt-spools
inventory-missing-identity-spools
inventory-missing-overview-spools
inventory-nonroot-command-identity
inventory-operation-failed
inventory-owned-agent-systemd-unit
inventory-owned-artifact-hash
inventory-partial-apt-spools
inventory-partial-identity-spools
inventory-partial-overview-spools
inventory-pending-activation-changed
inventory-plan-does-not-accept-apply-flags
inventory-previously-completed-scope-changed
inventory-protected-agent-config
inventory-protected-agent-directory
inventory-protected-apt-state
inventory-protected-directory
inventory-protected-file
inventory-protected-identity-state
inventory-protected-overview-state
inventory-public-bootstrap-scope
inventory-published-helper-units
inventory-resume-ownership-changed
inventory-resume-protected-state-unverified
inventory-reviewed-installation-changed
inventory-reviewed-plan-changed
inventory-root-linux-local-administration
inventory-socket-activation
inventory-socket-ownership
inventory-source-deadline
inventory-source-hash
inventory-source-manifest-entry
inventory-source-manifest-hash
inventory-source-manifest-members
inventory-source-redirect-rejected
inventory-source-response
inventory-source-size
inventory-state-shape-contract
inventory-stopped-agent
inventory-stopped-agent-preview
inventory-systemd-reload-command-failed
inventory-systemd-unit-inspection-command-failed
inventory-systemd-unit-status
inventory-terminal-write-failed
inventory-transport-specific-acknowledgement
inventory-uncertain-apt-initialization
inventory-uncertain-identity-initialization
inventory-uncertain-overview-initialization
inventory-unchanged-agent-identity
inventory-unchanged-existing-accounts
inventory-unresolved-installer-ownership
inventory-unresolved-template-placeholder
inventory-validation-or-enable-incomplete
journal-account-membership
journal-activation-commit-changed
journal-agent-changed-after-stop
journal-agent-changed-before-activation
journal-agent-restart-blocked-retain-state
journal-agent-restart-command-failed
journal-agent-restart-ownership
journal-agent-restart-status
journal-agent-stop-command-failed
journal-changed-protected-file
journal-command-output-limit
journal-command-timeout
journal-committed-activation-changed
journal-consent-identity-changed
journal-content-acknowledgement-required
journal-created-artifact-changed
journal-creation-incomplete
journal-dedicated-account
journal-duplicate-json-member
journal-existing-helper-account
journal-existing-helper-path
journal-existing-state-domain
journal-existing-systemd-journal-group
journal-explicit-service-allowlist
journal-explicit-service-profile
journal-file-write
journal-fixed-activation-commit
journal-fixed-agent-unit
journal-fixed-command
journal-fixed-command-stage
journal-fixed-create-directory
journal-fixed-create-file
journal-fixed-unit
journal-foreign-helper-systemd-unit
journal-group-identity
journal-helper-account-command-failed
journal-helper-numeric-identity
journal-helper-socket-start-command-failed
journal-inactive-new-helper
journal-initialized-policy-generation
journal-installed-manifest
journal-installed-owner-record
journal-installer-lock-changed
journal-interrupted
journal-invalid-json
journal-journal-group-identity
journal-json-members
journal-local-account-database
journal-local-nss-only
journal-local-operation-failed
journal-owned-agent-systemd-unit
journal-owned-artifact-hash
journal-pending-activation-changed
journal-plan-does-not-accept-apply-flags
journal-preview-command-failed
journal-protected-directory
journal-protected-file
journal-public-bootstrap-scope
journal-published-helper-units
journal-reviewed-plan-changed
journal-root-linux-local-administration
journal-socket-activation
journal-socket-ownership
journal-state-changed
journal-stopped-agent
journal-stopped-agent-preview
journal-systemd-reload-command-failed
journal-systemd-unit-inspection-command-failed
journal-systemd-unit-status
journal-transport-specific-acknowledgement
journal-unchanged-agent-identity
journal-unchanged-existing-accounts
journal-unresolved-installer-ownership
journal-unresolved-template-placeholder
json-members
loaded-executable-arguments
loaded-pid-namespace
loaded-unit-mainpid
loaded-unit-ownership
loaded-unit-security-contract
local-account-database
local-nss-only
local-operation-failed
local-root-linux-required
local-root-terminal-required
local-terminal-required
maintenance-operation-failed
manager-capability-origin
manager-capability-unavailable-or-upgrade-required
manager-public-ca
manager-upgrade-required
native-directory-contract
network-content-encoding
network-content-length
network-deadline
network-redirect-rejected
network-response-limit
network-response-size
network-status-or-origin
network-transport
none
nonroot-amendment-result
nonroot-command-identity
nonroot-offline-identity
not_attempted
offline-capabilities-cli-failed
offline-cli-failed
offline-cli-output-limit
offline-cli-timeout
offline-consent-result
offline-consent-state
offline-disable-cli-failed
offline-endpoint-identity
offline-identity-cli-failed
offline-initialize-cli-failed
offline-mutation-readback
offline-policy-binding
offline-policy-write
offline-preview-cli-failed
offline-unexpected-discard
offline-unexpected-mutation
offline-validate-cli-failed
original-artifact-evidence
original-deployment-changed
original-deployment-evidence
original-files-changed
original-grant-changed-or-disabled
original-identity-evidence
original-install-receipt
original-policy-evidence
original-private-grant-changed
owned-agent-systemd-unit
owned-artifact-hash
owned-fixed-unit
owned-read-admin-receipt-required
owned-socket-enablement-link
parent-intent-changed
parent-phase-evidence
partial-or-foreign-source-cache
pending-activation-changed
phase-receipt-changed
phase-receipt-mismatch
phase-start-receipt-missing
plaintext-ca-rejected
plan-does-not-accept-apply-flags
platform-file
platform-read-limit
policy-byte-limit
policy-generation
policy-members
policy-revision
policy-revision-overflow
preexisting-loaded-unit
preexisting-private-socket-consent
previously-completed-scope-changed
private-consent-readback
profile-and-units-are-exclusive
protected-agent-config
protected-agent-directory
protected-directory
protected-file
protected-file-changed
protected-parent-changed
protected-source-directory
protected-source-file
protected-source-path
public-bootstrap-changed
public-bootstrap-scope
published-helper-units
read-admin-phase-incomplete
read-admin-receipt-mismatch
read-admin-result-invalid
read-admin-result-unavailable
readback-agent-not-stopped
readback-resume-identity-changed
readback-resume-unconfirmed
receipt-parent
receipt-readback
receipt-write
replacement-expected-absence
replacement-old-file-changed
replacement-readback
replacement-stage-changed
replacement-target-appeared
restart-enablement-changed
restart-ownership-changed
restart-unit-status
resume-identity-changed
resume-ownership-changed
resume-protected-state-unverified
reviewed-installation-changed
reviewed-launcher-hashes
reviewed-plan-changed
reviewed-source-changed
revoke-completion-readback
revoke-helper-shutdown-unconfirmed
revoke-incomplete
revoke-incomplete-shutdown-unconfirmed
revoke-private-identity-changed
revoke-socket-admission
revoked-or-uncertain-grant
root-linux-local-administration
runtime-directory
safety-socket-disable-unconfirmed
safety-socket-stop-unconfirmed
setup-provenance
socket-activation
socket-admission-not-disabled
socket-configuration-unconfirmed
socket-enablement
socket-enablement-link
socket-maintenance-source-changed
socket-manager-capability-origin
socket-manager-capability-unavailable-or-upgrade-required
socket-manager-upgrade-required
socket-metadata
socket-ownership
socket-parent-identity-changed
socket-parent-intent-required
socket-parent-phase-required
socket-revocation-unconfirmed
source-deadline
source-download-verification
source-file-changed
source-hash
source-manifest-entry
source-manifest-hash
source-manifest-members
source-parent-changed
source-redirect-rejected
source-response
source-revision
source-short-write
source-size
source-stage-readback
source-staging-changed
stage-appeared
stage-metadata
stage-write
staged-declarations-changed
staged-installation-changed
staging-remnant
state-shape-contract
stopped-agent
stopped-agent-preview
stopped-installation-changed
supported-linux-amd64-kernel
systemd-pid1-required
systemd-reload-command-failed
systemd-status-members
systemd-unit-inspection-command-failed
systemd-unit-status
terminal-write-failed
transaction-metadata
transaction-revision
transport-specific-acknowledgement
uncertain-inventory-phase-retained
uncertain-journal-phase-retained
uncertain-socket-phase-retained
unchanged-agent-identity
unchanged-existing-accounts
unchanged-main-artifacts
unexpected-account-change
unexpected-socket-enablement-link
unit-drain-unconfirmed
unit-dropin
unit-stop-unconfirmed
units-not-stopped
unowned-configuration-state
unresolved-amendment-stage
unresolved-amendment-transaction
unresolved-installer-ownership
unresolved-template-placeholder
unresolved-unit-placeholder
verified-helper-artifact`

func readAdminSetupFailure(value string) string {
	for _, allowed := range strings.Fields(readAdminSetupFailureCodes) {
		if value == allowed {
			return allowed
		}
	}
	return "read-admin-phase-incomplete"
}
func (o *readAdminNativeOptions) observeSetup(event ptyEvent) {
	value := event.ReadAdminFailure
	if value == "" {
		value = "read-admin-result-unavailable"
		if event.Phase == "exit" && event.ExitCode == 0 && !event.SecretEcho && event.ScopeApprovals == 1 && (event.ReadAdminComplete || event.ReadAdminCanceled) {
			value = "none"
		}
	}
	o.setupFailure = readAdminSetupFailure(value)
}
func (o *readAdminNativeOptions) setupDiagnostic() string {
	if o.setupFailure == "" {
		return "not_attempted"
	}
	return readAdminSetupFailure(o.setupFailure)
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
	setupFailure              string
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
	} else {
		c.options.setupFailure = "driver-execution-failed"
	}
	output, err := cmd.Output()
	defer clear(output)
	if len(output) > 8192 {
		if !cancel {
			c.options.setupFailure = "driver-output-invalid"
		}
		if cancel {
			c.options.initialProbe.Failure = "driver-output-invalid"
		}
		t.Fatal("read-admin bounded PTY probe failed")
	}
	var event ptyEvent
	if json.Unmarshal(bytes.TrimSpace(output), &event) != nil || event.Phase != "exit" || event.SecretEcho {
		if !cancel {
			c.options.setupFailure = "driver-output-invalid"
		}
		if cancel && !(err != nil && len(output) == 0) {
			c.options.initialProbe.Failure = "driver-output-invalid"
		}
		t.Fatal("read-admin probe produced unexpected prompt or data")
	}
	if cancel {
		c.options.initialProbe = readAdminProbeEventDiagnostic(event)
	} else {
		c.options.observeSetup(event)
	}
	if err != nil {
		if !cancel && c.options.setupDiagnostic() == "none" {
			c.options.setupFailure = "driver-execution-failed"
		}
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

func TestReadAdminSetupDiagnosticIsClosed(t *testing.T) {
	o := &readAdminNativeOptions{}
	if o.setupDiagnostic() != "not_attempted" {
		t.Fatal("missing setup diagnostic changed")
	}
	for _, reason := range strings.Fields(readAdminSetupFailureCodes) {
		o.observeSetup(ptyEvent{Phase: "exit", ExitCode: 1, ReadAdminFailure: reason})
		if o.setupDiagnostic() != reason {
			t.Fatal("fixed setup reason lost")
		}
	}
	o.observeSetup(ptyEvent{ReadAdminFailure: "private token or arbitrary error"})
	if o.setupDiagnostic() != "read-admin-phase-incomplete" {
		t.Fatal("private setup error escaped")
	}
	o.observeSetup(ptyEvent{})
	if o.setupDiagnostic() == "none" {
		t.Fatal("missing event claimed success")
	}
	o.observeSetup(ptyEvent{Phase: "exit", ScopeApprovals: 1, ReadAdminComplete: true})
	if o.setupDiagnostic() != "none" {
		t.Fatal("confirmed setup success lost")
	}
}
