//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"localrmm/internal/agentinstall"
)

const readAdminPriorVersion = "v0.1.0-rc.2"
const readAdminPriorSource = "a6368b0202b1efecdb6214dc34c4302d239854f7"
const readAdminPriorManifest = "5eae7faad1e9f3d15881c44d2c8878f5956f5ee5a91ca591a3c9dbba1e650559"

var readAdminPriorHashes = map[string]string{
	"agent-service":       "2b4e8f3174ab831bab3522d7119c0973819e214d2800d9328e7be72282e207e0",
	"enroll-agent":        "44a2235072459cc73fc918c9596e51fe441407b721f3d7cfc2b796fc1bbe645c",
	"lan-agent":           "6e1ac6ca7b50ae11141b1d345dc69cd59e0ff97583aa3cefd52152b209509bb5",
	"socket-owner-reader": "5e360633dbc1acda24acd5b24317f3ce7619af7598dd7ed6119f5d5c4e5585f8",
	"source":              "3813b61b0565e9becd8c6921769b8448437d5c0adca4348ba4cbff8510356856",
}

type readAdminUpgradeNativeChecks struct {
	PriorVersion              string `json:"priorVersion"`
	PriorSourceCommit         string `json:"priorSourceCommit"`
	PriorAgentSHA256          string `json:"priorAgentSHA256"`
	CandidateAgentSHA256      string `json:"candidateAgentSHA256"`
	ArtifactReplaced          bool   `json:"artifactReplaced"`
	IdentityAndScopesRetained bool   `json:"identityAndScopesRetained"`
	PrivateStateVerified      bool   `json:"privateStateVerified"`
	LocalApprovalObserved     bool   `json:"localApprovalObserved"`
}

func readAdminPriorArtifacts(t *testing.T) (map[string]string, string) {
	t.Helper()
	dir := os.Getenv("TRACEBOLT_READ_ADMIN_PRIOR_DIRECTORY")
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || systemdHash(t, filepath.Join(dir, "manifest.json")) != readAdminPriorManifest {
		t.Fatal("verified prior release fixture unavailable")
	}
	binaries := map[string]string{}
	for role, want := range readAdminPriorHashes {
		name := "tracebolt-" + readAdminPriorVersion + "-linux-amd64-" + role
		if role == "source" {
			name = "tracebolt-" + readAdminPriorVersion + "-source.tar"
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || systemdHash(t, path) != want {
			t.Fatal("prior release artifact contract mismatch")
		}
		binaries[role] = path
	}
	return binaries, binaries["source"]
}

func readAdminRunApprovedUpgrade(t *testing.T, c *readAdminNativeCommand, stage *string) {
	t.Helper()
	if c.replacement == nil || !c.options.upgrade || c.options.scenario != "complete" {
		t.Fatal("explicit native upgrade gate missing")
	}
	*stage = "read_admin_upgrade"
	next := c.replacement
	oldHash := systemdHash(t, agentinstall.AgentPath)
	replacement := filepath.Join(filepath.Dir(next.configs[false]), "tracebolt-"+readAdminFixtureVersion+"-linux-amd64-lan-agent")
	newHash := systemdHash(t, replacement)
	checks := &readAdminUpgradeNativeChecks{PriorVersion: readAdminPriorVersion, PriorSourceCommit: readAdminPriorSource, PriorAgentSHA256: readAdminPriorHashes["lan-agent"], CandidateAgentSHA256: newHash}
	c.options.upgradeChecks = checks
	if oldHash != readAdminPriorHashes["lan-agent"] || oldHash == newHash {
		t.Fatal("native upgrade requires exact prior and different candidate bytes")
	}
	before := readAdminIdentitySnapshot(t)
	authority := readAdminAuthoritySnapshot(t)
	receipt := systemdHash(t, "/var/lib/tracebolt-agent-installer/socket-owner-install-complete.json")
	sequence := systemdSequence(t, agentinstall.EnrollmentDirectory)
	approval := "UPGRADE READ ADMIN"
	if c.options.profile == "http-test" {
		approval += " OVER HTTP"
	}
	args := []string{next.python, "-I", "-c", readAdminLauncher, next.maintenance["upgrade"]}
	raw, _ := json.Marshal(readAdminPTYInput(args, "", approval, false))
	defer clear(raw)
	cmd := exec.Command(next.python, "-I", "-c", readAdminPTY)
	cmd.Env = next.environment()
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	defer clear(output)
	var event ptyEvent
	validEvent := len(output) <= 8192 && json.Unmarshal(bytes.TrimSpace(output), &event) == nil && event.Phase == "exit" && !event.SecretEcho
	if validEvent {
		c.options.observeSetup(event)
	} else {
		c.options.setupFailure = "driver-output-invalid"
	}
	if err != nil && c.options.setupDiagnostic() == "none" {
		c.options.setupFailure = "driver-execution-failed"
	}
	if err != nil || !validEvent || event.ExitCode != 0 || event.ScopeApprovals != 1 || !event.ReadAdminComplete || !event.ReadAdminPhasesComplete {
		t.Fatal("coordinated native upgrade did not complete")
	}
	checks.LocalApprovalObserved = true
	if !reflect.DeepEqual(before, readAdminIdentitySnapshot(t)) || !reflect.DeepEqual(authority, readAdminAuthoritySnapshot(t)) || systemdHash(t, "/var/lib/tracebolt-agent-installer/socket-owner-install-complete.json") != receipt || systemdSequence(t, agentinstall.EnrollmentDirectory) < sequence {
		t.Fatal("native upgrade changed identity grant or floor")
	}
	checks.IdentityAndScopesRetained = true
	// A complete coordinator result requires exact nonroot whole-state equality
	// before it resumes the service. Later ordinary sequence advancement is expected.
	checks.PrivateStateVerified = true
	if systemdHash(t, agentinstall.AgentPath) != newHash {
		t.Fatal("native upgrade did not replace executable")
	}
	checks.ArtifactReplaced = true
	*c = *next
}

func TestReadAdminPriorReleaseContractIsImmutable(t *testing.T) {
	if readAdminPriorVersion != "v0.1.0-rc.2" || readAdminPriorSource != "a6368b0202b1efecdb6214dc34c4302d239854f7" || len(readAdminPriorHashes) != 5 || readAdminPriorHashes["lan-agent"] == readAdminPriorHashes["source"] {
		t.Fatal("prior release contract changed")
	}
}

func TestReadAdminUpgradeClosedFailureProjection(t *testing.T) {
	for _, phase := range []string{"preflight", "prepare", "drain", "retained-state", "native-upgrade", "helper-rebind", "same-scope-validation", "restore-runtime", "commit", "lock-release"} {
		options := &readAdminNativeOptions{}
		expected := "read-admin-upgrade-" + phase
		options.observeSetup(ptyEvent{Phase: "exit", ExitCode: 1, ReadAdminFailure: expected, ReadAdminComplete: false})
		if options.setupDiagnostic() != expected {
			t.Fatal("closed upgrade phase lost")
		}
	}
	for _, value := range []string{"private-host-value", "read-admin-upgrade-unrecognized"} {
		options := &readAdminNativeOptions{}
		options.observeSetup(ptyEvent{Phase: "exit", ExitCode: 1, ReadAdminFailure: value})
		if options.setupDiagnostic() != "read-admin-phase-incomplete" {
			t.Fatal("untrusted upgrade diagnostic exported")
		}
	}
}
