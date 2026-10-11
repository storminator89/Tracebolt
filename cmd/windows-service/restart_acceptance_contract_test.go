//go:build tracebolt_restart_acceptance && !tracebolt_fresh_native && !tracebolt_setup_native

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowspath"
)

// This schema is deliberately separate from all shipped CLI and earlier native
// gates. Values are accidental-invocation guards, never proof of host authority.
type restartAcceptancePlan struct {
	Schema                           string              `json:"schema"`
	RunID                            string              `json:"runId"`
	PlanSHA256                       string              `json:"planSHA256"`
	BrowserBaselineSHA256            string              `json:"browserBaselineSHA256"`
	ApprovalID                       string              `json:"approvalId"`
	InteractiveAuthority             bool                `json:"interactiveAuthority"`
	TwoCLIInvocationsApproved        bool                `json:"twoCLIInvocationsApproved"`
	NotBefore                        string              `json:"notBefore"`
	ExpiresAt                        string              `json:"expiresAt"`
	Workspace                        string              `json:"workspace"`
	MachineID                        string              `json:"machineIdSHA256"`
	OSBuild                          string              `json:"osBuild"`
	ControllerSHA256                 string              `json:"controllerSHA256"`
	ControllerSourceCommit           string              `json:"controllerSourceCommit"`
	ControllerSourceTree             string              `json:"controllerSourceTree"`
	ControllerSourceInventorySHA256  string              `json:"controllerSourceInventorySHA256"`
	ApplicationSourceCommit          string              `json:"applicationSourceCommit"`
	ApplicationSourceTree            string              `json:"applicationSourceTree"`
	ApplicationSourceInventorySHA256 string              `json:"applicationSourceInventorySHA256"`
	InstalledSHA256                  string              `json:"installedSHA256"`
	ReceiptSHA256                    string              `json:"receiptSHA256"`
	IntentSHA256                     string              `json:"intentSHA256"`
	DeviceID                         string              `json:"deviceId"`
	CertificateSHA256                string              `json:"certificateSHA256"`
	ManagerInstanceID                string              `json:"managerInstanceId"`
	AgentOrigin                      string              `json:"agentOrigin"`
	EnrollmentOrigin                 string              `json:"enrollmentOrigin"`
	PublicSHA256                     restartPublicHashes `json:"publicSHA256"`
}

type restartPublicHashes struct {
	Bootstrap   string `json:"bootstrap"`
	Config      string `json:"config"`
	Ready       string `json:"ready"`
	Certificate string `json:"certificate"`
}

type restartAcceptanceReport struct {
	Schema                        string  `json:"schema"`
	RunID                         string  `json:"runId"`
	PlanSHA256                    string  `json:"planSHA256"`
	BrowserBaselineSHA256         string  `json:"browserBaselineSHA256"`
	Status                        string  `json:"status"`
	Phase                         string  `json:"phase"`
	FullAcceptance                bool    `json:"fullAcceptance"`
	InstallerContentionRefused    bool    `json:"installerContentionRefused"`
	OldProcessExited              bool    `json:"oldProcessExited"`
	NewRunningProcess             bool    `json:"newRunningProcess"`
	ReceiptPublicIdentityRetained bool    `json:"receiptPublicIdentityRetained"`
	CommandInvocations            int     `json:"commandInvocations"`
	OldExitCode                   *uint32 `json:"oldExitCode"`
	NewProcessCreationFiletime    string  `json:"newProcessCreationFiletime"`
	NewProcessCreationUTC         string  `json:"newProcessCreationUTC"`
	OldProcessGenerationSHA256    string  `json:"oldProcessGenerationSHA256"`
	NewProcessGenerationSHA256    string  `json:"newProcessGenerationSHA256"`
	DeviceID                      string  `json:"deviceId"`
	CertificateSHA256             string  `json:"certificateSHA256"`
	InstalledSHA256               string  `json:"installedSHA256"`
	ControllerSHA256              string  `json:"controllerSHA256"`
	WindowStartFiletime           string  `json:"windowStartFiletime"`
	WindowEndFiletime             string  `json:"windowEndFiletime"`
}

var restartAcceptanceRejected = errors.New("restart acceptance guard rejected")
var restartID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`)
var restartApproval = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`)
var restartDeviceID = regexp.MustCompile(`^agent_[a-f0-9]{32}$`)
var restartManagerID = regexp.MustCompile(`^manager_[a-f0-9]{32}$`)

func restartHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func restartHex(s string, size int) bool {
	b, e := hex.DecodeString(s)
	return size > 0 && e == nil && len(b) == size && hex.EncodeToString(b) == s && s != strings.Repeat(string(s[0]), size*2)
}
func restartOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && len(s) <= 512 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && u.Opaque == "" && s == "https://"+u.Host && u.Host == strings.ToLower(u.Host) && !strings.ContainsAny(s, "\\%\r\n\t ")
}

// Decode exactly one finite object, rejecting duplicates at every depth before
// the typed unknown-field decoder. Null is never a substitute for a required key.
func restartStrictJSON(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return restartAcceptanceRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return restartAcceptanceRejected
		}
		v, e := d.Token()
		if e != nil || v == nil {
			return restartAcceptanceRejected
		}
		delim, ok := v.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				key, ok := k.(string)
				if e != nil || !ok || seen[key] {
					return restartAcceptanceRejected
				}
				seen[key] = true
				if value(depth+1) != nil {
					return restartAcceptanceRejected
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return restartAcceptanceRejected
			}
		case '[':
			for d.More() {
				if value(depth+1) != nil {
					return restartAcceptanceRejected
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return restartAcceptanceRejected
			}
		default:
			return restartAcceptanceRejected
		}
		return nil
	}
	if value(0) != nil {
		return restartAcceptanceRejected
	}
	if _, e := d.Token(); e != io.EOF {
		return restartAcceptanceRejected
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return restartAcceptanceRejected
	}
	return nil
}
func restartParsePlan(raw []byte, now time.Time) (restartAcceptancePlan, error) {
	var p restartAcceptancePlan
	if restartStrictJSON(raw, &p, 16<<10) != nil {
		return p, restartAcceptanceRejected
	}
	// Required-key presence includes booleans and nested public bindings.
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	canonical, _ := json.Marshal(p)
	var want map[string]json.RawMessage
	_ = json.Unmarshal(canonical, &want)
	if len(keys) != len(want) {
		return p, restartAcceptanceRejected
	}
	for k := range want {
		if _, ok := keys[k]; !ok {
			return p, restartAcceptanceRejected
		}
	}
	var pub map[string]json.RawMessage
	_ = json.Unmarshal(keys["publicSHA256"], &pub)
	if len(pub) != 4 {
		return p, restartAcceptanceRejected
	}
	for _, key := range []string{"bootstrap", "config", "ready", "certificate"} {
		if _, ok := pub[key]; !ok {
			return p, restartAcceptanceRejected
		}
	}
	if strings.HasPrefix(p.RunID, "REPLACE") || strings.HasPrefix(p.ApprovalID, "REPLACE") {
		return p, restartAcceptanceRejected
	}
	if p.Schema != "tracebolt.windows-own-restart-controller-plan.v1" || !restartID.MatchString(p.RunID) || !restartApproval.MatchString(p.ApprovalID) || !p.InteractiveAuthority || !p.TwoCLIInvocationsApproved || !windowspath.Canonical(p.Workspace) || len(p.Workspace) < 4 || !restartDeviceID.MatchString(p.DeviceID) || !restartManagerID.MatchString(p.ManagerInstanceID) || !restartOrigin(p.AgentOrigin) || !restartOrigin(p.EnrollmentOrigin) || !regexp.MustCompile(`^[1-9][0-9]{3,7}$`).MatchString(p.OSBuild) {
		return p, restartAcceptanceRejected
	}
	for _, s := range []string{p.PlanSHA256, p.BrowserBaselineSHA256, p.MachineID, p.ControllerSHA256, p.ControllerSourceInventorySHA256, p.ApplicationSourceInventorySHA256, p.InstalledSHA256, p.ReceiptSHA256, p.IntentSHA256, p.CertificateSHA256, p.PublicSHA256.Bootstrap, p.PublicSHA256.Config, p.PublicSHA256.Ready, p.PublicSHA256.Certificate} {
		if !restartHex(s, 32) {
			return p, restartAcceptanceRejected
		}
	}
	if p.ApplicationSourceCommit != "858d7846b4fa2f7b3cdaf672c067400d894369a4" || p.ApplicationSourceTree != "91999db7fcf6687795ba052b0029e670c01b01c7" {
		return p, restartAcceptanceRejected
	}
	for _, s := range []string{p.ControllerSourceCommit, p.ControllerSourceTree, p.ApplicationSourceCommit, p.ApplicationSourceTree} {
		if !restartHex(s, 20) {
			return p, restartAcceptanceRejected
		}
	}
	a, e := time.Parse(time.RFC3339, p.NotBefore)
	b, f := time.Parse(time.RFC3339, p.ExpiresAt)
	if e != nil || f != nil || !strings.HasSuffix(p.NotBefore, "Z") || !strings.HasSuffix(p.ExpiresAt, "Z") || now.Before(a) || !now.Before(b) || b.Sub(a) < 240*time.Second || b.Sub(a) > time.Hour {
		return p, restartAcceptanceRejected
	}
	return p, nil
}

func TestRestartAcceptanceStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":1}`, `{"a":{"x":1,"x":2}}`, `{"a":null}`, `{"a":1} {"a":2}`, `{"unexpected":true}`} {
		var v struct {
			A int `json:"a"`
		}
		if restartStrictJSON([]byte(raw), &v, 1024) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	var v struct {
		A int `json:"a"`
	}
	if restartStrictJSON([]byte(`{"a":1}`), &v, 1024) != nil || v.A != 1 {
		t.Fatal("strict object rejected")
	}
}
func TestRestartAcceptancePlanRejectsMissingAuthority(t *testing.T) {
	for _, raw := range []string{`{}`, `{"schema":"tracebolt.windows-own-restart-controller-plan.v1"}`, `null`, `[]`} {
		if _, e := restartParsePlan([]byte(raw), time.Now()); e == nil {
			t.Fatal("incomplete authority accepted")
		}
	}
}

// Portable evidence predicates accept only values derived from native held
// objects. They contain no native backend, clock override or PASS injection.
const restartObserverRights uint32 = 0x0005    // QUERY_CONFIG | QUERY_STATUS
const restartProcessRights uint32 = 0x00101000 // QUERY_LIMITED_INFORMATION | SYNCHRONIZE
const restartTokenRights uint32 = 0x0008       // TOKEN_QUERY

type restartGeneration struct {
	pid     uint32
	created uint64
}

func restartSameGeneration(a, b restartGeneration) bool {
	return a.pid != 0 && b.pid == a.pid && a.created != 0 && b.created == a.created
}
func restartNewGeneration(old, next restartGeneration, start, end uint64) bool {
	return old.pid != 0 && next.pid != 0 && old.created != 0 && next.created != old.created && start <= next.created && next.created <= end && start <= end
}
func restartClockCoherent(start, end uint64, elapsed time.Duration) bool {
	if end < start || elapsed < 0 || elapsed > time.Hour || end-start > uint64(time.Hour/100) {
		return false
	}
	wall := time.Duration(end-start) * 100
	drift := wall - elapsed
	if drift < 0 {
		drift = -drift
	}
	return drift <= 250*time.Millisecond
}
func restartSameFile(a, b [3]uint32, acl, afterACL, digest, afterDigest string) bool {
	return a == b && acl != "" && acl == afterACL && digest == afterDigest
}

func TestRestartAcceptanceGenerationAndClockContracts(t *testing.T) {
	old := restartGeneration{7, 100}
	reused := restartGeneration{7, 200}
	other := restartGeneration{8, 200}
	if !restartSameGeneration(old, old) || restartSameGeneration(old, reused) || restartSameGeneration(old, restartGeneration{0, 100}) {
		t.Fatal("PID-generation bracket invalid")
	}
	for _, next := range []restartGeneration{reused, other} {
		if !restartNewGeneration(old, next, 150, 250) {
			t.Fatal("distinct retained generation rejected")
		}
	}
	for _, next := range []restartGeneration{old, {8, 100}, {0, 200}, {8, 149}, {8, 251}} {
		if restartNewGeneration(old, next, 150, 250) {
			t.Fatal("unproved generation accepted")
		}
	}
	if !restartClockCoherent(100, 100+10000000, time.Second) || restartClockCoherent(101, 100, 0) || restartClockCoherent(100, 100+20000000, time.Second) || restartClockCoherent(0, ^uint64(0), time.Second) {
		t.Fatal("same-clock precision/drift contract failed")
	}
	if restartObserverRights != 0x5 || restartProcessRights != 0x101000 || restartTokenRights != 0x8 || restartProcessRights&0x1 != 0 || restartObserverRights&(0x10|0x20|0x2|0x10000) != 0 {
		t.Fatal("native read-only rights expanded")
	}
	id := [3]uint32{1, 2, 3}
	if !restartSameFile(id, id, "acl", "acl", "digest", "digest") || restartSameFile(id, [3]uint32{1, 2, 4}, "acl", "acl", "digest", "digest") || restartSameFile(id, id, "acl", "changed", "digest", "digest") || restartSameFile(id, id, "acl", "acl", "digest", "changed") {
		t.Fatal("file binding accepted mutation")
	}
}

func restartPortablePlan(now time.Time) restartAcceptancePlan {
	h := restartHash([]byte("inert portable contract fixture"))
	return restartAcceptancePlan{Schema: "tracebolt.windows-own-restart-controller-plan.v1", RunID: "fixture_123", PlanSHA256: h, BrowserBaselineSHA256: h, ApprovalID: "approval_123", InteractiveAuthority: true, TwoCLIInvocationsApproved: true, NotBefore: now.Add(-time.Minute).UTC().Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).UTC().Format(time.RFC3339), Workspace: `C:\private`, MachineID: h, OSBuild: "26100", ControllerSHA256: h, ControllerSourceCommit: "0123456789012345678901234567890123456789", ControllerSourceTree: "1234567890123456789012345678901234567890", ControllerSourceInventorySHA256: h, ApplicationSourceCommit: "858d7846b4fa2f7b3cdaf672c067400d894369a4", ApplicationSourceTree: "91999db7fcf6687795ba052b0029e670c01b01c7", ApplicationSourceInventorySHA256: h, InstalledSHA256: h, ReceiptSHA256: h, IntentSHA256: h, DeviceID: "agent_01234567890123456789012345678901", CertificateSHA256: h, ManagerInstanceID: "manager_01234567890123456789012345678901", AgentOrigin: "https://agent.test:9443", EnrollmentOrigin: "https://manager.test:8443", PublicSHA256: restartPublicHashes{h, h, h, h}}
}
func TestRestartAcceptanceCompletePlanGrammar(t *testing.T) {
	now := time.Date(2026, 10, 11, 3, 0, 0, 0, time.UTC)
	p := restartPortablePlan(now)
	raw, _ := json.Marshal(p)
	if _, e := restartParsePlan(raw, now); e != nil {
		t.Fatal("complete inert plan rejected")
	}
	for name, mutate := range map[string]func(*restartAcceptancePlan){"expiry": func(p *restartAcceptancePlan) { p.ExpiresAt = p.NotBefore }, "window": func(p *restartAcceptancePlan) { p.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339) }, "interactive": func(p *restartAcceptancePlan) { p.InteractiveAuthority = false }, "two commands": func(p *restartAcceptancePlan) { p.TwoCLIInvocationsApproved = false }, "app source": func(p *restartAcceptancePlan) { p.ApplicationSourceCommit = p.ControllerSourceCommit }, "artifact placeholder": func(p *restartAcceptancePlan) { p.ControllerSHA256 = strings.Repeat("a", 64) }, "workspace alias": func(p *restartAcceptancePlan) { p.Workspace = `C:\private\..\public` }, "approval punctuation": func(p *restartAcceptancePlan) { p.ApprovalID = "approval:123" }} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			raw, _ := json.Marshal(bad)
			if _, e := restartParsePlan(raw, now); e == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"bootstrap":`), []byte(`"Bootstrap":`), 1), bytes.Replace(raw, []byte(`"publicSHA256":{`), []byte(`"publicSHA256":{"bootstrap":"`+p.PublicSHA256.Bootstrap+`",`), 1)} {
		if _, e := restartParsePlan(bad, now); e == nil {
			t.Fatal("nested alias or duplicate accepted")
		}
	}
}

func TestRestartAcceptanceFilePinsPermitProductionReads(t *testing.T) {
	// Windows share checks concern data read/execute, data write/append and delete.
	// Production's readAccess/share=0 must see no conflicting retained data access.
	const shareSensitiveRead = uint32(0x0001 | 0x0020)
	const shareSensitiveWrite = uint32(0x0002 | 0x0004)
	const deleteAccess = uint32(0x10000)
	if restartFilePinRights&(shareSensitiveRead|shareSensitiveWrite|deleteAccess) != 0 || restartFilePinShare != 3 {
		t.Fatal("retained metadata would block exclusive production content reads")
	}
}

const restartFilePinRights uint32 = 0x00020080 // READ_CONTROL | FILE_READ_ATTRIBUTES; OpenChild adds SYNCHRONIZE only.
const restartFilePinShare uint32 = 3           // FILE_SHARE_READ | FILE_SHARE_WRITE, no delete.

func restartNativeArguments(args []string) bool {
	return len(args) == 3 && args[1] == "-test.run=^TestOwnRestartNativeAcceptance$" && args[2] == "-test.timeout=0"
}
func restartRejectCI(entries []string) bool {
	for _, entry := range entries {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(k)
		if k == "CI" || k == "CONTINUOUS_INTEGRATION" || k == "BUILD_BUILDID" || k == "TF_BUILD" || k == "TEAMCITY_VERSION" || k == "JENKINS_URL" || k == "HUDSON_URL" || strings.HasPrefix(k, "GITHUB_") || strings.HasPrefix(k, "GITLAB_") || strings.HasPrefix(k, "CIRCLE_") || strings.HasPrefix(k, "BUILDKITE_") || strings.HasPrefix(k, "TRAVIS_") || strings.HasPrefix(k, "RUNNER_") {
			return true
		}
	}
	return false
}
func TestRestartAcceptanceNativeEntryIsExplicit(t *testing.T) {
	good := []string{"controller.exe", "-test.run=^TestOwnRestartNativeAcceptance$", "-test.timeout=0"}
	if !restartNativeArguments(good) {
		t.Fatal("fixed entry denied")
	}
	for _, args := range [][]string{good[:2], append(append([]string{}, good...), "-test.v"), {"controller.exe", "-test.run=TestOwnRestartNativeAcceptance", "-test.timeout=0"}, {"controller.exe", "-test.run=^TestOwnRestartNativeAcceptance$", "-test.timeout=45s"}} {
		if restartNativeArguments(args) {
			t.Fatal("expanded entry accepted")
		}
	}
	for _, entry := range []string{"CI=false", "CI=", "ci=0", "GITHUB_ACTIONS=false", "TF_BUILD=0", "JENKINS_URL=", "RUNNER_OS=Windows"} {
		if !restartRejectCI([]string{entry}) {
			t.Fatal("CI presence accepted")
		}
	}
	if restartRejectCI([]string{`PATH=C:\Windows`, "TRACEBOLT_RESTART_PLAN=public metadata"}) {
		t.Fatal("ordinary environment rejected")
	}
}
