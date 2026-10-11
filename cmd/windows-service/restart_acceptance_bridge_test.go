//go:build tracebolt_restart_acceptance && !tracebolt_fresh_native && !tracebolt_setup_native

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// This invokes only the isolated Python coordinator's pure JSON projection.
// Neither native entry point, Windows API, CLI, manager nor browser is launched.
// The dedicated Linux source-validation job supplies Python 3.12 explicitly.
func TestRestartAcceptancePythonBridge(t *testing.T) {
	python, e := exec.LookPath("python3.12")
	if e != nil {
		t.Fatal("source-only bridge test requires Python 3.12")
	}
	wd, e := os.Getwd()
	if e != nil {
		t.Fatal("source workspace unavailable")
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", "tests", "windows_own_restart_native"))
	const script = `
import importlib.util, json, pathlib, sys
assert sys.version_info[:2] == (3,12)
root = pathlib.Path(sys.argv[1]).resolve(strict=True)
def load(name):
    path = root / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    assert pathlib.Path(module.__file__).resolve(strict=True) == path.resolve(strict=True)
    return module
contract = load('contract')
fixtures = load('test_contract')
bridge = load('windows_native')
p = fixtures.fixture_plan()
contract.validate_plan(p, 1791662400 + 300)
plan_hash = contract.digest(b'bridge-plan')
baseline_hash = contract.digest(b'bridge-baseline')
result = bridge.controller_plan(p, plan_hash, baseline_hash)
# No fixture, success override or native implementation is injected.
print(json.dumps(result, separators=(',', ':'), sort_keys=True))
`
	raw, e := exec.Command(python, "-I", "-B", "-c", script, root).Output()
	if e != nil {
		t.Fatal("source-only Python coordinator projection failed")
	}
	p, e := restartParsePlan(raw, time.Unix(1791662400+300, 0))
	if e != nil {
		t.Fatal("actual Go parser rejected actual Python coordinator plan")
	}
	if p.RunID != "portable-only-001" || p.PlanSHA256 != restartHash([]byte("bridge-plan")) || p.BrowserBaselineSHA256 != restartHash([]byte("bridge-baseline")) || p.Workspace != `C:\Private\workspace` || p.ApprovalID != "test-restart-approval" || !p.InteractiveAuthority || !p.TwoCLIInvocationsApproved || p.ControllerSourceCommit != restartHash([]byte("harness"))[:40] || p.ApplicationSourceCommit != "858d7846b4fa2f7b3cdaf672c067400d894369a4" || p.ApplicationSourceTree != "91999db7fcf6687795ba052b0029e670c01b01c7" || p.InstalledSHA256 != restartHash([]byte("service")) || p.ControllerSHA256 != restartHash([]byte("controller")) || p.DeviceID != "agent_34343434343434343434343434343434" || p.CertificateSHA256 != restartHash([]byte("cert")) || p.AgentOrigin != "https://manager.test:8444" || p.EnrollmentOrigin != "https://manager.test:8443" {
		t.Fatal("coordinator/native identity or authority binding diverged")
	}
	expected := restartPublicHashes{Bootstrap: restartHash([]byte("bootstrap")), Config: restartHash([]byte("config")), Ready: restartHash([]byte("ready")), Certificate: restartHash([]byte("certificate"))}
	if !reflect.DeepEqual(p.PublicSHA256, expected) {
		t.Fatal("public binding projection diverged")
	}
	// Exact key sets are part of the cross-language protocol, not just field values.
	var original, roundTrip map[string]json.RawMessage
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("Python JSON unavailable")
	}
	canonical, _ := json.Marshal(p)
	if json.Unmarshal(canonical, &roundTrip) != nil || len(original) != len(roundTrip) {
		t.Fatal("schema key sets diverged")
	}
	for k := range roundTrip {
		if _, ok := original[k]; !ok {
			t.Fatal("native schema key missing from Python projection")
		}
	}
}
