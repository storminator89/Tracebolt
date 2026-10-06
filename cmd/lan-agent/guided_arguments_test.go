//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Both child invocations stop before any credential, collector or network
// access. The old flags fail admission; the supported flags reach only the
// local validator, which rejects our deliberately invalid temporary config.
func TestGuidedValidationCLIArgumentContract(t *testing.T) {
	if mode := os.Getenv("TRACEBOLT_INERT_GUIDED_ARGS"); mode != "" {
		os.Args = []string{"lan-agent", "--config", os.Getenv("TRACEBOLT_INERT_GUIDED_CONFIG"), "--validate-guided"}
		if mode == "old" {
			os.Args = append(os.Args, "--service-identity", "200:201")
		}
		main()
		os.Exit(9)
	}
	path := filepath.Join(t.TempDir(), "invalid-config.json")
	if os.WriteFile(path, []byte(`{"inert":true}`), 0600) != nil {
		t.Fatal("inert config creation failed")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	for _, mode := range []string{"old", "supported"} {
		cmd := exec.Command(executable, "-test.run=^TestGuidedValidationCLIArgumentContract$")
		cmd.Env = []string{"TRACEBOLT_INERT_GUIDED_ARGS=" + mode, "TRACEBOLT_INERT_GUIDED_CONFIG=" + path}
		output, err := cmd.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 {
			t.Fatal("inert CLI boundary did not reject")
		}
		expected := "Tracebolt service identity rejected before private-state access.\n"
		if mode == "supported" {
			expected = "Tracebolt guided handoff validation failed; identity and state preserved.\n"
		}
		if !bytes.Equal(output, []byte(expected)) {
			t.Fatal("CLI invocation did not reach its expected fixed boundary")
		}
	}
}
