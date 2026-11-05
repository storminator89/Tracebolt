package rustagent

import (
	"os"
	"strings"
	"testing"
)

// Source-order evidence only, not execution of PowerShell/SCM on Windows.
func TestRustCompatibilityPrecedesPersistentInitialization(t *testing.T) {
	read := func(path string) string {
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	script := read("deploy/windows-rust/Install-Tracebolt.ps1")
	requireOrder := func(source string, markers ...string) {
		previous := -1
		for _, marker := range markers {
			at := strings.Index(source, marker)
			if at < 0 || at <= previous {
				t.Fatalf("required preflight ordering missing: %q", marker)
			}
			previous = at
		}
	}
	requireOrder(script, "if ($mode -ne 'preprovided') { $validationArguments += '--check-manager' }", "& $Executable @validationArguments", "if ($LASTEXITCODE -ne 0)", "New-TraceboltProtectedDirectory $bin", "New-Service -Name")
	source := read("rust/windows-agent/src/enrollment.rs")
	requireOrder(source, "if initialize {\n            crate::compatibility::check(&config, &ca)?;", ".open(state.join(\"enrollment.lock\"))?", "Connection::open_with_flags", "let key = KeyPair::generate_for")
	source = read("rust/windows-agent/src/main.rs")
	start := strings.Index(source, "let config = Config::load(&directory)?;")
	if start < 0 {
		t.Fatal("init config read missing")
	}
	source = source[start:]
	requireOrder(source, "if config.enrollment_mode != EnrollmentMode::Preprovided", "tracebolt_windows_agent::compatibility::check(", "if config.enrollment_mode == EnrollmentMode::Preprovided", "Enrollment::open(&directory, true, bootstrap)?")
}
