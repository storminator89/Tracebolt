package rustagent

import (
	"os"
	"strings"
	"testing"
)

// Source-order contract only: this does not execute PowerShell or Windows SCM.
func TestRustInvitationBootstrapPrecedesInstallerAndEnrollmentMutations(t *testing.T) {
	read := func(path string) string {
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	order := func(source string, markers ...string) {
		t.Helper()
		last := -1
		for _, marker := range markers {
			at := strings.Index(source, marker)
			if at < 0 || at <= last {
				t.Fatalf("bootstrap preflight ordering missing: %q", marker)
			}
			last = at
		}
	}
	order(read("deploy/windows-rust/Install-Tracebolt.ps1"),
		"if ($mode -eq 'invitation') { $validationArguments += '--bootstrap',$InvitationBootstrap }",
		"& $Executable @validationArguments", "if ($LASTEXITCODE -ne 0)",
		"New-TraceboltProtectedDirectory $bin", "New-Service -Name")
	source := read("rust/windows-agent/src/main.rs")
	start := strings.Index(source, "Command::ValidateConfig {")
	order(source[start:], "config.validate()?;", "read_bounded(&p, 65536)",
		"validate_initial_bootstrap(&config, bootstrap.as_ref())?;", "if check_manager {")
	start = strings.Index(source, "let config = Config::load(&directory)?;")
	order(source[start:], "read_bounded(&p, 65536)",
		"validate_initial_bootstrap(&config, bootstrap.as_ref())?;",
		"tracebolt_windows_agent::compatibility::check(",
		"Sender::open(&directory, true)?", "Enrollment::open(&directory, true, bootstrap)?")
	source = read("rust/windows-agent/src/enrollment.rs")
	start = strings.Index(source, "pub fn open(")
	order(source[start:], "validate_initial_bootstrap(&config, bootstrap.as_ref())?;",
		"crate::compatibility::check(&config, &ca)?;", ".open(state.join(\"enrollment.lock\"))?",
		"Connection::open_with_flags", "let key = KeyPair::generate_for")
}
