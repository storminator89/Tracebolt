//go:build windows && cgo && tracebolt_setup_rust && tracebolt_setup_gui_fixture && tracebolt_setup_gui_ci_fixture

package windowssetupui

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Injected by the exact-source CI test-image build; absent from ordinary builds.
var fixtureCIBuildSource string

func TestRustNativeGUITLSCI(t *testing.T) {
	values := make(map[string]string)
	for key := range fixtureCIValues() {
		if value, exists := os.LookupEnv(key); exists {
			values[key] = value
		}
	}
	for _, key := range []string{"GITLAB_CI", "BUILD_BUILDID", "TF_BUILD", "JENKINS_URL", "CONTINUOUS_INTEGRATION", "TEAMCITY_VERSION", "CIRCLECI", "BUILDKITE"} {
		if value, exists := os.LookupEnv(key); exists {
			values[key] = value
		}
	}
	if !fixtureCIContextAllowed(fixtureCIBuildSource, values) || strings.TrimSpace(fixtureCIBuildSource) != fixtureCIBuildSource {
		t.Fatal("exact inert TLS GitHub CI build and context required")
	}
	fmt.Println("RUST_GUI_FIXTURE_CI_SOURCE " + fixtureCIBuildSource)
	runRustNativeGUIFixture(t, "tls")
}
