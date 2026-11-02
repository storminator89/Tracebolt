package windowssetupui

// Test-only configuration guards, not authentication. The reviewed PR-only
// workflow and immutable checkout are the authority; no production entry exists.
import (
	"regexp"
	"strings"
	"testing"
)

var fixtureCICommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var fixtureCINumber = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

func fixtureCIContextAllowed(source string, values map[string]string) bool {
	if !fixtureCICommit.MatchString(source) {
		return false
	}
	env := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.ToUpper(key)
		if _, duplicate := env[key]; duplicate {
			return false
		}
		env[key] = value
	}
	exact := map[string]string{
		"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_EVENT_NAME": "pull_request",
		"GITHUB_REF": "refs/pull/201/merge", "GITHUB_JOB": "rust-gui-tls",
		"GITHUB_WORKFLOW":     "Build unsigned Windows Setup candidates",
		"GITHUB_WORKFLOW_REF": "storminator89/Tracebolt/.github/workflows/windows-setup-build.yml@refs/pull/201/merge",
		"GITHUB_SHA":          source, "GITHUB_WORKFLOW_SHA": source,
		"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
		"TRACEBOLT_RUST_GUI_CI":              "github-actions-pr201-tls-only-v1",
		"TRACEBOLT_RUST_GUI_CI_SOURCE":       source,
		"TRACEBOLT_RUST_GUI_FIXTURE_EXECUTE": "synthetic-window-only-v1",
		"TRACEBOLT_RUST_GUI_FIXTURE_CASE":    "tls",
	}
	for key, expected := range exact {
		if env[key] != expected {
			return false
		}
	}
	for _, key := range []string{"TRACEBOLT_RUST_GUI_CI_HEAD", "TRACEBOLT_RUST_GUI_CI_BASE"} {
		if !fixtureCICommit.MatchString(env[key]) {
			return false
		}
	}
	for _, key := range []string{"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"} {
		if !fixtureCINumber.MatchString(env[key]) {
			return false
		}
	}
	for _, key := range []string{"GITLAB_CI", "BUILD_BUILDID", "TF_BUILD", "JENKINS_URL", "CONTINUOUS_INTEGRATION", "TEAMCITY_VERSION", "CIRCLECI", "BUILDKITE"} {
		if _, exists := env[key]; exists {
			return false
		}
	}
	return true
}

func fixtureCIValues() map[string]string {
	source := strings.Repeat("a", 40)
	return map[string]string{
		"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
		"GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_EVENT_NAME": "pull_request",
		"GITHUB_REF": "refs/pull/201/merge", "GITHUB_JOB": "rust-gui-tls",
		"GITHUB_WORKFLOW":     "Build unsigned Windows Setup candidates",
		"GITHUB_WORKFLOW_REF": "storminator89/Tracebolt/.github/workflows/windows-setup-build.yml@refs/pull/201/merge",
		"GITHUB_SHA":          source, "GITHUB_WORKFLOW_SHA": source,
		"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
		"GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
		"TRACEBOLT_RUST_GUI_CI": "github-actions-pr201-tls-only-v1", "TRACEBOLT_RUST_GUI_CI_SOURCE": source,
		"TRACEBOLT_RUST_GUI_CI_HEAD": strings.Repeat("b", 40), "TRACEBOLT_RUST_GUI_CI_BASE": strings.Repeat("c", 40),
		"TRACEBOLT_RUST_GUI_FIXTURE_EXECUTE": "synthetic-window-only-v1", "TRACEBOLT_RUST_GUI_FIXTURE_CASE": "tls",
	}
}

func TestRustGUICIContextRequiresEveryHostedPR201TLSBinding(t *testing.T) {
	values := fixtureCIValues()
	source := strings.Repeat("a", 40)
	if !fixtureCIContextAllowed(source, values) {
		t.Fatal("complete inert context rejected")
	}
	for key := range values {
		copy := fixtureCIValues()
		delete(copy, key)
		if fixtureCIContextAllowed(source, copy) {
			t.Fatal("missing binding admitted")
		}
		copy[key] = "wrong"
		if fixtureCIContextAllowed(source, copy) {
			t.Fatal("wrong binding admitted")
		}
	}
	for _, key := range []string{"GITLAB_CI", "BUILD_BUILDID", "TF_BUILD", "JENKINS_URL", "CONTINUOUS_INTEGRATION", "TEAMCITY_VERSION", "CIRCLECI", "BUILDKITE"} {
		copy := fixtureCIValues()
		copy[key] = ""
		if fixtureCIContextAllowed(source, copy) {
			t.Fatal("other CI marker admitted")
		}
	}
	values["ci"] = "true"
	if fixtureCIContextAllowed(source, values) || fixtureCIContextAllowed("", fixtureCIValues()) {
		t.Fatal("ambiguous or unbound context admitted")
	}
}
