package main

import (
	"errors"
	"localrmm/internal/windowsacceptance/freshgate"
	"localrmm/internal/windowsservice"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This pure test helper is shared with portable fixtures. Native code supplies
// GetSystemWindowsDirectory; callers never supply an inherited SystemDrive.
func freshChildEnvironmentEntries(bootstrap string, systemDirectory func() (string, error), getenv func(string) string) ([]string, error) {
	directory, err := systemDirectory()
	if err != nil {
		return nil, freshgate.ErrGuard
	}
	drive, err := windowsservice.SystemDriveFromWindowsDirectory(directory)
	if err != nil || strings.ContainsRune(bootstrap, 0) {
		return nil, freshgate.ErrGuard
	}
	keys := []string{"SystemRoot", "WINDIR", "COMPUTERNAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR", "GITHUB_EVENT_NAME", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "TRACEBOLT_FRESH_PROFILE", "TRACEBOLT_FRESH_SOURCE", "TRACEBOLT_FRESH_TEST_SHA256", "TRACEBOLT_FRESH_SERVICE_SHA256", "TRACEBOLT_FRESH_SERVICE_ARTIFACT", "TRACEBOLT_FRESH_MACHINE", "TRACEBOLT_FRESH_RUN_ID", "TRACEBOLT_FRESH_ATTEMPT", "TRACEBOLT_FRESH_EXPIRES_UNIX", "TRACEBOLT_FRESH_APPROVE_SERVICES", "TRACEBOLT_FRESH_APPROVE_IDENTITY", "TRACEBOLT_FRESH_APPROVE_APP_ACLS", "TRACEBOLT_FRESH_APPROVE_FIVE_READ_SCOPES", "TRACEBOLT_FRESH_APPROVE_SYNTHETIC_CONSOLE", "TRACEBOLT_FRESH_APPROVE_LOOPBACK_TLS", "TRACEBOLT_FRESH_APPROVE_RETAIN_FOR_VM_DISPOSAL", "TRACEBOLT_FRESH_APPROVE_STOP_OWNED_SERVICE"}
	entries := []string{"SystemDrive=" + drive, "TRACEBOLT_FRESH_ROLE=child", "TRACEBOLT_FRESH_BOOTSTRAP=" + bootstrap, "GOTRACEBACK=none"}
	for _, k := range keys {
		v := getenv(k)
		if strings.ContainsRune(v, 0) {
			return nil, freshgate.ErrGuard
		}
		entries = append(entries, k+"="+v)
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j]) })
	return entries, nil
}

func TestFreshChildEnvironmentAddsOnlyTrustedSystemDrive(t *testing.T) {
	expectedKeys := []string{"SystemRoot", "WINDIR", "COMPUTERNAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR", "GITHUB_EVENT_NAME", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "TRACEBOLT_FRESH_PROFILE", "TRACEBOLT_FRESH_SOURCE", "TRACEBOLT_FRESH_TEST_SHA256", "TRACEBOLT_FRESH_SERVICE_SHA256", "TRACEBOLT_FRESH_SERVICE_ARTIFACT", "TRACEBOLT_FRESH_MACHINE", "TRACEBOLT_FRESH_RUN_ID", "TRACEBOLT_FRESH_ATTEMPT", "TRACEBOLT_FRESH_EXPIRES_UNIX", "TRACEBOLT_FRESH_APPROVE_SERVICES", "TRACEBOLT_FRESH_APPROVE_IDENTITY", "TRACEBOLT_FRESH_APPROVE_APP_ACLS", "TRACEBOLT_FRESH_APPROVE_FIVE_READ_SCOPES", "TRACEBOLT_FRESH_APPROVE_SYNTHETIC_CONSOLE", "TRACEBOLT_FRESH_APPROVE_LOOPBACK_TLS", "TRACEBOLT_FRESH_APPROVE_RETAIN_FOR_VM_DISPOSAL", "TRACEBOLT_FRESH_APPROVE_STOP_OWNED_SERVICE"}
	expected := []string{"TRACEBOLT_FRESH_ROLE=child", "TRACEBOLT_FRESH_BOOTSTRAP=public-bootstrap", "GOTRACEBACK=none", "SystemDrive=D:"}
	for _, key := range expectedKeys {
		expected = append(expected, key+"=public-"+key)
	}
	sort.Slice(expected, func(i, j int) bool { return strings.ToUpper(expected[i]) < strings.ToUpper(expected[j]) })
	var lookedUp []string
	calls := 0
	entries, err := freshChildEnvironmentEntries("public-bootstrap", func() (string, error) { calls++; return `D:\Windows`, nil }, func(key string) string {
		lookedUp = append(lookedUp, key)
		switch key {
		case "SystemDrive", "ProgramData", "ProgramFiles", "PATH", "GITHUB_TOKEN":
			return "HOSTILE_NOT_FORWARDED"
		}
		return "public-" + key
	})
	if err != nil || calls != 1 || !reflect.DeepEqual(entries, expected) || !reflect.DeepEqual(lookedUp, expectedKeys) {
		t.Fatal("child environment changed beyond trusted drive")
	}
}

func TestFreshChildEnvironmentRejectsInvalidDirectoryWithoutDisclosure(t *testing.T) {
	for _, directory := range []string{"", `C:`, `C:\`, `C:Windows`, `\\server\Windows`, `%SystemRoot%`, `C:\..\Windows`, `C:\Windows.`, `C:\Windows `, `C:\Windows%bad%`, `C:\Windows*`, `C:\Windows` + "\x00"} {
		calls := 0
		entries, err := freshChildEnvironmentEntries("public-bootstrap", func() (string, error) { return directory, nil }, func(string) string { calls++; return "public" })
		if err != freshgate.ErrGuard || entries != nil || calls != 0 {
			t.Fatal("invalid directory was not rejected before environment lookup")
		}
	}
	entries, err := freshChildEnvironmentEntries("public-bootstrap", func() (string, error) { return `C:\Windows`, errors.New("private native error") }, func(string) string { t.Fatal("lookup after directory failure"); return "" })
	if entries != nil || err != freshgate.ErrGuard || strings.Contains(err.Error(), "private") {
		t.Fatal("directory API failure not sanitized")
	}
}

func TestFreshChildEnvironmentRejectsNULAndRetainsEmptyValues(t *testing.T) {
	directory := func() (string, error) { return `C:\Windows`, nil }
	for _, pair := range [][2]string{{"public-bootstrap", "public\x00value"}, {"public\x00bootstrap", "public-value"}} {
		entries, err := freshChildEnvironmentEntries(pair[0], directory, func(string) string { return pair[1] })
		if entries != nil || err != freshgate.ErrGuard {
			t.Fatal("NUL environment accepted")
		}
	}
	entries, err := freshChildEnvironmentEntries("public-bootstrap", directory, func(string) string { return "" })
	if err != nil {
		t.Fatal("empty forwarded values changed")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if seen[key] {
			t.Fatal("duplicate environment key")
		}
		seen[key] = true
	}
	if !seen["SYSTEMDRIVE"] {
		t.Fatal("trusted drive missing")
	}
}
