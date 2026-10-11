package windowsfullservices

import (
	"regexp"
	"testing"
	"time"
)

// Set only when building the separately approved native test artifact. These
// fields prevent accidental use of an unbound ordinary go-test executable; they
// are public binding metadata, never authorization evidence.
var fullServicesNativeSource string

func fullServicesNativeGate(env func(string) string, now time.Time, source string) bool {
	if env("CI") != "" || env("GITHUB_ACTIONS") != "" || env("TRACEBOLT_FULL_SERVICES_NATIVE") != "caller-visible-win32-localservice" {
		return false
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) || env("TRACEBOLT_FULL_SERVICES_NATIVE_SOURCE") != source {
		return false
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$`).MatchString(env("TRACEBOLT_FULL_SERVICES_NATIVE_APPROVAL")) {
		return false
	}
	expiry, e := time.Parse(time.RFC3339, env("TRACEBOLT_FULL_SERVICES_NATIVE_UNTIL"))
	return e == nil && now.Before(expiry) && expiry.Sub(now) <= 20*time.Minute
}
func TestFullServicesNativeGateRequiresSeparateExactOptIn(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	source := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	good := map[string]string{"TRACEBOLT_FULL_SERVICES_NATIVE": "caller-visible-win32-localservice", "TRACEBOLT_FULL_SERVICES_NATIVE_SOURCE": source, "TRACEBOLT_FULL_SERVICES_NATIVE_APPROVAL": "separate-reviewed-local-grant", "TRACEBOLT_FULL_SERVICES_NATIVE_UNTIL": now.Add(time.Minute).Format(time.RFC3339)}
	env := func(k string) string { return good[k] }
	if !fullServicesNativeGate(env, now, source) {
		t.Fatal("exact test binding rejected")
	}
	for key, value := range map[string]string{"CI": "true", "GITHUB_ACTIONS": "true", "TRACEBOLT_FULL_SERVICES_NATIVE": "1", "TRACEBOLT_FULL_SERVICES_NATIVE_SOURCE": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "TRACEBOLT_FULL_SERVICES_NATIVE_APPROVAL": "", "TRACEBOLT_FULL_SERVICES_NATIVE_UNTIL": now.Format(time.RFC3339)} {
		old := good[key]
		good[key] = value
		if fullServicesNativeGate(env, now, source) {
			t.Fatal("invalid native binding accepted")
		}
		good[key] = old
	}
	if fullServicesNativeGate(env, now, "") || fullServicesNativeGate(env, now.Add(-time.Hour), source) {
		t.Fatal("unbound or overlong grant accepted")
	}
}
