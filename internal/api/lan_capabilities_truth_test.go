package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuidedCapabilitiesDescribeShippedScopeWithoutInstallationClaim(t *testing.T) {
	s := &Server{lanOnly: true, guidedEnrollment: true, insecureHTTPTest: true, ai: &aiState{}}
	w := httptest.NewRecorder()
	if !s.lanCapabilities(w) || w.Code != 200 {
		t.Fatal("guided capabilities unavailable")
	}
	var got struct {
		ShellExecution bool     `json:"shellExecution"`
		Limitations    []string `json:"limitations"`
	}
	if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ShellExecution {
		t.Fatal("invalid capabilities or remote execution enabled")
	}
	text := strings.Join(got.Limitations, "\n")
	for _, want := range []string{"UNENCRYPTED LAN TEST", "does not establish service installation", "v3 profile supports complete dpkg", "original ages", "rather than confirmed CVE", "Managed inventory is excluded from AI"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing scope boundary %q", want)
		}
	}
	for _, obsolete := range []string{"service installation/reboot acceptance and credential renewal are not implemented", "no history, complete inventory"} {
		if strings.Contains(text, obsolete) {
			t.Fatal("obsolete implementation claim retained")
		}
	}
}
