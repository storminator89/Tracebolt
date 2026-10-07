package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJournalCapabilitiesExclusiveBeforeSenderState(t *testing.T) {
	for _, args := range [][]string{
		{"--journal-capabilities"},
		{"--journal-capabilities", "--config", "/never/read/private-key"},
		{"--config", "/never/read/private-key", "--journal-capabilities"},
		{"--journal-reader", "--journal-capabilities"},
		{"--journal-capabilities", "--journal-reader"},
		{"--journal-capabilities=true"}, {"--journal-capabilities=false"},
		{"-journal-capabilities"}, {"-journal-capabilities=true"},
		{"--journal-capabilities", "--journal-capabilities"},
	} {
		selected, exclusive := journalCapabilitiesInvocation(args)
		if !selected || exclusive != (len(args) == 1 && args[0] == "--journal-capabilities") {
			t.Fatal("incorrect mode selection", args)
		}
		var stdout, stderr bytes.Buffer
		exit := runJournalCapabilities(exclusive, &stdout, &stderr)
		if !exclusive {
			if exit != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatal("mixed or malformed capability invocation accepted", args)
			}
			continue
		}
		if exit != 0 || stderr.Len() != 0 {
			t.Fatal("exclusive capabilities failed")
		}
		// Pin the contract used by the guide before it may stop an agent.
		want := `{"schemaVersion":"tracebolt.journal-runtime-capabilities.v1","policyVersions":["tracebolt.journal-content-policy.v1","tracebolt.journal-content-policy.v2","tracebolt.journal-content-policy.v3","tracebolt.journal-content-policy.v4"],"generationReportVersions":["tracebolt.journal-generation-report.v1","tracebolt.journal-generation-report.v2","tracebolt.journal-generation-report.v3"],"requestVersions":["tracebolt.journal-request.v1","tracebolt.journal-request.v2","tracebolt.journal-request.v3"],"helperProtocols":["TBJ1","TBJ2","TBJ3"],"activationVersions":["tracebolt.journal-activation.v1"],"serviceAuthorization":["exact-units","all-system-services"],"scopes":["on-demand-allowlisted-system-service-log-content","on-demand-system-service-log-content","on-demand-retained-system-service-log-content"]}`
		if stdout.String() != want+"\n" || !json.Valid(stdout.Bytes()) {
			t.Fatal("capability contract changed", stdout.String())
		}
	}
	for _, args := range [][]string{nil, {"--config", "/unchanged/agent.json"}, {"--journal-reader"}, {"--foreground", "--service-identity", "1200:1200"}} {
		if selected, _ := journalCapabilitiesInvocation(args); selected {
			t.Fatal("normal sender intercepted")
		}
	}
	var stderr bytes.Buffer
	if runJournalCapabilities(true, failedCapabilityWriter{}, &stderr) != 2 || strings.Contains(stderr.String(), "PRIVATE") {
		t.Fatal("raw writer error leaked")
	}
}

type failedCapabilityWriter struct{}

func (failedCapabilityWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE RAW ERROR") }
