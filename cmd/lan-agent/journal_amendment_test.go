package main

import (
	"bytes"
	"localrmm/internal/lanclient"
	"testing"
)

func TestAmendmentCLIRejectsBeforePrivateAccess(t *testing.T) {
	for _, o := range []journalAmendmentOptions{{Path: "/inert", Mode: "accept", Identity: "1:1"}, {Path: "/inert", Mode: "preview", Identity: "1:1", Plaintext: true}, {Path: "/inert", Mode: "accept", Acknowledged: true}, {Path: "/inert", Mode: "enable", Identity: "1:1"}} {
		called := false
		var out bytes.Buffer
		code := runJournalAmendment(o, journalAmendmentHooks{identity: func(string) bool { called = true; return true }, configure: func(string, string, bool, bool) (lanclient.JournalAmendmentResult, error) {
			called = true
			return lanclient.JournalAmendmentResult{}, nil
		}}, &out, &out)
		if code != 2 || called {
			t.Fatal("invalid flags accessed private state")
		}
	}
}
func TestAmendmentCLIExplicitModes(t *testing.T) {
	for _, mode := range []string{"preview", "accept"} {
		var out, errOut bytes.Buffer
		called := false
		code := runJournalAmendment(journalAmendmentOptions{Path: "/inert", Mode: mode, Identity: "1001:1001", Acknowledged: mode == "accept", Plaintext: mode == "accept"}, journalAmendmentHooks{identity: func(string) bool { return true }, configure: func(path, m string, ack, plain bool) (lanclient.JournalAmendmentResult, error) {
			called = true
			if path != "/inert" || m != mode || ack != (mode == "accept") || plain != (mode == "accept") {
				t.Fatal("changed consent")
			}
			return lanclient.JournalAmendmentResult{Mode: m}, nil
		}}, &out, &errOut)
		if code != 0 || !called || out.Len() == 0 || errOut.Len() != 0 {
			t.Fatal("CLI failed")
		}
	}
}
