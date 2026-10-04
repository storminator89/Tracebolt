package main

import (
	"bytes"
	"localrmm/internal/lanclient"
	"testing"
)

func TestJournalConsentCLIRejectsBeforePrivateAccess(t *testing.T) {
	for _, o := range []journalConsentOptions{{Path: "/inert", Mode: "initialize", Identity: "1:1"}, {Path: "/inert", Mode: "preview", Identity: "1:1", Plaintext: true}, {Path: "/inert", Mode: "initialize", Acknowledged: true}, {Path: "/inert", Mode: "enable", Identity: "1:1"}} {
		called := false
		var out bytes.Buffer
		code := runJournalConsent(o, journalConsentHooks{identity: func(string) bool { called = true; return true }, configure: func(string, string, bool, bool) (lanclient.JournalConsentResult, error) {
			called = true
			return lanclient.JournalConsentResult{}, nil
		}}, &out, &out)
		if code != 2 || called {
			t.Fatal("invalid flags accessed private state")
		}
	}
}
func TestJournalConsentCLIPreviewAndInitializeContract(t *testing.T) {
	for _, mode := range []string{"preview", "initialize"} {
		var out, errOut bytes.Buffer
		called := false
		code := runJournalConsent(journalConsentOptions{Path: "/inert", Mode: mode, Identity: "1001:1001", Acknowledged: mode == "initialize", Plaintext: mode == "initialize"}, journalConsentHooks{identity: func(string) bool { return true }, configure: func(path, m string, ack, plain bool) (lanclient.JournalConsentResult, error) {
			called = true
			if path != "/inert" || m != mode || ack != (mode == "initialize") || plain != (mode == "initialize") {
				t.Fatal("changed consent")
			}
			return lanclient.JournalConsentResult{Mode: m}, nil
		}}, &out, &errOut)
		if code != 0 || !called || out.Len() == 0 || errOut.Len() != 0 {
			t.Fatal("consent CLI failed")
		}
	}
}
