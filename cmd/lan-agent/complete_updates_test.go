package main

import (
	"bytes"
	"localrmm/internal/lanclient"
	"testing"
)

func TestCompleteUpdatesConsentIdentityBeforePrivateReadAndExplicitAck(t *testing.T) {
	calls := 0
	h := completeUpdatesConsentHooks{identity: func(string) bool { return false }, configure: func(string, string, bool) (lanclient.CompleteUpdatesConsentResult, error) {
		calls++
		return lanclient.CompleteUpdatesConsentResult{}, nil
	}}
	var out, errOut bytes.Buffer
	if code := runCompleteUpdatesConsent(completeUpdatesConsentOptions{Path: "/inert/config", Mode: "enable", Identity: "1001:1001", Acknowledged: true}, h, &out, &errOut); code != 2 || calls != 0 {
		t.Fatal("identity guard bypassed")
	}
	h.identity = func(string) bool { return true }
	for _, o := range []completeUpdatesConsentOptions{{Path: "/inert/config", Mode: "enable", Identity: "1001:1001"}, {Path: "/inert/config", Mode: "preview", Identity: "1001:1001", Acknowledged: true}, {Path: "/inert/config", Mode: "other", Identity: "1001:1001"}, {Path: "/inert/config", Mode: "disable"}} {
		if code := runCompleteUpdatesConsent(o, h, &out, &errOut); code != 2 || calls != 0 {
			t.Fatal("invalid mode reached private read")
		}
	}
	if code := runCompleteUpdatesConsent(completeUpdatesConsentOptions{Path: "/inert/config", Mode: "preview", Identity: "1001:1001"}, h, &out, &errOut); code != 0 || calls != 1 {
		t.Fatal("preview refused")
	}
}
