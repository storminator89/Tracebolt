package main

import (
	"bytes"
	"localrmm/internal/lanclient"
	"testing"
)

func TestOverviewConsentIdentityBeforePrivateReadAndExplicitAck(t *testing.T) {
	calls := 0
	h := overviewConsentHooks{identity: func(string) bool { return false }, configure: func(string, string, bool) (lanclient.OverviewConsentResult, error) {
		calls++
		return lanclient.OverviewConsentResult{}, nil
	}}
	var out, errOut bytes.Buffer
	if code := runOverviewConsent(overviewConsentOptions{Path: "/inert/config", Mode: "enable", Identity: "1001:1001", Acknowledged: true}, h, &out, &errOut); code != 2 || calls != 0 {
		t.Fatal("identity guard bypassed")
	}
	h.identity = func(string) bool { return true }
	for _, o := range []overviewConsentOptions{{Path: "/inert/config", Mode: "enable", Identity: "1001:1001"}, {Path: "/inert/config", Mode: "preview", Identity: "1001:1001", Acknowledged: true}, {Path: "/inert/config", Mode: "other", Identity: "1001:1001"}, {Path: "/inert/config", Mode: "disable"}} {
		if code := runOverviewConsent(o, h, &out, &errOut); code != 2 || calls != 0 {
			t.Fatal("invalid mode reached private read")
		}
	}
	if code := runOverviewConsent(overviewConsentOptions{Path: "/inert/config", Mode: "preview", Identity: "1001:1001"}, h, &out, &errOut); code != 0 || calls != 1 {
		t.Fatal("preview refused")
	}
}
