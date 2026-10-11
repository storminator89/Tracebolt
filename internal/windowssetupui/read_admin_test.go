package windowssetupui

import (
	"context"
	"strings"
	"testing"
)

func readAdminUIFixture() (Config, Hooks) {
	return Config{Disclosure: "legacy-five", HTTPDisclosure: "legacy-http", ReadAdminDisclosure: "twelve-full-details", ReadAdminHTTPDisclosure: "twelve-http-details", ReadAdminSummary: "twelve-grouped-summary", ReadAdminHTTPSummary: "explicit-plaintext-risk-summary"}, Hooks{InstallReadAdmin: func(context.Context, []byte, bool, func(string)) error { return nil }}
}

func selectedReadAdminFlow(t *testing.T) *flow {
	t.Helper()
	c, h := readAdminUIFixture()
	f := freshFlow(c, h)
	if err := f.selectBootstrap([]byte(`{"public":"fixture"}`), fixtureTrust()); err != nil {
		t.Fatal(err)
	}
	return &f
}

func TestReadAdminFreshProfileKeepsConsentUncheckedAcrossNavigation(t *testing.T) {
	f := selectedReadAdminFlow(t)
	if !f.readAdmin || f.scope || f.canInstall() || f.toggleDetails() {
		t.Fatal("fresh profile granted consent or opened review early")
	}
	if !f.next() || !f.readAdmin || f.canInstall() || f.details {
		t.Fatal("profile selection granted consent")
	}
	if !f.toggleDetails() || f.scope || f.canInstall() {
		t.Fatal("optional details granted consent")
	}
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	if !f.back() || !f.readAdmin || f.scope || f.details || f.canInstall() {
		t.Fatal("back changed profile or reused consent")
	}
	if !f.next() || !f.readAdmin || f.scope || f.details || f.canInstall() {
		t.Fatal("repeat review reused consent")
	}
	f.back()
	if !f.clearSelection() || !f.readAdmin || f.scope || f.details || len(f.bootstrap) != 0 {
		t.Fatal("new bootstrap changed profile or reused consent")
	}
}

func TestReadAdminBusyAndRepeatedDetailsCannotExpandConsent(t *testing.T) {
	f := selectedReadAdminFlow(t)
	f.next()
	// Opening the full details is optional; the actual data approval is not.
	f.service, f.identity, f.compared = true, true, true
	if f.canInstall() || f.begin(opInstall, false) {
		t.Fatal("unchecked data consent admitted")
	}
	f.scope = true
	if !f.begin(opInstall, false) || f.toggleDetails() || f.begin(opInstall, false) {
		t.Fatal("busy selection changed")
	}
	if f.requestClose() || f.toggleDetails() {
		t.Fatal("cancel permitted another operation")
	}
	f.complete(context.Canceled)
	if f.toggleDetails() || f.next() || f.back() {
		t.Fatal("failed setup retried")
	}
}

func TestReadAdminReviewUsesSummaryWithOptionalExactDetails(t *testing.T) {
	c, h := readAdminUIFixture()
	if !freshFlow(c, h).readAdmin || readAdminAvailable(c, Hooks{}) {
		t.Fatal("wrong profile availability")
	}
	for _, details := range []bool{false, true} {
		shown := reviewPresentation(c, true, details)
		want, wantHTTP := c.ReadAdminSummary, c.ReadAdminHTTPSummary
		if details {
			want, wantHTTP = c.ReadAdminDisclosure, c.ReadAdminHTTPDisclosure
		}
		if shown.Disclosure != want || shown.HTTPDisclosure != wantHTTP {
			t.Fatal("wrong profile disclosure")
		}
		trust := fixtureTrust()
		if strings.Contains(reviewText(shown, trust), wantHTTP) {
			t.Fatal("HTTP warning shown for TLS")
		}
		trust.HTTPTest = true
		text := reviewText(shown, trust)
		if !strings.Contains(text, want) || !strings.Contains(text, wantHTTP) || strings.Contains(text, "legacy-five") {
			t.Fatal("scope or plaintext risk hidden")
		}
	}
	// Retain the internal earlier contract without presenting a second choice.
	if reviewProfile(c, false).Disclosure != c.Disclosure || freshFlow(Config{}, Hooks{}).readAdmin {
		t.Fatal("internal compatibility changed")
	}
	c.ReadAdminSummary = ""
	if readAdminAvailable(c, h) {
		t.Fatal("missing concise disclosure admitted")
	}
}
