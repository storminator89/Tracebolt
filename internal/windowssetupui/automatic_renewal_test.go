package windowssetupui

import (
	"strings"
	"testing"
)

func TestAutomaticRenewalNeedsSeparateFreshUncheckedConsent(t *testing.T) {
	trust := fixtureTrust()
	trust.AutomaticRenewal = true
	f := new(flow)
	if f.selectBootstrap([]byte(`{"public":"fixture"}`), trust) != nil || !f.next() {
		t.Fatal("preview")
	}
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	if f.renewalAcknowledged || f.canInstall() || f.begin(opInstall, false) {
		t.Fatal("renewal consent inferred")
	}
	f.renewalAcknowledged = true
	if !f.canInstall() {
		t.Fatal("explicit renewal rejected")
	}
	if !f.back() || f.renewalAcknowledged || !f.next() || f.canInstall() {
		t.Fatal("renewal consent survived Back")
	}
	f.scope, f.service, f.identity, f.compared, f.renewalAcknowledged = true, true, true, true, true
	if !f.begin(opInstall, false) || f.renewalAcknowledged {
		t.Fatal("operation did not clear consent")
	}
	legacy := consentedFlow(t)
	legacy.renewalAcknowledged = true
	if legacy.canInstall() {
		t.Fatal("legacy consent upgraded bootstrap")
	}
}

func TestAutomaticRenewalPreviewRequiresTLSAndDisclosure(t *testing.T) {
	trust := fixtureTrust()
	trust.AutomaticRenewal = true
	c := Config{Disclosure: "scope", AutomaticRenewalDisclosure: "same key until revocation"}
	if !previewAllowed(c, trust) || !strings.Contains(reviewText(c, trust), c.AutomaticRenewalDisclosure) {
		t.Fatal("renewal disclosure missing")
	}
	c.AutomaticRenewalDisclosure = ""
	if previewAllowed(c, trust) {
		t.Fatal("undisclosed renewal")
	}
	trust.HTTPTest = true
	trust.EnrollmentOrigin, trust.AgentOrigin = "http://manager.test", "http://agent.test"
	if validTrust(trust) {
		t.Fatal("HTTP renewal admitted")
	}
}

func TestAutomaticRenewalLayoutKeepsSeparateCheckboxVisible(t *testing.T) {
	for _, dpi := range []int{96, 120, 144, 192, 240} {
		layout, ok := layoutForClient(scaleUp(600, dpi), scaleUp(440, dpi), dpi, pageReview, false, true)
		if !ok {
			t.Fatal("renewal layout rejected")
		}
		check, present := layout[idAutomaticRenewal]
		if !present || check.Height < scale(32, dpi) || check.Y+check.Height > layout[idNote].Y || layout[idReviewText].Height < scale(64, dpi) {
			t.Fatal("renewal consent clipped")
		}
	}
	if _, ok := layoutForClient(840, 680, 96, pageReview, true, true); ok {
		t.Fatal("HTTP renewable layout")
	}
}
