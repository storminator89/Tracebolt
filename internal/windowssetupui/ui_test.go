package windowssetupui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureTrust() TrustPreview {
	return TrustPreview{ManagerID: "manager-fixture", EnrollmentOrigin: "https://enroll.example.test:8443", AgentOrigin: "https://agent.example.test:8444", Fingerprints: []string{strings.Repeat("ab", 32)}}
}

func selectedFlow(t *testing.T) *flow {
	t.Helper()
	f := new(flow)
	if err := f.selectBootstrap([]byte(`{"public":"fixture"}`), fixtureTrust()); err != nil {
		t.Fatal(err)
	}
	return f
}

func consentedFlow(t *testing.T) *flow {
	t.Helper()
	f := selectedFlow(t)
	if !f.next() {
		t.Fatal("review unavailable")
	}
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	return f
}

func TestNoInstallWithoutEveryExplicitAcknowledgement(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		f := selectedFlow(t)
		if !f.next() {
			t.Fatal("next failed")
		}
		f.scope = mask&1 != 0
		f.service = mask&2 != 0
		f.identity = mask&4 != 0
		f.compared = mask&8 != 0
		want := mask == 15
		if got := f.canInstall(); got != want {
			t.Fatalf("mask %d canInstall=%v", mask, got)
		}
		if got := f.begin(opInstall, false); got != want {
			t.Fatalf("mask %d begin=%v", mask, got)
		}
		if !want && (f.attempted || f.busy) {
			t.Fatal("missing consent changed apply state")
		}
	}
}

func TestInitialAndBackConsentAreOff(t *testing.T) {
	f := selectedFlow(t)
	if f.scope || f.service || f.identity || f.compared {
		t.Fatal("initial consent enabled")
	}
	if !f.next() {
		t.Fatal("next")
	}
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	if !f.back() || f.page != pageInput {
		t.Fatal("back")
	}
	if !f.next() || f.canInstall() || f.scope || f.service || f.identity || f.compared {
		t.Fatal("back/next reused consent")
	}
}

func TestCancelBeforeApplyIsInert(t *testing.T) {
	for _, review := range []bool{false, true} {
		f := selectedFlow(t)
		if review {
			f.next()
		}
		if !f.requestClose() || f.attempted || f.busy || f.cancelRequested || f.finished || f.operation != opNone {
			t.Fatal("pre-apply close changed installation state")
		}
	}
	var f flow
	if f.next() || f.begin(opInstall, false) || f.canInstall() {
		t.Fatal("empty wizard can install")
	}
}

func TestCancelRetainsOperationUntilHookReturned(t *testing.T) {
	f := consentedFlow(t)
	if !f.begin(opInstall, false) {
		t.Fatal("begin")
	}
	frozen := append([]byte(nil), f.bootstrap...)
	for i := 0; i < 5; i++ {
		if f.requestClose() || !f.busy || !f.cancelRequested {
			t.Fatal("closed during console ownership")
		}
		if f.begin(opInstall, false) || f.begin(opUninstall, true) || f.back() || f.next() || f.clearSelection() {
			t.Fatal("interrupted operation permitted another transition")
		}
		if !bytes.Equal(f.bootstrap, frozen) {
			t.Fatal("cancel cleared retained input binding")
		}
	}
	if !f.complete(context.Canceled) || f.busy || !f.finished || !errors.Is(f.result, ErrOperation) {
		t.Fatal("cancel completion lost")
	}
	if !f.requestClose() {
		t.Fatal("returned operation still owns window")
	}
	if f.begin(opInstall, false) || f.begin(opUninstall, true) || f.complete(nil) || f.back() || f.next() {
		t.Fatal("completion allows repeat or rewrite")
	}
}

func TestSuccessAndFailureNeverRetry(t *testing.T) {
	for _, err := range []error{nil, errors.New("raw error with secret-shaped content must not escape")} {
		f := consentedFlow(t)
		if !f.begin(opInstall, false) || !f.complete(err) {
			t.Fatal("transition failed")
		}
		if err == nil && f.result != nil {
			t.Fatal("success changed")
		}
		if err != nil && f.result != ErrOperation {
			t.Fatal("raw error retained")
		}
		if f.begin(opInstall, false) || f.begin(opUninstall, true) || f.clearSelection() {
			t.Fatal("attempted installation can retry")
		}
		if !f.requestClose() {
			t.Fatal("completed operation cannot close")
		}
	}
}

func TestLateCancelDoesNotOverrideAuthoritativeCompletion(t *testing.T) {
	f := consentedFlow(t)
	f.begin(opInstall, false)
	f.requestClose()
	f.complete(nil)
	if f.result != nil {
		t.Fatal("late cancellation falsely reports failure after hook success")
	}
}

func TestUninstallHasSeparateConfirmation(t *testing.T) {
	f := selectedFlow(t)
	if f.begin(opUninstall, false) || f.attempted {
		t.Fatal("unconfirmed uninstall")
	}
	f.next()
	if f.begin(opUninstall, true) {
		t.Fatal("review page can trigger uninstall")
	}
	f.back()
	if !f.begin(opUninstall, true) || f.operation != opUninstall {
		t.Fatal("confirmed service-only uninstall blocked")
	}
	if f.begin(opUninstall, true) || f.begin(opInstall, false) {
		t.Fatal("uninstall double-submit")
	}
	if f.requestClose() {
		t.Fatal("uninstall closes while busy")
	}
	f.complete(nil)
	if !f.requestClose() || f.begin(opUninstall, true) {
		t.Fatal("uninstall final state")
	}
	for _, text := range []string{"files", "identity", "state", "not been revoked"} {
		if !strings.Contains(uninstallCompleted, text) {
			t.Fatalf("uninstall outcome omits %q", text)
		}
	}
}

func TestSelectedInputAndTrustAreFrozen(t *testing.T) {
	f := new(flow)
	data := []byte("public fixture")
	trust := fixtureTrust()
	if err := f.selectBootstrap(data, trust); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	trust.Fingerprints[0] = strings.Repeat("cd", 32)
	if string(f.bootstrap) != "public fixture" || f.trust.Fingerprints[0] != strings.Repeat("ab", 32) {
		t.Fatal("caller can mutate reviewed selection")
	}
	f.next()
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	f.back()
	bad := fixtureTrust()
	bad.AgentOrigin = "http://agent.example.test"
	if f.selectBootstrap([]byte("replacement"), bad) == nil {
		t.Fatal("HTTP accepted")
	}
	if len(f.bootstrap) != 0 || f.scope || f.service || f.identity || f.compared || f.next() {
		t.Fatal("invalid replacement leaves stale consent or binding")
	}
}

func TestExplicitHTTPNeedsSeparateRiskApprovalAndMatchingTransport(t *testing.T) {
	trust := fixtureTrust()
	trust.HTTPTest = true
	trust.EnrollmentOrigin = "http://enroll.example.test:8080"
	trust.AgentOrigin = "http://agent.example.test:8081"
	if !validTrust(trust) {
		t.Fatal("explicit HTTP-test rejected")
	}
	if previewAllowed(Config{}, trust) {
		t.Fatal("missing HTTP disclosure accepted")
	}
	if !previewAllowed(Config{HTTPDisclosure: "Full HTTP-test fixture risk notice."}, trust) {
		t.Fatal("complete HTTP disclosure rejected")
	}
	f := new(flow)
	if err := f.selectBootstrap([]byte("public HTTP-test fixture"), trust); err != nil {
		t.Fatal(err)
	}
	f.next()
	f.scope, f.service, f.identity, f.compared = true, true, true, true
	if f.canInstall() || f.httpApproved() || f.begin(opInstall, false) {
		t.Fatal("ordinary consent authorized HTTP")
	}
	f.httpAcknowledged = true
	if !f.canInstall() || !f.httpApproved() {
		t.Fatal("explicit risk approval lost")
	}
	if !f.back() || f.httpAcknowledged || !f.next() || f.httpAcknowledged {
		t.Fatal("Back retained HTTP approval")
	}
	f.scope, f.service, f.identity, f.compared, f.httpAcknowledged = true, true, true, true, true
	if !f.begin(opInstall, false) || f.httpAcknowledged || f.httpApproved() {
		t.Fatal("HTTP consent not consumed")
	}
	for _, tlsSide := range []string{"enrollment", "agent"} {
		mixed := trust
		if tlsSide == "enrollment" {
			mixed.EnrollmentOrigin = "https://enroll.example.test"
		} else {
			mixed.AgentOrigin = "https://agent.example.test"
		}
		if validTrust(mixed) {
			t.Fatal("mixed HTTP/TLS origins admitted")
		}
	}
	trust.HTTPTest = false
	if validTrust(trust) {
		t.Fatal("HTTP origins silently enabled HTTP mode")
	}
	tls := consentedFlow(t)
	tls.httpAcknowledged = true
	if tls.httpApproved() {
		t.Fatal("TLS emits HTTP authorization")
	}
}

func TestHTTPDisclosureShownOnlyForHTTP(t *testing.T) {
	c := Config{Disclosure: "READ FIXTURE", HTTPDisclosure: "FULL PLAINTEXT INVITATION AND TELEMETRY RISK FIXTURE"}
	trust := fixtureTrust()
	if strings.Contains(reviewText(c, trust), c.HTTPDisclosure) {
		t.Fatal("TLS review adds unrelated HTTP consent")
	}
	trust.HTTPTest = true
	trust.EnrollmentOrigin = "http://enroll.example.test"
	trust.AgentOrigin = "http://agent.example.test"
	text := reviewText(c, trust)
	if !strings.Contains(text, c.HTTPDisclosure) || !strings.Contains(text, "SEPARATE RISK APPROVAL REQUIRED") {
		t.Fatal("HTTP review omits full risk notice")
	}
}

func TestTrustMustBePublicHTTPSAndFullDigests(t *testing.T) {
	for _, bad := range []string{"", "http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?", "https://example.test?q=x", "https://example.test/#fragment", "https://example.test\nspoof", "https://example.test/\u202e"} {
		v := fixtureTrust()
		v.AgentOrigin = bad
		if validTrust(v) {
			t.Fatalf("bad origin admitted %q", bad)
		}
	}
	for _, bad := range []string{"", "ab", strings.Repeat("AB", 32), "sha256:" + strings.Repeat("ab", 32), strings.Repeat("gg", 32)} {
		v := fixtureTrust()
		v.Fingerprints = []string{bad}
		if validTrust(v) {
			t.Fatal("invalid fingerprint admitted")
		}
	}
	v := fixtureTrust()
	v.ManagerID = "Manager\r\nTrust approved"
	if validTrust(v) {
		t.Fatal("multiline manager ID admitted")
	}
	v = fixtureTrust()
	v.ManagerID = "manager\u202eexample"
	if validTrust(v) {
		t.Fatal("bidirectional spoof admitted")
	}
	v = fixtureTrust()
	v.Fingerprints = nil
	if validTrust(v) {
		t.Fatal("no trust fingerprints admitted")
	}
}

func TestConfigRequiresCompleteDisclosureAndHooks(t *testing.T) {
	c := Config{Version: "candidate", SourceCommit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64), Architecture: "amd64", Disclosure: "Full five-scope fixture privacy disclosure."}
	h := Hooks{Preview: func([]byte) (TrustPreview, error) { return fixtureTrust(), nil }, Install: func(context.Context, []byte, bool, func(string)) error { return nil }, Uninstall: func(context.Context, func(string)) error { return nil }}
	if !validConfig(c, h) {
		t.Fatal("valid configuration blocked")
	}
	bad := c
	bad.Disclosure = " "
	if validConfig(bad, h) {
		t.Fatal("empty disclosure admitted")
	}
	bad = c
	bad.PayloadSHA256 = "unbuilt"
	if validConfig(bad, h) {
		t.Fatal("unbuilt payload admitted")
	}
	bad = c
	bad.Architecture = "386"
	if validConfig(bad, h) {
		t.Fatal("unsupported architecture admitted")
	}
	h.Install = nil
	if validConfig(c, h) {
		t.Fatal("missing hook admitted")
	}
}

func TestReviewIncludesFullDisclosureAndTruthfulLimitations(t *testing.T) {
	c := Config{Version: "candidate", SourceCommit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64), Architecture: "amd64", Disclosure: "FULL SCOPE ONE\nFULL SCOPE TWO"}
	review := reviewText(c, fixtureTrust())
	for _, want := range []string{"FULL SCOPE ONE\r\nFULL SCOPE TWO", fixtureTrust().ManagerID, fixtureTrust().Fingerprints[0], "LocalService", "persistent device identity", "disabled", "automatic startup", "Existing services", "input hidden", "approve it separately", "cancellation is not rollback", "No transport downgrade"} {
		if !strings.Contains(review, want) {
			t.Fatalf("review missing %q", want)
		}
	}
	for _, want := range []string{c.Version, c.SourceCommit, c.PayloadSHA256, c.Architecture, "unverified"} {
		if !strings.Contains(provenance(c), want) {
			t.Fatal("provenance missing")
		}
	}
	if !strings.Contains(installCompleted, "start requested") || !strings.Contains(installCompleted, "First report") || !strings.Contains(installCompleted, "reboot remain unverified") {
		t.Fatal("success overclaims")
	}
}

func TestPublicBootstrapFileBoundsAndKinds(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{0, 1, maxBootstrapBytes, maxBootstrapBytes + 1} {
		path := filepath.Join(dir, "bootstrap.json")
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), n), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readPublicBootstrap(path)
		if n == 0 || n > maxBootstrapBytes {
			if err == nil {
				t.Fatal("out-of-bounds file accepted")
			}
		} else if err != nil || len(got) != n {
			t.Fatalf("size %d: got %d, %v", n, len(got), err)
		}
	}
	if _, err := readPublicBootstrap(dir); err == nil {
		t.Fatal("directory admitted")
	}
	if _, err := readPublicBootstrap(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file admitted")
	}
	path := filepath.Join(dir, "target.json")
	if err := os.WriteFile(path, []byte("public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readPublicBootstrap(link); err == nil {
			t.Fatal("symlink admitted")
		}
	}
}
