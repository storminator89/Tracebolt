package windowssetupui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type rustCall struct {
	name string
	data []byte
	ack  bool
}

func rustFixture(t *testing.T, readAdmin, http, renewal bool) (*rustController, chan rustCall) {
	t.Helper()
	c := Config{Version: "candidate", SourceCommit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64), Architecture: "amd64", Disclosure: "Full five-scope fixture privacy disclosure.", HTTPDisclosure: "Full plaintext fixture risk.", AutomaticRenewalDisclosure: "Full same-key fixture renewal disclosure.", InitialPublicBootstrap: []byte(`{"public":"raw-fixture-must-not-cross-ffi"}`)}
	trust := fixtureTrust()
	trust.AutomaticRenewal = renewal
	if http {
		trust.HTTPTest = true
		trust.EnrollmentOrigin = "http://enroll.example.test"
		trust.AgentOrigin = "http://agent.example.test"
	}
	calls := make(chan rustCall, 8)
	hook := func(name string) func(context.Context, []byte, bool, func(string)) error {
		return func(_ context.Context, b []byte, ack bool, progress func(string)) error {
			calls <- rustCall{name, append([]byte(nil), b...), ack}
			progress("PUBLIC_PHASE_COMPLETE")
			return nil
		}
	}
	h := Hooks{Preview: func([]byte) (TrustPreview, error) { return trust, nil }, Install: hook("basic"), InstallRenewable: hook("renewable-basic"), Uninstall: func(context.Context, func(string)) error { calls <- rustCall{name: "uninstall"}; return nil }}
	if readAdmin {
		c.ReadAdminDisclosure = "Full 21-scope fixture details."
		c.ReadAdminHTTPDisclosure = "Full Read admin plaintext fixture risk."
		c.ReadAdminSummary = "Full grouped fixture summary."
		c.ReadAdminHTTPSummary = "Full grouped plaintext fixture risk."
		h.InstallReadAdmin = hook("read-admin")
		h.InstallReadAdminRenewable = hook("renewable-read-admin")
	}
	r, err := newRustController(c, h)
	if err != nil {
		t.Fatal(err)
	}
	r.resize(840, 680, 96)
	t.Cleanup(func() { r.finish() })
	return r, calls
}

func rustApprove(r *rustController) {
	r.command(idNext, 0, 0)
	for _, id := range []int{idScope, idService, idIdentity, idCompared} {
		r.command(id, 1, 0)
	}
	if r.flow.trust.HTTPTest {
		r.command(idHTTPRisk, 1, 0)
	}
	if r.flow.trust.AutomaticRenewal {
		r.command(idAutomaticRenewal, 1, 0)
	}
}

func rustWait(t *testing.T, r *rustController) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for r.flow.busy && time.Now().Before(deadline) {
		r.poll()
		runtime.Gosched()
	}
	if r.flow.busy {
		t.Fatal("hook did not return")
	}
}

func TestRustFrontendExactMappingsRequireRenderedOperationAndSingleAttempt(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, transport := range []string{"tls", "http", "renewal"} {
			t.Run(transport+boolNameRust(admin), func(t *testing.T) {
				r, calls := rustFixture(t, admin, transport == "http", transport == "renewal")
				data, err := r.view()
				if err != nil || bytes.Contains(data, []byte("raw-fixture-must-not-cross-ffi")) {
					t.Fatal("raw public input reached view", err)
				}
				r.command(idNext, 0, 0)
				r.command(idNext, 0, 0)
				if r.pending || r.flow.busy || r.flow.canInstall() {
					t.Fatal("unchecked consent admitted work")
				}
				r.command(idScope, 2, 0)
				if r.flow.scope {
					t.Fatal("invalid checkbox value admitted")
				}
				r.command(idBack, 0, 0)
				rustApprove(r)
				if !r.flow.canInstall() {
					t.Fatal("exact consent not admitted")
				}
				r.command(idNext, 0, 0)
				if !r.pending || r.started {
					t.Fatal("hook started before successful native render")
				}
				select {
				case <-calls:
					t.Fatal("unrendered operation invoked hook")
				default:
				}
				r.command(rustPresented, 0, 0)
				r.command(rustPresented, 0, 0)
				r.command(idNext, 0, 0)
				rustWait(t, r)
				call := <-calls
				want := "basic"
				if admin {
					want = "read-admin"
				}
				if transport == "renewal" {
					want = "renewable-" + want
				}
				if call.name != want || call.ack != (transport != "tls") || !bytes.Equal(call.data, r.flow.bootstrap) {
					t.Fatal("hook mapping or frozen bytes changed", call)
				}
				r.command(rustPresented, 0, 0)
				r.command(idNext, 0, 0)
				r.command(idUninstall, 0, 0)
				select {
				case <-calls:
					t.Fatal("terminal result retried")
				default:
				}
				view, err := r.view()
				if err != nil || !bytes.Contains(view, []byte(installCompleted)) || bytes.Contains(view, []byte("raw-fixture-must-not-cross-ffi")) {
					t.Fatal("terminal truth changed", err)
				}
			})
		}
	}
}

func boolNameRust(b bool) string {
	if b {
		return "/admin"
	}
	return "/basic"
}

func TestRustFrontendBackAndReselectionClearAllConsent(t *testing.T) {
	r, _ := rustFixture(t, true, false, true)
	rustApprove(r)
	r.command(idDetails, 0, 0)
	r.command(idBack, 0, 0)
	if r.flow.scope || r.flow.service || r.flow.identity || r.flow.compared || r.flow.renewalAcknowledged || r.flow.details {
		t.Fatal("Back retained consent")
	}
	r.command(idNext, 0, 0)
	if r.flow.canInstall() {
		t.Fatal("repeat review retained consent")
	}
	r.command(idBack, 0, 0)
	r.choose = func(uintptr) (string, bool, error) { return "", true, nil }
	r.command(idChoose, 0, 0)
	if len(r.flow.bootstrap) != 0 || r.flow.scope {
		t.Fatal("cancelled replacement retained prior selection")
	}
}

func TestRustFrontendReviewUsesOriginalExactPresentation(t *testing.T) {
	for _, transport := range []string{"tls", "http", "renewal"} {
		r, _ := rustFixture(t, true, transport == "http", transport == "renewal")
		r.command(idNext, 0, 0)
		for _, details := range []bool{false, true} {
			if details {
				r.command(idDetails, 0, 0)
			}
			data, err := r.view()
			if err != nil {
				t.Fatal(err)
			}
			var view rustView
			if json.Unmarshal(data, &view) != nil {
				t.Fatal("invalid view")
			}
			found := false
			for _, c := range view.Controls {
				if c.Checked {
					t.Fatal("presentation granted consent")
				}
				if c.ID == idReviewText {
					found = true
					if c.Text != reviewText(reviewPresentation(r.config, true, details), r.flow.trust) {
						t.Fatal("original full review/disclosures changed")
					}
				}
			}
			if !found {
				t.Fatal("review disclosure omitted")
			}
		}
	}
}

func TestRustFrontendCloseAndBadLayoutBeforePresentationAreInert(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		r, calls := rustFixture(t, true, false, false)
		rustApprove(r)
		r.command(idNext, 0, 0)
		if closeFirst {
			r.command(rustClose, 0, 0)
		} else {
			r.resize(40, 40, 96)
		}
		r.command(rustPresented, 0, 0)
		if r.started || r.pending || r.flow.busy {
			t.Fatal("unpresented operation ran")
		}
		select {
		case <-calls:
			t.Fatal("cancelled/invalid render invoked hook")
		default:
		}
		view, err := r.view()
		if err != nil || bytes.Contains(view, []byte(`"controls":null`)) {
			t.Fatal("unavailable layout has invalid ABI", err)
		}
	}
}

func TestRustFrontendCancellationWaitsForConsoleOwnerAndFinishJoins(t *testing.T) {
	r, calls := rustFixture(t, true, false, false)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.hooks.InstallReadAdmin = func(ctx context.Context, b []byte, ack bool, progress func(string)) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		progress("PUBLIC_FINAL_PHASE")
		return errors.New("private-fixture-error-must-not-cross-ffi")
	}
	rustApprove(r)
	r.command(idNext, 0, 0)
	r.command(rustPresented, 0, 0)
	<-entered
	r.command(rustClose, 0, 0)
	r.command(rustClose, 0, 0)
	<-canceled
	if !r.flow.busy || r.closeWindow || !r.flow.cancelRequested {
		t.Fatal("close detached console owner")
	}
	view, _ := r.view()
	if !bytes.Contains(view, []byte("Waiting for the active operation")) {
		t.Fatal("cancel wait not visible")
	}
	close(release)
	if r.finish() == nil || r.flow.busy {
		t.Fatal("finish failed to join hook")
	}
	view, _ = r.view()
	if bytes.Contains(view, []byte("private-fixture-error")) {
		t.Fatal("raw error crossed view boundary")
	}
	r.command(rustClose, 0, 0)
	if !r.closeWindow {
		t.Fatal("settled close blocked")
	}
	select {
	case <-calls:
		t.Fatal("unexpected alternative hook")
	default:
	}
}

func TestRustFrontendUninstallNeedsIndependentConfirmationAndRender(t *testing.T) {
	r, calls := rustFixture(t, true, false, false)
	r.confirm = func(uintptr) bool { return false }
	r.command(idUninstall, 0, 0)
	if r.pending || r.flow.attempted {
		t.Fatal("No admitted uninstall")
	}
	r.confirm = func(uintptr) bool { return true }
	r.command(idUninstall, 0, 0)
	if !r.pending {
		t.Fatal("confirmed uninstall not prepared")
	}
	select {
	case <-calls:
		t.Fatal("unrendered uninstall invoked hook")
	default:
	}
	r.command(rustPresented, 0, 0)
	rustWait(t, r)
	if (<-calls).name != "uninstall" {
		t.Fatal("wrong hook")
	}
	view, _ := r.view()
	if !bytes.Contains(view, []byte(uninstallCompleted)) {
		t.Fatal("removal truth changed")
	}
}

func TestRustFrontendProtectedSelectionErrorsDoNotRenderPrivateInput(t *testing.T) {
	r, _ := rustFixture(t, true, false, false)
	path := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(path, []byte(`{"secret":"invented-private-fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	r.hooks.Preview = func([]byte) (TrustPreview, error) { return TrustPreview{}, errors.New("invented-private-fixture") }
	r.choose = func(uintptr) (string, bool, error) { return path, false, nil }
	r.command(idChoose, 0, 0)
	r.command(idNext, 0, 0)
	view, err := r.view()
	if err != nil || bytes.Contains(view, []byte("invented-private-fixture")) || len(r.flow.bootstrap) != 0 || r.flow.page != pageInput {
		t.Fatal("invalid selection retained/rendered", err)
	}
	var decoded rustView
	if json.Unmarshal(view, &decoded) != nil {
		t.Fatal("invalid view JSON")
	}
	for _, c := range decoded.Controls {
		if c.Checked {
			t.Fatal("invalid selection granted consent")
		}
	}
}
