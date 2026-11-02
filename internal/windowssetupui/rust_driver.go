package windowssetupui

// The optional Rust frontend is only a native view. This controller keeps the
// existing Go consent flow, protected bootstrap reader and original Hooks in
// process. It is private and is not a command, IPC, silent-install or retry API.
import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
)

const (
	rustPoll = 1000 + iota
	rustResize
	rustClose
	rustPresented
	rustViewLimit = 512 * 1024
)

type rustControl struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"`
	Text    string `json:"text"`
	Enabled bool   `json:"enabled"`
	Checked bool   `json:"checked"`
	Box     box    `json:"box"`
}

type rustView struct {
	Revision uint64        `json:"revision"`
	Controls []rustControl `json:"controls"`
	Close    bool          `json:"close"`
	Pending  bool          `json:"pending"`
	LayoutOK bool          `json:"layoutOK"`
}

// Except for report(), all methods run serially on the locked window thread.
// Worker goroutines never call Rust, store a Rust pointer or own the Go flow.
type rustController struct {
	config                                  Config
	hooks                                   Hooks
	flow                                    flow
	choose                                  func(uintptr) (string, bool, error)
	confirm                                 func(uintptr) bool
	fileName, progress, notice              string
	width, height, dpi                      int
	layoutOK, closeWindow, pending, started bool
	http, renewal                           bool
	revision                                uint64
	cancel                                  context.CancelFunc
	done                                    chan error
	mu                                      sync.Mutex
	latest                                  string
}

func newRustController(c Config, h Hooks) (*rustController, error) {
	if !validConfig(c, h) {
		return nil, ErrConfiguration
	}
	r := &rustController{config: c, hooks: h, flow: freshFlow(c, h), width: 840, height: 680, dpi: 96, revision: 1}
	if selectInitialBootstrap(&r.flow, c, h) != nil {
		return nil, ErrConfiguration
	}
	if len(r.flow.bootstrap) != 0 {
		r.fileName = "Embedded public configuration (review required)"
	}
	return r, nil
}

func (r *rustController) command(id, value int, owner uintptr) {
	r.poll()
	if id == rustClose || id == idCancel {
		if r.flow.requestClose() {
			r.closeWindow = true
		} else if r.started {
			r.cancel()
		} else {
			r.pending = false
			r.flow.complete(ErrUI)
		}
		r.revision++
		return
	}
	if id == rustPoll {
		return
	}
	if id == rustPresented {
		if r.pending && r.layoutOK && r.flow.busy && !r.started && !r.flow.cancelRequested {
			r.pending = false
			r.start()
			r.revision++
		}
		return
	}
	if !r.layoutOK || r.flow.busy || r.flow.attempted {
		return
	}
	switch id {
	case idChoose:
		if !r.flow.clearSelection() {
			return
		}
		r.fileName, r.notice = "", ""
		if r.choose == nil {
			return
		}
		path, canceled, err := r.choose(owner)
		if canceled {
			break
		}
		if err != nil {
			r.notice = "The file chooser could not open. Nothing was installed."
			break
		}
		data, err := readPublicBootstrap(path)
		if err != nil {
			r.notice = "Choose a regular public bootstrap of 1 byte to 64 KiB on a local fixed/removable drive; links and reparse paths are not accepted."
			break
		}
		preview, err := r.hooks.Preview(append([]byte(nil), data...))
		if err != nil || !previewAllowed(r.config, preview) || r.flow.selectBootstrap(data, preview) != nil {
			r.notice = "Invalid public bootstrap. Never select an invitation, password or private material. Nothing was installed."
			break
		}
		r.fileName = filepath.Base(path) + " (public bootstrap validated)"
	case idNext:
		if r.flow.page == pageInput {
			r.flow.next()
		} else {
			r.prepare(opInstall, false)
		}
	case idBack:
		r.flow.back()
	case idDetails:
		r.flow.toggleDetails()
	case idScope, idService, idIdentity, idCompared, idHTTPRisk, idAutomaticRenewal:
		if r.flow.page != pageReview || (value != 0 && value != 1) {
			return
		}
		checked := value == 1
		switch id {
		case idScope:
			r.flow.scope = checked
		case idService:
			r.flow.service = checked
		case idIdentity:
			r.flow.identity = checked
		case idCompared:
			r.flow.compared = checked
		case idHTTPRisk:
			r.flow.httpAcknowledged = r.flow.trust.HTTPTest && checked
		case idAutomaticRenewal:
			r.flow.renewalAcknowledged = r.flow.trust.AutomaticRenewal && checked
		}
	case idUninstall:
		if r.flow.page == pageInput && r.confirm != nil && r.confirm(owner) {
			r.prepare(opUninstall, true)
		}
	default:
		return
	}
	r.revision++
}

func (r *rustController) resize(width, height, dpi int) {
	r.layoutOK = false
	r.width, r.height, r.dpi = width, height, dpi
	_, r.layoutOK = layoutForClient(width, height, dpi, r.flow.page, r.flow.trust.HTTPTest, r.flow.trust.AutomaticRenewal)
	if !r.layoutOK && r.flow.busy {
		if r.started {
			r.flow.requestClose()
			r.cancel()
		} else {
			r.pending = false
			r.flow.complete(ErrUI)
		}
	}
	r.revision++
}

func (r *rustController) prepare(kind operation, confirmed bool) {
	r.http, r.renewal = r.flow.httpApproved(), r.flow.canInstall() && r.flow.renewalAcknowledged
	if kind == opInstall && r.flow.trust.AutomaticRenewal && ((!r.flow.readAdmin && r.hooks.InstallRenewable == nil) || (r.flow.readAdmin && r.hooks.InstallReadAdminRenewable == nil)) {
		return
	}
	if kind == opInstall && r.flow.readAdmin && !readAdminAvailable(r.config, r.hooks) {
		return
	}
	if !r.flow.begin(kind, confirmed) {
		return
	}
	r.pending = true
	r.progress = "Starting the confirmed operation..."
}

// Native code must first render the operation page and establish its polling
// timer, then acknowledge presentation. A failed render never invokes a Hook.
func (r *rustController) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done, r.started = cancel, make(chan error, 1), true
	kind, readAdmin, http, renewal := r.flow.operation, r.flow.readAdmin, r.http, r.renewal
	data := append([]byte(nil), r.flow.bootstrap...)
	go func() {
		var err error
		if kind == opUninstall {
			err = r.hooks.Uninstall(ctx, r.report)
		} else if readAdmin && renewal {
			err = r.hooks.InstallReadAdminRenewable(ctx, data, renewal, r.report)
		} else if renewal {
			err = r.hooks.InstallRenewable(ctx, data, renewal, r.report)
		} else if readAdmin {
			err = r.hooks.InstallReadAdmin(ctx, data, http, r.report)
		} else {
			err = r.hooks.Install(ctx, data, http, r.report)
		}
		cancel()
		r.done <- err
	}()
}

func (r *rustController) report(text string) {
	if !publicLine(text, 512) {
		return
	}
	r.mu.Lock()
	r.latest = text
	r.mu.Unlock()
}

func (r *rustController) poll() {
	if !r.flow.busy || !r.started {
		return
	}
	r.mu.Lock()
	latest := r.latest
	r.mu.Unlock()
	if latest != "" && latest != r.progress {
		r.progress = latest
		r.revision++
	}
	select {
	case err := <-r.done:
		r.mu.Lock()
		latest = r.latest
		r.mu.Unlock()
		if latest != "" {
			r.progress = latest
		}
		r.flow.complete(err)
		if err != nil {
			r.progress += "\r\n\r\n" + interruptedMessage
		} else if r.flow.operation == opInstall {
			r.progress += "\r\n\r\n" + installCompleted
		} else {
			r.progress += "\r\n\r\n" + uninstallCompleted
		}
		r.revision++
	default:
	}
}

// Always called before deleting the cgo.Handle. Even native pump/render failure
// cooperatively cancels and joins the original console-owning Go hook first.
func (r *rustController) finish() error {
	if r.flow.busy {
		if r.started {
			r.cancel()
			r.flow.complete(<-r.done)
		} else {
			r.pending = false
			r.flow.complete(ErrUI)
		}
	}
	return r.flow.result
}

func (r *rustController) view() ([]byte, error) {
	r.poll()
	l, ok := layoutForClient(r.width, r.height, r.dpi, r.flow.page, r.flow.trust.HTTPTest, r.flow.trust.AutomaticRenewal)
	r.layoutOK = ok
	v := rustView{Revision: r.revision, Controls: []rustControl{}, Close: r.closeWindow, Pending: r.pending, LayoutOK: ok}
	add := func(id int, kind, text string, enabled, checked bool) {
		if b, exists := l[id]; exists {
			v.Controls = append(v.Controls, rustControl{id, kind, text, enabled, checked, b})
		}
	}
	add(idProvenance, "edit", provenance(r.config), true, false)
	add(idBack, "button", "< &Back", r.flow.page == pageReview && !r.flow.attempted, false)
	add(idNext, "button", "&Next >", r.flow.page == pageInput && len(r.flow.bootstrap) != 0, false)
	cancelText := "&Cancel"
	if r.flow.finished {
		cancelText = "&Close"
	} else if r.flow.cancelRequested {
		cancelText = "Stopping..."
	}
	add(idCancel, "button", cancelText, !r.flow.cancelRequested || r.flow.finished, false)
	note := "Cancel now leaves installation state unchanged. Uninstall requires separate confirmation."
	switch r.flow.page {
	case pageInput:
		add(idHeading, "label", "Step 1 of 3: Read admin setup", true, false)
		add(idInputText, "edit", "Choose the manager's PUBLIC bootstrap JSON. Never put an invitation, password or private key here. Only regular local fixed/removable-drive files up to 64 KiB are accepted.\r\n\r\nThis fresh installer never adopts or resets existing services, identities, grants or state. HTTPS is the default; explicit HTTP-test and same-key renewal each require separate approval.\r\n\r\nNext, review the exact scope and independently compare every public trust value. All consent starts unchecked. The invitation is entered later in the original hidden-input console. No browser is opened and nothing is downloaded by this frontend.", true, false)
		profile := "Read admin: 21 read scopes. Review and explicitly approve on the next page."
		if !r.flow.readAdmin {
			profile = "Legacy five-scope read profile. Review and explicitly approve on the next page."
		}
		add(idReadAdmin, "label", profile, true, false)
		add(idSelectedFile, "edit", r.fileName, true, false)
		add(idChoose, "button", "Choose &file...", true, false)
		add(idUninstall, "button", "&Uninstall service...", true, false)
	case pageReview:
		add(idHeading, "label", "Step 2 of 3: Review scope, service, identity and trust", true, false)
		for i := range v.Controls {
			if v.Controls[i].ID == idNext {
				v.Controls[i].Text = "&Install"
				v.Controls[i].Enabled = r.flow.canInstall()
			}
		}
		add(idReviewText, "edit", reviewText(reviewPresentation(r.config, r.flow.readAdmin, r.flow.details), r.flow.trust), true, false)
		scope := "I approve the exact five READ scopes and the full privacy disclosure above."
		if r.flow.readAdmin {
			scope = "I approve all 21 Read admin scopes, including identifying/personal metadata, bounded Application/System history and selected messages that may contain credentials or other secrets."
		}
		add(idScope, "check", scope, true, r.flow.scope)
		add(idService, "check", "I approve a LocalService Windows service and automatic startup after verified activation and grants.", true, r.flow.service)
		add(idIdentity, "check", "I approve creation and protected storage of a persistent device identity on this computer.", true, r.flow.identity)
		add(idCompared, "check", "I independently compared the manager ID, both origins and every full trust fingerprint above.", true, r.flow.compared)
		if r.flow.trust.HTTPTest {
			add(idHTTPRisk, "check", "I accept plaintext invitation and selected-scope telemetry, and forged manager-response risks for this HTTP test.", true, r.flow.httpAcknowledged)
		}
		if r.flow.trust.AutomaticRenewal {
			add(idAutomaticRenewal, "check", "I approve recurring seven-day certificates for this same identity/key until revocation or issuer/scope expiry.", true, r.flow.renewalAcknowledged)
		}
		if r.flow.readAdmin {
			text := "Scope &details"
			if r.flow.details {
				text = "Scope &summary"
			}
			add(idDetails, "button", text, true, false)
		}
		note = "Install opens the original hidden-input console. Manager device-fingerprint approval is still required. Back clears all checkboxes."
	case pageOperation:
		add(idHeading, "label", "Step 3 of 3: Confirmed operation status", true, false)
		add(idOperationText, "edit", r.progress, true, false)
		note = "Keep Setup and its hidden-input console open. Cancel requests a safe stop; retained state is not rolled back."
		if r.flow.finished {
			note = "The operation has returned. No retry or automatic recovery will run from this wizard."
		}
	}
	if r.notice != "" {
		note = r.notice
	}
	if r.flow.cancelRequested && !r.flow.finished {
		note = "Cancellation requested. Waiting for the active operation to release its console. Files, identity and state are retained."
	}
	if !ok {
		note = "Window layout unavailable. No new operation can begin; active work is being stopped."
	}
	add(idNote, "label", note, true, false)
	data, err := json.Marshal(v)
	if err != nil || len(data) > rustViewLimit {
		return nil, ErrUI
	}
	return data, nil
}
