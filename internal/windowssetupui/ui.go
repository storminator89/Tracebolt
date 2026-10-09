// Package windowssetupui is a native, fresh-install-only Windows setup wizard.
// It owns presentation and an inert consent state machine, never enrollment,
// service configuration, trust storage, or network access. Those operations belong
// to the caller's narrowly scoped hooks, invoked only after local confirmation.
package windowssetupui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
)

const maxBootstrapBytes = 64 * 1024

var (
	ErrUnsupported   = errors.New("Windows setup UI is unavailable on this platform")
	ErrConfiguration = errors.New("Windows setup UI configuration is incomplete or invalid")
	ErrOperation     = errors.New("setup did not complete; retained state requires inspection")
	ErrUI            = errors.New("Windows setup UI is unavailable")
)

// Config contains public provenance and the caller's complete five-scope privacy
// disclosure. Disclosure is shown verbatim, with a scrollable review control.
// HTTPDisclosure must additionally contain every full plaintext-risk notice
// when a validated public bootstrap explicitly selects isolated HTTP-test.
type Config struct {
	Version, SourceCommit, PayloadSHA256, Architecture, Disclosure string
	HTTPDisclosure                                                 string
}

// TrustPreview contains only validated public bootstrap identity and trust.
// Fingerprints must be full, unlabelled, lowercase SHA-256 hexadecimal digests.
// HTTPTest is never inferred from a failed TLS operation or a user text field.
type TrustPreview struct {
	ManagerID, EnrollmentOrigin, AgentOrigin string
	Fingerprints                             []string
	HTTPTest                                 bool
}

// Hooks is the boundary to the existing installation coordinator. Preview must
// be read-only and reject unknown/secret bootstrap fields. Install must retain
// existing state on every exit, never adopt an existing installation, and read
// the invitation only with the existing hidden local console implementation.
// Uninstall must retain installed files, identity and state, and cannot revoke
// the manager identity. Both mutating hooks must observe cancellation and return
// only after releasing console ownership. Progress must contain fixed, public
// statuses or finite diagnostic codes only; raw errors or input are forbidden.
// Install's bool is true only for an explicitly reviewed HTTP-test bootstrap
// whose separate local plaintext-risk checkbox was checked. It is always false
// for TLS. Hooks must verify the same immutable bootstrap transport themselves.
type Hooks struct {
	Preview   func(publicBootstrap []byte) (TrustPreview, error)
	Install   func(context.Context, []byte, bool, func(string)) error
	Uninstall func(context.Context, func(string)) error
}

type page uint8

const (
	pageInput page = iota
	pageReview
	pageOperation
)

type operation uint8

const (
	opNone operation = iota
	opInstall
	opUninstall
)

// flow is exclusively owned by the UI thread. No hook is called by a transition;
// this makes consent, double-submit, Back and interrupted flows testable without
// touching any Windows API or installation state.
type flow struct {
	page                                       page
	bootstrap                                  []byte
	trust                                      TrustPreview
	scope, service, identity, compared         bool
	httpAcknowledged                           bool
	operation                                  operation
	busy, attempted, cancelRequested, finished bool
	result                                     error
}

func (f *flow) clearConsent() {
	f.scope, f.service, f.identity, f.compared = false, false, false, false
	f.httpAcknowledged = false
}

func (f *flow) clearSelection() bool {
	if f.busy || f.attempted || f.page != pageInput {
		return false
	}
	f.bootstrap, f.trust = nil, TrustPreview{}
	f.clearConsent()
	return true
}

func (f *flow) selectBootstrap(data []byte, trust TrustPreview) error {
	if !f.clearSelection() {
		return ErrConfiguration
	}
	if len(data) == 0 || len(data) > maxBootstrapBytes || !validTrust(trust) {
		return ErrConfiguration
	}
	f.bootstrap = append([]byte(nil), data...)
	trust.Fingerprints = append([]string(nil), trust.Fingerprints...)
	f.trust = trust
	return nil
}

func (f *flow) next() bool {
	if f.page != pageInput || f.busy || f.attempted || len(f.bootstrap) == 0 {
		return false
	}
	f.clearConsent()
	f.page = pageReview
	return true
}

func (f *flow) back() bool {
	if f.page != pageReview || f.busy || f.attempted {
		return false
	}
	f.clearConsent()
	f.page = pageInput
	return true
}

func (f *flow) canInstall() bool {
	return f.page == pageReview && !f.busy && !f.attempted && len(f.bootstrap) != 0 &&
		f.scope && f.service && f.identity && f.compared && (!f.trust.HTTPTest || f.httpAcknowledged)
}

func (f *flow) httpApproved() bool {
	return f.canInstall() && f.trust.HTTPTest && f.httpAcknowledged
}

func previewAllowed(c Config, t TrustPreview) bool {
	return validTrust(t) && (!t.HTTPTest || validDisclosure(c.HTTPDisclosure))
}

func (f *flow) begin(kind operation, uninstallConfirmed bool) bool {
	if f.busy || f.attempted {
		return false
	}
	switch kind {
	case opInstall:
		if !f.canInstall() {
			return false
		}
	case opUninstall:
		if f.page != pageInput || !uninstallConfirmed {
			return false
		}
	default:
		return false
	}
	f.operation, f.page, f.busy, f.attempted = kind, pageOperation, true, true
	f.clearConsent()
	return true
}

// requestClose permits immediate close before apply or after the hook returned.
// While any hook owns the operation, Close instead asks it to cancel and leaves
// the window/message pump alive. Calling this repeatedly cannot start work.
func (f *flow) requestClose() bool {
	if !f.busy {
		return true
	}
	f.cancelRequested = true
	return false
}

func (f *flow) complete(err error) bool {
	if !f.busy {
		return false
	}
	f.busy, f.finished = false, true
	if err != nil {
		f.result = ErrOperation
	}
	return true
}

func validConfig(c Config, h Hooks) bool {
	return publicLine(c.Version, 128) && publicLine(c.SourceCommit, 128) &&
		validDigest(c.PayloadSHA256) && (c.Architecture == "amd64" || c.Architecture == "arm64") &&
		validDisclosure(c.Disclosure) && (c.HTTPDisclosure == "" || validDisclosure(c.HTTPDisclosure)) &&
		h.Preview != nil && h.Install != nil && h.Uninstall != nil
}

func validDisclosure(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 64*1024 && !strings.ContainsRune(s, 0)
}

func publicLine(s string, limit int) bool {
	if strings.TrimSpace(s) == "" || len(s) > limit {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

func validOrigin(s string, httpTest bool) bool {
	if !publicLine(s, 2048) {
		return false
	}
	u, err := url.Parse(s)
	scheme := "https"
	if httpTest {
		scheme = "http"
	}
	return err == nil && u.Scheme == scheme && u.Host != "" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		u.Opaque == "" && (u.Path == "" || u.Path == "/") && u.RawPath == ""
}

func validTrust(t TrustPreview) bool {
	if !publicLine(t.ManagerID, 256) || !validOrigin(t.EnrollmentOrigin, t.HTTPTest) || !validOrigin(t.AgentOrigin, t.HTTPTest) ||
		len(t.Fingerprints) == 0 || len(t.Fingerprints) > 32 {
		return false
	}
	for _, f := range t.Fingerprints {
		if !validDigest(f) {
			return false
		}
	}
	return true
}

// readPublicBootstrap never follows a final symlink/reparse point and never
// accepts a directory, pipe, device or more than 64 KiB. Windows adds local-disk
// and handle/reparse checks in openPublicFile. Nothing is written or logged.
func readPublicBootstrap(path string) ([]byte, error) {
	if !validPublicPath(path) {
		return nil, ErrConfiguration
	}
	f, err := openPublicFile(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() <= 0 || after.Size() > maxBootstrapBytes {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBootstrapBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxBootstrapBytes || int64(len(data)) != after.Size() {
		return nil, ErrConfiguration
	}
	return data, nil
}

func provenance(c Config) string {
	return fmt.Sprintf("Version: %s    Architecture: %s\r\nSource revision / snapshot base: %s\r\nEmbedded service SHA-256: %s\r\nPREVIEW BUILD. Native Windows installation and reboot acceptance are unverified.\r\nSee the release manifest for complete source-input identity; the snapshot base alone is insufficient.",
		c.Version, c.Architecture, c.SourceCommit, c.PayloadSHA256)
}

func reviewText(c Config, t TrustPreview) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PUBLIC TRUST COMPARISON\r\nManager ID: %s\r\nEnrollment origin: %s\r\nAgent origin: %s\r\n", t.ManagerID, t.EnrollmentOrigin, t.AgentOrigin)
	for i, p := range t.Fingerprints {
		fmt.Fprintf(&b, "Trust SHA-256 %d: %s\r\n", i+1, p)
	}
	b.WriteString("\r\nIndependently compare every value above with your authorized manager operator before checking the trust box. This does not replace the later device fingerprint comparison and manager approval.\r\n\r\n")
	if t.HTTPTest {
		b.WriteString("ISOLATED HTTP TEST: SEPARATE RISK APPROVAL REQUIRED\r\n")
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(c.HTTPDisclosure, "\r\n", "\n"), "\n", "\r\n"))
		b.WriteString("\r\n\r\n")
	}
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(c.Disclosure, "\r\n", "\n"), "\n", "\r\n"))
	b.WriteString("\r\n\r\nSERVICE AND IDENTITY\r\nInstall a Windows service running as LocalService with its own service SID, protected local files and persistent device identity. The fresh coordinator keeps startup disabled until that identity is activated and all five exact grants are verified; it then configures automatic startup and requests Start. Existing services, identities, grants or setup state block this fresh installer. No upgrade or recovery is performed.\r\n\r\nA separate local console will request the invitation with input hidden. Never paste the invitation into this wizard, a file, command line, environment variable or log. When the console shows the public device identity, compare it with the pending device and approve it separately in your manager dashboard while setup waits. Keep both windows open until the operation finishes. This wizard does not open a browser.\r\n\r\nCancellation after Install may leave durable changes. Existing files, identity and state are retained for inspection; cancellation is not rollback. HTTPS is the default. No transport downgrade or fallback is performed. An explicitly marked HTTP-test bootstrap requires its own plaintext-risk acknowledgement.")
	return b.String()
}

const installCompleted = "Service start requested. First report and startup after reboot remain unverified."
const uninstallCompleted = "Service removal completed. Installed files, identity and state are retained. Manager identity has not been revoked."
const interruptedMessage = "The operation did not complete. Durable changes may exist; files, identity and state are retained. Inspect the retained state before any further action. This wizard will not retry or reset it."
