package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowssetupui"
)

// Every backend below is injected and memory-only. The PE is parser input, never
// a file or process. These tests create no listener, host service, persistent
// identity, protected store, native window, console or operating-system grant.
func setupFrontendPackageFixture(t *testing.T) ([]byte, windowspackage.Manifest) {
	t.Helper()
	payload := make([]byte, 1024)
	copy(payload, "MZ")
	binary.LittleEndian.PutUint32(payload[0x3c:], 0x80)
	copy(payload[0x80:], "PE\x00\x00")
	var header bytes.Buffer
	for _, value := range []any{
		pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 1, SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE},
		pe.OptionalHeader64{Magic: 0x20b, AddressOfEntryPoint: 0x1000, ImageBase: 0x140000000, SectionAlignment: 4096, FileAlignment: 512, SizeOfImage: 8192, SizeOfHeaders: 512, Subsystem: 3, NumberOfRvaAndSizes: 16},
	} {
		if err := binary.Write(&header, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(payload[0x84:], header.Bytes())
	section := 0x84 + 20 + 240
	copy(payload[section:], ".text")
	for offset, value := range map[int]uint32{8: 1, 12: 0x1000, 16: 512, 20: 512, 36: 0x60000020} {
		binary.LittleEndian.PutUint32(payload[section+offset:], value)
	}
	digest := sha256.Sum256(payload)
	manifest := windowspackage.Manifest{SchemaVersion: windowspackage.ManifestSchema, Version: "v0.0.0-fixture", SourceCommit: strings.Repeat("a", 40), Architecture: "amd64", SHA256: hex.EncodeToString(digest[:])}
	if err := manifest.Validate(payload); err != nil {
		t.Fatal(err)
	}
	return payload, manifest
}

type setupFrontendFixture struct {
	t              *testing.T
	fail           string
	calls          []string
	raw, payload   []byte
	manifest       windowspackage.Manifest
	console        bytes.Buffer
	context        context.Context
	consoleCancel  bool
	cancelAt       string
	cancel         context.CancelFunc
	readAdmin      bool
	consent        lanclient.WindowsCapabilityConsent
	renewal        bool
	provisionPath  string
	provisionClose bool
}

func (f *setupFrontendFixture) call(ctx context.Context, name string) error {
	f.calls = append(f.calls, name)
	if name == f.cancelAt && f.cancel != nil {
		f.cancel()
		return ctx.Err()
	}
	if name == f.fail {
		return errors.New("private fixture failure must never enter progress")
	}
	return nil
}

func (f *setupFrontendFixture) backend() setupFrontendBackend {
	return setupFrontendBackend{
		preflight: func(ctx context.Context) error {
			f.context = ctx
			return f.call(ctx, "preflight")
		},
		compatibility: func(ctx context.Context, raw []byte, readAdmin bool) error {
			if ctx != f.context || !bytes.Equal(raw, f.raw) {
				f.t.Fatal("compatibility lost child context or exact public bytes")
			}
			f.readAdmin = readAdmin
			return f.call(ctx, "compatibility")
		},
		console: func(cancel context.CancelFunc) (io.Writer, func() error, error) {
			if err := f.call(f.context, "console"); err != nil {
				return nil, nil, err
			}
			if f.consoleCancel {
				cancel()
			}
			return &f.console, func() error { return f.call(f.context, "console-close") }, nil
		},
		provision: func(ctx context.Context, payload []byte, manifest windowspackage.Manifest, raw []byte) (string, func() error, error) {
			if ctx != f.context || !bytes.Equal(payload, f.payload) || manifest != f.manifest || !bytes.Equal(raw, f.raw) {
				f.t.Fatal("package/public bootstrap or child context changed")
			}
			var close func() error
			if f.provisionClose {
				close = func() error { return f.call(f.context, "pins-close") }
			}
			return f.provisionPath, close, f.call(ctx, "provision")
		},
		install: func(ctx context.Context, path string, consent lanclient.WindowsCapabilityConsent, console io.Writer, progress func(string), renewal bool) error {
			if ctx != f.context || path != f.provisionPath || console != &f.console || progress == nil {
				f.t.Fatal("coordinator lost package path, original console or context")
			}
			f.consent, f.renewal = consent, renewal
			return f.call(ctx, "install")
		},
		uninstall: func(ctx context.Context, progress func(string)) error {
			if ctx == nil || progress == nil {
				f.t.Fatal("invalid removal dependency")
			}
			return f.call(ctx, "uninstall")
		},
	}
}

func newSetupFrontendFixture(t *testing.T) (*setupFrontendFixture, []byte, windowspackage.Manifest) {
	t.Helper()
	payload, manifest := setupFrontendPackageFixture(t)
	f := &setupFrontendFixture{t: t, payload: bytes.Clone(payload), manifest: manifest, provisionPath: "public-fixture-bootstrap", provisionClose: true}
	return f, payload, manifest
}

func frontendPublicBytes(t *testing.T, transport string, renewable bool) []byte {
	t.Helper()
	b, _ := setupPublicBootstrapFixture(t, transport)
	if renewable {
		b.SchemaVersion, b.RenewalPolicy = enrollmentclient.RenewableBootstrapVersion, "same-key-v1"
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type setupFrontendHook func(context.Context, []byte, bool, func(string)) error

func frontendHooks(h windowssetupui.Hooks) map[string]setupFrontendHook {
	return map[string]setupFrontendHook{"basic": h.Install, "read-admin": h.InstallReadAdmin, "renewable-basic": h.InstallRenewable, "renewable-read-admin": h.InstallReadAdminRenewable}
}

func TestSetupFrontendConstructionIsInertAndPreservesExactPresentation(t *testing.T) {
	f, payload, manifest := newSetupFrontendFixture(t)
	raw := frontendPublicBytes(t, "tls", false)
	wantRaw := bytes.Clone(raw)
	config, hooks, err := setupFrontend(payload, manifest, raw, f.backend())
	if err != nil || len(f.calls) != 0 {
		t.Fatal("factory performed a backend operation", err, f.calls)
	}
	want := windowssetupui.Config{InitialPublicBootstrap: wantRaw, Version: manifest.Version, SourceCommit: manifest.SourceCommit, PayloadSHA256: manifest.SHA256, Architecture: manifest.Architecture, Disclosure: setupWizardDisclosure(), HTTPDisclosure: setupWizardHTTPDisclosure(), AutomaticRenewalDisclosure: enrollmentclient.AutomaticRenewalPrivacy, ReadAdminDisclosure: setupWizardReadAdminDisclosure(false), ReadAdminHTTPDisclosure: setupWizardReadAdminDisclosure(true), ReadAdminSummary: setupWizardReadAdminSummary(), ReadAdminHTTPSummary: setupWizardReadAdminHTTPRiskSummary}
	if !reflect.DeepEqual(config, want) {
		t.Fatal("existing disclosure/provenance/profile presentation changed")
	}
	raw[0] = '!'
	payload[0] = '!'
	if !bytes.Equal(config.InitialPublicBootstrap, wantRaw) {
		t.Fatal("initial public bootstrap aliases caller storage")
	}
	f.raw = wantRaw
	if err := hooks.InstallReadAdmin(context.Background(), wantRaw, false, func(string) {}); err != nil {
		t.Fatal("caller changed private package snapshot", err)
	}
	if f.context.Err() != context.Canceled {
		t.Fatal("operation context was not released")
	}
}

func TestSetupFrontendRejectsInvalidConstructionBeforeAnyBackendOperation(t *testing.T) {
	for _, name := range []string{"payload", "manifest", "bootstrap-empty", "bootstrap-secret", "bootstrap-oversized", "preflight", "compatibility", "console", "provision", "install", "uninstall"} {
		t.Run(name, func(t *testing.T) {
			f, payload, manifest := newSetupFrontendFixture(t)
			backend := f.backend()
			var raw []byte
			switch name {
			case "payload":
				payload[0] = 0
			case "manifest":
				manifest.Architecture = "386"
			case "bootstrap-empty":
				raw = []byte{}
			case "bootstrap-secret":
				raw = []byte(`{"invitationSecret":"invented-fixture"}`)
			case "bootstrap-oversized":
				raw = make([]byte, windowspackage.MaxBootstrapBytes+1)
			case "preflight":
				backend.preflight = nil
			case "compatibility":
				backend.compatibility = nil
			case "console":
				backend.console = nil
			case "provision":
				backend.provision = nil
			case "install":
				backend.install = nil
			case "uninstall":
				backend.uninstall = nil
			}
			config, hooks, err := setupFrontend(payload, manifest, raw, backend)
			if err == nil || !reflect.DeepEqual(config, windowssetupui.Config{}) || !reflect.DeepEqual(hooks, windowssetupui.Hooks{}) || len(f.calls) != 0 {
				t.Fatal("invalid factory returned usable frontend or ran backend")
			}
		})
	}
}

func TestSetupFrontendAllProfileTransportAndRenewalHookMappings(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		for _, renewable := range []bool{false, true} {
			for _, name := range []string{"basic", "read-admin", "renewable-basic", "renewable-read-admin"} {
				for _, acknowledged := range []bool{false, true} {
					t.Run(transport+"/renewal="+boolName(renewable)+"/"+name+"/ack="+boolName(acknowledged), func(t *testing.T) {
						f, payload, manifest := newSetupFrontendFixture(t)
						_, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
						if err != nil {
							t.Fatal(err)
						}
						f.raw = frontendPublicBytes(t, transport, renewable)
						renewalHook := strings.HasPrefix(name, "renewable-")
						httpAck, renewalAck := acknowledged && !renewalHook, acknowledged && renewalHook
						allowed := httpAck == (transport == "http-test") && renewalAck == renewable && !(transport == "http-test" && renewable)
						err = frontendHooks(hooks)[name](context.Background(), f.raw, acknowledged, func(string) {})
						if (err == nil) != allowed {
							t.Fatalf("hook widened or lost exact consent: %v, calls=%v", err, f.calls)
						}
						if !allowed {
							if len(f.calls) != 0 {
								t.Fatal("invalid consent reached preflight", f.calls)
							}
							return
						}
						readAdmin := strings.Contains(name, "read-admin")
						want := setupWizardConsent()
						want.InsecureHTTPAcknowledged = httpAck
						if readAdmin {
							want = freshReadAdminSetupConsent(httpAck)
							if want.SchemaVersion != lanclient.WindowsCapabilityConsentVersionV14 || len(want.Scopes) != 21 || readSetupReceiptVersion(want) != 12 {
								t.Fatal("authoritative fresh Read admin contract changed")
							}
						}
						if !reflect.DeepEqual(f.consent, want) || f.readAdmin != readAdmin || f.renewal != renewalAck {
							t.Fatal("backend received a different profile, scopes, transport or renewal")
						}
						wantCalls := []string{"preflight", "compatibility", "console", "provision", "install", "pins-close", "console-close"}
						if !reflect.DeepEqual(f.calls, wantCalls) {
							t.Fatal("coordinator order changed", f.calls)
						}
					})
				}
			}
		}
	}
}

func boolName(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestSetupFrontendEveryFailureRetainsOrderingAndFiniteDiagnostics(t *testing.T) {
	for _, fail := range []string{"preflight", "compatibility", "console", "provision", "install", "pins-close", "console-close"} {
		t.Run(fail, func(t *testing.T) {
			f, payload, manifest := newSetupFrontendFixture(t)
			f.fail = fail
			_, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
			if err != nil {
				t.Fatal(err)
			}
			f.raw = frontendPublicBytes(t, "tls", false)
			var progress []string
			err = hooks.InstallReadAdmin(context.Background(), f.raw, false, func(text string) { progress = append(progress, text) })
			if err == nil || len(progress) == 0 {
				t.Fatal("failure lost")
			}
			for _, text := range progress {
				if strings.Contains(text, "private fixture") || strings.Contains(text, "public-fixture-bootstrap") || strings.Contains(text, "BEGIN CERTIFICATE") {
					t.Fatal("private/raw material reached progress")
				}
			}
			want := []string{"preflight", "compatibility", "console", "provision", "install"}
			if fail != "pins-close" && fail != "console-close" {
				for i, name := range want {
					if name == fail {
						want = want[:i+1]
						break
					}
				}
			}
			if fail == "provision" || fail == "install" || fail == "pins-close" || fail == "console-close" {
				want = append(want, "pins-close")
			}
			if fail == "provision" || fail == "install" || fail == "pins-close" || fail == "console-close" {
				want = append(want, "console-close")
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal("later operation or lost cleanup", f.calls, want)
			}
		})
	}
}

func TestSetupFrontendCancellationAndIncompleteProvisionNeverInstall(t *testing.T) {
	for _, name := range []string{"parent-canceled", "console-canceled", "preflight", "compatibility", "provision", "missing-path", "missing-pin"} {
		t.Run(name, func(t *testing.T) {
			f, payload, manifest := newSetupFrontendFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.cancel = cancel
			switch name {
			case "parent-canceled":
				cancel()
			case "console-canceled":
				f.consoleCancel = true
			case "missing-path":
				f.provisionPath = ""
			case "missing-pin":
				f.provisionClose = false
			default:
				f.cancelAt = name
			}
			_, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
			if err != nil {
				t.Fatal(err)
			}
			f.raw = frontendPublicBytes(t, "tls", false)
			if hooks.InstallReadAdmin(ctx, f.raw, false, func(string) {}) == nil {
				t.Fatal("incomplete/canceled apply accepted")
			}
			for _, call := range f.calls {
				if call == "install" {
					t.Fatal("canceled or unpinned installation advanced")
				}
			}
			if name == "parent-canceled" && len(f.calls) != 0 {
				t.Fatal("pre-canceled operation invoked a dependency")
			}
		})
	}
}

func TestSetupFrontendSnapshotsPublicInputBeforeProgressCallbacks(t *testing.T) {
	f, payload, manifest := newSetupFrontendFixture(t)
	_, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
	if err != nil {
		t.Fatal(err)
	}
	raw := frontendPublicBytes(t, "tls", false)
	f.raw = bytes.Clone(raw)
	if err := hooks.InstallReadAdmin(context.Background(), raw, false, func(string) { raw[0] = '!' }); err != nil {
		t.Fatal("frontend alias changed validated operation bytes", err)
	}
}

func TestSetupFrontendPreviewAndOversizedApplyRemainReadOnly(t *testing.T) {
	f, payload, manifest := newSetupFrontendFixture(t)
	config, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
	if err != nil || config.InitialPublicBootstrap != nil {
		t.Fatal("optional initial selection changed", err)
	}
	raw := frontendPublicBytes(t, "tls", false)
	want, err := setupWizardPreview(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hooks.Preview(raw)
	if err != nil || !reflect.DeepEqual(got, want) || len(f.calls) != 0 {
		t.Fatal("preview changed or reached a backend")
	}
	for _, invalid := range [][]byte{nil, []byte(`{"invitationSecret":"invented-fixture"}`), append(bytes.Clone(raw), []byte(`{}`)...)} {
		if _, err := hooks.Preview(invalid); err == nil || len(f.calls) != 0 {
			t.Fatal("preview admitted malformed/secret bytes or invoked a backend")
		}
	}
	for _, hook := range frontendHooks(hooks) {
		if hook(context.Background(), make([]byte, windowspackage.MaxBootstrapBytes+1), false, func(string) {}) == nil || len(f.calls) != 0 {
			t.Fatal("oversized input reached a backend")
		}
	}
}

func TestSetupFrontendRejectsMissingOperationInputsAndPreservesRemovalAdapter(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f, payload, manifest := newSetupFrontendFixture(t)
		if fail {
			f.fail = "uninstall"
		}
		_, hooks, err := setupFrontend(payload, manifest, nil, f.backend())
		if err != nil {
			t.Fatal(err)
		}
		for _, hook := range frontendHooks(hooks) {
			if hook(nil, nil, false, func(string) {}) == nil || hook(context.Background(), nil, false, nil) == nil {
				t.Fatal("invalid operation input accepted")
			}
		}
		if hooks.Uninstall(nil, func(string) {}) == nil || hooks.Uninstall(context.Background(), nil) == nil || len(f.calls) != 0 {
			t.Fatal("invalid input reached backend")
		}
		var progress []string
		err = hooks.Uninstall(context.Background(), func(text string) { progress = append(progress, text) })
		if (err != nil) != fail || !reflect.DeepEqual(f.calls, []string{"uninstall"}) {
			t.Fatal("removal adapter changed")
		}
		if fail && (len(progress) != 1 || progress[0] != setupRemovalFailureText(err) || strings.Contains(progress[0], "private fixture")) {
			t.Fatal("removal failure lost finite diagnostic")
		}
	}
}
