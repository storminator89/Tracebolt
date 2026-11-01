//go:build windows && cgo && tracebolt_setup_rust && tracebolt_setup_gui_fixture

package windowssetupui

// This test-only entry exercises the real Rust view and Go flow. Its hooks are
// deliberately memory-only: no service, package, enrollment, crypto or network
// backend is imported or called. A passed fixture is never installation proof.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

type nativeGUIFixtureResult struct {
	Schema                        string `json:"schema"`
	Case                          string `json:"case"`
	Hook                          string `json:"hook"`
	HookCount                     int    `json:"hookCount"`
	Cancelled                     bool   `json:"cancelled"`
	CleanupJoined                 bool   `json:"cleanupJoined"`
	ExactHookSelection            bool   `json:"exactHookSelection"`
	LayoutAtHookAdmission         bool   `json:"layoutAtHookAdmission"`
	UIReturned                    bool   `json:"uiReturned"`
	InstallerHostActionsAttempted bool   `json:"installerHostActionsAttempted"`
	InstallerAcceptance           bool   `json:"installerAcceptance"`
	FontProbeCount                int    `json:"fontProbeCount"`
	FontProbesValid               bool   `json:"fontProbesValid"`
	ProbeReaderJoined             bool   `json:"probeReaderJoined"`
}

func fixtureNativeRead(check func(uintptr, int) bool) (valid bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous, _, _ := setThreadDpiAwareness.Call(^uintptr(3)) // Per-monitor-v2, this thread only.
	if previous == 0 {
		return false
	}
	defer func() {
		if restored, _, _ := setThreadDpiAwareness.Call(previous); restored == 0 {
			valid = false
		}
	}()
	find := user32.NewProc("FindWindowW")
	process := user32.NewProc("GetWindowThreadProcessId")
	h, _, _ := find.Call(uintptr(unsafe.Pointer(utf16("TraceboltRustFreshSetupWizard"))), 0)
	if h == 0 {
		return false
	}
	var pid uint32
	process.Call(h, uintptr(unsafe.Pointer(&pid)))
	if pid != uint32(os.Getpid()) {
		return false
	}
	dpi, _, _ := getDpiForWindow.Call(h)
	return dpi >= 96 && dpi <= 768 && check(h, int(dpi))
}

func fixtureNativeClientMeetsMinimum() bool {
	return fixtureNativeRead(func(h uintptr, dpi int) bool {
		var area rect
		ok, _, _ := getClientRect.Call(h, uintptr(unsafe.Pointer(&area)))
		return ok != 0 && int(area.Right-area.Left) >= scaleUp(minimumClientWidth, dpi) && int(area.Bottom-area.Top) >= scaleUp(minimumClientHeight, dpi)
	})
}

type fixtureLogFont struct {
	Height, Width, Escapement, Orientation, Weight                                     int32
	Italic, Underline, Strikeout, CharSet, OutPrecision, ClipPrecision, Quality, Pitch uint8
	Face                                                                               [32]uint16
}

// GDI font objects are queried only here, inside their owning test process.
// The external driver receives just an ordinal and a bounded Boolean.
func fixtureNativeFontsMatch() bool {
	return fixtureNativeRead(func(root uintptr, dpi int) bool {
		getItem := user32.NewProc("GetDlgItem")
		getPID := user32.NewProc("GetWindowThreadProcessId")
		send := user32.NewProc("SendMessageTimeoutW")
		object := gdi32.NewProc("GetObjectW")
		for _, id := range []int{201, 104, 105, 106, 107, 108, 111} {
			h, _, _ := getItem.Call(root, uintptr(id))
			if h == 0 {
				if id == 201 {
					return false
				}
				continue
			}
			var pid uint32
			getPID.Call(h, uintptr(unsafe.Pointer(&pid)))
			if pid != uint32(os.Getpid()) {
				return false
			}
			var font uintptr
			ok, _, _ := send.Call(h, 0x0031, 0, 0, 2, 1000, uintptr(unsafe.Pointer(&font)))
			var info fixtureLogFont
			if ok == 0 || font == 0 || unsafe.Sizeof(info) != 92 {
				return false
			}
			size, _, _ := object.Call(font, unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
			if size != unsafe.Sizeof(info) || info.Height != int32(-scale(12, dpi)) || windows.UTF16ToString(info.Face[:]) != "Segoe UI" {
				return false
			}
		}
		return true
	})
}

func TestRustNativeGUIFixture(t *testing.T) {
	if os.Getenv("TRACEBOLT_RUST_GUI_FIXTURE_EXECUTE") != "synthetic-window-only-v1" {
		t.Fatal("explicit synthetic GUI execution acknowledgement required")
	}
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_BUILDID", "TF_BUILD"} {
		if _, exists := os.LookupEnv(name); exists {
			t.Fatal("native GUI fixture requires a separately approved interactive session")
		}
	}
	which := os.Getenv("TRACEBOLT_RUST_GUI_FIXTURE_CASE")
	allowed := map[string]bool{"tls": true, "http": true, "renewal": true, "cancel": true, "failure": true, "uninstall": true, "modal-resize": true, "close-input": true}
	if !allowed[which] || !rustFrontendEnabled() {
		t.Fatal("unsupported synthetic GUI fixture configuration")
	}
	r, _ := rustFixture(t, true, which == "http", which == "renewal")
	r.config.Version = "INERT_GUI_FIXTURE_NO_HOST_ACTION"
	result := nativeGUIFixtureResult{Schema: "tracebolt.rust-gui-inert-hook-result.v1", Case: which, ExactHookSelection: true}
	var mu sync.Mutex
	probeDone := make(chan struct{})
	var probeCount int
	probeValid := true
	go func() {
		defer close(probeDone)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64), 64)
		for scanner.Scan() {
			probeCount++
			if probeCount > 16 || scanner.Text() != "FONT_CHECK" {
				probeValid = false
				return
			}
			matches := fixtureNativeFontsMatch()
			probeValid = probeValid && matches
			raw, e := json.Marshal(struct {
				Ordinal int  `json:"ordinal"`
				Matches bool `json:"matchesOriginal"`
			}{probeCount, matches})
			if e != nil {
				probeValid = false
				return
			}
			fmt.Println("RUST_GUI_FIXTURE_FONT " + string(raw))
		}
		if scanner.Err() != nil {
			probeValid = false
		}
	}()
	hook := func(name string) func(context.Context, []byte, bool, func(string)) error {
		return func(ctx context.Context, data []byte, ack bool, progress func(string)) error {
			mu.Lock()
			result.HookCount++
			result.Hook = name
			want := "read-admin"
			if which == "renewal" {
				want = "renewable-read-admin"
			}
			if which == "uninstall" || which == "modal-resize" {
				want = "uninstall"
			}
			result.ExactHookSelection = result.ExactHookSelection && name == want && (name == "uninstall" || bytes.Equal(data, r.config.InitialPublicBootstrap) && ack == (which == "http" || which == "renewal"))
			result.LayoutAtHookAdmission = fixtureNativeClientMeetsMinimum()
			mu.Unlock()
			progress("INERT GUI fixture hook entered; no host action exists.")
			if which == "cancel" {
				<-ctx.Done()
				mu.Lock()
				result.Cancelled = true
				mu.Unlock()
				// Prove that Close keeps the native window alive while an admitted
				// hook still owns cleanup. This delay belongs only to this fixture.
				time.Sleep(time.Second)
			} else {
				time.Sleep(350 * time.Millisecond)
			}
			mu.Lock()
			result.CleanupJoined = true
			mu.Unlock()
			if which == "failure" {
				return errors.New("SYNTHETIC_PRIVATE_ERROR_MUST_NOT_REACH_VIEW")
			}
			if which == "cancel" {
				return ctx.Err()
			}
			return nil
		}
	}
	h := r.hooks
	h.Preview = func(data []byte) (TrustPreview, error) {
		if !bytes.Equal(data, r.config.InitialPublicBootstrap) {
			return TrustPreview{}, errors.New("only the embedded invented fixture is supported")
		}
		return r.flow.trust, nil
	}
	h.Install = hook("basic")
	h.InstallReadAdmin = hook("read-admin")
	h.InstallRenewable = hook("renewable-basic")
	h.InstallReadAdminRenewable = hook("renewable-read-admin")
	h.Uninstall = func(ctx context.Context, progress func(string)) error {
		return hook("uninstall")(ctx, nil, false, progress)
	}
	err := Run(r.config, h)
	// Parent closes its retained stdin write end before waiting for completion.
	// Never rely on closing a synchronous Windows read from another goroutine.
	select {
	case <-probeDone:
		result.ProbeReaderJoined = true
	case <-time.After(2 * time.Second):
		t.Fatal("fixture font probe reader did not join")
	}
	result.FontProbeCount, result.FontProbesValid = probeCount, probeValid && probeCount >= 1 && probeCount <= 16
	mu.Lock()
	defer mu.Unlock()
	result.UIReturned = true
	good := result.ExactHookSelection && result.FontProbesValid && result.ProbeReaderJoined
	if which == "close-input" {
		good = good && result.HookCount == 0 && err == nil
	} else {
		good = good && result.HookCount == 1 && result.CleanupJoined && result.LayoutAtHookAdmission
		expectFailure := which == "failure" || which == "cancel"
		good = good && (expectFailure && errors.Is(err, ErrOperation) || !expectFailure && err == nil) && result.Cancelled == (which == "cancel")
	}
	if !good {
		t.Fatal("synthetic GUI fixture contract did not complete")
	}
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal("synthetic GUI fixture report unavailable")
	}
	fmt.Println("RUST_GUI_FIXTURE_RESULT " + string(data))
}
