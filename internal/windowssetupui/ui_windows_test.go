//go:build windows

package windowssetupui

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// These are inert ABI layout assertions, not Win32 window/native acceptance.
func TestWin32Supported64BitLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("installer supports amd64 and arm64 only")
	}
	if unsafe.Sizeof(winClass{}) != 80 {
		t.Fatal("WNDCLASSEXW layout")
	}
	if unsafe.Sizeof(winMessage{}) != 48 {
		t.Fatal("MSG layout")
	}
	if unsafe.Sizeof(openFileName{}) != 152 {
		t.Fatal("OPENFILENAMEW layout")
	}
	if unsafe.Offsetof(openFileName{}.File) != 48 || unsafe.Offsetof(openFileName{}.Flags) != 96 || unsafe.Offsetof(openFileName{}.Reserved) != 136 {
		t.Fatal("OPENFILENAMEW offsets")
	}
	if unsafe.Sizeof(rect{}) != 16 || unsafe.Sizeof(monitorInfo{}) != 40 || unsafe.Offsetof(monitorInfo{}.Work) != 20 {
		t.Fatal("RECT/MONITORINFO layout")
	}
	if unsafe.Sizeof(minMaxInfo{}) != 40 || unsafe.Offsetof(minMaxInfo{}.MinTrackSize) != 24 {
		t.Fatal("MINMAXINFO layout")
	}
}

func TestAdjacentBootstrapSelectsOnlyAfterPreviewAndNeverGrantsConsent(t *testing.T) {
	const id = "invite_0123456789abcdef0123456789abcdef"
	const name = "tracebolt-bootstrap-" + id + ".json"
	const data = `{"invitationId":"` + id + `"}`
	c, h := readAdminUIFixture()
	h.Preview = func(b []byte) (TrustPreview, error) {
		if string(b) != data {
			t.Fatal("wrong public bytes")
		}
		return fixtureTrust(), nil
	}
	w := wizard{config: c, hooks: h, flow: freshFlow(c, h)}
	exe := filepath.Join(t.TempDir(), "Setup.exe")
	read := func(path string) ([]byte, error) {
		if path != filepath.Join(filepath.Dir(exe), name) {
			t.Fatalf("unexpected sidecar: %q", path)
		}
		return []byte(data), nil
	}
	list := func(string) ([]string, error) { return []string{"Setup.exe", name}, nil }
	if !w.selectAdjacentBootstrap(func() (string, error) { return exe, nil }, list, read) ||
		!strings.Contains(w.fileName, name) || !strings.Contains(w.fileName, "automatically selected") || !w.flow.next() || w.flow.canInstall() ||
		w.flow.scope || w.flow.service || w.flow.identity || w.flow.compared {
		t.Fatal("automatic selection bypassed review or failed")
	}
	if w.selectAdjacentBootstrap(func() (string, error) { return exe, nil }, list, read) {
		t.Fatal("selection changed during review")
	}
}

func TestAdjacentBootstrapFailureKeepsManualSelectionAvailable(t *testing.T) {
	for _, scenario := range []string{"no-executable", "relative-executable", "missing", "preview-error", "invalid-trust", "multiple", "wrong-id", "listing-error", "no-candidate", "too-many"} {
		t.Run(scenario, func(t *testing.T) {
			c, h := readAdminUIFixture()
			h.Preview = func([]byte) (TrustPreview, error) {
				if scenario == "preview-error" {
					return TrustPreview{}, errors.New("invalid")
				}
				if scenario == "invalid-trust" {
					return TrustPreview{}, nil
				}
				return fixtureTrust(), nil
			}
			w := wizard{config: c, hooks: h, flow: freshFlow(c, h)}
			executable := func() (string, error) {
				if scenario == "no-executable" {
					return "", errors.New("unavailable")
				}
				if scenario == "relative-executable" {
					return "Setup.exe", nil
				}
				return filepath.Join(t.TempDir(), "Setup.exe"), nil
			}
			read := func(string) ([]byte, error) {
				if scenario == "missing" {
					return nil, errors.New("missing")
				}
				if scenario == "wrong-id" {
					return []byte(`{"invitationId":"invite_11111111111111111111111111111111"}`), nil
				}
				return []byte(`{"invitationId":"invite_0123456789abcdef0123456789abcdef"}`), nil
			}
			list := func(string) ([]string, error) {
				name := "tracebolt-bootstrap-invite_0123456789abcdef0123456789abcdef.json"
				if scenario == "listing-error" {
					return nil, errors.New("denied")
				}
				if scenario == "multiple" {
					return []string{name, "tracebolt-bootstrap-invite_11111111111111111111111111111111.json"}, nil
				}
				if scenario == "no-candidate" {
					return []string{"tracebolt-bootstrap-invite_0123456789ABCDEF0123456789abcdef.json"}, nil
				}
				if scenario == "too-many" {
					return make([]string, maxAdjacentEntries+1), nil
				}
				return []string{name}, nil
			}
			if w.selectAdjacentBootstrap(executable, list, read) || len(w.flow.bootstrap) != 0 || w.flow.canInstall() || w.fileName != "" {
				t.Fatal("failed sidecar was selected")
			}
			if err := w.flow.selectBootstrap([]byte(`{"public":"manual"}`), fixtureTrust()); err != nil || !w.flow.next() || w.flow.canInstall() {
				t.Fatal("manual fallback unavailable or granted consent")
			}
		})
	}
}

func TestAdjacentBootstrapNativeLocalDirectoryAndNetworkRejection(t *testing.T) {
	dir := t.TempDir()
	name := "tracebolt-bootstrap-invite_0123456789abcdef0123456789abcdef.json"
	data := []byte(`{"invitationId":"invite_0123456789abcdef0123456789abcdef"}`)
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	c, h := readAdminUIFixture()
	h.Preview = func([]byte) (TrustPreview, error) { return fixtureTrust(), nil }
	w := wizard{config: c, hooks: h, flow: freshFlow(c, h)}
	if !w.selectAdjacentBootstrap(func() (string, error) { return filepath.Join(dir, "Setup.exe"), nil }, adjacentBootstrapEntries, readPublicBootstrap) {
		t.Fatal("native local sidecar not selected")
	}
	if _, err := adjacentBootstrapEntries(`\\server\share`); err == nil {
		t.Fatal("network directory accepted")
	}
}

func TestNativeLayoutMessagePointerDecoding(t *testing.T) {
	// Inert local structures only; no Windows API or HWND is touched.
	// Pin the Go fixtures while modeling native-owned, nonmoving memory.
	var pinned runtime.Pinner
	defer pinned.Unpin()
	r := &rect{-1920, -40, 0, 1040}
	pinned.Pin(r)
	parameter := uintptr(unsafe.Pointer(r))
	if got := *nativeMessagePointer[rect](&parameter); got != *r {
		t.Fatalf("WM_DPICHANGED rectangle changed: %+v", got)
	}
	m := &minMaxInfo{}
	pinned.Pin(m)
	parameter = uintptr(unsafe.Pointer(m))
	nativeMessagePointer[minMaxInfo](&parameter).MinTrackSize = point{770, 599}
	if m.MinTrackSize != (point{770, 599}) {
		t.Fatal("WM_GETMINMAXINFO output pointer lost")
	}
	parameter = 0
	if nativeMessagePointer[rect](&parameter) != nil {
		t.Fatal("null LPARAM became non-null")
	}
}
