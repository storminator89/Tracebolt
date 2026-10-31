package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Source-call-graph evidence complements the injected tests and cross-build.
// It does not execute the Windows entry, console, transport or service backend.
func setupFrontendSourceBody(t *testing.T, name string) string {
	t.Helper()
	source, err := os.ReadFile("entry_setup_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	return setupFrontendSourceBodyBytes(t, name, source)
}

func setupFrontendSourceBodyBytes(t *testing.T, name string, source []byte) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "entry_setup_windows.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			var canonical bytes.Buffer
			if err := format.Node(&canonical, fset, fn.Body); err != nil {
				t.Fatal(err)
			}
			return canonical.String()
		}
	}
	t.Fatal("missing native function", name)
	return ""
}

func TestSetupFrontendNativeEntryRetainsDefaultUIAndNoNewApplySurface(t *testing.T) {
	entry := setupFrontendSourceBody(t, "main")
	for _, call := range []string{
		"if len(os.Args) != 1",
		"manifest.Validate(payload)",
		"setupFrontend(payload, manifest, publicBootstrap, nativeSetupFrontendBackend())",
		"windowssetupui.Run(config, hooks)",
	} {
		if !strings.Contains(entry, call) {
			t.Fatal("native entry lost original default/validation boundary", call)
		}
	}
	if strings.Count(entry, "setupFrontend(") != 1 || strings.Count(entry, "windowssetupui.Run(") != 1 {
		t.Fatal("multiple frontend/apply paths")
	}
	for _, text := range []string{entry, setupFrontendSourceBody(t, "nativeSetupFrontendBackend")} {
		for _, forbidden := range []string{"exec.", "os.StartProcess", "LoadLibrary", "net.Listen", "ApplyRestart", "claim-invitation", "TraceboltRustAgent"} {
			if strings.Contains(text, forbidden) {
				t.Fatal("new execution/native authority in frontend wiring", forbidden)
			}
		}
	}
}

func TestSetupFrontendNativeBackendRetainsExactHardenedCoordinator(t *testing.T) {
	source, err := os.ReadFile("entry_setup_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	lf := bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
	for name, input := range map[string][]byte{"LF": lf, "CRLF": bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))} {
		t.Run(name, func(t *testing.T) {
			native := setupFrontendSourceBodyBytes(t, "nativeSetupFrontendBackend", input)
			for _, required := range []string{
				"preflight: windowspackage.Preflight",
				"b, err := setupWizardBootstrap(raw)",
				"context.WithTimeout(ctx, 20*time.Second)",
				"expected := windowssetup.Expected(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)",
				"if readAdmin {\n\t\t\t\texpected = windowssetup.ExpectedReadAdminV10(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin)",
				"lanclient.CheckWindowsSetupManager(requestCtx, b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), expected)",
				"console: setupWizardConsole",
				"windowspackage.Provision(ctx, payload, manifest, raw)",
				"return r.BootstrapPath, r.Close, nil",
				"installReadObservationWithProgress(ctx, path, consent, console, console, progress, renewal)",
				"setupWizardUninstallWithLease(ctx, openReceiptStore",
				"inspectOwned: windowsservice.InspectOwned, inspectRemoval: windowsservice.InspectRemoval, stop: windowsservice.ApplyStop, remove: uninstallWithUpdateOwnership",
				"windowsservice.CanWaitRemovalObservation(err) && setupRemovalPending(err)",
				"time.NewTimer(250 * time.Millisecond)",
				"case <-ctx.Done():",
			} {
				if !strings.Contains(native, required) {
					t.Fatal("native adapter lost original coordinator binding", required)
				}
			}
		})
	}
}
