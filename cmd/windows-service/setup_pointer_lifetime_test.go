package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This portable test compiles the actual native driver's syscall wrappers with
// inert stand-ins for the DLL procedures. It never executes the generated code,
// loads a DLL, creates a window, or invokes a privileged operation. The compiler
// must keep pointer arguments off movable Go stacks across every wrapper layer.
func TestSetupNativePointerWrapperLifetime(t *testing.T) {
	source, err := os.ReadFile("setup_acceptance_ui_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "setup_acceptance_ui_windows_test.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"setupCall", "setupKernel", "setupSend"}
	bodies := make(map[string]string)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		for _, name := range names {
			if fn.Name.Name != name {
				continue
			}
			annotated := false
			if fn.Doc != nil {
				for _, comment := range fn.Doc.List {
					annotated = annotated || comment.Text == "//go:uintptrescapes"
				}
			}
			if !annotated {
				t.Fatalf("%s loses pointer lifetime before the native syscall", name)
			}
			bodies[name] = string(source[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
		}
	}
	for _, name := range names {
		if bodies[name] == "" {
			t.Fatalf("native syscall wrapper %s is missing", name)
		}
	}
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	// Match the test's own toolchain, rather than another executable named go.
	goTool := filepath.Join(runtime.GOROOT(), "bin", goName)
	for _, variant := range []struct {
		name    string
		removed string
		moved   map[string]bool
	}{
		{"actual", "", map[string]bool{"userBuffer": true, "kernelBuffer": true, "textBuffer": true, "result": true}},
		{"without_setupCall", "setupCall", map[string]bool{"userBuffer": false, "kernelBuffer": true, "textBuffer": true, "result": false}},
		{"without_setupKernel", "setupKernel", map[string]bool{"userBuffer": true, "kernelBuffer": false, "textBuffer": true, "result": true}},
		{"without_setupSend", "setupSend", map[string]bool{"userBuffer": true, "kernelBuffer": true, "textBuffer": false, "result": true}},
		{"original_unannotated", "all", map[string]bool{"userBuffer": false, "kernelBuffer": false, "textBuffer": false, "result": false}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			var fixture strings.Builder
			fixture.WriteString(setupPointerCompilerStubs)
			for _, name := range names {
				if variant.removed != name && variant.removed != "all" {
					fixture.WriteString("//go:uintptrescapes\n")
				}
				fixture.WriteString(bodies[name])
				fixture.WriteString("\n\n")
			}
			fixture.WriteString(setupPointerCompilerProbes)
			dir := t.TempDir()
			path := filepath.Join(dir, "probe.go")
			if err := os.WriteFile(path, []byte(fixture.String()), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(goTool, "tool", "compile", "-m=2", "-o", filepath.Join(dir, "probe.o"), path)
			command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("inert compiler fixture failed: %v\n%s", err, output)
			}
			for name, want := range variant.moved {
				got := regexp.MustCompile(`moved to heap: ` + name + `\b`).Match(output)
				if got != want {
					t.Errorf("%s heap placement = %v, want %v\n%s", name, got, want, output)
				}
			}
		})
	}
}

const setupPointerCompilerStubs = `package pointerproof
import "unsafe"

type fakeDLL struct{}
type fakeProc struct{}
var setupUser32, setupKernel32 fakeDLL
var proc fakeProc
func (fakeDLL) NewProc(string) *fakeProc { return &proc }
// This is the same contract used by x/sys/windows LazyProc.Call.
//go:uintptrescapes
func (*fakeProc) Call(args ...uintptr) (uintptr, uintptr, error) { return 1, 0, nil }
type guardError struct{}
func (guardError) Error() string { return "guard" }
var setupgate = struct { ErrGuard error }{guardError{}}

`

// Observe the buffers after each call: mere liveness must not be mistaken for
// the heap placement needed while uintptr arguments cross stack-growing calls.
const setupPointerCompilerProbes = `
//go:noinline
func ProbeUserGeometry() int32 {
    var userBuffer [4]int32
    setupCall("GetWindowRect", uintptr(1), uintptr(unsafe.Pointer(&userBuffer)))
    return userBuffer[0]
}
//go:noinline
func ProbeKernelOutput() uint32 {
    var kernelBuffer uint32
    setupKernel("ProcessIdToSessionId", uintptr(1), uintptr(unsafe.Pointer(&kernelBuffer)))
    return kernelBuffer
}
//go:noinline
func ProbeMessageText() uint16 {
    var textBuffer [32]uint16
    setupSend(1, 0x000d, uintptr(len(textBuffer)), uintptr(unsafe.Pointer(&textBuffer[0])))
    return textBuffer[0]
}
`
