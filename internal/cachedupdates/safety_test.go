package cachedupdates

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Regression tripwire, not proof against a privileged local administrator. No
// collector/parser may silently gain network, install, shell or filesystem-write
// authority. Protected consent writes belong to the separately reviewed runtime.
func TestCollectorReadOnlyDependencyBoundary(t *testing.T) {
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, "net") || p == "syscall" || p == "unsafe" {
				t.Fatalf("review new execution/network dependency %s", p)
			}
			if p == "os/exec" && entry.Name() != "source_linux.go" {
				t.Fatal("command execution escaped fixed native source")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if (pkg.Name == "os" || pkg.Name == "unix") && oneOf(sel.Sel.Name, "WriteFile", "Create", "OpenFile", "Remove", "RemoveAll", "Rename", "Mkdir", "MkdirAll", "Chmod", "Chown", "Setenv", "Write", "Unlink", "Renameat", "Openat2", "Socket") {
				t.Fatalf("mutating or network API %s.%s", pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
}
