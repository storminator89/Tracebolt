package assessment

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// A narrow regression tripwire, not a substitute for code review: foundation
// production code may not quietly grow networking, write APIs or extra commands.
func TestReadOnlyProductionDependencyBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bufio": true, "bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "io": true, "os": true, "os/exec": true, "regexp": true, "runtime": true, "sort": true, "strings": true, "sync": true, "time": true, "unicode/utf8": true}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Fatalf("review new production dependency %s in %s", path, name)
			}
			if path == "os/exec" && name != "debversion.go" {
				t.Fatal("execution capability escaped the fixed comparator")
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "os" && oneOf(selector.Sel.Name, "WriteFile", "Create", "OpenFile", "Remove", "RemoveAll", "Rename", "Mkdir", "MkdirAll", "Chmod", "Chown", "Setenv") {
				t.Fatalf("mutating API %s in %s", selector.Sel.Name, name)
			}
			if pkg.Name == "exec" {
				if name != "debversion.go" || selector.Sel.Name != "CommandContext" || len(call.Args) < 3 {
					t.Fatal("unexpected command constructor")
				}
				path, ok := call.Args[1].(*ast.BasicLit)
				if !ok || path.Value != `"/usr/bin/dpkg"` {
					t.Fatal("comparator executable must remain fixed")
				}
				operation, ok := call.Args[2].(*ast.BasicLit)
				if !ok || operation.Value != `"--compare-versions"` {
					t.Fatal("comparator operation must remain fixed")
				}
			}
			return true
		})
	}
}
