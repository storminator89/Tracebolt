package updategeneration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// This is a direct dependency/call-boundary regression tripwire, not a proof of
// arbitrary future transitive behavior. cachedupdates is used only through its
// pure typed validators; source construction/collection is never reachable here.
func TestGenerationAdapterHasNoIOOrRuntimeRegistration(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "hash": true, "io": true, "strings": true, "time": true, "unicode/utf8": true, "localrmm/internal/bulkrows": true, "localrmm/internal/cachedupdates": true, "localrmm/internal/linuxpackages": true}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Fatalf("review new generation adapter dependency %s", path)
			}
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
				if name == "." || name == "_" {
					t.Fatal("ambiguous import bypasses pure-call review")
				}
			}
			names[name] = path
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
			namespace, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if names[namespace.Name] == "localrmm/internal/cachedupdates" && selector.Sel.Name != "Validate" && selector.Sel.Name != "ValidateCandidate" {
				t.Fatalf("source/runtime call escaped pure adapter: %s", selector.Sel.Name)
			}
			return true
		})
	}
}
