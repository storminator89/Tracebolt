package offlinecatalog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// This narrowly scoped regression tripwire is not a complete security proof.
// The catalog may call the fixed parser and accept the comparator interface,
// never the foundation's native comparator, local inventory reader, or matcher.
// The conditional-review core may validate already supplied package snapshots.
// Production code has no network, process, file-write, logging, or external-
// service dependencies; no default comparator is constructed.
func TestOfflineProductionBoundary(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "context": true, "crypto/rand": true, "crypto/sha256": true,
		"encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true,
		"io": true, "sort": true, "sync": true, "time": true,
		"localrmm/internal/assessment": true, "localrmm/internal/linuxpackages": true,
	}
	assessmentSymbols := map[string]bool{
		"MaxSnapshotBytes": true, "MaxSnapshotRules": true, "ParseDebianSnapshot": true,
		"SourceSnapshot": true, "ErrSnapshotLimit": true, "DebianSnapshotSchema": true,
		"VersionComparator": true,
	}
	packageSymbols := map[string]bool{
		"Snapshot": true, "Validate": true, "PackageRow": true, "ReleaseFields": true,
		"Healthy": true, "Incomplete": true, "Inconsistent": true, "Debian13": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	parserCalls := 0
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
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !allowed[path] {
				t.Fatalf("review production import %s", imp.Path.Value)
			}
			if imp.Name != nil {
				t.Fatal("review import aliases before allowing new capabilities")
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if ok && pkg.Name == "assessment" {
				if !assessmentSymbols[selector.Sel.Name] {
					t.Fatalf("unexpected foundation capability %s", selector.Sel.Name)
				}
				if selector.Sel.Name == "ParseDebianSnapshot" {
					parserCalls++
				}
			}
			if ok && pkg.Name == "linuxpackages" && !packageSymbols[selector.Sel.Name] {
				t.Fatalf("unexpected package observation capability %s", selector.Sel.Name)
			}
			return true
		})
	}
	if parserCalls != 1 {
		t.Fatal("upload must use the existing fixed parser exactly once")
	}
}
