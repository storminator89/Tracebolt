package windowsstorageio

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Source-only audit: parsing the Windows adapter never loads pdh.dll or opens a
// native query. The API surface must remain exactly the five fixed PDH calls.
func TestNativeAPIAllowlist(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "native_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]bool{"PdhOpenQueryW": true, "PdhAddEnglishCounterW": true, "PdhCollectQueryData": true, "PdhGetFormattedCounterValue": true, "PdhCloseQuery": true}
	dlls := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "NewProc" || sel.Sel.Name == "NewLazySystemDLL" {
			if len(call.Args) != 1 {
				t.Fatal("nonliteral native binding")
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				t.Fatal("dynamic native binding")
			}
			s, e := strconv.Unquote(lit.Value)
			if e != nil {
				t.Fatal(e)
			}
			if sel.Sel.Name == "NewLazySystemDLL" {
				if s != "pdh.dll" {
					t.Fatal("unexpected native DLL")
				}
				dlls++
			} else {
				if !want[s] {
					t.Fatal("unexpected native API", s)
				}
				delete(want, s)
			}
		}
		return true
	})
	if len(want) != 0 || dlls != 1 {
		t.Fatal("fixed PDH native bindings incomplete")
	}
}
