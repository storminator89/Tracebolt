package windowsevents

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// This portable source-boundary test is not native acceptance. It makes adding
// message formatting, XML/content exports, remote sessions or write APIs an
// explicit review change rather than accidental expansion of this adapter.
func TestNativeAPISurfaceStaysReadOnly(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "source_windows.go", nil, 0)
	if err != nil {
		t.Fatal("cannot inspect native source boundary")
	}
	want := map[string]bool{"EvtQuery": false, "EvtNext": false, "EvtCreateRenderContext": false, "EvtRender": false, "EvtClose": false}
	systemDLL := false
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal("invalid import")
		}
		switch path {
		case "context", "errors", "runtime", "time", "unsafe", "golang.org/x/sys/windows":
		default:
			t.Fatal("native source gained an unreviewed import")
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "NewProc" && selector.Sel.Name != "NewLazySystemDLL") {
			return true
		}
		if len(call.Args) != 1 {
			t.Fatal("dynamic native API selection")
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			t.Fatal("native API name is not fixed")
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal("invalid native API name")
		}
		if selector.Sel.Name == "NewLazySystemDLL" {
			if name != "wevtapi.dll" || systemDLL {
				t.Fatal("native DLL boundary expanded")
			}
			systemDLL = true
		} else {
			seen, ok := want[name]
			if !ok || seen {
				t.Fatal("native API boundary expanded")
			}
			want[name] = true
		}
		return true
	})
	if !systemDLL {
		t.Fatal("safe system DLL loading missing")
	}
	for _, seen := range want {
		if !seen {
			t.Fatal("required read-only native API missing")
		}
	}
}
