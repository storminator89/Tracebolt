package windowsresourcecontext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Parse fixed Windows code without invoking a provider or Windows API.
func TestFixedNativeProjectionAndPagefilePrivacy(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "native_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"processorNamespace": `Root\CIMV2`, "processorQuery": "SELECT Name, Architecture, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"}
	var callbacks int
	ast.Inspect(f, func(n ast.Node) bool {
		if v, ok := n.(*ast.ValueSpec); ok && len(v.Names) == 1 && len(v.Values) == 1 {
			if expected, exists := want[v.Names[0].Name]; exists {
				value, ok := v.Values[0].(*ast.BasicLit)
				if !ok {
					t.Fatal("nonliteral source")
				}
				text, e := strconv.Unquote(value.Value)
				if e != nil || text != expected {
					t.Fatal("fixed projection changed")
				}
				delete(want, v.Names[0].Name)
			}
		}
		if function, ok := n.(*ast.FuncDecl); ok && function.Name.Name == "pagefileCallback" {
			callbacks++
			params := function.Type.Params.List
			if len(params) != 3 || len(params[2].Names) != 1 || params[2].Names[0].Name != "_" {
				t.Fatal("filename entered callback scope")
			}
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "PeakUsage", "CommitPeak", "SystemCache", "KernelTotal", "KernelPaged", "KernelNonpaged", "HandleCount", "ProcessCount", "ThreadCount", "Reserved":
				t.Fatal("excluded native member read", sel.Sel.Name)
			}
		}
		return true
	})
	if len(want) != 0 || callbacks != 1 {
		t.Fatal("missing fixed native boundary")
	}
}
