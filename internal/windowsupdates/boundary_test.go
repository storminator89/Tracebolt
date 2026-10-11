package windowsupdates

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// Source fixtures do not prove native read behavior. This review tripwire does
// make new imports, DLLs, COM writes, searches and mutation APIs explicit.
func TestNativeAPISurfaceStaysOfflineMetadataOnly(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "native_windows.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	imports := map[string]bool{"context": true, "runtime": true, "syscall": true, "unicode/utf16": true, "unsafe": true, "golang.org/x/sys/windows": true}
	for _, imp := range f.Imports {
		p, e := strconv.Unquote(imp.Path.Value)
		if e != nil || !imports[p] {
			t.Fatal("unreviewed native import", p)
		}
	}
	procs := map[string]bool{"CoInitializeEx": false, "CoUninitialize": false, "CoCreateInstance": false, "VariantClear": false, "SysAllocStringLen": false, "SysStringLen": false}
	dlls := map[string]bool{"ole32.dll": false, "oleaut32.dll": false}
	methods := map[string]bool{"CreateUpdateSearcher": true, "Search": true}
	properties := map[string]bool{"Online": true, "CanAutomaticallyUpgradeService": true, "ResultCode": true, "Updates": true, "Count": true, "Item": true, "Type": true, "IsInstalled": true, "IsHidden": true, "Identity": true, "UpdateID": true, "RevisionNumber": true, "Title": true, "MsrcSeverity": true, "IsDownloaded": true, "KBArticleIDs": true}
	literal := func(expr ast.Expr) string {
		v, ok := expr.(*ast.BasicLit)
		if !ok {
			t.Fatal("native member must be fixed")
		}
		s, e := strconv.Unquote(v.Value)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "NewProc":
			name := literal(c.Args[0])
			seen, ok := procs[name]
			if !ok || seen {
				t.Fatal("unreviewed native API", name)
			}
			procs[name] = true
		case "NewLazySystemDLL":
			name := literal(c.Args[0])
			seen, ok := dlls[name]
			if !ok || seen {
				t.Fatal("unreviewed DLL", name)
			}
			dlls[name] = true
		case "putFalse":
			name := literal(c.Args[1])
			if name != "Online" && name != "CanAutomaticallyUpgradeService" {
				t.Fatal("unreviewed COM write", name)
			}
		case "objectValue", "integer", "boolean", "text":
			name := literal(c.Args[1])
			if !properties[name] && !methods[name] {
				t.Fatal("unreviewed COM read", name)
			}
		case "invoke":
			name, ok := c.Args[1].(*ast.Ident)
			if !ok || name.Name != "name" {
				t.Fatal("unreviewed direct COM invocation")
			}
		}
		return true
	})
	for name, seen := range procs {
		if !seen {
			t.Fatal("missing expected API", name)
		}
	}
	for name, seen := range dlls {
		if !seen {
			t.Fatal("missing system DLL boundary", name)
		}
	}
}
