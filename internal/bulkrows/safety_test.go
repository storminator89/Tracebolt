package bulkrows

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPlannerHasNoIOOrDynamicExecutionCapability(t *testing.T) {
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	allowed := map[string]bool{"context": true, "crypto/sha256": true, "encoding/hex": true, "errors": true, "sort": true, "strings": true}
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
			if !allowed[p] {
				t.Fatalf("review new planner capability %s", p)
			}
		}
	}
}
