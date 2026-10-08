package windowsconsole

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The text is inert adversarial test material, never console or user input.
const hostileText = "private-input\nPRIVATE mode=123456 native-code=987654"

type hostileError struct{ cause error }

func (hostileError) Error() string          { panic(hostileText) }
func (hostileError) As(any) bool            { panic(hostileText) }
func (hostileError) Is(error) bool          { panic(hostileText) }
func (hostileError) Format(fmt.State, rune) { panic(hostileText) }
func (e hostileError) Unwrap() error        { return e.cause }

type hostileUnwrap struct{}

func (hostileUnwrap) Error() string { panic(hostileText) }
func (hostileUnwrap) Unwrap() error { panic(hostileText) }

type cyclicError struct{}

func (cyclicError) Error() string   { panic(hostileText) }
func (e cyclicError) Unwrap() error { return e }

type joinedErrors []error

func (joinedErrors) Error() string     { panic(hostileText) }
func (e joinedErrors) Unwrap() []error { return e }

func TestDiagnosticClosedCategories(t *testing.T) {
	cases := []struct {
		name       string
		category   Category
		diagnostic string
	}{
		{"CategoryUnknown", CategoryUnknown, "unknown"},
		{"CategoryInvalid", CategoryInvalid, "invalid"},
		{"CategoryUnsupported", CategoryUnsupported, "unsupported"},
		{"CategoryResolve", CategoryResolve, "resolve"},
		{"CategoryOpen", CategoryOpen, "open"},
		{"CategoryType", CategoryType, "type"},
		{"CategoryModeRead", CategoryModeRead, "mode_read"},
		{"CategoryModeSet", CategoryModeSet, "mode_set"},
		{"CategoryModeVerify", CategoryModeVerify, "mode_verify"},
		{"CategoryDiscard", CategoryDiscard, "discard"},
		{"CategoryPrompt", CategoryPrompt, "prompt"},
		{"CategoryRead", CategoryRead, "read"},
		{"CategoryDecode", CategoryDecode, "decode"},
		{"CategoryContext", CategoryContext, "context"},
		{"CategoryCleanupDiscard", CategoryCleanupDiscard, "cleanup_discard"},
		{"CategoryRestoreSet", CategoryRestoreSet, "restore_set"},
		{"CategoryRestoreVerify", CategoryRestoreVerify, "restore_verify"},
		{"CategoryClose", CategoryClose, "close"},
	}
	names := make(map[string]bool)
	values := make(map[Category]string)
	for _, tc := range cases {
		if names[tc.name] || values[tc.category] != "" {
			t.Fatal("duplicate finite category")
		}
		names[tc.name] = true
		values[tc.category] = tc.diagnostic
		for _, err := range []error{failure(tc.category), hostileError{failure(tc.category)}, joinedErrors{hostileError{}, failure(tc.category)}} {
			if CategoryOf(err) != tc.category || Diagnostic(err) != tc.diagnostic {
				t.Fatalf("finite category mapping changed for %s", tc.name)
			}
		}
		err := failure(tc.category)
		if !errors.Is(err, ErrInput) || err.Error() != ErrInput.Error() || errors.Unwrap(err) != ErrInput {
			t.Fatal("fixed text or public sentinel changed")
		}
	}
	// Inspect the declaration so adding an enum constant cannot silently leave
	// this closed mapping test stale. This reads source, never native state.
	source, err := parser.ParseFile(token.NewFileSet(), "diagnostic.go", nil, 0)
	if err != nil {
		t.Fatal("cannot inspect finite category declarations")
	}
	declared := make(map[string]bool)
	ast.Inspect(source, func(node ast.Node) bool {
		if declaration, ok := node.(*ast.GenDecl); ok && declaration.Tok == token.CONST {
			for _, specification := range declaration.Specs {
				for _, name := range specification.(*ast.ValueSpec).Names {
					if strings.HasPrefix(name.Name, "Category") {
						declared[name.Name] = true
						if !names[name.Name] {
							t.Fatalf("untested category %s", name.Name)
						}
					}
				}
			}
		}
		return true
	})
	if len(declared) != len(names) {
		t.Fatal("category fixture no longer matches declarations")
	}
	for raw := 0; raw <= 255; raw++ {
		category := Category(raw)
		if _, known := values[category]; !known && (CategoryOf(failure(category)) != CategoryUnknown || Diagnostic(failure(category)) != "unknown") {
			t.Fatal("unrecognized category escaped closed mapping")
		}
	}
}

func TestDiagnosticHostileUnknownAndBoundedChains(t *testing.T) {
	var deep error = failure(CategoryRead)
	for range 64 {
		deep = hostileError{deep}
	}
	wide := make(joinedErrors, 10000)
	wide[len(wide)-1] = failure(CategoryRead)
	for _, err := range []error{nil, ErrInput, fixtureFailure, hostileError{}, hostileUnwrap{}, cyclicError{}, joinedErrors{hostileUnwrap{}, failure(CategoryRead)}, deep, wide, (*inputFailure)(nil)} {
		if CategoryOf(err) != CategoryUnknown || Diagnostic(err) != "unknown" {
			t.Fatal("unknown or hostile error did not fail closed")
		}
	}
	var atBoundary error = failure(CategoryRead)
	for range 63 {
		atBoundary = hostileError{atBoundary}
	}
	if CategoryOf(atBoundary) != CategoryRead {
		t.Fatal("valid bounded chain was lost")
	}
}

func TestOpenFailureCategoriesAreSanitized(t *testing.T) {
	for _, category := range []Category{CategoryUnsupported, CategoryResolve, CategoryOpen, CategoryType, CategoryClose} {
		secret, err := readWithConsole(context.Background(), func() error { t.Fatal("unexpected prompt"); return nil },
			func() (console, error) { return nil, hostileError{failure(category)} })
		if secret != nil || CategoryOf(err) != category || !errors.Is(err, ErrInput) || errors.Unwrap(err) != ErrInput {
			t.Fatal("closed open category was lost or wrapper was retained")
		}
	}
	for _, cause := range []error{nil, fixtureFailure, hostileUnwrap{}, hostileError{}, failure(CategoryRead)} {
		secret, err := readWithConsole(context.Background(), func() error { t.Fatal("unexpected prompt"); return nil },
			func() (console, error) { return nil, cause })
		if secret != nil || CategoryOf(err) != CategoryOpen || !errors.Is(err, ErrInput) || errors.Unwrap(err) != ErrInput {
			t.Fatal("unknown open failure was not sanitized")
		}
	}
}
