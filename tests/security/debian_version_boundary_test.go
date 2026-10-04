package security_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"localrmm/internal/assessment"
	"localrmm/internal/debianversion"
	"localrmm/internal/linuxpackages"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These independent fixtures use supplied strings, the existing public parser
// and matcher, and repository-source inspection only. No native comparator,
// collector, host inventory, network, APT operation or advisory lookup runs.
var _ assessment.VersionComparator = debianversion.Comparator{}

func TestIndependentDebianVersionOrdering(t *testing.T) {
	var comparator assessment.VersionComparator = debianversion.Comparator{}
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"epoch dominates both remaining parts", "1:0-0", "999999999-999999999", 1},
		{"decimal epoch", "0009:9", "10:0", -1},
		{"epoch bound with zero padding", "0002147483647:01", "2147483647:1", 0},
		{"absent components are zero", "001", "000:1-0000", 0},
		{"missing revision beats tilde", "1", "1-~9", 1},
		{"upstream wins over revision", "1.1-0", "1.0-999999999999999999999", 1},
		{"numeric run length", "1.999999999999999999999", "1.1000000000000000000000", -1},
		{"tilde precedes digit", "1a~1", "1a0", -1},
		{"multiple tildes", "1~~a", "1~", -1},
		{"terminal numeric zero", "1a000", "1a", 0},
		{"zero does not disappear between letters", "1a0b", "1ab", -1},
		{"case remains significant", "1-A", "1-a", -1},
		{"letters precede punctuation", "1-z", "1-+", -1},
		{"ASCII punctuation order", "1-+", "1-.", -1},
		{"last hyphen separates revision", "1-a-2", "1-a-11", -1},
		{"binNMU text is retained", "1-1+b10", "1-1+b2", 1},
		{"vendor-looking text remains literal", "1-1ubuntu9", "1-1ubuntu10", -1},
		{"no semver build metadata equality", "1+build9", "1+build10", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, pair := range []struct {
				a, b string
				want int
			}{{tc.a, tc.b, tc.want}, {tc.b, tc.a, -tc.want}, {tc.a, tc.a, 0}} {
				if !assessment.ValidDebianVersion(pair.a) || !assessment.ValidDebianVersion(pair.b) {
					t.Fatal("ordinary ordering fixture left the existing source grammar")
				}
				got, err := comparator.Compare(context.Background(), pair.a, pair.b)
				if err != nil || got != pair.want {
					t.Fatalf("portable interface result = %d, %v; want %d, nil", got, err, pair.want)
				}
			}
		})
	}
}

func TestIndependentDebianVersionGrammarAndObservationRetention(t *testing.T) {
	cases := []struct {
		name           string
		version        string
		sourceAccepted bool
		wantError      error
	}{
		{"ordinary epoch maximum", "2147483647:1", true, nil},
		{"maximum bytes", strings.Repeat("0", debianversion.MaxVersionBytes-1) + "1", true, nil},
		{"ordinary revision letters", "1-a+z.0~rc1", true, nil},
		{"legacy upstream colon", "1:1:2", true, debianversion.ErrVersionUnsupported},
		{"legacy trailing upstream colon", "0:1:", true, debianversion.ErrVersionUnsupported},
		{"legacy repeated upstream colons", "2:1::2-1", true, debianversion.ErrVersionUnsupported},
		{"epoch one above portability bound", "2147483648:1", true, debianversion.ErrEpochUnsupported},
		{"epoch wider than machine integer", "18446744073709551616:1", true, debianversion.ErrEpochUnsupported},
		{"epoch zeros do not change unsupported value", "0002147483648:1", true, debianversion.ErrEpochUnsupported},
		{"legacy colon precedes epoch support check", "2147483648:1:2", true, debianversion.ErrVersionUnsupported},
		{"non-digit initial upstream", "1:a", false, debianversion.ErrVersionInvalid},
		{"empty revision", "1-", false, debianversion.ErrVersionInvalid},
		{"revision colon", "1:1-1:2", false, debianversion.ErrVersionInvalid},
		{"malformed before epoch range", "2147483648:1-", false, debianversion.ErrVersionInvalid},
		{"no trimming in comparator", "1 ", false, debianversion.ErrVersionInvalid},
		{"ASCII only", "1é", false, debianversion.ErrVersionInvalid},
		{"one byte over bound", strings.Repeat("1", debianversion.MaxVersionBytes+1), false, debianversion.ErrVersionInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if assessment.ValidDebianVersion(tc.version) != tc.sourceAccepted {
				t.Fatal("source grammar changed; comparison support must not redefine observation acceptance")
			}
			for _, pair := range [][2]string{{tc.version, tc.version}, {tc.version, "1"}, {"1", tc.version}} {
				got, err := (debianversion.Comparator{}).Compare(context.Background(), pair[0], pair[1])
				if tc.wantError == nil {
					if err != nil || got < -1 || got > 1 || pair[0] == pair[1] && got != 0 {
						t.Fatalf("supported comparison result = %d, %v", got, err)
					}
				} else if got != 0 || !errors.Is(err, tc.wantError) || err.Error() != tc.wantError.Error() {
					t.Fatalf("unsupported/invalid result = %d, %v; want zero and fixed diagnostic", got, err)
				}
			}
			if !tc.sourceAccepted {
				return
			}
			// Both parsers receive this inert record through a supplied reader. The
			// missing Source field intentionally preserves the full Version budget.
			raw := "Package: version-review\nStatus: install ok installed\nVersion: " + tc.version + "\nArchitecture: amd64\n"
			rows, _, err := assessment.ParseDpkgStatus(context.Background(), strings.NewReader(raw))
			if err != nil || len(rows) != 1 || rows[0].Version != tc.version || rows[0].SourceVersion != tc.version {
				t.Fatal("portable comparison limitation erased or normalized accepted observation")
			}
			exported, err := linuxpackages.ParseDpkgStatus(context.Background(), strings.NewReader(raw))
			if err != nil || len(exported) != 1 || exported[0].Version != tc.version || exported[0].SourceVersion != tc.version {
				t.Fatal("selected package parser lost accepted source facts")
			}
		})
	}
	// An earlier decisive epoch cannot bypass validation of the other operand.
	for _, pair := range [][2]string{{"2147483647:1", "0:1-"}, {"0:1-", "2147483647:1"}} {
		got, err := (debianversion.Comparator{}).Compare(context.Background(), pair[0], pair[1])
		if got != 0 || !errors.Is(err, debianversion.ErrVersionInvalid) {
			t.Fatal("decisive prefix hid a malformed operand")
		}
	}
}

func TestIndependentDebianVersionUsesExistingMatcherFailureBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, installed, fixed string
		want                   assessment.Verdict
	}{
		{"supported below fix", "1.0-1", "2.0-1", assessment.Affected},
		{"supported equivalent fix", "1.0-1", "00:01.00-0001", assessment.Fixed},
		{"unsupported installed epoch", "2147483648:1", "2.0-1", assessment.NeedsReview},
		{"unsupported fixed epoch", "1.0-1", "2147483648:1", assessment.NeedsReview},
		{"unsupported installed colon", "1:1:2", "2.0-1", assessment.NeedsReview},
		{"unsupported fixed colon", "1.0-1", "1:1:2", assessment.NeedsReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, feed, now := reviewAssessmentFixture(t, tc.fixed, nil)
			inv.Packages[0].SourceVersion = tc.installed
			inv.Packages[0].Origin.SourceVersion = tc.installed
			result := assessment.AssessDebian(context.Background(), inv, feed, debianversion.Comparator{}, now)
			if len(result.Matches) != 1 || result.Matches[0].Verdict != tc.want || result.Matches[0].InstalledSourceVersion != tc.installed {
				t.Fatal("existing matcher changed comparison meaning or erased installed version")
			}
			if tc.want == assessment.NeedsReview && (result.Quality.Coverage != assessment.Partial || result.AffectedCVEs != nil ||
				result.Matches[0].Basis != "candidate_only" || result.Matches[0].Reason != "debian_comparison_failed") {
				t.Fatal("comparison limitation became authoritative equality, unaffected status, or exact zero")
			}
		})
	}
}

type versionReviewContext struct {
	context.Context
	cancel context.CancelFunc
	polls  int
	stopAt int
}

func (c *versionReviewContext) Err() error {
	c.polls++
	if c.polls == c.stopAt {
		c.cancel()
	}
	return c.Context.Err()
}

func TestIndependentDebianVersionContextAndBoundedWork(t *testing.T) {
	comparator := debianversion.Comparator{}
	got, err := comparator.Compare(nil, "1", "1")
	if got != 0 || !errors.Is(err, debianversion.ErrContextRequired) {
		t.Fatal("nil context silently disabled cancellation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = comparator.Compare(ctx, "invalid", "invalid")
	if got != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancelled input lost its context error")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	got, err = comparator.Compare(ctx, "1", "1")
	if got != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired context returned equality")
	}
	for _, input := range []string{
		strings.Repeat("9", debianversion.MaxVersionBytes),
		strings.Repeat("0", debianversion.MaxVersionBytes-2) + ":1",
		"1" + strings.Repeat("a0", 255) + "a",
		"1-" + strings.Repeat("~", debianversion.MaxVersionBytes-2),
	} {
		underlying, cancel := context.WithCancel(context.Background())
		full := &versionReviewContext{Context: underlying, cancel: cancel}
		got, err := comparator.Compare(full, input, input)
		cancel()
		// A deliberately loose linear polling budget is a regression check,
		// not a wall-clock promise or an effect-system proof.
		if got != 0 || err != nil || full.polls <= len(input) || full.polls > 16*(2*len(input))+64 {
			t.Fatal("maximum-size comparison lost its bounded polling contract")
		}
		for _, stopAt := range []int{2, len(input), len(input) + 2, full.polls / 2, full.polls} {
			underlying, cancel := context.WithCancel(context.Background())
			interrupted := &versionReviewContext{Context: underlying, cancel: cancel, stopAt: stopAt}
			got, err := comparator.Compare(interrupted, input, input)
			cancel()
			if got != 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation at poll %d/%d returned %d, %v", stopAt, full.polls, got, err)
			}
		}
	}
}

func TestIndependentDebianVersionPureDependencyBoundary(t *testing.T) {
	// A source regression tripwire, not a substitute for reviewing production
	// changes. Test-only imports and the opt-in literal oracle are excluded.
	dir := filepath.Join("..", "..", "internal", "debianversion")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("cannot inspect portable comparator source")
	}
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal("cannot parse portable comparator source")
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || imp.Name != nil || path != "context" && path != "errors" {
				t.Fatalf("review new or aliased production capability in %s", name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				t.Fatal("portable comparison gained a background goroutine")
			}
			if declaration, ok := node.(*ast.FuncDecl); ok && declaration.Recv == nil && declaration.Name.Name == "init" {
				t.Fatal("portable comparison gained package initialization behavior")
			}
			return true
		})
	}
	if files == 0 {
		t.Fatal("portable comparison production source missing")
	}
}
