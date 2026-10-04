package debianversion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Only synthetic literal inputs are listed here. The optional native oracle
// uses this corpus only; generated, fuzzed, invalid and external input never
// becomes a native command argument.
var literalCases = []struct {
	name string
	a, b string
	want int
}{
	{"equal", "1.2.3-4", "1.2.3-4", 0},
	{"epoch dominates upstream", "1:1.0-1", "9.0-99", 1},
	{"epoch numeric", "2:1-1", "10:0-1", -1},
	{"explicit zero epoch", "0:1.0", "1.0", 0},
	{"epoch leading zeros", "0002:1.0", "2:1.0", 0},
	{"maximum supported epoch", "2147483647:0", "2147483646:9", 1},
	{"maximum epoch leading zeros", "0002147483647:0", "2147483647:0", 0},
	{"upstream numeric", "1.9", "1.10", -1},
	{"numeric rather than lexical", "10", "2", 1},
	{"upstream before revision", "2.0-1", "1.99-999", 1},
	{"revision numeric", "1.0-2", "1.0-10", -1},
	{"missing revision zero", "1.0", "1.0-0", 0},
	{"missing revision many zeros", "1.0", "1.0-000", 0},
	{"missing revision before one", "1.0", "1.0-1", -1},
	{"zero revision before suffix", "1.0", "1.0-0+b1", -1},
	{"missing revision after tilde", "1.0", "1.0-~", 1},
	{"leading upstream zeros", "0001.002", "1.2", 0},
	{"leading revision zeros", "1-0002", "1-2", 0},
	{"empty numeric tail is zero", "1a", "1a0", 0},
	{"zero numeric tail then letter", "1a0b", "1ab", -1},
	{"numeric tail after letter", "1a9", "1a10", -1},
	{"release candidate", "1.0~rc1-1", "1.0-1", -1},
	{"tilde before empty", "1~", "1", -1},
	{"repeated tilde", "1~~", "1~", -1},
	{"tilde prefix then letter", "1~~a", "1~", -1},
	{"repeated tilde then letter", "1~~", "1~~a", -1},
	{"tilde before zero tail", "1a~", "1a0", -1},
	{"empty before letter", "1", "1a", -1},
	{"uppercase before lowercase", "1Z", "1a", -1},
	{"letters before plus", "1z", "1+", -1},
	{"letters before dot", "1z", "1.", -1},
	{"plus before dot", "1+", "1.", -1},
	{"hyphen before dot", "1-0-1", "1.0-1", -1},
	{"plus before hyphen", "1+0-1", "1-0-1", -1},
	{"letter before hyphen", "1a-1", "1-0-1", -1},
	{"last hyphen separates revision", "1.0-alpha-2", "1.0-alpha-10", -1},
	{"repeated upstream hyphens", "1--1", "1--2", -1},
	{"revision letters allowed", "1-a", "1-b", -1},
	{"binary rebuild increment", "1.0-1+b1", "1.0-1+b2", -1},
	{"binary rebuild not stripped", "1.0-1+b1", "1.0-1", 1},
	{"stable suffix is literal", "1.0-1+deb13u1", "1.0-1+deb13u2", -1},
	{"backport before revision", "1.0-1~bpo13+1", "1.0-1", -1},
	{"vendor looking suffix is literal", "1.0-1ubuntu1", "1.0-1ubuntu2", -1},
	{"git suffix", "1.0+git1-1", "1.0-1", 1},
	{"not semantic version dots", "1.0", "1.0.0", -1},
	{"not semantic version build metadata", "1+build2", "1+build1", 1},
	{"rollback text is not stripped", "2.3+really2.2-1", "2.3-1", 1},
	{"large numeric run", "1.9999999999999999999999999999999999999999", "1.10000000000000000000000000000000000000000", -1},
	{"large revision run", "1-9999999999999999999999999999999999999999", "1-10000000000000000000000000000000000000000", -1},
	{"equal long padded run", "1.0000000000000000000000000000000000000001", "1.1", 0},
	{"numeric differing last digit", "1.9999999999999999999999999999999999999998", "1.9999999999999999999999999999999999999999", -1},
}

var _ interface {
	Compare(context.Context, string, string) (int, error)
} = Comparator{}

func TestCompareFixtures(t *testing.T) {
	for _, tc := range literalCases {
		t.Run(tc.name, func(t *testing.T) {
			assertOrder(t, tc.a, tc.b, tc.want)
			assertOrder(t, tc.b, tc.a, -tc.want)
			assertOrder(t, tc.a, tc.a, 0)
		})
	}
}

func assertOrder(t *testing.T, a, b string, want int) {
	t.Helper()
	got, err := (Comparator{}).Compare(context.Background(), a, b)
	if err != nil || got != want {
		t.Fatalf("Compare(%q, %q) = %d, %v; want %d, nil", a, b, got, err, want)
	}
}

func TestCompareInvalidInputs(t *testing.T) {
	cases := []string{
		"", " ", "1 ", " 1", "1\t", "1\n", "1\r", "1\x00", "1\x7f", "1\xff",
		"1\u00e9", "\u0661.0", "a1", ".1", "+1", "~1", "-1", "--help",
		"1_0", "1/0", "1\\0", "1;0", "1=0", "1#0", "1*0", "1?0", "1$0",
		"1(0)", "1[0]", "1{0}", "1@0", "1%0", "1!0", "1^0", "1,0", "1&0",
		"1|0", "1<0", "1>0", "1\"0", "1'0", "1`0",
		":1", "1:", "a:1", "+1:1", "-1:1", "1.0:1", "1~0:1", "1:abc",
		"1:1-2:3", "1::1", "1-", "1:1-",
		strings.Repeat("1", MaxVersionBytes+1),
		strings.Repeat("0", MaxVersionBytes-1) + ":1",
	}
	for _, input := range cases {
		for _, pair := range [][2]string{{input, "1"}, {"1", input}, {input, input}} {
			got, err := (Comparator{}).Compare(context.Background(), pair[0], pair[1])
			if got != 0 || !errors.Is(err, ErrVersionInvalid) {
				t.Fatalf("invalid input %q: got %d, %v", input, got, err)
			}
			if err.Error() != "debian_version_invalid" {
				t.Fatal("invalid-input diagnostic must be a fixed code")
			}
		}
	}
}

func TestCompareUnsupportedEpochs(t *testing.T) {
	for _, input := range []string{
		"2147483648:1", "4294967295:1", "4294967296:1", "18446744073709551616:1",
		"0002147483648:1", strings.Repeat("9", MaxVersionBytes-2) + ":1",
	} {
		for _, pair := range [][2]string{{input, "1"}, {"1", input}, {input, input}} {
			got, err := (Comparator{}).Compare(context.Background(), pair[0], pair[1])
			if got != 0 || !errors.Is(err, ErrEpochUnsupported) || err.Error() != "debian_epoch_unsupported" {
				t.Fatalf("unsupported epoch: got %d, %v", got, err)
			}
		}
	}
	// The range check must not hide malformed grammar in the same operand.
	for _, input := range []string{"2147483648:", "2147483648:x", "2147483648:1-", "2147483648:1-1:2"} {
		got, err := (Comparator{}).Compare(context.Background(), input, "1")
		if got != 0 || !errors.Is(err, ErrVersionInvalid) {
			t.Fatalf("malformed unsupported-epoch input: got %d, %v", got, err)
		}
	}
}

func TestCompareUnsupportedLegacyUpstreamColons(t *testing.T) {
	for _, input := range []string{"1:1:2", "0:1:", "2:1::2-1", "2147483648:1:2"} {
		for _, pair := range [][2]string{{input, "1"}, {"1", input}, {input, input}} {
			got, err := (Comparator{}).Compare(context.Background(), pair[0], pair[1])
			if got != 0 || !errors.Is(err, ErrVersionUnsupported) || err.Error() != "debian_version_unsupported" {
				t.Fatalf("legacy upstream colon: got %d, %v", got, err)
			}
		}
	}
}

func TestCompareBoundariesAndLongRuns(t *testing.T) {
	maxDigits := strings.Repeat("9", MaxVersionBytes)
	assertOrder(t, maxDigits, strings.Repeat("9", MaxVersionBytes-1), 1)
	assertOrder(t, maxDigits[:MaxVersionBytes-1]+"8", maxDigits, -1)
	assertOrder(t, strings.Repeat("0", MaxVersionBytes-1)+"1", "1", 0)
	assertOrder(t, strings.Repeat("0", MaxVersionBytes), "0", 0)
	assertOrder(t, strings.Repeat("0", MaxVersionBytes-2)+":1", "1", 0)
	assertOrder(t, "1-"+strings.Repeat("9", MaxVersionBytes-2), "1-"+strings.Repeat("9", MaxVersionBytes-3), 1)
	assertOrder(t, "1"+strings.Repeat("a", MaxVersionBytes-1), "1"+strings.Repeat("a", MaxVersionBytes-2), 1)
	assertOrder(t, "1"+strings.Repeat("~", MaxVersionBytes-1), "1"+strings.Repeat("~", MaxVersionBytes-2), -1)
	assertOrder(t, "1"+strings.Repeat("a0", 255)+"a", "1"+strings.Repeat("a0", 255)+"b", -1)
}

func TestCompareContext(t *testing.T) {
	got, err := (Comparator{}).Compare(nil, "1", "2")
	if got != 0 || !errors.Is(err, ErrContextRequired) {
		t.Fatalf("nil context: got %d, %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, pair := range [][2]string{{"1", "2"}, {"1", "1"}, {"", ""}} {
		got, err := (Comparator{}).Compare(ctx, pair[0], pair[1])
		if got != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled: got %d, %v", got, err)
		}
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	got, err = (Comparator{}).Compare(ctx, "1", "2")
	if got != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline: got %d, %v", got, err)
	}
}

// pollContext cancels deterministically at an observed poll, avoiding timing
// races, sleeps or extra goroutines in cancellation-path tests.
type pollContext struct {
	context.Context
	cancel context.CancelFunc
	polls  int
	stopAt int
}

func (c *pollContext) Err() error {
	c.polls++
	if c.polls == c.stopAt {
		c.cancel()
	}
	return c.Context.Err()
}

func newPollContext(stopAt int) *pollContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &pollContext{Context: ctx, cancel: cancel, stopAt: stopAt}
}

func TestCancellationDuringEveryPhase(t *testing.T) {
	for _, input := range []string{
		strings.Repeat("9", MaxVersionBytes),
		strings.Repeat("0", MaxVersionBytes-2) + ":1",
		"1" + strings.Repeat("a0", 255) + "a",
		"1-" + strings.Repeat("a", MaxVersionBytes-2),
	} {
		full := newPollContext(0)
		got, err := (Comparator{}).Compare(full, input, input)
		full.cancel()
		if err != nil || got != 0 || full.polls < len(input) {
			t.Fatalf("uninterrupted baseline: got %d, %v; %d polls", got, err, full.polls)
		}
		for _, stopAt := range []int{1, len(input) / 2, len(input) + 2, full.polls / 2, full.polls - 1, full.polls} {
			ctx := newPollContext(stopAt)
			got, err := (Comparator{}).Compare(ctx, input, input)
			ctx.cancel()
			if got != 0 || !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel at poll %d/%d: got %d, %v", stopAt, full.polls, got, err)
			}
		}
	}
}

func TestCancellationAtEveryShortInputPoll(t *testing.T) {
	const input = "000001:001aa000bbb000-000aa000bbb000"
	full := newPollContext(0)
	got, err := (Comparator{}).Compare(full, input, input)
	full.cancel()
	if err != nil || got != 0 {
		t.Fatalf("uninterrupted baseline: got %d, %v", got, err)
	}
	for stopAt := 1; stopAt <= full.polls; stopAt++ {
		ctx := newPollContext(stopAt)
		got, err := (Comparator{}).Compare(ctx, input, input)
		ctx.cancel()
		if got != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel at poll %d/%d: got %d, %v", stopAt, full.polls, got, err)
		}
	}
}

func TestBoundedOrderProperties(t *testing.T) {
	// A fixed finite corpus keeps normal test execution bounded. Compute each
	// pair once, then check transitivity without re-running the comparator.
	versions := []string{"0", "00", "0-0", "1", "01", "0:1", "1-0", "1-00", "1-~", "1-1", "1-a", "1:0", "2:0"}
	for _, tail := range []string{"~", "~~", "~a", "a", "a0", "a1", "b", "Z", "+", ".", "-0-1"} {
		for _, prefix := range []string{"1", "01", "2"} {
			versions = append(versions, prefix+tail)
		}
	}
	matrix := make([][]int, len(versions))
	for i, a := range versions {
		matrix[i] = make([]int, len(versions))
		for j, b := range versions {
			got, err := (Comparator{}).Compare(context.Background(), a, b)
			if err != nil || got < -1 || got > 1 {
				t.Fatalf("bounded corpus comparison failed: %d, %v", got, err)
			}
			matrix[i][j] = got
		}
		if matrix[i][i] != 0 {
			t.Fatal("reflexivity failed")
		}
	}
	for i := range versions {
		for j := range versions {
			if matrix[i][j] != -matrix[j][i] {
				t.Fatal("antisymmetry failed")
			}
			for k := range versions {
				if matrix[i][j] <= 0 && matrix[j][k] <= 0 && matrix[i][k] > 0 {
					t.Fatal("transitivity failed")
				}
				if matrix[i][j] == 0 && matrix[i][k] != matrix[j][k] {
					t.Fatal("ordering-equivalence substitution failed")
				}
			}
		}
	}
}

func FuzzCompareBounded(f *testing.F) {
	for _, tc := range literalCases {
		f.Add(tc.a, tc.b, "1")
	}
	f.Add("", "1:1:1", "\xff")
	f.Add("2147483648:1", "1", "2")
	f.Add(strings.Repeat("1", MaxVersionBytes+1), "1", "2")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		compare := func(left, right string) (int, error) {
			got, err := (Comparator{}).Compare(context.Background(), left, right)
			if got < -1 || got > 1 || err != nil && got != 0 {
				t.Fatal("invalid result/error contract")
			}
			if (len(left) > MaxVersionBytes || len(right) > MaxVersionBytes) && err == nil {
				t.Fatal("over-limit input accepted")
			}
			if err != nil && !errors.Is(err, ErrVersionInvalid) && !errors.Is(err, ErrEpochUnsupported) && !errors.Is(err, ErrVersionUnsupported) {
				t.Fatal("unexpected diagnostic")
			}
			return got, err
		}
		ab, abErr := compare(a, b)
		ba, baErr := compare(b, a)
		if (abErr == nil) != (baErr == nil) || abErr == nil && ab != -ba {
			t.Fatal("success symmetry or order antisymmetry failed")
		}
		if abErr != nil {
			return
		}
		aa, err := compare(a, a)
		if err != nil || aa != 0 {
			t.Fatal("reflexivity failed")
		}
		bc, bcErr := compare(b, c)
		ac, acErr := compare(a, c)
		if bcErr == nil && acErr == nil {
			if ab <= 0 && bc <= 0 && ac > 0 {
				t.Fatal("transitivity failed")
			}
			if ab == 0 && ac != bc {
				t.Fatal("ordering-equivalence substitution failed")
			}
		}
	})
}
