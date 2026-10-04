//go:build debianversion_oracle

package debianversion

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestCompareDpkgOracle is excluded from ordinary builds and tests. Its separate
// environment opt-in prevents a broad tagged test run from starting commands.
// It passes only the checked-in literalCases to a fixed compare-only action;
// no inventory, package database, APT, install or advisory operation is used.
func TestCompareDpkgOracle(t *testing.T) {
	if os.Getenv("TRACEBOLT_DPKG_VERSION_ORACLE") != "1" {
		t.Skip("set TRACEBOLT_DPKG_VERSION_ORACLE=1 for the synthetic-only native oracle")
	}
	info, err := os.Lstat("/usr/bin/dpkg")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("fixed native oracle unavailable; no fallback or installation")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		t.Fatal("fixed native oracle must be a regular executable without group/world write access")
	}
	if len(literalCases) > 64 {
		t.Fatal("oracle literal corpus exceeds its 64-pair budget")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, tc := range literalCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (Comparator{}).Compare(ctx, tc.a, tc.b)
			if err != nil || got != tc.want {
				t.Fatalf("pure literal fixture failed: got %d, %v; want %d", got, err, tc.want)
			}
			pairCtx, pairCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer pairCancel()
			less := nativeLiteralPredicate(t, pairCtx, tc.a, "lt", tc.b)
			greater := nativeLiteralPredicate(t, pairCtx, tc.a, "gt", tc.b)
			if less && greater {
				t.Fatal("native predicates are inconsistent")
			}
			want := 0
			if less {
				want = -1
			} else if greater {
				want = 1
			}
			if got != want {
				t.Fatalf("literal %q vs %q: pure %d, native %d", tc.a, tc.b, got, want)
			}
		})
		if ctx.Err() != nil {
			t.Fatal("native oracle exceeded its total deadline")
		}
	}
}

func nativeLiteralPredicate(t *testing.T, ctx context.Context, a, operator, b string) bool {
	t.Helper()
	command := exec.CommandContext(ctx, "/usr/bin/dpkg", "--compare-versions", a, operator, b)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = 100 * time.Millisecond
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("native literal comparison timed out or was canceled")
	}
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false
	}
	t.Fatal("native literal comparison failed")
	return false
}
