package assessment

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

var ErrVersionInvalid = errors.New("debian_version_invalid")
var ErrComparatorUnavailable = errors.New("debian_comparator_unavailable")

// ValidDebianVersion checks the Debian policy grammar; comparison itself is ONLY
// delegated to native dpkg or an explicitly injected Debian-aware comparator.
func ValidDebianVersion(version string) bool {
	if len(version) == 0 || len(version) > maxIdentityLength {
		return false
	}
	remainder := version
	if before, after, ok := strings.Cut(version, ":"); ok {
		if before == "" {
			return false
		}
		for _, c := range before {
			if c < '0' || c > '9' {
				return false
			}
		}
		remainder = after
	}
	if len(remainder) == 0 || remainder[0] < '0' || remainder[0] > '9' {
		return false
	}
	upstream := remainder
	if i := strings.LastIndexByte(remainder, '-'); i >= 0 {
		upstream = remainder[:i]
		revision := remainder[i+1:]
		if revision == "" {
			return false
		}
		for _, c := range revision {
			if !(alphaNumeric(c) || c == '.' || c == '+' || c == '~') {
				return false
			}
		}
	}
	for _, c := range upstream {
		if !(alphaNumeric(c) || c == '.' || c == '+' || c == '~' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}
func alphaNumeric(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

type NativeDebianComparator struct{}

// Compare has no configurable executable/arguments/environment, uses no shell,
// captures no subprocess output and shares one 500ms deadline across both calls.
// dpkg --compare-versions does not read or modify the package database.
func (NativeDebianComparator) Compare(ctx context.Context, a, b string) (int, error) {
	if !ValidDebianVersion(a) || !ValidDebianVersion(b) {
		return 0, ErrVersionInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	lt, err := nativeComparison(ctx, a, "lt", b)
	if err != nil {
		return 0, err
	}
	if lt {
		return -1, nil
	}
	gt, err := nativeComparison(ctx, a, "gt", b)
	if err != nil {
		return 0, err
	}
	if gt {
		return 1, nil
	}
	return 0, nil
}
func nativeComparison(ctx context.Context, a, operator, b string) (bool, error) {
	info, statErr := os.Lstat("/usr/bin/dpkg")
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return false, ErrComparatorUnavailable
	}
	command := exec.CommandContext(ctx, "/usr/bin/dpkg", "--compare-versions", a, operator, b)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = 100 * time.Millisecond
	err := command.Run()
	if ctx.Err() != nil {
		return false, ErrComparatorUnavailable
	}
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, ErrComparatorUnavailable
}
