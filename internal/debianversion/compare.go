// Package debianversion implements a bounded, pure Debian version ordering
// primitive. It does not establish package origin, update availability, source
// mapping, installability, vulnerability status, or release applicability.
package debianversion

import (
	"context"
	"errors"
)

// MaxVersionBytes bounds each complete input, including epoch and revision.
const MaxVersionBytes = 512

// maxEpoch is a deliberate supported-subset bound, not a Debian Policy limit.
const maxEpoch = "2147483647"

var (
	ErrVersionInvalid     = errors.New("debian_version_invalid")
	ErrVersionUnsupported = errors.New("debian_version_unsupported")
	ErrEpochUnsupported   = errors.New("debian_epoch_unsupported")
	ErrContextRequired    = errors.New("debian_context_required")
)

// Comparator is stateless and safe for concurrent use. Its zero value is ready
// to use. The method shape satisfies assessment.VersionComparator without
// importing or registering with assessment or any runtime component.
type Comparator struct{}

// Compare returns only -1, 0, or 1 on success, and always 0 on error. Both inputs
// must pass the supported grammar and bounds, even if an earlier component or
// byte-for-byte equality would otherwise determine the result. A nil context is
// rejected; observed cancellation/deadline errors are returned unchanged.
func (Comparator) Compare(ctx context.Context, a, b string) (int, error) {
	if ctx == nil {
		return 0, ErrContextRequired
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	left, err := parse(ctx, a)
	if err != nil {
		return 0, err
	}
	right, err := parse(ctx, b)
	if err != nil {
		return 0, err
	}
	order, err := compareDecimal(ctx, left.epoch, right.epoch)
	if err == nil && order == 0 {
		order, err = comparePart(ctx, left.upstream, right.upstream)
	}
	if err == nil && order == 0 {
		order, err = comparePart(ctx, left.revision, right.revision)
	}
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return order, nil
}

type version struct {
	epoch    string
	upstream string
	revision string
}

func parse(ctx context.Context, input string) (version, error) {
	if len(input) == 0 || len(input) > MaxVersionBytes {
		return version{}, ErrVersionInvalid
	}
	colon, lastColon, hyphen := -1, -1, -1
	for i := 0; i < len(input); i++ {
		if err := ctx.Err(); err != nil {
			return version{}, err
		}
		c := input[i]
		switch {
		case digit(c), letter(c), c == '.', c == '+', c == '~':
		case c == '-':
			hyphen = i
		case c == ':':
			if colon == -1 {
				colon = i
			}
			lastColon = i
		default:
			return version{}, ErrVersionInvalid
		}
	}
	result := version{epoch: "0", revision: "0"}
	start := 0
	if colon >= 0 {
		if colon == 0 {
			return version{}, ErrVersionInvalid
		}
		for i := 0; i < colon; i++ {
			if err := ctx.Err(); err != nil {
				return version{}, err
			}
			if !digit(input[i]) {
				return version{}, ErrVersionInvalid
			}
		}
		result.epoch = input[:colon]
		start = colon + 1
	}
	end := len(input)
	if hyphen >= 0 {
		if hyphen < start || hyphen == len(input)-1 {
			return version{}, ErrVersionInvalid
		}
		end = hyphen
		result.revision = input[hyphen+1:]
	}
	if start == end || !digit(input[start]) || lastColon >= end {
		return version{}, ErrVersionInvalid
	}
	result.upstream = input[start:end]
	// The source parser and dpkg manual permit extra colons in the upstream
	// component. That metadata is outside this strict comparison subset, not
	// necessarily malformed installed-package metadata. Colons in a revision
	// are rejected above, before this supported-subset distinction.
	if lastColon != colon {
		return version{}, ErrVersionUnsupported
	}
	order, err := compareDecimal(ctx, result.epoch, maxEpoch)
	if err != nil {
		return version{}, err
	}
	if order > 0 {
		return version{}, ErrEpochUnsupported
	}
	return result, nil
}

// comparePart follows the alternating non-digit / decimal-run steps of Debian
// Policy section 5.6.12. It consumes slices, never integer-parses digit runs.
func comparePart(ctx context.Context, a, b string) (int, error) {
	for len(a) != 0 || len(b) != 0 {
		textA, restA, err := takeRun(ctx, a, false)
		if err != nil {
			return 0, err
		}
		textB, restB, err := takeRun(ctx, b, false)
		if err != nil {
			return 0, err
		}
		order, err := compareText(ctx, textA, textB)
		if err != nil || order != 0 {
			return order, err
		}
		numberA, restA, err := takeRun(ctx, restA, true)
		if err != nil {
			return 0, err
		}
		numberB, restB, err := takeRun(ctx, restB, true)
		if err != nil {
			return 0, err
		}
		order, err = compareDecimal(ctx, numberA, numberB)
		if err != nil || order != 0 {
			return order, err
		}
		a, b = restA, restB
	}
	return 0, nil
}

func takeRun(ctx context.Context, input string, numeric bool) (string, string, error) {
	i := 0
	for i < len(input) && digit(input[i]) == numeric {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		i++
	}
	return input[:i], input[i:], nil
}

func compareText(ctx context.Context, a, b string) (int, error) {
	for i := 0; i < len(a) || i < len(b); i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		left, right := textRank(a, i), textRank(b, i)
		if left < right {
			return -1, nil
		}
		if left > right {
			return 1, nil
		}
	}
	return 0, nil
}

func textRank(input string, index int) int {
	if index >= len(input) {
		return 0
	}
	c := input[index]
	if c == '~' {
		return -1
	}
	if letter(c) {
		return int(c)
	}
	return 128 + int(c)
}

func compareDecimal(ctx context.Context, a, b string) (int, error) {
	var err error
	a, err = significant(ctx, a)
	if err != nil {
		return 0, err
	}
	b, err = significant(ctx, b)
	if err != nil {
		return 0, err
	}
	if len(a) < len(b) {
		return -1, nil
	}
	if len(a) > len(b) {
		return 1, nil
	}
	for i := 0; i < len(a); i++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if a[i] < b[i] {
			return -1, nil
		}
		if a[i] > b[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func significant(ctx context.Context, input string) (string, error) {
	i := 0
	for i < len(input) && input[i] == '0' {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		i++
	}
	return input[i:], nil
}

func digit(c byte) bool { return c >= '0' && c <= '9' }
func letter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
