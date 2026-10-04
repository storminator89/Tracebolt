package linuxpackages

import (
	"context"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxOSReleaseBytes = 64 << 10
	MaxOSReleaseLine  = 4 << 10 // Bytes before LF, inclusive of any whitespace.
	MaxOSReleaseKeys  = 256
	MaxReleaseValue   = 128
	maxReleaseKey     = 128
)

var (
	ErrReleaseInvalid = errors.New("os_release_invalid")
	ErrReleaseLimit   = errors.New("os_release_limit_exceeded")
	ErrReleaseRead    = errors.New("os_release_read_failed")
)

// ParseOSRelease reads at most MaxOSReleaseBytes+1 bytes from a supplied reader.
// It does not open files or evaluate shell expressions. It accepts literal
// assignment syntax and rejects duplicates (a deliberate fail-closed departure
// from os-release's last-entry recovery recommendation). Unknown field values
// are syntax checked, then discarded. Any failure discards all selected fields.
// The caller must bound a reader's blocking time; context cannot interrupt Read.
func ParseOSRelease(ctx context.Context, r io.Reader) (ReleaseFields, error) {
	if r == nil || ctx.Err() != nil {
		return ReleaseFields{}, ErrReleaseRead
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: r}, MaxOSReleaseBytes+1))
	if len(data) > MaxOSReleaseBytes {
		return ReleaseFields{}, ErrReleaseLimit
	}
	if err != nil || ctx.Err() != nil {
		return ReleaseFields{}, ErrReleaseRead
	}
	if !utf8.Valid(data) {
		return ReleaseFields{}, ErrReleaseInvalid
	}
	for _, ch := range string(data) {
		if !unicode.IsPrint(ch) && ch != '\n' && ch != '\t' {
			return ReleaseFields{}, ErrReleaseInvalid
		}
	}
	result := ReleaseFields{}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if ctx.Err() != nil {
			return ReleaseFields{}, ErrReleaseRead
		}
		if len(line) > MaxOSReleaseLine {
			return ReleaseFields{}, ErrReleaseLimit
		}
		line = strings.Trim(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !validReleaseKey(key) || seen[key] {
			return ReleaseFields{}, ErrReleaseInvalid
		}
		if len(seen) >= MaxOSReleaseKeys {
			return ReleaseFields{}, ErrReleaseLimit
		}
		seen[key] = true
		value, ok := releaseLiteral(raw)
		if !ok {
			return ReleaseFields{}, ErrReleaseInvalid
		}
		var selected **string
		switch key {
		case "ID":
			selected = &result.ID
		case "VERSION_ID":
			selected = &result.VersionID
		case "VERSION_CODENAME":
			selected = &result.VersionCodename
		default:
			continue
		}
		if len(value) > MaxReleaseValue {
			return ReleaseFields{}, ErrReleaseLimit
		}
		if !validReleaseIdentifier(value) {
			return ReleaseFields{}, ErrReleaseInvalid
		}
		*selected = &value
	}
	return result, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func validReleaseKey(key string) bool {
	if len(key) == 0 || len(key) > maxReleaseKey {
		return false
	}
	for i, ch := range key {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || i > 0 && ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func validReleaseIdentifier(value string) bool {
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

// releaseLiteral supports one unquoted, single-quoted, or double-quoted literal.
// Shell expansion, concatenation, inline comments, and multiline values are
// intentionally unsupported. Double quotes use shell's restricted escapes.
func releaseLiteral(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	quote := byte(0)
	if raw[0] == '\'' || raw[0] == '"' {
		quote = raw[0]
		if len(raw) < 2 || raw[len(raw)-1] != quote {
			return "", false
		}
		raw = raw[1 : len(raw)-1]
	}
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if quote == '\'' {
			if ch == '\'' {
				return "", false
			}
			out.WriteByte(ch)
			continue
		}
		if ch == '\\' {
			if i+1 == len(raw) {
				return "", false
			}
			i++
			next := raw[i]
			if quote == '"' && !strings.ContainsRune("$`\"\\", rune(next)) {
				// A backslash before an ordinary character stays literal in a
				// double-quoted shell value. Selected identifiers reject it.
				out.WriteByte('\\')
			}
			out.WriteByte(next)
			continue
		}
		if ch == '$' || ch == '`' || ch == '"' || quote == 0 && strings.ContainsRune(" \t;'|&<>(){}#*?[]~", rune(ch)) {
			return "", false
		}
		out.WriteByte(ch)
	}
	return out.String(), true
}
