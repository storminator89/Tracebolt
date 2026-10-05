package cachedupdates

import (
	"bufio"
	"context"
	"localrmm/internal/assessment"
	"strings"
	"unicode/utf8"
)

const maxCommandBytes = 8 << 20
const maxCommandLine = 64 << 10

// Parse only selected fixed fields; never retain repository URLs or raw stderr.
func parseInstalled(ctx context.Context, raw []byte) (map[string]installedPackage, error) {
	out := map[string]installedPackage{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), maxCommandLine)
	if len(raw) > maxCommandBytes || !utf8.Valid(raw) {
		return nil, sourceFailure(ReasonInvalidSource)
	}
	records := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		records++
		if records > 100000 {
			return nil, sourceFailure(ReasonWorkLimit)
		}
		f := strings.Split(scanner.Text(), "\t")
		if len(f) != 6 {
			return nil, sourceFailure(ReasonInvalidSource)
		}
		name := f[0]
		if base, arch, ok := strings.Cut(name, ":"); ok {
			if arch != f[2] {
				return nil, sourceFailure(ReasonInvalidSource)
			}
			name = base
		}
		if !packagePattern.MatchString(name) || !oneOf(f[3], "unknown", "install", "hold", "deinstall", "purge") || !oneOf(f[4], "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed") || !oneOf(f[5], "ok", "reinstreq") {
			return nil, sourceFailure(ReasonInvalidSource)
		}
		if f[4] != "installed" || f[5] != "ok" {
			continue
		}
		if !architecturePattern.MatchString(f[2]) || !assessment.ValidDebianVersion(f[1]) {
			return nil, sourceFailure(ReasonInvalidSource)
		}
		p := installedPackage{name: name, architecture: f[2], version: f[1], held: f[3] == "hold"}
		if _, ok := out[p.key()]; ok {
			return nil, sourceFailure(ReasonInvalidSource)
		}
		out[p.key()] = p
		if len(out) > MaxInstalledRows {
			return nil, sourceFailure(ReasonWorkLimit)
		}
	}
	if scanner.Err() != nil {
		return nil, sourceFailure(ReasonInvalidSource)
	}
	return out, nil
}
func parsePolicy(ctx context.Context, raw []byte, expected []installedPackage) (map[string]string, error) {
	bad := func() (map[string]string, error) { return nil, sourceFailure(ReasonInvalidSource) }
	if len(raw) > maxCommandBytes || !utf8.Valid(raw) {
		return bad()
	}
	byHeader := map[string]installedPackage{}
	for _, p := range expected {
		if !packagePattern.MatchString(p.name) || !architecturePattern.MatchString(p.architecture) || !assessment.ValidDebianVersion(p.version) {
			return bad()
		}
		if prior, ok := byHeader[p.name]; ok && prior.architecture != p.architecture {
			return bad()
		}
		byHeader[p.name] = p
		byHeader[p.key()] = p
	}
	out := map[string]string{}
	seen := map[string]bool{}
	current := installedPackage{}
	gotInstalled, gotCandidate := false, false
	flush := func() bool { return current.name == "" || gotInstalled && gotCandidate }
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), maxCommandLine)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.ContainsAny(line, "\x00\r") {
			return bad()
		}
		if line[0] != ' ' && line[0] != '\t' {
			if !flush() || !strings.HasSuffix(line, ":") {
				return bad()
			}
			var ok bool
			current, ok = byHeader[strings.TrimSuffix(line, ":")]
			if !ok || seen[current.key()] {
				return bad()
			}
			seen[current.key()] = true
			gotInstalled = false
			gotCandidate = false
			continue
		}
		if current.name == "" {
			return bad()
		}
		value := strings.TrimSpace(line)
		if strings.HasPrefix(value, "Installed:") {
			if gotInstalled || strings.TrimSpace(strings.TrimPrefix(value, "Installed:")) != current.version {
				return nil, sourceFailure(ReasonSourceChanged)
			}
			gotInstalled = true
		} else if strings.HasPrefix(value, "Candidate:") {
			if gotCandidate {
				return bad()
			}
			candidate := strings.TrimSpace(strings.TrimPrefix(value, "Candidate:"))
			if candidate == "(none)" {
				candidate = ""
			} else if !assessment.ValidDebianVersion(candidate) {
				return bad()
			}
			out[current.key()] = candidate
			gotCandidate = true
		}
	}
	if scanner.Err() != nil || !flush() {
		return bad()
	}
	// Missing blocks are unknown, not an empty successful all-current result.
	return out, nil
}
func oneOf(s string, choices ...string) bool {
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}
