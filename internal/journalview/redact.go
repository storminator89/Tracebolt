package journalview

import "regexp"

// Narrow heuristic masking is not a sanitizer or a guarantee of secrecy. Every
// snapshot carries the warning, including empty and failed observations.
var masks = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|$)`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`(?i)(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|token)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@:\s]+:[^/@\s]+@`), "${1}[REDACTED]@"},
}

func redact(s string) (string, bool) {
	original := s
	for _, m := range masks {
		s = m.re.ReplaceAllString(s, m.replacement)
	}
	return s, s != original
}
