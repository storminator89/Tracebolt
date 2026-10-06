//go:build linux

package cachedupdates

import "strings"

// maskInactiveDebianDefaults recognizes only the three flat scalar defaults
// emitted by Debian's installer and apt-listchanges. apt-cache policy neither
// mounts installation media nor invokes dpkg's pre-install hooks. These keys do
// not redirect the APT configuration, package lists, status or preferences.
//
// This is deliberately not a general APT parser. The bounded grammar accepts
// bare keys, quoted literal values, lists, scopes and line comments. It masks
// only a recognized top-level key after checking its exact value and statement
// terminator. Everything else remains subject to the original conservative
// directory-token gate, including comments and strings. Unrecognized syntax,
// escapes, block comments and deeper/nested alternatives fail closed.
func maskInactiveDebianDefaults(raw []byte) ([]byte, bool) {
	p := aptDefaultParser{raw: raw, masked: append([]byte(nil), raw...)}
	return p.masked, p.scope(0)
}

type aptDefaultParser struct {
	raw, masked []byte
	pos         int
}

func (p *aptDefaultParser) space() {
	for p.pos < len(p.raw) {
		if strings.ContainsRune(" \t\r\n", rune(p.raw[p.pos])) {
			p.pos++
		} else if p.raw[p.pos] == '#' || p.pos+1 < len(p.raw) && string(p.raw[p.pos:p.pos+2]) == "//" {
			for p.pos < len(p.raw) && p.raw[p.pos] != '\n' {
				p.pos++
			}
		} else {
			return
		}
	}
}

func (p *aptDefaultParser) take(ch byte) bool {
	p.space()
	if p.pos == len(p.raw) || p.raw[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

func (p *aptDefaultParser) literal() (string, bool) {
	if !p.take('"') {
		return "", false
	}
	start := p.pos
	for p.pos < len(p.raw) && p.raw[p.pos] != '"' {
		ch := p.raw[p.pos]
		if ch < 0x20 || ch > 0x7e || ch == '\\' {
			return "", false
		}
		p.pos++
	}
	if p.pos == len(p.raw) {
		return "", false
	}
	value := string(p.raw[start:p.pos])
	p.pos++
	return value, true
}

func (p *aptDefaultParser) scope(depth int) bool {
	if depth > 32 {
		return false
	}
	for {
		p.space()
		if p.pos == len(p.raw) {
			return depth == 0
		}
		if p.raw[p.pos] == '}' {
			p.pos++
			return depth > 0 && p.take(';')
		}
		if p.raw[p.pos] == '"' {
			if _, ok := p.literal(); !ok || depth == 0 || !p.take(';') {
				return false
			}
			continue
		}
		start := p.pos
		for p.pos < len(p.raw) {
			ch := p.raw[p.pos]
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("_:-/.", rune(ch))) {
				break
			}
			p.pos++
		}
		end := p.pos
		if start == end {
			return false
		}
		key := strings.ToLower(string(p.raw[start:end]))
		if p.take('{') {
			if !p.scope(depth + 1) {
				return false
			}
			continue
		}
		value, ok := p.literal()
		if !ok || !p.take(';') {
			return false
		}
		if depth == 0 && inactiveDebianDefault(key, value) {
			for i := start; i < end; i++ {
				p.masked[i] = '_'
			}
		}
	}
}

func inactiveDebianDefault(key, value string) bool {
	switch key {
	case "dir::media::mountpath":
		return value == "/media/cdrom"
	case "dir::etc::apt-listchanges-main":
		return value == "listchanges.conf"
	case "dir::etc::apt-listchanges-parts":
		return value == "listchanges.conf.d"
	default:
		return false
	}
}
