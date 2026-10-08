// Package conptyrendering classifies bounded public terminal rendering. It is
// not an acceptance parser, terminal emulator, or source of security approval.
package conptyrendering

import (
	"fmt"
	"io"
)

const maxBytes = 64 << 10

// Summary contains only finite observations, never terminal bytes or parameters.
type Summary struct {
	CursorPosition, Clear, CursorVisibility, Presentation, Title bool
	Unknown, Overflow, Incomplete                                bool
}

// Observer retains at most 256 sequence bytes; no output accessor exists.
// Calls must be serialized. It classifies families, not sequence semantics.
type Observer struct {
	result   Summary
	total    int
	state    byte
	sequence [256]byte
	n        int
}

func (o *Observer) Feed(p []byte) {
	for _, c := range p {
		if o.total == maxBytes {
			o.result.Overflow = true
			return
		}
		o.total++
		switch o.state {
		case 0:
			if c == 27 {
				o.state = 1
			} else if (c < 32 && c != '\r' && c != '\n') || c > 126 {
				o.result.Unknown = true
			}
		case 1:
			switch c {
			case '[':
				o.state = 2
			case ']':
				o.state = 3
			default:
				o.result.Unknown = true
				o.reset()
			}
		case 2:
			if c >= 0x40 && c <= 0x7e {
				switch c {
				case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'f', 'd':
					o.result.CursorPosition = true
				case 'J', 'K':
					o.result.Clear = true
				case 'm':
					o.result.Presentation = true
				case 'h', 'l':
					if o.n == 3 && o.sequence[0] == '?' && o.sequence[1] == '2' && o.sequence[2] == '5' {
						o.result.CursorVisibility = true
					} else {
						o.result.Unknown = true
					}
				default:
					o.result.Unknown = true
				}
				o.reset()
			} else if c < 0x20 || c > 0x3f {
				o.result.Unknown = true
				o.reset()
			} else {
				o.append(c, 64)
			}
		case 3:
			if c == 7 {
				o.endOSC()
			} else if c == 27 {
				o.state = 4
			} else if c < 32 || c > 126 {
				o.result.Unknown = true
				o.reset()
			} else {
				o.append(c, len(o.sequence))
			}
		case 4:
			if c == '\\' {
				o.endOSC()
			} else {
				o.result.Unknown = true
				o.reset()
			}
		}
	}
}

func (o *Observer) append(c byte, limit int) {
	if o.n == limit {
		o.result.Overflow = true
		o.reset()
		return
	}
	o.sequence[o.n] = c
	o.n++
}
func (o *Observer) endOSC() {
	if o.n >= 2 && (o.sequence[0] == '0' || o.sequence[0] == '2') && o.sequence[1] == ';' {
		o.result.Title = true
	} else {
		o.result.Unknown = true
	}
	o.reset()
}
func (o *Observer) reset() { clear(o.sequence[:]); o.n = 0; o.state = 0 }
func (o *Observer) Finish() Summary {
	o.result.Incomplete = o.result.Incomplete || o.state != 0
	o.reset()
	return o.result
}

// Format prevents accidental dumping of the bounded private sequence buffer.
func (Observer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "conptyrendering.Observer{redacted}")
}
