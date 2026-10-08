// Package conptyrendering classifies bounded public terminal rendering. It is
// not an acceptance parser, terminal emulator, or source of security approval.
package conptyrendering

import (
	"bytes"
	"fmt"
	"io"
)

const maxBytes = 64 << 10

// ResidualKind is a fixed category, never a terminal byte or parameter.
type ResidualKind string

const (
	ResidualNone        ResidualKind = "none"
	ResidualTextControl ResidualKind = "text_control"
	ResidualNonASCII    ResidualKind = "non_ascii"
	ResidualEscape      ResidualKind = "escape"
	ResidualCSI         ResidualKind = "csi"
	ResidualOSC         ResidualKind = "osc"
)

// Summary contains only finite observations, never terminal bytes or parameters.
type Summary struct {
	CursorPosition, Clear, CursorVisibility, Presentation, Title                     bool
	Unknown, Overflow, Incomplete                                                    bool
	Win32InputEnable, Win32InputDisable, FocusReportingEnable, FocusReportingDisable bool
	ResidualUnknown                                                                  bool
	FirstResidualKind                                                                ResidualKind
	LiveOutput, PublicTrust, ExactPrompt, PromptWithoutFinalSpace                    bool
}

// Observer retains at most 256 sequence bytes and a 4096-byte current public
// text line; no output accessor exists.
// Calls must be serialized. It classifies families, not sequence semantics.
type Observer struct {
	result   Summary
	total    int
	state    byte
	sequence [256]byte
	n        int
	public   publicTextObservation
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
			o.public.consume(c)
			if c == 27 {
				o.state = 1
			} else if c >= 0x80 {
				o.markResidual(ResidualNonASCII)
			} else if (c < 32 && c != '\r' && c != '\n') || c == 127 {
				o.markResidual(ResidualTextControl)
			}
		case 1:
			switch c {
			case '[':
				o.state = 2
			case ']':
				o.state = 3
			default:
				o.markResidual(ResidualEscape)
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
					} else if bytes.Equal(o.sequence[:o.n], []byte("?9001")) {
						// Historical Unknown remains true: these are outside
						// the original family set, now precisely classified.
						o.result.Unknown = true
						if c == 'h' {
							o.result.Win32InputEnable = true
						} else {
							o.result.Win32InputDisable = true
						}
					} else if bytes.Equal(o.sequence[:o.n], []byte("?1004")) {
						o.result.Unknown = true
						if c == 'h' {
							o.result.FocusReportingEnable = true
						} else {
							o.result.FocusReportingDisable = true
						}
					} else {
						o.markResidual(ResidualCSI)
					}
				default:
					o.markResidual(ResidualCSI)
				}
				o.reset()
			} else if c < 0x20 || c > 0x3f {
				o.markResidual(ResidualCSI)
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
				o.markResidual(ResidualOSC)
				o.reset()
				o.state = 5
			} else {
				o.append(c, len(o.sequence))
			}
		case 4:
			if c == '\\' {
				o.endOSC()
			} else {
				o.markResidual(ResidualOSC)
				o.reset()
				if c == 27 {
					o.state = 6
				} else if c != 7 {
					o.state = 5
				}
			}
		case 5: // Discard malformed OSC content until its terminator.
			if c == 7 {
				o.reset()
			} else if c == 27 {
				o.state = 6
			}
		case 6:
			if c == '\\' || c == 7 {
				o.reset()
			} else if c != 27 {
				o.state = 5
			}
		}
	}
}

func (o *Observer) markResidual(kind ResidualKind) {
	o.result.Unknown = true
	if !o.result.ResidualUnknown {
		o.result.FirstResidualKind = kind
	}
	o.result.ResidualUnknown = true
}

func (o *Observer) append(c byte, limit int) {
	if o.n == limit {
		o.result.Overflow = true
		inOSC := o.state == 3
		o.reset()
		if inOSC {
			o.state = 5
		}
		return
	}
	o.sequence[o.n] = c
	o.n++
}
func (o *Observer) endOSC() {
	if o.n >= 2 && (o.sequence[0] == '0' || o.sequence[0] == '2') && o.sequence[1] == ';' {
		o.result.Title = true
	} else {
		o.markResidual(ResidualOSC)
	}
	o.reset()
}
func (o *Observer) reset() { clear(o.sequence[:]); o.n = 0; o.state = 0 }
func (o *Observer) Finish() Summary {
	o.result.Incomplete = o.result.Incomplete || o.state != 0
	o.reset()
	result := o.result
	if !result.ResidualUnknown {
		result.FirstResidualKind = ResidualNone
	}
	return result
}

// Format prevents accidental dumping of the bounded private sequence buffer.
func (Observer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "conptyrendering.Observer{redacted}")
}
