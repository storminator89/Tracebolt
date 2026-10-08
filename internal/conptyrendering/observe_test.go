package conptyrendering

import (
	"fmt"
	"strings"
	"testing"
)

func TestFamiliesEverySplit(t *testing.T) {
	p := "\x1b[2J\x1b[1;1H\x1b[?25l\x1b[0mPUBLIC\r\n\x1b]0;public\x07\x1b[?25h"
	want := Summary{CursorPosition: true, Clear: true, CursorVisibility: true, Presentation: true, Title: true}
	for i := 0; i <= len(p); i++ {
		var o Observer
		o.Feed([]byte(p[:i]))
		o.Feed([]byte(p[i:]))
		if o.Finish() != want {
			t.Fatal("classification_mismatch")
		}
	}
	var o Observer
	for i := range p {
		o.Feed([]byte{p[i]})
	}
	if o.Finish() != want {
		t.Fatal("classification_mismatch")
	}
}
func TestUnknownAndBounds(t *testing.T) {
	for _, p := range []string{"\x1b[?1000h", "\x1b]52;public\a", "\t", "\x1bX", "\x1b]0;\x01"} {
		var o Observer
		o.Feed([]byte(p))
		if !o.Finish().Unknown {
			t.Fatal("unknown_missing")
		}
	}
	for _, p := range []string{strings.Repeat("x", maxBytes+1), "\x1b[" + strings.Repeat("1", 65), "\x1b]" + strings.Repeat("x", 257)} {
		var o Observer
		o.Feed([]byte(p))
		if !o.Finish().Overflow {
			t.Fatal("overflow_missing")
		}
	}
	for _, p := range []string{"\x1b", "\x1b[1", "\x1b]0;public", "\x1b]0;public\x1b"} {
		var o Observer
		o.Feed([]byte(p))
		if !o.Finish().Incomplete {
			t.Fatal("incomplete_missing")
		}
		if o.n != 0 || o.sequence != [256]byte{} {
			t.Fatal("buffer_not_cleared")
		}
	}
}
func FuzzObserverBounded(f *testing.F) {
	f.Add([]byte("PUBLIC\r\n"))
	f.Fuzz(func(t *testing.T, p []byte) {
		var o Observer
		o.Feed(p)
		_ = o.Finish()
		if o.total > maxBytes || o.n != 0 || o.sequence != [256]byte{} {
			t.Fatal("bound_violation")
		}
	})
}

func TestObserverRedactsFormatting(t *testing.T) {
	var o Observer
	o.Feed([]byte("\x1b]0;PUBLIC_PRIVATE_BUFFER_SENTINEL"))
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, o), "SENTINEL") || strings.Contains(fmt.Sprintf(format, &o), "SENTINEL") {
			t.Fatal("format_disclosure")
		}
	}
}

func TestFinishKeepsIncompleteSticky(t *testing.T) {
	var o Observer
	o.Feed([]byte("\x1b[1"))
	first := o.Finish()
	if !first.Incomplete || o.Finish() != first {
		t.Fatal("incomplete_not_sticky")
	}
}
