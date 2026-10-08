package freshgate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

const (
	testFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testComparison  = "fedcba9876543210fedcba9876543210"
	testTrust       = "Device SPKI SHA-256: " + testFingerprint + "\r\nComparison: " + testComparison + "\r\n"
)

func newTestGuard(t *testing.T) (*OutputGuard, []byte) {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	secret := make([]byte, secretLength)
	base64.RawURLEncoding.Encode(secret, raw[:])
	clear(raw[:])
	g, err := NewOutputGuard(secret)
	if err != nil {
		t.Fatal("construct guard failed")
	}
	t.Cleanup(func() { g.Close(); clear(secret) })
	return g, secret
}

func feedPublic(t *testing.T, g *OutputGuard, text string) {
	t.Helper()
	if err := g.Feed([]byte(text)); err != nil {
		t.Fatal("public output rejected")
	}
}

func readyTestGuard(t *testing.T) *OutputGuard {
	t.Helper()
	g, _ := newTestGuard(t)
	feedPublic(t, g, testTrust+PublicPrompt)
	if !g.PromptReady() {
		t.Fatal("exact prompt not ready")
	}
	return g
}

func finishTestGuard(t *testing.T, g *OutputGuard) {
	t.Helper()
	if err := g.MarkInputSent(); err != nil {
		t.Fatal("input transition failed")
	}
	feedPublic(t, g, "\r\n"+SuccessMarker+"\r\n")
	if err := g.Finish(); err != nil {
		t.Fatal("complete stream rejected")
	}
}

func TestOutputGuardExactPublicFlowEveryChunkSplit(t *testing.T) {
	pre := "Manager: manager_public\r\nEnrollment: http://127.0.0.1:1\r\n" +
		"Public production disclosures are discarded.\r\n" + testTrust +
		"Compare the complete public fingerprint and comparison value in the manager before approving.\r\n" + PublicPrompt
	for split := 0; split <= len(pre); split++ {
		g, _ := newTestGuard(t)
		feedPublic(t, g, pre[:split])
		feedPublic(t, g, pre[split:])
		if !g.PromptReady() {
			t.Fatal("chunked exact prompt missing")
		}
		fp, code, ok := g.PublicTrust()
		if !ok || fp != testFingerprint || code != testComparison {
			t.Fatal("exact public trust missing")
		}
		finishTestGuard(t, g)
		assertSensitiveClear(t, g)
		g.Close()
	}
	post := "\r\n" + SuccessMarker + "\r\n"
	for split := 0; split <= len(post); split++ {
		g := readyTestGuard(t)
		if g.MarkInputSent() != nil {
			t.Fatal("input transition failed")
		}
		feedPublic(t, g, post[:split])
		feedPublic(t, g, post[split:])
		if g.Finish() != nil {
			t.Fatal("chunked exact marker missing")
		}
	}
}

func TestOutputGuardVTAndOneByteChunks(t *testing.T) {
	g, _ := newTestGuard(t)
	pre := "\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;public title\a" +
		"\x1b[32mDevice SPKI SHA-256: \x1b[0m" + testFingerprint + "\r\n" +
		"Compar\x1b]2;another title\x1b\\ison: " + testComparison + "\n" +
		"\x1b[1m" + PublicPrompt[:20] + "\x1b[22m" + PublicPrompt[20:] + "\x1b[?25h"
	for i := range pre {
		feedPublic(t, g, pre[i:i+1])
	}
	if !g.PromptReady() {
		t.Fatal("VT-normalized prompt missing")
	}
	if g.MarkInputSent() != nil {
		t.Fatal("input transition failed")
	}
	post := "\r\x1b[m\n\x1b[32m" + SuccessMarker + "\x1b[0m\r\n\x1b[?25h"
	for i := range post {
		feedPublic(t, g, post[i:i+1])
	}
	if g.Finish() != nil {
		t.Fatal("VT-normalized marker missing")
	}
}

func TestOutputGuardEchoEveryChunkSplit(t *testing.T) {
	for split := 0; split <= secretLength; split++ {
		g, secret := newTestGuard(t)
		err := g.Feed(secret[:split])
		if err == nil {
			err = g.Feed(secret[split:])
		}
		if err != ErrOutputEcho {
			t.Fatal("split synthetic echo not rejected")
		}
		assertSensitiveClear(t, g)
		if g.Feed([]byte("public")) != ErrOutputEcho {
			t.Fatal("echo failure was not sticky")
		}
	}
}

func TestOutputGuardEchoAcrossVTAndLines(t *testing.T) {
	for _, separator := range []string{"\x1b[0m", "\x1b[?25h", "\x1b]0;public\a", "\x1b]2;public\x1b\\", "\r\n"} {
		g, secret := newTestGuard(t)
		var stream []byte
		defer func() { clear(stream) }()
		for i, c := range secret {
			stream = append(stream, c)
			if i != len(secret)-1 {
				stream = append(stream, separator...)
			}
		}
		var err error
		for i := range stream {
			err = g.Feed(stream[i : i+1])
			if err != nil {
				break
			}
		}
		if err != ErrOutputEcho {
			t.Fatal("normalized synthetic echo not rejected")
		}
		assertSensitiveClear(t, g)
		clear(stream)
	}
}

func TestOutputGuardEchoInTitlePayload(t *testing.T) {
	g, secret := newTestGuard(t)
	feedPublic(t, g, "\x1b]0;")
	if g.Feed(secret) != ErrOutputEcho {
		t.Fatal("raw OSC secret echo not rejected")
	}
	assertSensitiveClear(t, g)
}

func TestOutputGuardEchoPrefixOverlap(t *testing.T) {
	secret := bytes.Repeat([]byte{'A'}, secretLength)
	defer clear(secret)
	g, err := NewOutputGuard(secret)
	if err != nil {
		t.Fatal("canonical repeated synthetic input rejected")
	}
	defer g.Close()
	partial := bytes.Repeat([]byte{'A'}, secretLength-1)
	defer clear(partial)
	if g.Feed(partial) != nil || g.Feed([]byte{'B'}) != nil || g.Feed(secret) != ErrOutputEcho {
		t.Fatal("overlapping echo matcher incorrect")
	}
}

func TestOutputGuardTrustRequiresExactWholeOrderedLines(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"fingerprint short", fingerprintLabel + testFingerprint[:63] + "\n"},
		{"fingerprint uppercase", fingerprintLabel + strings.ToUpper(testFingerprint) + "\n"},
		{"fingerprint suffix", fingerprintLabel + testFingerprint + "x\n"},
		{"fingerprint spacing", "Device SPKI SHA-256:" + testFingerprint + "\n"},
		{"comparison before fingerprint", comparisonLabel + testComparison + "\n"},
		{"comparison short", fingerprintLabel + testFingerprint + "\n" + comparisonLabel + testComparison[:31] + "\n"},
		{"comparison suffix", testTrust[:len(testTrust)-2] + "x\n"},
		{"duplicate fingerprint", testTrust + fingerprintLabel + testFingerprint + "\n"},
		{"conflicting fingerprint", testTrust + fingerprintLabel + strings.Repeat("b", 64) + "\n"},
		{"duplicate comparison", testTrust + comparisonLabel + testComparison + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newTestGuard(t)
			if g.Feed([]byte(tc.text)) == nil {
				t.Fatal("invalid public trust accepted")
			}
			if _, _, ok := g.PublicTrust(); ok || g.PromptReady() {
				t.Fatal("failed trust remained observable")
			}
			assertSensitiveClear(t, g)
		})
	}
	g, _ := newTestGuard(t)
	feedPublic(t, g, "prefix "+fingerprintLabel+testFingerprint+"\n"+"prefix "+comparisonLabel+testComparison+"\n")
	if _, _, ok := g.PublicTrust(); ok {
		t.Fatal("substring labels counted as public trust")
	}
	if g.Finish() == nil {
		t.Fatal("missing trust completed")
	}
	g, _ = newTestGuard(t)
	feedPublic(t, g, testTrust[:len(testTrust)-2])
	if _, _, ok := g.PublicTrust(); ok {
		t.Fatal("unterminated comparison counted")
	}
	feedPublic(t, g, "\r\n")
	if _, _, ok := g.PublicTrust(); !ok {
		t.Fatal("terminated comparison missing")
	}
}

func TestOutputGuardPromptAndMarkerNotSubstrings(t *testing.T) {
	for _, bad := range []string{"prefix " + PublicPrompt, PublicPrompt + "suffix", " " + PublicPrompt, PublicPrompt[:len(PublicPrompt)-1]} {
		g, _ := newTestGuard(t)
		feedPublic(t, g, testTrust+bad)
		if g.PromptReady() {
			t.Fatal("non-exact prompt accepted")
		}
		if g.MarkInputSent() == nil {
			t.Fatal("input allowed without exact prompt")
		}
	}
	for _, bad := range []string{"prefix " + SuccessMarker, SuccessMarker + "suffix", " " + SuccessMarker, SuccessMarker + " "} {
		g := readyTestGuard(t)
		if g.MarkInputSent() != nil {
			t.Fatal("input transition failed")
		}
		if g.Feed([]byte("\r\n"+bad+"\r\n")) == nil {
			t.Fatal("non-exact marker accepted")
		}
	}
	g := readyTestGuard(t)
	feedPublic(t, g, "suffix")
	if g.PromptReady() || g.MarkInputSent() == nil {
		t.Fatal("later prompt extension remained ready")
	}
}

func TestOutputGuardRejectsMisorderedOrDuplicatePhases(t *testing.T) {
	for _, text := range []string{PublicPrompt, SuccessMarker + "\n", testTrust + SuccessMarker + "\n", testTrust + PublicPrompt + "\n"} {
		g, _ := newTestGuard(t)
		if g.Feed([]byte(text)) == nil {
			t.Fatal("misordered phase accepted")
		}
	}
	g := readyTestGuard(t)
	if g.MarkInputSent() != nil || g.MarkInputSent() == nil {
		t.Fatal("duplicate input transition accepted")
	}
	g = readyTestGuard(t)
	if g.MarkInputSent() != nil {
		t.Fatal("input transition failed")
	}
	if g.Feed([]byte(SuccessMarker+"\n")) == nil {
		t.Fatal("marker joined to prompt accepted")
	}
	g = readyTestGuard(t)
	if g.MarkInputSent() != nil {
		t.Fatal("input transition failed")
	}
	feedPublic(t, g, "\n"+SuccessMarker+"\n")
	if g.Feed([]byte(SuccessMarker+"\n")) == nil {
		t.Fatal("duplicate marker accepted")
	}
}

func TestOutputGuardUnsupportedControlsFailClosed(t *testing.T) {
	cases := []struct{ name, input string }{
		{"bell", "\a"}, {"tab", "\t"}, {"backspace", "\b"}, {"nul", "\x00"},
		{"delete", "\x7f"}, {"C1 CSI", "\x9b"}, {"non ASCII", "\xc3\xa9"},
		{"cursor move", "\x1b[1A"}, {"cursor save", "\x1b7"},
		{"DCS", "\x1bPdata\x1b\\"}, {"alternate screen", "\x1b[?1049h"},
		{"erase after text", "public\x1b[2J"}, {"home after text", "public\x1b[H"},
		{"line erase", "\x1b[K"}, {"bare overwrite", "public\rchanged"},
		{"repeated CR", "\r\r"}, {"conceal", "\x1b[8m"}, {"unknown SGR", "\x1b[999m"},
		{"extended color", "\x1b[38;2;1;2;3m"}, {"malformed CSI", "\x1b[0\x1b[m"},
		{"OSC hyperlink", "\x1b]8;;https://example.test\a"}, {"OSC clipboard", "\x1b]52;c;AAAA\a"},
		{"malformed OSC escape", "\x1b]0;title\x1b[m"}, {"OSC newline", "\x1b]0;title\n"},
		{"CSI overflow", "\x1b[" + strings.Repeat(";", maxCSI+1)},
		{"OSC overflow", "\x1b]0;" + strings.Repeat("x", maxOSC)},
		{"line overflow", strings.Repeat("x", maxLine+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newTestGuard(t)
			if g.Feed([]byte(tc.input)) == nil {
				t.Fatal("unsupported control accepted")
			}
			assertSensitiveClear(t, g)
		})
	}
}

func TestOutputGuardIncompleteVTAndMarkerFailAtEOF(t *testing.T) {
	for _, tail := range []string{"\x1b", "\x1b[", "\x1b[0", "\x1b]0;title", "\x1b]0;title\x1b", "\r"} {
		g := readyTestGuard(t)
		if g.MarkInputSent() != nil {
			t.Fatal("input transition failed")
		}
		feedPublic(t, g, "\n"+SuccessMarker+"\n"+tail)
		if g.Finish() == nil {
			t.Fatal("incomplete parser state accepted at EOF")
		}
		assertSensitiveClear(t, g)
	}
	g := readyTestGuard(t)
	if g.MarkInputSent() != nil {
		t.Fatal("input transition failed")
	}
	feedPublic(t, g, "\n"+SuccessMarker)
	if g.Finish() == nil {
		t.Fatal("unterminated marker accepted at EOF")
	}
}

func TestOutputGuardTotalBoundAndStickyFailure(t *testing.T) {
	g, _ := newTestGuard(t)
	if g.Feed(bytes.Repeat([]byte{'\n'}, maxOutput)) != nil {
		t.Fatal("inclusive total bound rejected")
	}
	if g.Feed([]byte{'\n'}) != ErrOutputGuard || g.Finish() != ErrOutputGuard {
		t.Fatal("total overflow not sticky")
	}
	assertSensitiveClear(t, g)
}

func TestOutputGuardSecretOwnershipAndRedactedFormatting(t *testing.T) {
	g, secret := newTestGuard(t)
	clear(secret)
	if bytes.Equal(g.state.secret[:], secret) {
		t.Fatal("guard borrowed caller secret")
	}
	feedPublic(t, g, "partial private-looking output")
	for _, value := range []any{g, *g} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			got := fmt.Sprintf(format, value)
			if got != "freshgate.OutputGuard{redacted}" {
				t.Fatal("guard formatting was not redacted")
			}
		}
	}
	g.Close()
	g.Close()
	assertSensitiveClear(t, g)
	if !bytes.Equal(g.state.fingerprint[:], make([]byte, 64)) || !bytes.Equal(g.state.comparison[:], make([]byte, 32)) {
		t.Fatal("close retained public buffers")
	}
	if g.Feed(nil) != ErrOutputState || g.MarkInputSent() != ErrOutputState || g.Finish() != ErrOutputState || g.PromptReady() {
		t.Fatal("closed guard usable")
	}
}

func TestOutputGuardZeroAndInvalidSecret(t *testing.T) {
	var g OutputGuard
	var nilGuard *OutputGuard
	for _, guard := range []*OutputGuard{&g, nilGuard} {
		if guard.Feed(nil) != ErrOutputState || guard.MarkInputSent() != ErrOutputState || guard.Finish() != ErrOutputState || guard.PromptReady() {
			t.Fatal("zero guard accepted")
		}
		if _, _, ok := guard.PublicTrust(); ok {
			t.Fatal("zero guard returned trust")
		}
		guard.Close()
	}
	for _, secret := range [][]byte{nil, bytes.Repeat([]byte{'A'}, 42), bytes.Repeat([]byte{'A'}, 44), bytes.Repeat([]byte{'!'}, 43), bytes.Repeat([]byte{'B'}, 43)} {
		if guard, err := NewOutputGuard(secret); err != ErrOutputState || guard != nil {
			t.Fatal("invalid synthetic input accepted")
		}
		clear(secret)
	}
}

func assertSensitiveClear(t *testing.T, g *OutputGuard) {
	t.Helper()
	s := g.state
	if s.secret != [secretLength]byte{} || s.prefix != [secretLength]int{} ||
		s.line != [maxLine]byte{} || s.sequence != [maxOSC]byte{} ||
		s.rawMatch != 0 || s.textMatch != 0 || s.lineLen != 0 || s.sequenceLen != 0 {
		t.Fatal("guard retained mutable sensitive buffers")
	}
}

func FuzzOutputGuardStreamingNeverExposesOutput(f *testing.F) {
	f.Add([]byte(testTrust+PublicPrompt+"\r\n"+SuccessMarker+"\r\n"), uint8(1))
	f.Add([]byte("\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;public\x1b\\"), uint8(3))
	f.Add([]byte("public\rrewritten\x1b[999m"), uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, width uint8) {
		g, _ := newTestGuard(t)
		step := int(width) + 1
		var err error
		for start := 0; start < len(data); start += step {
			end := min(start+step, len(data))
			err = g.Feed(data[start:end])
			if err != nil {
				break
			}
			if g.PromptReady() {
				err = g.MarkInputSent()
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			err = g.Finish()
		}
		if err != nil && err != ErrOutputGuard && err != ErrOutputEcho && err != ErrOutputState {
			t.Fatal("non-static guard error")
		}
		assertSensitiveClear(t, g)
		if fmt.Sprintf("%#v", g) != "freshgate.OutputGuard{redacted}" {
			t.Fatal("guard exposed internal representation")
		}
	})
}

func TestPostInputTitleCannotCarryPartialEcho(t *testing.T) {
	secret := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	g, e := NewOutputGuard(secret)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	pre := []byte("Device SPKI SHA-256: " + strings.Repeat("a", 64) + "\r\nComparison: " + strings.Repeat("b", 32) + "\r\n" + PublicPrompt)
	if g.Feed(pre) != nil || g.MarkInputSent() != nil {
		t.Fatal("setup")
	}
	if g.Feed([]byte("\x1b]2;AAAA\a")) == nil {
		t.Fatal("post-input title payload admitted")
	}
}
