package freshgate

import (
	"bytes"
	"testing"
)

// Fixed public controls only; these tests open no console and send no input.
var publicConPTYModes = []string{"\x1b[?9001h", "\x1b[?9001l", "\x1b[?1004h", "\x1b[?1004l", "\x1b[?1003;1006h", "\x1b[?1003;1006l"}

func TestOutputGuardConPTYModesEverySplitAndPosition(t *testing.T) {
	for _, mode := range publicConPTYModes {
		for _, postInput := range []bool{false, true} {
			text := testTrust + PublicPrompt
			if postInput {
				text = "\r\n" + SuccessMarker + "\r\n"
			}
			for position := 0; position <= len(text); position++ {
				for split := 0; split <= len(mode); split++ {
					g, _ := newTestGuard(t)
					if postInput {
						feedPublic(t, g, testTrust+PublicPrompt)
						if g.MarkInputSent() != nil {
							t.Fatal("input transition failed")
						}
					}
					feedPublic(t, g, text[:position]+mode[:split])
					if !postInput && split > 0 && split < len(mode) && g.PromptReady() {
						t.Fatal("partial mode made prompt ready")
					}
					feedPublic(t, g, mode[split:]+text[position:])
					if postInput {
						if g.Finish() != nil {
							t.Fatal("mode changed complete flow")
						}
					} else {
						fp, comparison, ok := g.PublicTrust()
						if !ok || fp != testFingerprint || comparison != testComparison || !g.PromptReady() {
							t.Fatal("mode changed trust or prompt")
						}
						finishTestGuard(t, g)
					}
					assertSensitiveClear(t, g)
					g.Close()
				}
			}
		}
	}
}

func TestOutputGuardConPTYModesPreserveEcho(t *testing.T) {
	for _, mode := range publicConPTYModes {
		for _, postInput := range []bool{false, true} {
			g, secret := newTestGuard(t)
			if postInput {
				feedPublic(t, g, testTrust+PublicPrompt)
				if g.MarkInputSent() != nil {
					t.Fatal("input transition failed")
				}
			}
			var stream []byte
			for _, c := range secret {
				stream = append(stream, c)
				stream = append(stream, mode...)
			}
			var err error
			for _, c := range stream {
				err = g.Feed([]byte{c})
				if err != nil {
					break
				}
			}
			clear(stream)
			if err != ErrOutputEcho || g.RejectionReason() != OutputEcho {
				t.Fatal("mode concealed synthetic echo")
			}
			assertSensitiveClear(t, g)
		}
	}
}

func TestOutputGuardConPTYModeLookalikesRejected(t *testing.T) {
	controls := []string{
		"\x1b[?1003l", "\x1b[?1006h", "\x1b[?1006l", "\x1b[?1006;1003h", "\x1b[?1006;1003l",
		"\x1b[?01003;1006h", "\x1b[?1003;01006l", "\x1b[1003;1006h", "\x1b[?1003:1006h",
		"\x1b[?1003;;1006l", "\x1b[?;1003;1006h", "\x1b[?1003;1006;l", "\x1b[?1003;1006;25h",
		"\x1b[?1003;1006 h", "\x1b[?1003;1006$l", "\x1b[??1003;1006h", "\x1b[?1003;1006m",
		"\x1b[?1003;1006H", "\x1b[?1003;1006;1003h", "\x1b[?1002;1006h", "\x1b[?1003;1005l",
		"\x1b[?1003;\x1b[?1006h", "\x1b[?1003;\x00'1006l", "\x9b?1003;1006h",
		"\x1b[<0;1;1M", "\x1b[<0;1;1m",

		"\x1b[?9000h", "\x1b[?9002l", "\x1b[?1003h", "\x1b[?1005l",
		"\x1b[?09001h", "\x1b[?01004l", "\x1b[9001h", "\x1b[1004l",
		"\x1b[?9001;1004h", "\x1b[?25;9001l", "\x1b[?1004;h", "\x1b[?;9001h",
		"\x1b[?9001 h", "\x1b[?1004$l", "\x1b[??9001h", "\x1b[?1004:1h",
		"\x1b[?9001m", "\x1b[?1004H", "\x1b[I", "\x1b[O", "\x1b[65;30;97;1_",
		"\x1b[?9001\x00h", "\x9b?9001h",
	}
	for _, control := range controls {
		for split := 0; split <= len(control); split++ {
			for _, postInput := range []bool{false, true} {
				g, _ := newTestGuard(t)
				if postInput {
					feedPublic(t, g, testTrust+PublicPrompt)
					if g.MarkInputSent() != nil {
						t.Fatal("input transition failed")
					}
				}
				err := g.Feed([]byte(control[:split]))
				if err == nil {
					err = g.Feed([]byte(control[split:]))
				}
				if err != ErrOutputGuard {
					t.Fatal("unsupported mode accepted")
				}
				assertSensitiveClear(t, g)
			}
		}
	}
}

func TestOutputGuardConPTYModesKeepBarriersAndBounds(t *testing.T) {
	for _, mode := range publicConPTYModes {
		for prefix := 1; prefix < len(mode); prefix++ {
			g := readyTestGuard(t)
			feedPublic(t, g, mode[:prefix])
			if g.PromptReady() || g.MarkInputSent() != ErrOutputState {
				t.Fatal("partial mode bypassed input barrier")
			}
		}
		g, _ := newTestGuard(t)
		feedPublic(t, g, mode)
		if g.PromptReady() || g.MarkInputSent() != ErrOutputState {
			t.Fatal("mode supplied missing prompt")
		}
		g, _ = newTestGuard(t)
		feedPublic(t, g, testTrust+PublicPrompt+mode)
		if g.Feed([]byte("\r\n"+SuccessMarker+"\r\n")) != ErrOutputGuard {
			t.Fatal("mode supplied missing input transition")
		}
		g = readyTestGuard(t)
		if g.MarkInputSent() != nil {
			t.Fatal("input transition failed")
		}
		feedPublic(t, g, mode)
		if g.Feed([]byte("\x1b]0;public\a")) != ErrOutputGuard || g.RejectionReason() != OutputPostInputTitle {
			t.Fatal("mode weakened title policy")
		}
		g, _ = newTestGuard(t)
		feedPublic(t, g, mode+"public")
		if g.Feed([]byte("\x1b[2J")) != ErrOutputGuard {
			t.Fatal("mode weakened cursor policy")
		}
		g, _ = newTestGuard(t)
		feedPublic(t, g, mode)
		if g.Feed(bytes.Repeat([]byte{'x'}, maxLine+1)) != ErrOutputGuard || g.RejectionReason() != OutputLineLimit {
			t.Fatal("mode weakened line bound")
		}
		g, _ = newTestGuard(t)
		if g.Feed(bytes.Repeat([]byte(mode), maxOutput/len(mode)+1)) != ErrOutputGuard || g.RejectionReason() != OutputTotalLimit {
			t.Fatal("mode weakened total bound")
		}
	}
}

func TestOutputGuardMouseModeExactFinalAndRawEcho(t *testing.T) {
	for final := 0; final < 256; final++ {
		if final < 0x40 || final > 0x7e {
			continue
		}
		g, _ := newTestGuard(t)
		err := g.Feed(append([]byte("\x1b[?1003;1006"), byte(final)))
		if (err == nil) != (final == 'h' || final == 'l') {
			t.Fatal("mouse mode accepted unexpected final")
		}
		g.Close()
	}
	for _, mode := range []string{"\x1b[?1003;1006h", "\x1b[?1003;1006l"} {
		for _, postInput := range []bool{false, true} {
			g, secret := newTestGuard(t)
			if postInput {
				feedPublic(t, g, testTrust+PublicPrompt)
				if g.MarkInputSent() != nil {
					t.Fatal("input transition failed")
				}
			}
			feedPublic(t, g, mode)
			if g.Feed(secret) != ErrOutputEcho || g.RejectionReason() != OutputEcho {
				t.Fatal("mouse mode changed raw echo rejection")
			}
			assertSensitiveClear(t, g)
		}
		g, secret := newTestGuard(t)
		feedPublic(t, g, mode+"\x1b]0;")
		if g.Feed(secret) != ErrOutputEcho || g.RejectionReason() != OutputEcho {
			t.Fatal("mouse mode concealed raw title echo")
		}
		assertSensitiveClear(t, g)
		g, _ = newTestGuard(t)
		feedPublic(t, g, "\x1b]0;public [?1003;1006h text\a")
		if g.PromptReady() || g.MarkInputSent() != ErrOutputState {
			t.Fatal("mouse title lookalike supplied prompt")
		}
		g, _ = newTestGuard(t)
		if g.Feed([]byte("\x1b]0;"+mode+"\a")) != ErrOutputGuard || g.RejectionReason() != OutputOSCMalformed {
			t.Fatal("mouse mode escaped title context")
		}
	}
}
