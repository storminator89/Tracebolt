package freshgate

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestOutputRejectionSessionStopsBeforeInputAndApproval(t *testing.T) {
	g, _ := newTestGuard(t)
	chunk := []byte("\x1b[?12h")
	output := make(chan OutputChunk, 1)
	output <- OutputChunk{Data: chunk}
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outcome, err := ObserveSessionDiagnostic(ctx, g, SessionSteps{
		Output: output, Exited: make(chan struct{}), ConsoleClosed: make(chan struct{}),
		ProcessSucceeded: func() bool { calls++; return true },
		CloseConsole:     func() { calls++ }, Input: func() error { calls++; return nil },
		Approve: func() (bool, error) { calls++; return true, nil },
	})
	if outcome != SessionOutputRejected || err != ErrGuard || calls != 0 ||
		g.RejectionReason() != OutputCSIUnsupported || !bytes.Equal(chunk, make([]byte, len(chunk))) {
		t.Fatal("rejection changed session boundary or retained chunk")
	}
}

func TestOutputRejectionFiniteCategoriesEverySplit(t *testing.T) {
	cases := []struct {
		name string
		data string
		want OutputRejection
	}{
		{"escape", "\x1b7", OutputEscapeUnsupported},
		{"csi limit", "\x1b[" + strings.Repeat(";", maxCSI) + "m", OutputCSILimit},
		{"csi unsupported", "\x1b[?12h", OutputCSIUnsupported},
		{"csi malformed", "\x1b[\x00", OutputCSIMalformed},
		{"osc limit", "\x1b]0;" + strings.Repeat("x", maxOSC-1), OutputOSCLimit},
		{"osc malformed", "\x1b]0;\n", OutputOSCMalformed},
		{"osc terminator", "\x1b]0;\x1b!", OutputOSCMalformed},
		{"osc unsupported", "\x1b]8;\a", OutputOSCUnsupported},
		{"carriage return", "\rx", OutputCarriageReturn},
		{"text unsupported", "\x80", OutputTextUnsupported},
		{"protocol", "Comparison: invalid\n", OutputProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for split := 0; split <= len(tc.data); split++ {
				g, _ := newTestGuard(t)
				err := g.Feed([]byte(tc.data[:split]))
				if err == nil {
					err = g.Feed([]byte(tc.data[split:]))
				}
				if err != ErrOutputGuard || g.RejectionReason() != tc.want {
					t.Fatal("finite rejection category mismatch")
				}
				assertRejectionSticky(t, g, tc.want, err)
			}
		})
	}
}

func assertRejectionSticky(t *testing.T, g *OutputGuard, want OutputRejection, err error) {
	t.Helper()
	assertSensitiveClear(t, g)
	if g.PromptReady() {
		t.Fatal("rejection left prompt ready")
	}
	if fp, comparison, ok := g.PublicTrust(); ok || fp != "" || comparison != "" {
		t.Fatal("rejection left public trust available")
	}
	if g.Feed([]byte("\x1b7")) != err || g.Finish() != err || g.MarkInputSent() != err {
		t.Fatal("sticky rejection error changed")
	}
	g.Close()
	if g.RejectionReason() != want || fmt.Sprintf("%#v", g) != "freshgate.OutputGuard{redacted}" {
		t.Fatal("finite rejection lost or formatting changed")
	}
}

func TestOutputRejectionBoundsAndTerminalStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*OutputGuard) error
		want OutputRejection
		err  error
	}{
		{"total", func(g *OutputGuard) error { return g.Feed(bytes.Repeat([]byte{'\n'}, maxOutput+1)) }, OutputTotalLimit, ErrOutputGuard},
		{"line", func(g *OutputGuard) error { return g.Feed(bytes.Repeat([]byte{'x'}, maxLine+1)) }, OutputLineLimit, ErrOutputGuard},
		{"incomplete", func(g *OutputGuard) error { return g.Finish() }, OutputIncomplete, ErrOutputGuard},
		{"state", func(g *OutputGuard) error { return g.MarkInputSent() }, OutputStateInvalid, ErrOutputState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newTestGuard(t)
			if tc.run(g) != tc.err || g.RejectionReason() != tc.want {
				t.Fatal("bounded rejection category mismatch")
			}
			assertRejectionSticky(t, g, tc.want, tc.err)
		})
	}
	for _, ending := range []string{"\a", "\x1b\\"} {
		g := readyTestGuard(t)
		if g.MarkInputSent() != nil || g.Feed([]byte("\x1b]0;public"+ending)) != ErrOutputGuard {
			t.Fatal("post-input title accepted")
		}
		assertRejectionSticky(t, g, OutputPostInputTitle, ErrOutputGuard)
	}
}

func TestOutputRejectionEchoNeverIncludesBytes(t *testing.T) {
	for _, mode := range []string{"raw", "visible", "title"} {
		for split := 0; split <= secretLength; split++ {
			g, secret := newTestGuard(t)
			var data []byte
			switch mode {
			case "raw":
				data = append(data, secret...)
			case "visible":
				data = append(data, secret[:split]...)
				data = append(data, []byte("\x1b[0m\r\n")...)
				data = append(data, secret[split:]...)
			case "title":
				data = append(data, []byte("\x1b]0;")...)
				data = append(data, secret...)
				data = append(data, '\a')
			}
			var err error
			for _, b := range data {
				if err = g.Feed([]byte{b}); err != nil {
					break
				}
			}
			clear(data)
			if err != ErrOutputEcho || g.RejectionReason() != OutputEcho {
				t.Fatal("echo category mismatch")
			}
			assertRejectionSticky(t, g, OutputEcho, ErrOutputEcho)
		}
	}
}

func TestOutputRejectionNoneDoesNotClaimAcceptance(t *testing.T) {
	var nilGuard *OutputGuard
	var zero OutputGuard
	for _, g := range []*OutputGuard{nilGuard, &zero} {
		if g.RejectionReason() != OutputNotRejected || g.PromptReady() {
			t.Fatal("uninitialized diagnostic promoted")
		}
	}
	g, _ := newTestGuard(t)
	feedPublic(t, g, "\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;public\x1b\\\x1b[?25h")
	if g.RejectionReason() != OutputNotRejected || g.PromptReady() {
		t.Fatal("startup diagnostic promoted")
	}
	feedPublic(t, g, testTrust+PublicPrompt)
	finishTestGuard(t, g)
	g.Close()
	if g.RejectionReason() != OutputNotRejected {
		t.Fatal("passing stream has rejection")
	}
}
