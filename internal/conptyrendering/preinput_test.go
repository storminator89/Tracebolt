package conptyrendering

import (
	"os"
	"strings"
	"testing"

	"localrmm/internal/windowsacceptance/freshgate"
)

func TestPublicPreinputDisclosureSourceContract(t *testing.T) {
	raw, err := os.ReadFile("../enrollmentclient/bootstrap.go")
	if err != nil || !strings.Contains(string(raw), "const WindowsInventoryPrivacy = \""+publicInventoryDisclosure+"\"") {
		t.Fatal("fixed public disclosure differs from production")
	}
	raw, err = os.ReadFile("../../cmd/windows-service/operation_windows.go")
	if err != nil || !strings.Contains(string(raw), strings.TrimSuffix(publicComparisonReminder, "\r\n")) {
		t.Fatal("fixed public comparison reminder differs from production")
	}
	if len(publicInventoryDisclosure) <= 120 {
		t.Fatal("public disclosure must exercise viewport wrapping")
	}
}

func TestActualGuardPublicPreinputEverySplit(t *testing.T) {
	stream := publicDisclosureLines + publicTrustLines + publicComparisonReminder + publicPrompt
	for split := 0; split <= len(stream); split++ {
		sentinel := []byte(strings.Repeat("A", 43))
		g, err := freshgate.NewOutputGuard(sentinel)
		clear(sentinel)
		if err != nil {
			t.Fatal("inert guard setup")
		}
		if g.Feed([]byte(stream[:split])) != nil || g.Feed([]byte(stream[split:])) != nil {
			g.Close()
			t.Fatal("fixed public pre-input rejected")
		}
		fp, comparison, trust := g.PublicTrust()
		if !trust || fp != publicFingerprint || comparison != publicComparison || !g.PromptReady() || g.RejectionReason() != freshgate.OutputNotRejected {
			g.Close()
			t.Fatal("actual pre-input predicate differs")
		}
		g.Close()
	}
}

func TestPublicPreinputCSISignatures(t *testing.T) {
	cases := []struct {
		p     string
		final byte
		want  string
	}{
		{"?12", 'h', "cursor_blink_enable"}, {"?12", 'l', "cursor_blink_disable"},
		{" ", 'q', "cursor_style_default"}, {"0 ", 'q', "cursor_style_default"},
		{"1 ", 'q', "cursor_style_blink_block"}, {"2 ", 'q', "cursor_style_steady_block"},
		{"3 ", 'q', "cursor_style_blink_underline"}, {"4 ", 'q', "cursor_style_steady_underline"},
		{"5 ", 'q', "cursor_style_blink_bar"}, {"6 ", 'q', "cursor_style_steady_bar"},
		{"", 'K', "erase_line_default"}, {"0", 'K', "erase_line_right"}, {"2", 'K', "erase_line_all"},
		{"1;1", 'H', "cursor_position"}, {"1", 'A', "cursor_movement"}, {"38;2;1;2;3", 'm', "sgr"},
		{"?012", 'h', "other"}, {"?12;25", 'h', "other"}, {"2", 'q', "other"}, {"02 ", 'q', "other"},
		{"1", 'K', "other"}, {"", 'X', "other"},
	}
	for _, c := range cases {
		if publicCSISignature([]byte(c.p), c.final) != c.want {
			t.Fatal("finite public CSI classification differs")
		}
	}
}

func TestActualPreinputLiveSnapshotCannotMaskTrailingPartialControl(t *testing.T) {
	for _, suffix := range []string{"\r", "\x1b", "\x1b[", "\x1b]0;", "suffix"} {
		sentinel := []byte(strings.Repeat("A", 43))
		g, err := freshgate.NewOutputGuard(sentinel)
		clear(sentinel)
		if err != nil {
			t.Fatal("inert guard setup")
		}
		if g.Feed([]byte(publicDisclosureLines+publicTrustLines+publicComparisonReminder+publicPrompt)) != nil || !g.PromptReady() {
			g.Close()
			t.Fatal("live public prompt missing")
		}
		_ = g.Feed([]byte(suffix))
		if g.PromptReady() {
			g.Close()
			t.Fatal("saved live prompt masked trailing output")
		}
		g.Close()
	}
}

func TestPublicCSIDescriptorStrictAlphabetAndBounds(t *testing.T) {
	for final := 0; final < 256; final++ {
		got, params := publicCSIDescriptor([]byte("?12;0:2 "), byte(final))
		valid := final >= 0x40 && final <= 0x7e
		if (got != "none") != valid || valid && params != "?12;0:2 " || !valid && params != "" {
			t.Fatal("public CSI final bounds differ")
		}
	}
	for c := 0; c < 256; c++ {
		got, params := publicCSIDescriptor([]byte{byte(c)}, 'J')
		valid := c >= '0' && c <= '9' || c == ';' || c == ':' || c == '?' || c == ' '
		if (got == "4a") != valid || valid && params != string([]byte{byte(c)}) || !valid && params != "" {
			t.Fatal("public CSI parameter alphabet differs")
		}
	}
	for _, n := range []int{0, 63, 64, 65, 256} {
		got, params := publicCSIDescriptor([]byte(strings.Repeat("1", n)), 'X')
		if (got == "58") != (n <= 64) || n <= 64 && len(params) != n || n > 64 && params != "" {
			t.Fatal("public CSI descriptor bound differs")
		}
	}
}

func TestPublicCSIActualFirstRejectionEverySplit(t *testing.T) {
	// Accepted presentation/private mode controls and title text precede the
	// rejected erase control. A later unsupported mode must never replace it.
	stream := "\x1b]0;public title [?12h 999 X\a\x1b[?9001h\x1b[31mpublic\x1b[0m\x1b[12X\x1b[?777h"
	for split := 0; split <= len(stream); split++ {
		sentinel := []byte(strings.Repeat("A", 43))
		g, err := freshgate.NewOutputGuard(sentinel)
		clear(sentinel)
		if err != nil {
			t.Fatal("inert guard setup")
		}
		var o Observer
		p := preinputResult{rejection: freshgate.OutputNotRejected, firstCSI: "none", csiFinal: "none"}
		feedPublicPreinput(g, &o, &p, []byte(stream[:split]))
		feedPublicPreinput(g, &o, &p, []byte(stream[split:]))
		if p.rejection != freshgate.OutputCSIUnsupported || p.firstCSI != "other" || p.csiFinal != "58" || p.csiParams != "12" {
			g.Close()
			t.Fatal("descriptor did not bind actual first guard rejection")
		}
		g.Close()
	}
}

func TestPublicCSIDescriptorExcludesOSCAndOtherFailures(t *testing.T) {
	cases := []struct {
		stream string
		want   freshgate.OutputRejection
	}{
		{"\x1b]0;public [?12h text\a", freshgate.OutputNotRejected},
		{"\x1b]0;public \x1b[12X\a\x1b[3J", freshgate.OutputOSCMalformed},
		{"\x1b]8;;https://example.invalid/[12X\a\x1b[3J", freshgate.OutputOSCUnsupported},
		{"\x1b[" + strings.Repeat("1", 64) + "X\x1b[3J", freshgate.OutputCSILimit},
		{"\x1b[1\x01X\x1b[3J", freshgate.OutputCSIMalformed},
		{"\x1b[>12X\x1b[3J", freshgate.OutputCSIUnsupported},
		{strings.Repeat("A", 43) + "\x1b[3J", freshgate.OutputEcho},
	}
	for _, c := range cases {
		for split := 0; split <= len(c.stream); split++ {
			sentinel := []byte(strings.Repeat("A", 43))
			g, err := freshgate.NewOutputGuard(sentinel)
			clear(sentinel)
			if err != nil {
				t.Fatal("inert guard setup")
			}
			var o Observer
			p := preinputResult{rejection: freshgate.OutputNotRejected, firstCSI: "none", csiFinal: "none"}
			feedPublicPreinput(g, &o, &p, []byte(c.stream[:split]))
			feedPublicPreinput(g, &o, &p, []byte(c.stream[split:]))
			if p.rejection != c.want || p.csiFinal != "none" || p.csiParams != "" {
				g.Close()
				t.Fatal("non-CSI or unsafe payload escaped descriptor")
			}
			g.Close()
		}
	}
}
