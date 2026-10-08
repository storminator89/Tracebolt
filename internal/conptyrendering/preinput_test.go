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
