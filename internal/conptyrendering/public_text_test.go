package conptyrendering

import (
	"os"
	"strings"
	"testing"

	"localrmm/internal/windowsacceptance/freshgate"
)

func TestPublicPromptSourceContract(t *testing.T) {
	source, err := os.ReadFile("../../cmd/windows-service/operation_windows.go")
	if err != nil || !strings.Contains(string(source), `fmt.Fprint(stderr, "`+publicPrompt+`")`) || publicPrompt != freshgate.PublicPrompt {
		t.Fatal("fixed public prompt differs from production or guard")
	}
}

func TestPublicPromptTextEverySplit(t *testing.T) {
	for _, prompt := range []string{publicPrompt, publicPrompt[:len(publicPrompt)-1], publicPrompt + "suffix", "prefix " + publicPrompt} {
		stream := "\x1b[2J\x1b[H\x1b[?9001h\x1b]0;public title\a" + publicTrustLines + prompt + "\x1b[?25h"
		for split := 0; split <= len(stream); split++ {
			var o Observer
			o.Feed([]byte(stream[:split]))
			o.Feed([]byte(stream[split:]))
			trust, exact, omitted := o.liveTextSummary()
			if !trust || exact != (prompt == publicPrompt) || omitted != (prompt == publicPrompt[:len(publicPrompt)-1]) {
				t.Fatal("public text classification differs")
			}
		}
	}
}

func TestPublicTextExcludesTitlesAndWrappedTrust(t *testing.T) {
	for _, stream := range []string{"\x1b]0;" + publicTrustLines + publicPrompt + "\a", "Device SPKI SHA-256: " + publicFingerprint[:30] + "\r\n" + publicFingerprint[30:] + "\r\nComparison: " + publicComparison + "\r\n" + publicPrompt} {
		var o Observer
		o.Feed([]byte(stream))
		trust, _, _ := o.liveTextSummary()
		if trust {
			t.Fatal("title or wrapped line counted as exact trust")
		}
	}
	var o Observer
	o.Feed([]byte(publicTrustLines + publicPrompt))
	_, exact, omitted := o.liveTextSummary()
	if !exact || omitted {
		t.Fatal("exact public prompt missing")
	}
	o.Feed([]byte("suffix"))
	_, exact, omitted = o.liveTextSummary()
	if exact || omitted {
		t.Fatal("extended prompt remained exact")
	}
}

func TestActualGuardRequiresFinalPublicSpace(t *testing.T) {
	// This inert all-zero base64 value is public fixture data. It is never entered,
	// transmitted, or used to create any enrollment/identity/authority.
	fixture := []byte(strings.Repeat("A", 43))
	defer clear(fixture)
	for _, suffix := range []string{"", " "} {
		g, err := freshgate.NewOutputGuard(fixture)
		if err != nil {
			t.Fatal("inert guard setup")
		}
		stream := publicTrustLines + publicPrompt[:len(publicPrompt)-1] + suffix
		if g.Feed([]byte(stream)) != nil {
			t.Fatal("fixed public stream rejected")
		}
		_, _, trust := g.PublicTrust()
		if !trust || g.PromptReady() != (suffix == " ") || g.RejectionReason() != freshgate.OutputNotRejected {
			t.Fatal("actual guard predicate differs")
		}
		g.Close()
	}
}

func TestPublicTextPendingControlsAndBounds(t *testing.T) {
	for _, suffix := range []string{"\r", "\x1b", "\x1b[", "\x1b]0;title"} {
		var o Observer
		o.Feed([]byte(publicTrustLines + publicPrompt + suffix))
		trust, exact, omitted := o.liveTextSummary()
		if !trust || exact || omitted {
			t.Fatal("partial control counted as exact prompt")
		}
	}
	var o Observer
	o.Feed([]byte(strings.Repeat("x", 4097) + publicPrompt))
	_, exact, omitted := o.liveTextSummary()
	if exact || omitted {
		t.Fatal("overflowed line counted as prompt")
	}
	o.Feed([]byte("\r\n" + publicTrustLines + publicPrompt))
	trust, exact, omitted := o.liveTextSummary()
	if !trust || !exact || omitted {
		t.Fatal("bounded line did not recover on newline")
	}
}
