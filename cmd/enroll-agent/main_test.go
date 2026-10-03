package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLIRejectsSecretArgumentsWithoutEchoingValues(t *testing.T) {
	for _, args := range [][]string{{"--invitation", "SYNTHETIC_SECRET"}, {"--bootstrap", "/tmp/bootstrap", "--state-directory", "/tmp/state", "SYNTHETIC_SECRET"}, {"--token=SYNTHETIC_SECRET"}} {
		var out, errOut bytes.Buffer
		if n := run(context.Background(), args, &out, &errOut); n != 2 {
			t.Fatal("secret argument accepted")
		}
		if strings.Contains(out.String()+errOut.String(), "SYNTHETIC_SECRET") {
			t.Fatal("argument echoed")
		}
	}
}
func TestShellQuotedHandoffPath(t *testing.T) {
	if got := shellQuote("/tmp/a'b/agent.json"); got != "'/tmp/a'\"'\"'b/agent.json'" {
		t.Fatal(got)
	}
}
