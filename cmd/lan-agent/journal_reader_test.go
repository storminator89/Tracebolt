package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestJournalReaderExclusiveBeforeSenderState(t *testing.T) {
	for _, args := range [][]string{{"--journal-reader"}, {"--journal-reader", "--config", "/never/read/private-key"}, {"--config", "/never/read/private-key", "--journal-reader"}, {"--journal-reader=true"}, {"-journal-reader"}, {"--journal-reader=false"}} {
		selected, exclusive := journalReaderInvocation(args)
		if !selected || exclusive != (len(args) == 1 && args[0] == "--journal-reader") {
			t.Fatal("incorrect mode selection")
		}
		called := false
		var out bytes.Buffer
		exit := runJournalReader(context.Background(), exclusive, func(context.Context) error { called = true; return nil }, &out)
		if exclusive {
			if exit != 0 || !called {
				t.Fatal("exclusive runtime not selected")
			}
		} else if exit != 2 || called {
			t.Fatal("mixed mode reached runtime")
		}
	}
	for _, args := range [][]string{nil, {"--config", "/unchanged/agent.json"}, {"--foreground", "--service-identity", "1200:1200"}, {"--endpoint-identity-consent", "preview"}} {
		if selected, _ := journalReaderInvocation(args); selected {
			t.Fatal("normal sender intercepted")
		}
	}
	var out bytes.Buffer
	if runJournalReader(context.Background(), true, func(context.Context) error { return errors.New("PRIVATE RAW ERROR") }, &out) != 2 || strings.Contains(out.String(), "PRIVATE") {
		t.Fatal("raw runtime diagnostic escaped")
	}
}
