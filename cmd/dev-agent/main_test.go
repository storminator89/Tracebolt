package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpAndFailClosedArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{{[]string{"--help"}, 0}, {nil, 2}, {[]string{"--manager", "http://example.com:8787"}, 2}, {[]string{"--manager", "http://127.0.0.1:8787/path"}, 2}, {[]string{"--manager", "http://127.0.0.1:8787", "extra"}, 2}, {[]string{"--manager", "http://127.0.0.1:8787", "--timeout", "30s"}, 2}, {[]string{"--unknown"}, 2}} {
		var out, err bytes.Buffer
		if got := run(tc.args, &out, &err); got != tc.want {
			t.Fatalf("%v: got %d, want %d", tc.args, got, tc.want)
		}
		if out.Len() != 0 {
			t.Fatal("argument failure emitted data")
		}
	}
	var out, err bytes.Buffer
	run([]string{"--help"}, &out, &err)
	if !strings.Contains(err.String(), "no enrollment") {
		t.Fatal("missing preview caveat")
	}
}
