package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestArgumentsAndHelpNeverEchoPrivateInput(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--private-marker"}, {"--runtime-uid", "private-marker"},
		{"--lan-config", "/private-marker", "--runtime-uid", "0"},
		{"--lan-config", "/private-marker", "--output", "/other-marker", "--runtime-uid", "1000"},
		{"private-marker"},
	} {
		var out bytes.Buffer
		if run(args, &out) == 0 || strings.Contains(out.String(), "marker") {
			t.Fatal("invalid arguments accepted or leaked")
		}
		var r result
		if json.Unmarshal(out.Bytes(), &r) != nil || r.OK || r.Created || r.Code != "arguments" || r.NextStep == "" {
			t.Fatal("missing static structured diagnostic")
		}
	}
	var help bytes.Buffer
	if run([]string{"--help"}, &help) != 0 || !strings.Contains(help.String(), "never overwrites or deletes existing state") {
		t.Fatal("missing create-only help contract")
	}
}
