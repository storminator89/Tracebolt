package main

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/managersetup"
	"strings"
	"testing"
)

func TestHelpAndArgumentsAreStaticAndRedacted(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"private-operation-marker"},
		{"doctor", "--private-argument-marker"},
		{"doctor", "--runtime-uid", "private-uid-marker"},
		{"doctor", "--lan-config", "/private-path-marker", "--runtime-uid", "0"},
		{"init", "--output", "/private-path-marker", "--runtime-uid", "1000"},
		{"doctor", "private-position-marker"},
	} {
		var out, errOut bytes.Buffer
		if run(args, &out, &errOut) == 0 {
			t.Fatal("invalid arguments succeeded")
		}
		if strings.Contains(out.String(), "marker") || errOut.Len() != 0 {
			t.Fatal("argument/parser secret escaped")
		}
		var r managersetup.Report
		if json.Unmarshal(out.Bytes(), &r) != nil || r.OK || r.SchemaVersion != managersetup.SchemaVersion || len(r.Checks) != 1 || r.Checks[0].NextStep == "" {
			t.Fatal("failure is not structured")
		}
	}
	for _, args := range [][]string{{"--help"}, {"doctor", "--help"}, {"init", "--help"}} {
		var out, errOut bytes.Buffer
		if run(args, &out, &errOut) != 0 || !strings.Contains(out.String(), "Root CA private keys stay offline") {
			t.Fatal("help missing safe setup contract")
		}
	}
}
