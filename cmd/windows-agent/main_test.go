package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"localrmm/internal/windowsevents"
	"localrmm/internal/windowsinventory"
)

func fakeInventory(context.Context) (windowsinventory.Report, error) {
	return windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows"}, nil
}
func fakeEvents(context.Context, []string, int) (windowsevents.Report, error) {
	return windowsevents.Report{}, nil
}
func TestExplicitReadOnlyScopeRequired(t *testing.T) {
	for _, args := range [][]string{nil, {"--event-metadata"}, {"--collect-read-only=false"}, {"--manager", "private-target"}, {"--collect-read-only", "extra"}, {"--collect-read-only", "--config=private-path"}} {
		var out, stderr bytes.Buffer
		called := false
		read := func(context.Context) (windowsinventory.Report, error) {
			called = true
			return windowsinventory.Report{}, nil
		}
		if code := runWith(args, &out, &stderr, read, fakeEvents); code != 2 || called || out.Len() != 0 {
			t.Fatal("collection started without exact scope")
		}
		if strings.Contains(stderr.String(), "private-") {
			t.Fatal("caller-supplied argument leaked")
		}
	}
}
func TestHelpNeverCollects(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		var out, stderr bytes.Buffer
		read := func(context.Context) (windowsinventory.Report, error) {
			t.Fatal("help collected inventory")
			return windowsinventory.Report{}, nil
		}
		if runWith(args, &out, &stderr, read, fakeEvents) != 0 {
			t.Fatal("help failed")
		}
	}
}
func TestInventoryAndEventConsentAreSeparate(t *testing.T) {
	for _, eventConsent := range []bool{false, true} {
		var out, stderr bytes.Buffer
		calls := 0
		args := []string{"--collect-read-only"}
		if eventConsent {
			args = append(args, "--event-metadata")
		}
		events := func(_ context.Context, channels []string, limit int) (windowsevents.Report, error) {
			calls++
			if len(channels) != 2 || channels[0] != "Application" || channels[1] != "System" || limit != 25 {
				t.Fatal("unbounded event target")
			}
			return windowsevents.Report{}, nil
		}
		if runWith(args, &out, &stderr, fakeInventory, events) != 0 || stderr.Len() != 0 {
			t.Fatal("valid fixture run failed")
		}
		if (calls == 1) != eventConsent {
			t.Fatal("event consent boundary failed")
		}
		var value map[string]json.RawMessage
		if json.Unmarshal(out.Bytes(), &value) != nil || value["inventory"] == nil {
			t.Fatal("bad document")
		}
		_, present := value["eventMetadata"]
		if present != eventConsent {
			t.Fatal("event output present without consent")
		}
	}
}
func TestNativeFailuresAreSanitizedAndAtomic(t *testing.T) {
	var out, stderr bytes.Buffer
	read := func(context.Context) (windowsinventory.Report, error) {
		return windowsinventory.Report{}, errors.New("private native error")
	}
	if runWith([]string{"--collect-read-only"}, &out, &stderr, read, fakeEvents) != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "private native error") {
		t.Fatal("native failure leaked")
	}
	out.Reset()
	stderr.Reset()
	events := func(context.Context, []string, int) (windowsevents.Report, error) {
		return windowsevents.Report{}, errors.New("private event error")
	}
	if runWith([]string{"--collect-read-only", "--event-metadata"}, &out, &stderr, fakeInventory, events) != 1 || out.Len() != 0 || strings.Contains(stderr.String(), "private event error") {
		t.Fatal("partial report or event error leaked")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestShortWriteFails(t *testing.T) {
	if runWith([]string{"--collect-read-only"}, shortWriter{}, io.Discard, fakeInventory, fakeEvents) != 1 {
		t.Fatal("short write accepted")
	}
}

func TestEventDeniedRemainsExplicit(t *testing.T) {
	var out, stderr bytes.Buffer
	events := func(context.Context, []string, int) (windowsevents.Report, error) {
		return windowsevents.Report{Source: windowsevents.Source, Quality: windowsevents.QualityPartial, Channels: []windowsevents.ChannelReport{{Channel: "Application", Reason: windowsevents.ErrAccessDenied.Error()}, {Channel: "System"}}}, windowsevents.ErrAccessDenied
	}
	if runWith([]string{"--collect-read-only", "--event-metadata"}, &out, &stderr, fakeInventory, events) != 0 || stderr.Len() != 0 || !strings.Contains(out.String(), windowsevents.ErrAccessDenied.Error()) {
		t.Fatal("denied event channel was not reported explicitly")
	}
}
