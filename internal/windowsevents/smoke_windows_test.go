//go:build windows

package windowsevents

import (
	"context"
	"errors"
	"os"
	"testing"
)

// This gate intentionally never creates test events, modifies channels, enables
// privileges, or prints/exports metadata. Run only on an approved disposable VM.
func TestNativeWindowsEventMetadata(t *testing.T) {
	if os.Getenv("TRACEBOLT_WINDOWS_READONLY_NATIVE") != "1" {
		t.Skip("explicit disposable-VM metadata read opt-in required")
	}
	r, err := Collect(context.Background(), []string{"Application", "System"}, 3)
	if err != nil && !errors.Is(err, ErrAccessDenied) {
		t.Fatal("native metadata collection failed")
	}
	if len(r.Channels) != 2 || r.Source != Source {
		t.Fatal("native report provenance missing")
	}
	successful := 0
	validatedEvents := 0
	for _, channel := range r.Channels {
		if channel.Reason == ErrAccessDenied.Error() && len(channel.Events) == 0 && !channel.Complete && !channel.Truncated {
			continue
		}
		if len(channel.Events) > 3 || channel.Source != Source || channel.Reason != "" || channel.Complete == channel.Truncated {
			t.Fatal("native bounds/completeness invariant failed")
		}
		for _, event := range channel.Events {
			if !validEvent(event, channel.Channel) {
				t.Fatal("native metadata validation failed")
			}
			validatedEvents++
		}
		successful++
	}
	if successful == 0 {
		t.Fatal("native metadata gate requires an accessible allowed channel")
	}
	if validatedEvents == 0 {
		t.Fatal("native metadata gate requires at least one rendered event")
	}
}
