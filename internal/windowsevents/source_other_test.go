//go:build !windows

package windowsevents

import (
	"context"
	"errors"
	"testing"
)

func TestNonWindowsIsExplicitlyUnsupported(t *testing.T) {
	r, err := Collect(context.Background(), []string{"Application", "System"}, 1)
	if !errors.Is(err, ErrUnsupported) || r.Complete || r.Quality != QualityUnavailable || len(r.Channels) != 2 {
		t.Fatal("non-Windows result claimed native collection")
	}
	for _, channel := range r.Channels {
		if channel.Reason != ErrUnsupported.Error() || len(channel.Events) != 0 {
			t.Fatal("unsupported channel result was incorrect")
		}
	}
}
