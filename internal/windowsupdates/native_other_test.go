//go:build !windows

package windowsupdates

import (
	"context"
	"testing"
)

func TestNativeUnsupportedIsExplicit(t *testing.T) {
	s, e := Collect(context.Background(), request())
	if e != nil || s.Quality != "unavailable" || s.Reason != ErrUnsupported.Error() || s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 || s.CacheFreshness != "unknown" {
		t.Fatal(s, e)
	}
}
