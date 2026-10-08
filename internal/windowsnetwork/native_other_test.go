//go:build !windows

package windowsnetwork

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatformDoesNotObserveHost(t *testing.T) {
	if _, e := queryNative(tables[0], nil); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	s, e := Collect(context.Background(), generation, grant, epoch)
	if e != nil || s.Quality != "unavailable" || s.CountExact || s.ObservedCount != 0 || len(s.Rows) != 0 {
		t.Fatal(s, e)
	}
}
