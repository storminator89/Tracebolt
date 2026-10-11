//go:build !windows

package windowseventcontent

import (
	"context"
	"errors"
	"testing"
)

func TestNonWindowsUnavailableWithoutReading(t *testing.T) {
	req := Request{Events: []Event{fixtureEvent("System", 1)}}
	r, err := Read(context.Background(), req)
	if !errors.Is(err, ErrUnsupported) || r.Quality != QualityUnavailable || r.Complete || ValidateReport(r, req) != nil {
		t.Fatal("unsupported source did not fail closed")
	}
}
