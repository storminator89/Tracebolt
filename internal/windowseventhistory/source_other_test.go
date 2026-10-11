//go:build !windows

package windowseventhistory

import (
	"context"
	"testing"
)

func TestUnsupportedSearchIsUnavailableNotEmptySuccess(t *testing.T) {
	s := fixtureSearch()
	r, e := Read(context.Background(), Request{Search: &s})
	if e != ErrUnsupported || r.Complete || r.Quality != QualityUnavailable || ValidateReport(r, Request{Search: &s}) != nil {
		t.Fatal("unsupported search fabricated success")
	}
}
