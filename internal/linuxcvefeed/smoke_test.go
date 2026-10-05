package linuxcvefeed

import (
	"context"
	"errors"
	"fmt"
	"localrmm/internal/linuxcve"
	"os"
	"testing"
	"time"
)

// TestOfficialDebianFeedSmoke is an explicit developer/CI public-data GET. It
// never reads inventory, installs services, writes cache files, or saves the
// raw response as an artifact. Enable only in a network-authorized environment.
func TestOfficialDebianFeedSmoke(t *testing.T) {
	if os.Getenv("TRACEBOLT_CVE_FEED_SMOKE") != "1" {
		t.Skip("official feed smoke is opt-in")
	}
	c := &Cache{client: newHTTPClient()}
	defer c.client.CloseIdleConnections()
	now := time.Now().UTC()
	candidate, err := c.FetchDebian(context.Background(), now)
	if err != nil {
		var limit *responseLimitError
		if errors.As(err, &limit) {
			t.Logf("RESPONSE_SIZE_LIMIT layer=%s reason=%s declaredLength=%d observedBytes=%d maxBytes=%d", limit.layer, limit.reason, limit.declaredLength, limit.observedBytes, limit.maxBytes)
		}
		t.Fatalf("%s: %v", smokeFailureStage(err), err)
	}
	m := candidate.Metadata(now)
	if m.Provider != linuxcve.DebianProvider || m.Trust != "https_origin_only" || m.RecordCount < 1 || m.SourceCount < 1 || len(m.SHA256) != 64 {
		t.Fatal("PARSER_FAILED: invalid successful metadata")
	}
	t.Logf("SUCCESS sources=%d records=%d sha256=%s fetchedAt=%s", m.SourceCount, m.RecordCount, m.SHA256, m.FetchedAt.Format(time.RFC3339Nano))
}

func smokeFailureStage(err error) string {
	// Parser cancellation is never mistaken for an unavailable network.
	if errors.Is(err, ErrParse) {
		return "PARSER_FAILED"
	}
	if errors.Is(err, ErrResponse) {
		return "RESPONSE_INVALID"
	}
	if errors.Is(err, ErrFetch) || errors.Is(err, linuxcve.ErrCanceled) {
		return "NETWORK_UNAVAILABLE"
	}
	return "PARSER_FAILED"
}

func TestSmokeFailureStage(t *testing.T) {
	for _, tc := range []struct {
		err   error
		stage string
	}{
		{ErrFetch, "NETWORK_UNAVAILABLE"},
		{linuxcve.ErrCanceled, "NETWORK_UNAVAILABLE"},
		{ErrResponse, "RESPONSE_INVALID"},
		{&responseLimitError{reason: responseLimitDeclaredLength}, "RESPONSE_INVALID"},
		{&responseLimitError{reason: responseLimitRead}, "RESPONSE_INVALID"},
		{fmt.Errorf("%w: %w", ErrParse, linuxcve.ErrCanceled), "PARSER_FAILED"},
		{fmt.Errorf("%w: %w", ErrParse, linuxcve.ErrInvalid), "PARSER_FAILED"},
	} {
		if got := smokeFailureStage(tc.err); got != tc.stage {
			t.Fatalf("got %s, want %s", got, tc.stage)
		}
	}
}
