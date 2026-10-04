//go:build !linux

package packagecollector

import (
	"context"
	"localrmm/internal/linuxpackages"
	"sync/atomic"
	"testing"
)

// The non-Linux provider is inert. This does not call production Collect.
func TestOtherOSExplicitlyUnsupported(t *testing.T) {
	s, err := collectWith(context.Background(), generation, collectedAt, &atomic.Bool{}, newSystemProvider)
	if err != nil {
		t.Fatal(err)
	}
	assertUnavailable(t, s, true, linuxpackages.ReasonNotSupported)
	assertUnavailable(t, s, false, linuxpackages.ReasonNotSupported)
}
