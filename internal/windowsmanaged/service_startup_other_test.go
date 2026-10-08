//go:build !windows

package windowsmanaged

import (
	"context"
	"errors"
	"testing"
)

func TestServiceStartupNonWindowsNeverReads(t *testing.T) {
	read, close, err := serviceStartupNativeReader(context.Background())
	if read != nil || close != nil || !errors.Is(err, ErrServiceStartupUnsupported) {
		t.Fatal(err)
	}
	// The portable collector represents unsupported native reads per row.
	s, err := CollectServiceStartup(context.Background(), startupTestServices(), startupTestGeneration, startupTestGrant, startupTestAt)
	if err != nil || len(s.Rows) != 2 || s.Rows[0].StartupQuality != "unavailable" || s.Rows[1].DelayedAutoQuality != "unavailable" {
		t.Fatal(s, err)
	}
}
