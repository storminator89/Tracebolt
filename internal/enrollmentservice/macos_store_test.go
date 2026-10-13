package enrollmentservice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestMacOSServiceRequiresDedicatedStore(t *testing.T) {
	f := newFixture(t, "tls")
	if _, err := f.service.CreateInvitation(context.Background(), id("request", 1), "darwin"); !errors.Is(err, ErrPlatform) {
		t.Fatal("generic store admitted Darwin", err)
	}
	f.config.Platform = "darwin"
	f.path = filepath.Join(t.TempDir(), "private", "macos.db")
	f.restart(t)
	for n, p := range []string{"linux", "windows", "macos"} {
		if _, err := f.service.CreateInvitation(context.Background(), id("request", n+1), p); !errors.Is(err, ErrPlatform) {
			t.Fatal("Mac store admitted foreign platform", p, err)
		}
	}
	created, err := f.service.CreateInvitation(context.Background(), id("request", 5), "darwin")
	if err != nil || created.Snapshot().Platform != "darwin" {
		t.Fatal("explicit Mac store rejected Darwin", err)
	}
}
