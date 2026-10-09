//go:build !windows

package windowspackage

import (
	"context"
	"testing"
)

func TestUnsupportedHasNoNativeFallback(t *testing.T) {
	if err := Preflight(context.Background()); err != ErrUnsupported || Code(err) != "unsupported-platform" {
		t.Fatal(err)
	}
	payload := fixturePE("amd64")
	if _, err := provisionWith(context.Background(), payload, fixtureManifest(payload, "amd64"), []byte("public"), "amd64", nativeSession); err != ErrUnsupported {
		t.Fatal(err)
	}
}
