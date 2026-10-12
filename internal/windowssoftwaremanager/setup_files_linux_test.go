//go:build linux

package windowssoftwaremanager

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetupProtectedCreationRejectsUnsafePathsWithoutRepair(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if e := os.Mkdir(shared, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(shared, 0777); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"relative", filepath.Join(shared, "public-fixture"), "/var/../var/tracebolt", "/invalid\x00name"} {
		if e := checkSetupParent(path); e == nil {
			t.Fatal("unsafe output parent accepted", path)
		}
		if e := createSetupFile(path, []byte("inert public fixture")); e == nil {
			t.Fatal("unsafe output created", path)
		}
	}
}
