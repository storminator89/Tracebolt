package enrollmentstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMacOSStoreOpenPoliciesNeverAdoptOrRecreate(t *testing.T) {
	f := newFixture(t)
	f.config.Platform = "darwin"
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "macos.db")
	if s, err := OpenExisting(path, f.config, f.issuerDER); err == nil {
		s.Close()
		t.Fatal("missing ledger created")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("existing-only created parent")
	}
	s, err := Create(path, f.config, f.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if adopted, err := Create(path, f.config, f.issuerDER); err == nil {
		adopted.Close()
		t.Fatal("create-only adopted existing ledger")
	}
	s, err = OpenExisting(path, f.config, f.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if recreated, err := OpenExisting(path, f.config, f.issuerDER); err == nil {
		recreated.Close()
		t.Fatal("missing used ledger recreated")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		fragment := path + suffix
		if err = os.WriteFile(fragment, []byte("orphan"), 0600); err != nil {
			t.Fatal(err)
		}
		if s, err = Create(path, f.config, f.issuerDER); err == nil {
			s.Close()
			t.Fatal("orphan sidecar adopted")
		}
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("failed create left ledger")
		}
		if err = os.Remove(fragment); err != nil {
			t.Fatal(err)
		}
	}
}
