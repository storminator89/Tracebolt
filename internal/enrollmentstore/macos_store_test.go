package enrollmentstore

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMacOSStoreReopenRejectsRebinding(t *testing.T) {
	f := newFixture(t)
	f.config.Platform = "darwin"
	path := filepath.Join(t.TempDir(), "private", "macos.db")
	s := f.open(t, path)
	cmd := f.createCommand()
	cmd.Platform = "darwin"
	snap, err := s.CreateInvitation(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = f.open(t, path)
	got, err := s.Get(context.Background(), snap.InvitationID)
	if err != nil || got != snap {
		t.Fatal("reopen changed original identity", err)
	}
	s.Close()
	old := f.config
	old.Platform = ""
	if foreign, err := Open(path, old, f.issuerDER); err == nil {
		foreign.Close()
		t.Fatal("existing Mac state adopted as generic store")
	}
	s = f.open(t, path)
	cmd.Platform = "linux"
	if _, err = s.CreateInvitation(context.Background(), cmd); err == nil {
		t.Fatal("Linux admitted after reopen")
	}
}
