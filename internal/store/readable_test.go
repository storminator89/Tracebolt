package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCheckReadableIsReadOnlyAndFailsClosed(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReadable(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.CheckReadable(ctx) == nil || s.CheckReadable(nil) == nil || (*Store)(nil).CheckReadable(context.Background()) == nil {
		t.Fatal("invalid context/store ready")
	}
	if _, err := s.db.Exec("PRAGMA query_only=OFF; DROP TABLE cases"); err != nil {
		t.Fatal(err)
	}
	if s.CheckReadable(context.Background()) == nil {
		t.Fatal("missing required table readable")
	}
	_ = s.Close()
	if s.CheckReadable(context.Background()) == nil {
		t.Fatal("closed store readable")
	}
}
