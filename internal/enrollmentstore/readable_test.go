package enrollmentstore

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestCheckReadableIsReadOnlyAndFailsClosed(t *testing.T) {
	_, s, path := fixtureStore(t)
	defer s.Close()
	before, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReadable(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path + "-wal")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read changed committed authority bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.CheckReadable(ctx) == nil || s.CheckReadable(nil) == nil || (*Store)(nil).CheckReadable(context.Background()) == nil {
		t.Fatal("invalid context/store ready")
	}
	if _, err := s.db.Exec("PRAGMA query_only=OFF; DROP TABLE enrollment_credentials"); err != nil {
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
