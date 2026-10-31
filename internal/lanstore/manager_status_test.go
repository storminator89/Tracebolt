package lanstore

import (
	"context"
	"database/sql"
	"localrmm/internal/managerstatus"
	"path/filepath"
	"testing"
)

func TestManagerStatusStorage(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "private", "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Save(context.Background(), fixtureAgent()); e != nil {
		t.Fatal(e)
	}
	if r := s.ManagerStatus(context.Background()); r.State != managerstatus.OK || r.Capacity.Used != 1 || r.Storage.DatabaseBytes == 0 {
		t.Fatal(r)
	}
	if _, e = s.db.Exec("DROP TABLE lan_samples"); e != nil {
		t.Fatal(e)
	}
	if r := s.ManagerStatus(context.Background()); r.State == managerstatus.OK {
		t.Fatal("missing schema accepted")
	}
}

func TestManagerStatusDiscardReconnectPreservesSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	observer, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer observer.Close()
	observer.SetMaxOpenConns(1)
	var before, after int
	if e = observer.QueryRow("PRAGMA data_version").Scan(&before); e != nil {
		t.Fatal(e)
	}
	r := managerstatus.SQLiteProbe(context.Background(), s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
		_, e := c.ExecContext(ctx, "ROLLBACK")
		return managerstatus.ProbeResult{State: managerstatus.OK}, e
	})
	if r.State != managerstatus.Unavailable || r.Storage.PoolOpen != 0 {
		t.Fatal("uncertain connection was retained", r)
	}
	for q, want := range map[string]int{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA busy_timeout": 5000, "SELECT total_changes()": 0} {
		var got int
		if e = s.db.QueryRow(q).Scan(&got); e != nil || got != want {
			t.Fatalf("%s: got %d want %d: %v", q, got, want, e)
		}
	}
	if r = s.ManagerStatus(context.Background()); r.State != managerstatus.OK {
		t.Fatal(r)
	}
	var changes int
	if e = s.db.QueryRow("SELECT total_changes()").Scan(&changes); e != nil || changes != 0 {
		t.Fatal("probe mutated store", changes, e)
	}
	if e = observer.QueryRow("PRAGMA data_version").Scan(&after); e != nil || after != before {
		t.Fatal("probe changed durable data", before, after, e)
	}
}
