package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"localrmm/internal/managerstatus"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerStatusStorage(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if r := s.ManagerStatus(context.Background()); r.State != managerstatus.OK || r.Storage.DatabaseBytes == 0 {
		t.Fatal(r)
	}
	if _, e = s.db.Exec("DROP TABLE cases"); e != nil {
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

func TestManagerStatusQueuesAndFencesAreAggregateReadOnly(t *testing.T) {
	s, path := alarmStore(t)
	configureAlarm(t, s, &alarmBinding)
	alarmOpen(t, s, "device-private-sentinel", 0)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO windows_notification_outbox(id,binding,target_key,policy_key,revision,device,domain,target,body,transition,state,created,due) VALUES('event-private-sentinel','binding-private-sentinel','target-private-sentinel','policy-private-sentinel',1,'windows-device-private-sentinel','contact','{}','{"secret":"payload-private-sentinel"}','opened','uncertain',1,1)`); err != nil {
		t.Fatal("synthetic queued fixture failed")
	}
	if _, err := s.db.Exec(`INSERT INTO journal_ai_attempts(device,incident,revision,unit,state,created) VALUES('device-private-sentinel','incident-private-sentinel','revision-private-sentinel','unit-private-sentinel','capture_unconfirmed',1)`); err != nil {
		t.Fatal("synthetic fence fixture failed")
	}
	observer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("observer failed")
	}
	defer observer.Close()
	var before, after int
	if err = observer.QueryRow("PRAGMA data_version").Scan(&before); err != nil {
		t.Fatal("observer failed")
	}
	view := s.ManagerStatus(ctx)
	if view.State != managerstatus.OK || view.AlarmQueue == nil || view.AlarmQueue.Queued != 1 || view.WindowsQueue == nil || view.WindowsQueue.Uncertain != 1 || !view.Fences.JournalCaptureUnconfirmed || !view.Fences.JournalCancellationPending {
		t.Fatal("actual queue/fence aggregates missing")
	}
	if err = observer.QueryRow("PRAGMA data_version").Scan(&after); err != nil || after != before {
		t.Fatal("diagnostics changed authority or queue state")
	}
	raw, _ := json.Marshal(view)
	for _, secret := range []string{"private-sentinel", path, alarmBinding.ManagerInstanceID, alarmBinding.DestinationID, alarmBinding.Fingerprint} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("operational aggregates disclosed source metadata")
		}
	}
	var retainedState string
	if err = s.db.QueryRow(`SELECT state FROM journal_ai_attempts WHERE device='device-private-sentinel'`).Scan(&retainedState); err != nil || retainedState != "capture_unconfirmed" {
		t.Fatal("diagnostics cleared a fence")
	}
}
