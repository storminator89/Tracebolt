package enrollmentstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/managerstatus"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerStatusAuthorityReadOnly(t *testing.T) {
	f, s, _ := fixtureStore(t)
	defer s.Close()
	ctx := context.Background()
	if _, e := s.CreateInvitation(ctx, f.createCommand()); e != nil {
		t.Fatal(e)
	}
	var before, after []byte
	var versionBefore, versionAfter int
	var changesBefore, changesAfter int
	if e := s.db.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("PRAGMA data_version").Scan(&versionBefore); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("SELECT total_changes()").Scan(&changesBefore); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		r := s.ManagerStatus(ctx)
		if r.State != managerstatus.OK || r.Capacity.Used != 1 || r.Capacity.Pending != 1 || r.Storage.MaxDatabaseBytes == 0 {
			t.Fatal(r)
		}
	}
	if e := s.db.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&after); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("PRAGMA data_version").Scan(&versionAfter); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("SELECT total_changes()").Scan(&changesAfter); e != nil {
		t.Fatal(e)
	}
	if changesBefore != changesAfter || !bytes.Equal(before, after) || versionBefore != versionAfter {
		t.Fatal("probe changed authority")
	}
	if _, e := s.db.Exec("UPDATE enrollment_state SET ledger=x'7b7d' WHERE id=1"); e != nil {
		t.Fatal(e)
	}
	if r := s.ManagerStatus(ctx); r.State == managerstatus.OK {
		t.Fatal("corrupt authority accepted")
	}
}

func TestManagerStatusTerminalConsumesCapacity(t *testing.T) {
	f := newFixture(t)
	f.config.RecordLimit = 1
	f.config.PendingLimit = 1
	f.config.InvitationLimit = 1
	s := f.open(t, filepath.Join(t.TempDir(), "private", "state.db"))
	defer s.Close()
	ctx := context.Background()
	snap, e := s.CreateInvitation(ctx, f.createCommand())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control(snap, 2), State: enrollmentstate.Canceled}); e != nil {
		t.Fatal(e)
	}
	r := s.ManagerStatus(ctx)
	if r.State != managerstatus.Full || r.Capacity.Used != 1 || r.Capacity.Terminal != 1 || r.Capacity.Limit != 1 {
		t.Fatal(r)
	}
}

func TestManagerStatusDiscardReconnectPreservesSettings(t *testing.T) {
	for _, tc := range []struct{ profile, platform string }{{enrollmentcrypto.CollectionProfile, "linux"}, {enrollmentcrypto.CollectionProfileComplete, "linux"}, {enrollmentcrypto.CollectionProfileWindowsInventory, "windows"}, {enrollmentcrypto.CollectionProfileMacOSInventory, "darwin"}} {
		t.Run(tc.profile, func(t *testing.T) {
			f := newFixture(t)
			f.config.Binding.CollectionProfile = tc.profile
			if tc.platform == "darwin" {
				f.config.Platform = tc.platform
			}
			f.config.RecordLimit = 25
			f.config.InvitationLimit = 25
			f.config.PendingLimit = 25
			path := filepath.Join(t.TempDir(), "private", "state.db")
			s := f.open(t, path)
			defer s.Close()
			command := f.createCommand()
			command.Platform = tc.platform
			if _, e := s.CreateInvitation(context.Background(), command); e != nil {
				t.Fatal(e)
			}
			observer, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			defer observer.Close()
			observer.SetMaxOpenConns(1)
			var before, after int
			var ledgerBefore, ledgerAfter []byte
			if e = observer.QueryRow("PRAGMA data_version").Scan(&before); e != nil {
				t.Fatal(e)
			}
			if e = observer.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&ledgerBefore); e != nil {
				t.Fatal(e)
			}
			var originalMax, originalSpill int
			if e = s.db.QueryRow("PRAGMA max_page_count").Scan(&originalMax); e != nil {
				t.Fatal(e)
			}
			if e = s.db.QueryRow("PRAGMA cache_spill").Scan(&originalSpill); e != nil {
				t.Fatal(e)
			}
			r := managerstatus.SQLiteProbe(context.Background(), s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
				_, e := c.ExecContext(ctx, "ROLLBACK")
				return managerstatus.ProbeResult{State: managerstatus.OK}, e
			})
			if r.State != managerstatus.Unavailable || r.Storage.PoolOpen != 0 {
				t.Fatal("uncertain connection retained", r)
			}
			for q, want := range map[string]int{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA busy_timeout": 5000, "PRAGMA trusted_schema": 0, "PRAGMA max_page_count": originalMax, "PRAGMA cache_spill": originalSpill, "SELECT total_changes()": 0} {
				var got int
				if e = s.db.QueryRow(q).Scan(&got); e != nil || got != want {
					t.Fatalf("%s: got %d want %d: %v", q, got, want, e)
				}
			}
			if r = s.ManagerStatus(context.Background()); r.State != managerstatus.OK || r.Capacity.Used != 1 {
				t.Fatal(r)
			}
			var changes int
			if e = s.db.QueryRow("SELECT total_changes()").Scan(&changes); e != nil || changes != 0 {
				t.Fatal("probe mutated store", changes, e)
			}
			if e = observer.QueryRow("PRAGMA data_version").Scan(&after); e != nil || after != before {
				t.Fatal("probe changed durable data", before, after, e)
			}
			if e = observer.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&ledgerAfter); e != nil || !bytes.Equal(ledgerBefore, ledgerAfter) {
				t.Fatal("probe changed authority")
			}
		})
	}
}

func TestManagerStatusReconnectPreservesActivatedCredentialBytes(t *testing.T) {
	_, s, _, snap, _ := completeFixture(t)
	defer s.Close()
	var ledgerBefore, ledgerAfter, credentialBefore, credentialAfter []byte
	if e := s.db.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&ledgerBefore); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("SELECT body FROM enrollment_credentials WHERE invitation_id=?", snap.InvitationID).Scan(&credentialBefore); e != nil {
		t.Fatal(e)
	}
	r := managerstatus.SQLiteProbe(context.Background(), s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
		_, e := c.ExecContext(ctx, "ROLLBACK")
		return managerstatus.ProbeResult{State: managerstatus.OK}, e
	})
	if r.State != managerstatus.Unavailable {
		t.Fatal(r)
	}
	if r = s.ManagerStatus(context.Background()); r.State != managerstatus.OK || r.Capacity.Active != 1 {
		t.Fatal(r)
	}
	if e := s.db.QueryRow("SELECT ledger FROM enrollment_state WHERE id=1").Scan(&ledgerAfter); e != nil {
		t.Fatal(e)
	}
	if e := s.db.QueryRow("SELECT body FROM enrollment_credentials WHERE invitation_id=?", snap.InvitationID).Scan(&credentialAfter); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(ledgerBefore, ledgerAfter) || !bytes.Equal(credentialBefore, credentialAfter) {
		t.Fatal("probe changed activated authority")
	}
	var changes int
	if e := s.db.QueryRow("SELECT total_changes()").Scan(&changes); e != nil || changes != 0 {
		t.Fatal("probe mutated new connection", changes, e)
	}
}

func TestManagerStatusMacOSMaintenanceDeadlinePreservesFloorsAndContent(t *testing.T) {
	f := newMacInventoryFixture(t)
	f.grant(t)
	raw := f.report(t, 1, f.at, 1)
	if _, err := f.apply(raw, f.at); err != nil {
		t.Fatal("synthetic report failed")
	}
	var ledgerBefore, ledgerAfter, credentialBefore, credentialAfter, contentBefore, contentAfter []byte
	var clockBefore, clockAfter string
	if err := f.s.db.QueryRow(`SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&ledgerBefore); err != nil {
		t.Fatal("fixture read failed")
	}
	if err := f.s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snap.InvitationID).Scan(&credentialBefore); err != nil {
		t.Fatal("fixture read failed")
	}
	if err := f.s.db.QueryRow(`SELECT last_time FROM enrollment_macos_inventory_meta WHERE id=1`).Scan(&clockBefore); err != nil {
		t.Fatal("fixture read failed")
	}
	// Retained source DTO bytes are compared only in memory; never printed.
	if err := f.s.db.QueryRow(`SELECT body FROM enrollment_macos_inventory WHERE invitation=?`, f.snap.InvitationID).Scan(&contentBefore); err != nil {
		t.Fatal("fixture content read failed")
	}
	held, err := f.s.db.Conn(context.Background())
	if err != nil {
		t.Fatal("fixture hold failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = f.s.MaintainMacOSInventory(ctx, f.at.Add(time.Second))
	cancel()
	_ = held.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("maintenance ignored canceled pool admission")
	}
	if err = f.s.db.QueryRow(`SELECT ledger FROM enrollment_state WHERE id=1`).Scan(&ledgerAfter); err != nil {
		t.Fatal("fixture read failed")
	}
	if err = f.s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snap.InvitationID).Scan(&credentialAfter); err != nil {
		t.Fatal("fixture read failed")
	}
	if err = f.s.db.QueryRow(`SELECT last_time FROM enrollment_macos_inventory_meta WHERE id=1`).Scan(&clockAfter); err != nil {
		t.Fatal("fixture read failed")
	}
	if err = f.s.db.QueryRow(`SELECT body FROM enrollment_macos_inventory WHERE invitation=?`, f.snap.InvitationID).Scan(&contentAfter); err != nil {
		t.Fatal("fixture content read failed")
	}
	if !bytes.Equal(ledgerBefore, ledgerAfter) || !bytes.Equal(credentialBefore, credentialAfter) || !bytes.Equal(contentBefore, contentAfter) || clockBefore != clockAfter {
		t.Fatal("timed-out maintenance changed durable floors or identity")
	}
	if err = f.s.MaintainMacOSInventory(context.Background(), f.at.Add(time.Second)); err != nil {
		t.Fatal("same-state maintenance failed after bounded wait recovered")
	}
}
