//go:build linux

package operatorauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func journalFixture(t *testing.T) (*AccountJournal, string) {
	t.Helper()
	_, store, _, _ := accountFixture(t)
	path := filepath.Join(t.TempDir(), "accounts.jsonl")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	j, e := createAccountJournalFile(f, store.snapshot)
	if e != nil {
		f.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return j, path
}
func TestAccountJournalRealFileDurabilityReopenAndEpochFloor(t *testing.T) {
	j, path := journalFixture(t)
	m, e := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: j})
	if e != nil {
		t.Fatal(e)
	}
	admin, worker := seedLiveSession(m, "admin", 1), seedLiveSession(m, "worker", 2)
	c := changeFor(worker)
	c.Disabled = true
	if e = m.ChangeAccount(context.Background(), admin, c); e != nil {
		t.Fatal(e)
	}
	c.ExpectedRevision = 2
	c.Disabled = false
	if e = m.ChangeAccount(context.Background(), admin, c); e != nil {
		t.Fatal(e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := openAccountJournalFile(f)
	if e != nil {
		f.Close()
		t.Fatal(e)
	}
	defer reopened.Close()
	fresh, e := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: reopened})
	if e != nil {
		t.Fatal(e)
	}
	if r, e := fresh.BeginActorAdmission(context.Background(), worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("disk reopen revived old approval")
	}
	s, e := reopened.Load(context.Background())
	if e != nil || s.Revision != 3 || s.Accounts[1].RevocationFloor != 2 {
		t.Fatal("durable floor lost", e)
	}
	if r, e := fresh.BeginActorAdmission(context.Background(), worker.ActorID(), 3, RestartService); e != nil {
		t.Fatal(e)
	} else {
		r()
	}
}
func TestAccountJournalRejectsTornOrChangedHistory(t *testing.T) {
	for _, kind := range []string{"tail", "changed", "empty"} {
		t.Run(kind, func(t *testing.T) {
			j, path := journalFixture(t)
			j.Close()
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "tail":
				raw = append(raw, []byte("{partial")...)
			case "changed":
				raw[0] = '['
			case "empty":
				raw = nil
			}
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			f, e := os.OpenFile(path, os.O_RDWR, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			if reopened, e := openAccountJournalFile(f); e == nil {
				reopened.Close()
				t.Fatal("damaged journal adopted")
			}
		})
	}
}
func TestAccountJournalSyncUncertaintyIsNeverRetried(t *testing.T) {
	j, _ := journalFixture(t)
	m, e := New(Config{AuthorityID: "authority_11111111111111111111111111111111", AuthorityProfile: "tls", AuthorityStore: j})
	if e != nil {
		t.Fatal(e)
	}
	admin, worker := seedLiveSession(m, "admin", 1), seedLiveSession(m, "worker", 2)
	j.syncFile = func() error { return errors.New("fixture sync failure") }
	if e = m.ChangeAccount(context.Background(), admin, changeFor(worker)); !errors.Is(e, ErrAuthorityUncertain) {
		t.Fatal(e)
	}
	if _, e = j.Load(context.Background()); !errors.Is(e, ErrAuthorityUncertain) {
		t.Fatal("uncertain journal reused")
	}
	if m.ActorHasCapability(worker.ActorID(), RestartService) {
		t.Fatal("uncertain account active")
	}
}
func TestAccountJournalExclusiveWriterAndProtectedPath(t *testing.T) {
	j, path := journalFixture(t)
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if other, e := openAccountJournalFile(f); e == nil {
		other.Close()
		t.Fatal("second writer admitted")
	}
	if _, e := CreateAccountJournal(path, j.snapshot); e == nil {
		t.Fatal("existing path replaced")
	}
	if _, e := OpenAccountJournal(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("missing authority reseeded")
	}
}
