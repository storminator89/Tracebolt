//go:build linux

package operatorauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountJournalPreservesWorkPolicyAcrossTransitions(t *testing.T) {
	for _, mode := range []string{"commit", "replay"} {
		t.Run(mode, func(t *testing.T) {
			_, store, _ := singleAccountWorkFixture(t)
			path := filepath.Join(t.TempDir(), "accounts.jsonl")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			j, err := createAccountJournalFile(file, store.snapshot)
			if err != nil {
				file.Close()
				t.Fatal(err)
			}
			defer j.Close()
			next := copySnapshot(store.snapshot)
			next.Revision = 2
			next.Accounts[0].Revision = 2
			next.Accounts[0].RevocationFloor = 1
			next.Accounts[0].Operator.PasswordHash = strings.Replace(fixtureHash(), "t=2", "t=3", 1)
			id := next.Accounts[0].Operator.ID
			transition := AccountTransition{PreviousRevision: 1, Next: next, Audit: AccountAudit{Revision: 2, ActorID: id, TargetID: id, Previous: 1, Current: 2, At: 1, Operation: "credential_reset"}}
			if mode == "commit" {
				if err := j.Commit(context.Background(), transition); !errors.Is(err, ErrAccountConflict) {
					t.Fatal("journal admitted work-factor transition")
				}
				got, err := j.Load(context.Background())
				if err != nil || got.Revision != 1 {
					t.Fatal("rejected transition changed journal")
				}
				return
			}
			// Fixture constructs a correctly chained but policy-changing frame to test
			// replay validation independently of the normal Commit gate.
			if err := j.append(frameFor(next, j.previous, &transition.Audit)); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			reopened, err := openAccountJournalFile(f)
			if err == nil {
				reopened.Close()
				t.Fatal("replay adopted historical work-factor change")
			}
		})
	}
}
