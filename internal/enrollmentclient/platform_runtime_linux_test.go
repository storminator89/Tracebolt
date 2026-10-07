//go:build linux

package enrollmentclient

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeRejectsRemotePlatformBeforeLedgerMutation(t *testing.T) {
	f := claimServiceFixture(t, "tls")
	rows, err := f.service.Snapshots(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("fixture snapshot unavailable", err)
	}
	st, err := openExistingStore(f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	trust, err := validateBootstrap(f.bootstrap, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: f.state, ResumeOnly: true}, trust: trust}}
	defer func() { clear(s.key) }()
	if err = s.load(f.bootstrap); err != nil {
		t.Fatal(err)
	}
	s.trust.KeyFingerprint = fingerprint(s.publicDER)
	s.trust.ComparisonCode, err = enrollmentcrypto.ComparisonCode(f.bootstrap.ManagerInstanceID, f.bootstrap.InvitationID, s.l.ClaimID, s.trust.KeyFingerprint)
	if err != nil || s.acceptSnapshot(rows[0]) != nil {
		t.Fatal("unchanged Linux snapshot must be accepted", err)
	}
	beforeState := *s.l.ledgerData
	before, err := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	for _, platform := range []string{"windows", "darwin"} {
		v := rows[0]
		v.Platform = platform
		if enrollmentstate.ValidateSnapshot(v) != nil {
			t.Fatal("fixture must remain structurally valid")
		}
		if !errors.Is(s.acceptSnapshot(v), ErrResponse) {
			t.Fatal("remote platform replaced the trusted Linux runtime")
		}
		if *s.l.ledgerData != beforeState {
			t.Fatal("rejected remote platform mutated in-memory state")
		}
		after, readErr := os.ReadFile(filepath.Join(f.state, "ledger.json"))
		same := bytes.Equal(before, after)
		clear(after)
		if readErr != nil || !same {
			t.Fatal("rejected remote platform wrote private state", readErr)
		}
	}
}
