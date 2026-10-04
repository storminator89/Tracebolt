//go:build linux

package lanclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalConsentAdminCreateOnlyAndExistingLedgersUntouched(t *testing.T) {
	f := integrationFixture(t, "http-test", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	identity := func() (uint32, uint32, bool) { return 1001, 1001, true }
	localCalls := 0
	local := func(Material) (journalLocal, error) { localCalls++; return journalLocal{}, nil }
	paths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		before[p] = b
	}
	preview, e := configureJournalContent(path, "preview", false, false, identity, local)
	if e != nil || preview.SenderBinding != m.binding || preview.Initialized || localCalls != 0 {
		t.Fatal("preview altered or required policy", e)
	}
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := configureJournalContent(path, "initialize", true, true, identity, local); e == nil {
		t.Fatal("active sender allowed initialization")
	}
	owner.Close()
	if _, e := configureJournalContent(path, "initialize", true, false, identity, local); e == nil {
		t.Fatal("missing separate plaintext acknowledgement accepted")
	}
	result, e := configureJournalContent(path, "initialize", true, true, identity, local)
	if e != nil || !result.Initialized || !result.ExistingStatePreserved {
		t.Fatal("initialization failed", e)
	}
	if _, e := configureJournalContent(path, "initialize", true, true, identity, local); e == nil {
		t.Fatal("existing marker reset")
	}
	for p, want := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("existing ledger altered")
		}
	}
}
func TestJournalConsentRootOrInvalidIdentityRejected(t *testing.T) {
	called := false
	_, e := configureJournalContent("/never-read", "preview", false, false, func() (uint32, uint32, bool) { return 0, 0, false }, func(Material) (journalLocal, error) { called = true; return journalLocal{}, nil })
	if e == nil || called {
		t.Fatal("invalid identity reached policy")
	}
}
