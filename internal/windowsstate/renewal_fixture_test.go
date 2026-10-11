package windowsstate

import (
	"bytes"
	"slices"
	"testing"
)

func renewalProtectedFixture(t *testing.T) (*Store, *fixtureBackend) {
	t.Helper()
	o := optionsFixture()
	o.Names = []string{"agent-cert.pem", "agent-key.pem", "ready.json", "renewal-manifest.json", "renewal-transaction.json"}
	slices.Sort(o.Names)
	o.Create = true
	b := newFixture(o, nil)
	s, e := openBackend(`C:\ProgramData\Tracebolt`, o, b)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range o.Names {
		if e = s.Write(name, []byte("original:"+name)); e != nil {
			t.Fatal(e)
		}
	}
	return s, b
}

func TestRenewalProtectedManifestInterruptedWriteRetainsOriginalAuthority(t *testing.T) {
	for _, phase := range []string{"pending", "flush:pending", "temp-write", "temp-flush", "rename", "temp-create", "new-temp-flush", "commit", "flush:commit"} {
		t.Run(phase, func(t *testing.T) {
			s, b := renewalProtectedFixture(t)
			b.failAt = phase
			if e := s.Write("renewal-manifest.json", []byte("exact-activated-generation-two")); e == nil {
				t.Fatal("injected interruption accepted")
			}
			if e := s.Verify(); e != ErrPoisoned {
				t.Fatal("uncertain handle reused", e)
			}
			for _, name := range []string{"agent-cert.pem", "agent-key.pem", "ready.json", "renewal-transaction.json"} {
				if !bytes.Equal(b.files[name].data, []byte("original:"+name)) {
					t.Fatal("cutover rewrote original authority", name)
				}
			}
			b.failAt = ""
			_, e := reopenFixture(b)
			if phase != "pending" && phase != "flush:commit" && e == nil {
				t.Fatal("uncertain used protected state silently adopted")
			}
		})
	}
}
func TestRenewalProtectedMissingUsedManifestOrTransactionFailsClosed(t *testing.T) {
	for _, name := range []string{"renewal-manifest.json", "renewal-transaction.json"} {
		t.Run(name, func(t *testing.T) {
			_, b := renewalProtectedFixture(t)
			delete(b.files, name)
			before := len(b.files)
			if _, e := reopenFixture(b); e == nil {
				t.Fatal("missing previously used renewal file adopted")
			}
			if len(b.files) != before {
				t.Fatal("failed open recreated renewal state")
			}
		})
	}
}
