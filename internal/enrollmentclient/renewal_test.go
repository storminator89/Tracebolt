//go:build linux

package enrollmentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/renewalidentity"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrollRenewableFixture(t *testing.T) (*clientFixture, Result) {
	t.Helper()
	f := newClientFixture(t, "tls", enrollmentcrypto.CollectionProfile, "renewable")
	opts := f.options()
	opts.AutomaticRenewalAcknowledged = true
	result, e := Run(context.Background(), f.bootstrap, opts)
	if e != nil {
		t.Fatal("fresh renewable enrollment", e)
	}
	if result.Config.SchemaVersion != lanclient.RenewalConfigVersion || result.Config.RenewalManifestFile != filepath.Join(f.state, renewalidentity.ManifestName) {
		t.Fatal("renewable handoff not selected")
	}
	return f, result
}
func openRenewalFixture(t *testing.T, f *clientFixture) (*session, renewalidentity.Manifest, renewalTransaction) {
	t.Helper()
	st, e := openEnrollmentStore(f.state, true, true)
	if e != nil {
		t.Fatal(e)
	}
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: f.state, ResumeOnly: true, renewalReconcile: true}, renewalNow: func() time.Time { return f.clock }}}
	if e = s.load(f.bootstrap); e != nil {
		st.Close()
		t.Fatal("reopen durable enrollment", e)
	}
	raw, e := st.Read(renewalidentity.ManifestName)
	if e != nil {
		st.Close()
		t.Fatal(e)
	}
	m, e := renewalidentity.Parse(raw)
	if e != nil || s.validateRenewalManifestAt(m, f.clock, true) != nil {
		st.Close()
		t.Fatal("manifest", e)
	}
	tx, e := s.loadRenewalTransaction(m)
	if e != nil {
		st.Close()
		t.Fatal("transaction", e)
	}
	client, e := newEnrollmentHTTPClient(f.bootstrap)
	if e != nil {
		st.Close()
		t.Fatal(e)
	}
	s.wire = &wireClient{client: client, origin: f.bootstrap.EnrollmentOrigin, collectionProfile: f.bootstrap.CollectionProfile}
	t.Cleanup(func() { client.CloseIdleConnections(); clear(s.key); st.Close() })
	return s, m, tx
}
func countRenewalRequests(f *clientFixture, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.requests {
		if p == path {
			n++
		}
	}
	return n
}

func TestRenewalClientRequiresFreshExplicitTLSConsent(t *testing.T) {
	f := newClientFixture(t, "tls", enrollmentcrypto.CollectionProfile, "renewable")
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrBootstrap) {
		t.Fatal("unchecked renewal admitted", e)
	}
	if _, e := os.Stat(f.state); !os.IsNotExist(e) {
		t.Fatal("unchecked consent created state")
	}
	legacy := newClientFixture(t, "tls")
	o := legacy.options()
	o.AutomaticRenewalAcknowledged = true
	if _, e := Run(context.Background(), legacy.bootstrap, o); !errors.Is(e, ErrBootstrap) {
		t.Fatal("renewal silently downgraded", e)
	}
	bad := f.bootstrap
	bad.Profile = "http-test"
	if _, e := validateBootstrap(bad, time.Now()); !errors.Is(e, ErrBootstrap) {
		t.Fatal("signed HTTP renewal admitted")
	}
}

func TestRenewalClientIntegratedCutoverPreservesOriginalArtifacts(t *testing.T) {
	f, _ := enrollRenewableFixture(t)
	names := []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "agent.json", "ready.json", "telemetry/state.json"}
	before := map[string][]byte{}
	for _, name := range names {
		raw, e := os.ReadFile(filepath.Join(f.state, name))
		if e != nil {
			t.Fatal(e)
		}
		before[name] = raw
	}
	f.clock = f.clock.Add(5*24*time.Hour + 16*time.Minute)
	s, m, tx := openRenewalFixture(t, f)
	if e := s.renewOnce(context.Background(), m, &tx); e != nil {
		t.Fatal("renew", e)
	}
	next, e := s.loadRenewalManifest()
	if e != nil {
		t.Fatal(e)
	}
	if next.CredentialGeneration != 2 || next.IdentityGeneration != m.IdentityGeneration || next.AnchorIntent != m.AnchorIntent || next.KeyFingerprint != m.KeyFingerprint || next.AuthorityExpiresAt != m.AuthorityExpiresAt || bytes.Equal(next.CertificateDER, m.CertificateDER) || tx.Phase != "idle" {
		t.Fatal("invalid stable identity cutover")
	}
	for _, name := range names {
		after, e := os.ReadFile(filepath.Join(f.state, name))
		if e != nil || !bytes.Equal(after, before[name]) {
			t.Fatalf("renewal rewrote original %s", name)
		}
	}
	if countRenewalRequests(f, "renewal/issue") != 1 || countRenewalRequests(f, "renewal/activate") != 1 {
		t.Fatal("duplicate issuance or activation")
	}
}

func TestRenewalClientLostRepliesReconcileAfterRestart(t *testing.T) {
	for _, point := range []string{"issued", "activated"} {
		t.Run(point, func(t *testing.T) {
			f, _ := enrollRenewableFixture(t)
			f.clock = f.clock.Add(5*24*time.Hour + 16*time.Minute)
			if point == "issued" {
				f.dropRenewalIssueAfter = true
			} else {
				f.dropRenewalActivate = true
			}
			s, m, tx := openRenewalFixture(t, f)
			if e := s.renewOnce(context.Background(), m, &tx); !errors.Is(e, ErrTransport) {
				t.Fatal("expected exact lost reply", e)
			}
			if e := s.store.Close(); e != nil {
				t.Fatal(e)
			}
			if point == "activated" {
				f.clock = time.Unix(m.Intent.NotAfter+1, 0)
			}
			s, m, tx = openRenewalFixture(t, f)
			if e := s.renewOnce(context.Background(), m, &tx); e != nil {
				t.Fatal("reconcile", e)
			}
			next, e := s.loadRenewalManifest()
			if e != nil || next.CredentialGeneration != 2 {
				t.Fatal("generation not recovered", e)
			}
			if countRenewalRequests(f, "renewal/issue") != 1 {
				t.Fatal("uncertain issuance was repeated")
			}
			if countRenewalRequests(f, "renewal/activate") != 1 {
				t.Fatal("committed activation was repeated")
			}
		})
	}
}

func TestRenewalClientUsedStateNeverReinitialized(t *testing.T) {
	for _, name := range []string{renewalidentity.ManifestName, renewalidentity.LedgerName, "agent-cert.pem", "ready.json", "telemetry/state.json"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			f, _ := enrollRenewableFixture(t)
			if e := os.Remove(filepath.Join(f.state, name)); e != nil {
				t.Fatal(e)
			}
			if _, e := runRenewalCycle(context.Background(), f.state); e == nil {
				t.Fatal("missing used state was adopted")
			}
			if _, e := os.Stat(filepath.Join(f.state, name)); !os.IsNotExist(e) {
				t.Fatal("missing used state recreated")
			}
		})
	}
}

func TestRenewalClientManifestRollbackAndCandidateConflictFailClosed(t *testing.T) {
	f, _ := enrollRenewableFixture(t)
	s, m, tx := openRenewalFixture(t, f)
	tx.LastServerNow = f.clock.Add(time.Minute).Unix()
	if e := s.saveRenewalTransaction(tx); e != nil {
		t.Fatal(e)
	}
	if _, e := s.loadRenewalTransaction(m); !errors.Is(e, ErrState) {
		t.Fatal("clock rollback accepted", e)
	}
	malformed := m
	malformed.AgentOrigin = "https://other.invalid"
	if e := s.validateRenewalManifest(malformed, f.clock); !errors.Is(e, ErrState) {
		t.Fatal("origin rewritten", e)
	}
	raw, _ := json.Marshal(m)
	raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"x","version":`), 1)
	if _, e := renewalidentity.Parse(raw); e == nil {
		t.Fatal("duplicate manifest key accepted")
	}
}

func TestRenewalClientLostLocalManifestCommitReconcilesWithoutNetwork(t *testing.T) {
	f, _ := enrollRenewableFixture(t)
	f.clock = f.clock.Add(5*24*time.Hour + 16*time.Minute)
	s, m, tx := openRenewalFixture(t, f)
	if e := s.renewOncePrepared(context.Background(), m, &tx, false); !errors.Is(e, errRenewalCutover) {
		t.Fatal("candidate not prepared", e)
	}
	originalSync, originalRename := s.store.ops.sync, s.store.ops.rename
	published := false
	s.store.ops.rename = func(oldFD int, old string, newFD int, name string, flags uint) error {
		e := originalRename(oldFD, old, newFD, name, flags)
		if e == nil && name == renewalidentity.ManifestName {
			published = true
		}
		return e
	}
	s.store.ops.sync = func(fd int) error {
		if published {
			return errors.New("synthetic directory flush interruption")
		}
		return originalSync(fd)
	}
	if e := s.renewOnce(context.Background(), m, &tx); !errors.Is(e, ErrState) {
		t.Fatal("expected local publish interruption", e)
	}
	if !published {
		t.Fatal("did not reach manifest durable boundary")
	}
	if e := s.store.Close(); e != nil {
		t.Fatal(e)
	}
	before := countRenewalRequests(f, "renewal/status") + countRenewalRequests(f, "renewal/activate") + countRenewalRequests(f, "renewal/issue")
	s, m, tx = openRenewalFixture(t, f)
	if m.CredentialGeneration != 2 {
		t.Fatal("committed manifest lost")
	}
	if e := s.renewOnce(context.Background(), m, &tx); e != nil || tx.Phase != "idle" {
		t.Fatal("local transaction did not reconcile", e)
	}
	after := countRenewalRequests(f, "renewal/status") + countRenewalRequests(f, "renewal/activate") + countRenewalRequests(f, "renewal/issue")
	if after != before {
		t.Fatal("already published generation repeated network mutation")
	}
}

func TestRenewalClientInterruptedInitialReadyPublicationResumesExactly(t *testing.T) {
	for _, readyWritten := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-ready", true: "before-final-marker"}[readyWritten], func(t *testing.T) {
			f := newClientFixture(t, "tls", enrollmentcrypto.CollectionProfile, "renewable")
			f.autoApprove = false
			o := f.options()
			o.ClaimOnly = true
			o.AutomaticRenewalAcknowledged = true
			if _, e := Run(context.Background(), f.bootstrap, o); e != nil {
				t.Fatal(e)
			}
			fixtureApproveService(t, f)
			if _, e := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); e != nil {
				t.Fatal(e)
			}
			// Reconstruct each exact successfully durable prefix of the first handoff.
			st, e := openEnrollmentStore(f.state, true, true)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := st.Read("ledger.json")
			if e != nil {
				t.Fatal(e)
			}
			var l ledger
			if strictJSON(raw, &l) != nil {
				t.Fatal("fixture ledger")
			}
			l.RenewalReadyPublished = false
			raw, _ = json.Marshal(ledgerDisk(*l.ledgerData))
			if e = st.Write("ledger.json", raw); e != nil {
				t.Fatal(e)
			}
			st.Close()
			if !readyWritten {
				if e = os.Remove(filepath.Join(f.state, "ready.json")); e != nil {
					t.Fatal(e)
				}
			}
			stateBefore, e := os.ReadFile(filepath.Join(f.state, "telemetry", "state.json"))
			if e != nil {
				t.Fatal(e)
			}
			if e = PrepareServiceRenewal(context.Background(), f.bootstrap, f.state); e != nil {
				t.Fatal("first handoff treated as renewal", e)
			}
			inspected, e := InspectService(f.bootstrap, f.state, false)
			if e != nil || inspected.Ready {
				t.Fatal("interrupted publication was ready", e)
			}
			if _, e = ResumeService(context.Background(), f.bootstrap, f.state, false, nil); e != nil {
				t.Fatal("resume first publication", e)
			}
			inspected, e = InspectService(f.bootstrap, f.state, false)
			if e != nil || !inspected.Ready {
				t.Fatal("complete publication not ready", e)
			}
			stateAfter, e := os.ReadFile(filepath.Join(f.state, "telemetry", "state.json"))
			if e != nil || !bytes.Equal(stateBefore, stateAfter) {
				t.Fatal("resumed publication reset sender")
			}
		})
	}
}
