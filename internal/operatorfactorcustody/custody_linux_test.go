//go:build linux

package operatorfactorcustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorfactorclient"
)

func custodyFixture(t *testing.T) (Options, lanconfig.Config, lanconfig.AccountAuthorityReference) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("positive public custody requires the supported nonroot runtime")
	}
	root := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{"state", "web", "handoff"} {
		if e := os.Mkdir(filepath.Join(root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS, OperatorListen: "127.0.0.1:8443", AgentListen: "127.0.0.1:8444", OperatorOrigin: "https://manager.invalid:8443", AgentOrigin: "https://manager.invalid:8444", TLSCertificateFile: filepath.Join(root, "server.pem"), TLSPrivateKeyFile: filepath.Join(root, "must-not-read-private-key"), AgentClientCAFile: filepath.Join(root, "must-not-read-agent-ca"), OperatorAuthFile: filepath.Join(root, "auth.json"), StateDirectory: filepath.Join(root, "state"), WebDirectory: filepath.Join(root, "web")}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic custody fixture"}, DNSNames: []string{"manager.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.TLSCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		t.Fatal(e)
	}
	ref := lanconfig.AccountAuthorityReference{SchemaVersion: lanconfig.AccountAuthorityVersion, Profile: lanconfig.TLS, AuthorityID: "authority_11111111111111111111111111111111", AuthorityFile: filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityJournalFile)}
	raw, _ := json.Marshal(ref)
	if e = os.WriteFile(c.OperatorAuthFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	marker, e := lanconfig.AccountAuthorityMarkerBytes(c.StateDirectory, ref)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile), marker, 0600); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(root, "lan.json")
	raw, _ = json.Marshal(c)
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return Options{LanConfig: config, RuntimeUID: os.Geteuid(), ActorID: "operator_00000000000000000000000000000002", ExpectedRevision: 10, HandoffFile: filepath.Join(root, "handoff", "factor.json"), Acknowledge: true}, c, ref
}
func reviewed(o Options) operatorfactorclient.Account {
	return operatorfactorclient.Account{ID: o.ActorID, Revision: o.ExpectedRevision, FactorState: "enrollment_required"}
}
func proposalName(ref lanconfig.AccountAuthorityReference, o Options) string {
	return ref.AuthorityFile + ".factor-" + o.ActorID + ".json"
}
func writeOldProposal(t *testing.T, ref lanconfig.AccountAuthorityReference, o Options, revision uint64) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, e := rand.Read(secret); e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	p := proposal{"tracebolt.operator-factor-proposal.v1", ref.AuthorityID, o.ActorID, revision, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}
	raw, _ := json.Marshal(p)
	if e := os.WriteFile(proposalName(ref, o), raw, 0600); e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestCustodyStagesProtectedMaterialWithoutReadingServerPrivateKeyOrJournal(t *testing.T) {
	o, c, ref := custodyFixture(t)
	p, e := PlanFor(o)
	if e != nil {
		t.Fatal(Code(e))
	}
	// Deliberately missing private key, CA and authority journal prove the planner
	// does not call LoadMaterial, open authority or acquire the manager writer.
	for _, path := range []string{c.TLSPrivateKeyFile, c.AgentClientCAFile, ref.AuthorityFile} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("fixture unexpectedly contains runtime authority")
		}
	}
	cfg := p.ClientConfig()
	if cfg.Origin != c.OperatorOrigin || len(cfg.ServerCertificate) == 0 {
		t.Fatal("missing pinned public transport config")
	}
	cfg.ServerCertificate[0] = 'x'
	if p.ClientConfig().ServerCertificate[0] == 'x' {
		t.Fatal("public certificate slice aliases plan")
	}
	result, e := p.Stage(context.Background(), reviewed(o))
	if e != nil || !result.ProposalCreated || !result.HandoffCreated || result.Archived {
		t.Fatal("staging failed", result, Code(e))
	}
	var material proposal
	raw, e := lanconfig.ReadProtected(proposalName(ref, o), true, 4096)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if json.Unmarshal(raw, &material) != nil {
		t.Fatal("invalid proposal JSON")
	}
	decoded, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(material.Secret)
	if e != nil || len(decoded) != 32 {
		t.Fatal("secret is not exactly32 random bytes")
	}
	clear(decoded)
	if material.ActorID != o.ActorID || material.AuthorityID != ref.AuthorityID || material.ExpectedRevision != o.ExpectedRevision {
		t.Fatal("proposal binding mismatch")
	}
	h, e := lanconfig.ReadProtected(o.HandoffFile, true, 4096)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(h)
	var handoff map[string]any
	if json.Unmarshal(h, &handoff) != nil || handoff["secret"] != material.Secret || handoff["algorithm"] != "SHA256" || handoff["digits"] != float64(8) || handoff["period"] != float64(30) {
		t.Fatal("handoff algorithm or credential mismatch")
	}
	for _, path := range []string{o.HandoffFile, proposalName(ref, o)} {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("custody file is not private0600")
		}
	}
	for _, value := range []any{result, p, o} {
		encoded, _ := json.Marshal(value)
		if bytes.Contains(encoded, []byte(material.Secret)) || strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), material.Secret) {
			t.Fatal("custody result leaked secret")
		}
	}
	if _, e = p.Stage(context.Background(), reviewed(o)); !errors.Is(e, ErrUncertain) {
		t.Fatal("plan reused after state mutation")
	}
	if _, e = os.Lstat(ref.AuthorityFile); !os.IsNotExist(e) {
		t.Fatal("staging created or touched authority journal")
	}
}
func TestCustodyRejectsUnsafePathsAndUnreviewedTargetBeforeWriting(t *testing.T) {
	for _, kind := range []string{"served", "state", "insecure_parent", "symlink_parent", "existing_handoff", "missing_ack", "root_uid", "key_alias", "target_id", "target_revision", "disabled", "uncertain", "active", "pinned_config"} {
		t.Run(kind, func(t *testing.T) {
			o, c, _ := custodyFixture(t)
			switch kind {
			case "served":
				o.HandoffFile = filepath.Join(c.WebDirectory, "factor.json")
			case "state":
				o.HandoffFile = filepath.Join(c.StateDirectory, "factor.json")
			case "insecure_parent":
				if e := os.Chmod(filepath.Dir(o.HandoffFile), 0755); e != nil {
					t.Fatal(e)
				}
			case "symlink_parent":
				dest := filepath.Dir(o.HandoffFile) + "-link"
				if e := os.Symlink(filepath.Dir(o.HandoffFile), dest); e != nil {
					t.Fatal(e)
				}
				o.HandoffFile = filepath.Join(dest, "factor.json")
			case "existing_handoff":
				if e := os.WriteFile(o.HandoffFile, []byte("retained"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing_ack":
				o.Acknowledge = false
			case "root_uid":
				o.RuntimeUID = 0
			case "key_alias":
				c.TLSCertificateFile = c.TLSPrivateKeyFile
				raw, _ := json.Marshal(c)
				if e := os.WriteFile(o.LanConfig, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			p, e := PlanFor(o)
			if strings.HasPrefix(kind, "target_") || kind == "disabled" || kind == "uncertain" || kind == "active" || kind == "pinned_config" {
				if e != nil {
					t.Fatal(Code(e))
				}
				target := reviewed(o)
				switch kind {
				case "target_id":
					target.ID = "operator_00000000000000000000000000000003"
				case "target_revision":
					target.Revision++
				case "disabled":
					target.Disabled = true
				case "uncertain":
					target.Uncertain = true
				case "active":
					target.FactorState = "active"
				case "pinned_config":
					f, e := os.OpenFile(o.LanConfig, os.O_APPEND|os.O_WRONLY, 0)
					if e != nil {
						t.Fatal(e)
					}
					_, _ = f.WriteString("\n")
					f.Close()
				}
				r, e := p.Stage(context.Background(), target)
				if e == nil || r != (Result{}) {
					t.Fatal("unsafe review admitted", r)
				}
				if _, e = os.Lstat(o.HandoffFile); !os.IsNotExist(e) {
					t.Fatal("review failure created handoff")
				}
			} else if e == nil {
				t.Fatal("unsafe plan admitted")
			}
		})
	}
}
func TestCustodyExplicitStaleArchivalPreservesBytesAndNeverOverwrites(t *testing.T) {
	o, _, ref := custodyFixture(t)
	old := writeOldProposal(t, ref, o, 9)
	defer clear(old)
	p, e := PlanFor(o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Stage(context.Background(), reviewed(o)); !errors.Is(e, ErrExisting) {
		t.Fatal("stale proposal implicitly replaced")
	}
	o.ReplaceStale = true
	p, e = PlanFor(o)
	if e != nil {
		t.Fatal(e)
	}
	r, e := p.Stage(context.Background(), reviewed(o))
	if e != nil || !r.Archived || !r.ProposalCreated || !r.HandoffCreated {
		t.Fatal("explicit archive failed", r, Code(e))
	}
	retained, e := os.ReadFile(proposalName(ref, o) + ".retired-9")
	if e != nil || !bytes.Equal(old, retained) {
		t.Fatal("archived proposal bytes changed", e)
	}
	clear(retained)
	now, e := os.ReadFile(proposalName(ref, o))
	if e != nil || bytes.Equal(old, now) {
		t.Fatal("new proposal absent", e)
	}
	clear(now)
}
func TestCustodyRejectsExistingProposalHazardsWithoutMutation(t *testing.T) {
	for _, kind := range []string{"current", "future", "wrong_authority", "duplicate", "hardlink", "symlink", "insecure", "archive_exists"} {
		t.Run(kind, func(t *testing.T) {
			o, _, ref := custodyFixture(t)
			o.ReplaceStale = true
			raw := writeOldProposal(t, ref, o, 9)
			defer clear(raw)
			path := proposalName(ref, o)
			switch kind {
			case "current":
				raw = bytes.Replace(raw, []byte(`"expectedRevision":9`), []byte(`"expectedRevision":10`), 1)
			case "future":
				raw = bytes.Replace(raw, []byte(`"expectedRevision":9`), []byte(`"expectedRevision":11`), 1)
			case "wrong_authority":
				raw = bytes.Replace(raw, []byte(ref.AuthorityID), []byte("authority_22222222222222222222222222222222"), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"expectedRevision":9`), []byte(`"expectedRevision":9,"expectedRevision":9`), 1)
			}
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "hardlink":
				if e := os.Link(path, path+".link"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(path, path+".retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(path+".retained", path); e != nil {
					t.Fatal(e)
				}
			case "insecure":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "archive_exists":
				if e := os.WriteFile(path+".retired-9", []byte("retained"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			p, e := PlanFor(o)
			if e != nil {
				t.Fatal(Code(e))
			}
			r, e := p.Stage(context.Background(), reviewed(o))
			if e == nil || r != (Result{}) {
				t.Fatal("unsafe existing proposal changed", r)
			}
			if _, e = os.Lstat(o.HandoffFile); !os.IsNotExist(e) {
				t.Fatal("unsafe proposal created handoff")
			}
		})
	}
}
func TestCustodyPartialWritesAndSyncUncertaintyRetainEvidence(t *testing.T) {
	for _, kind := range []string{"handoff_write", "handoff_sync", "proposal_write", "archive_sync"} {
		t.Run(kind, func(t *testing.T) {
			o, _, ref := custodyFixture(t)
			if kind == "archive_sync" {
				o.ReplaceStale = true
				raw := writeOldProposal(t, ref, o, 9)
				clear(raw)
			}
			p, e := PlanFor(o)
			if e != nil {
				t.Fatal(e)
			}
			d := p.data.(*linuxPlan)
			writes := 0
			d.write = func(f *os.File, b []byte) (int, error) {
				writes++
				if kind == "handoff_write" && writes == 1 || kind == "proposal_write" && writes == 2 {
					n, e := f.Write(b[:1])
					if e != nil {
						return n, e
					}
					return n, io.ErrShortWrite
				}
				return f.Write(b)
			}
			d.sync = func(f *os.File) error {
				if kind == "handoff_sync" || kind == "archive_sync" {
					return io.ErrUnexpectedEOF
				}
				return f.Sync()
			}
			r, e := p.Stage(context.Background(), reviewed(o))
			if !errors.Is(e, ErrUncertain) {
				t.Fatal("partial result did not report uncertainty", r, Code(e))
			}
			if kind == "archive_sync" {
				if !r.Archived || r.HandoffCreated || r.ProposalCreated {
					t.Fatal("incorrect archive phase", r)
				}
				if _, e = os.Lstat(proposalName(ref, o) + ".retired-9"); e != nil {
					t.Fatal("archive was removed")
				}
			} else {
				if !r.HandoffCreated {
					t.Fatal("partial handoff not reported")
				}
				if _, e = os.Lstat(o.HandoffFile); e != nil {
					t.Fatal("partial handoff removed")
				}
				if kind == "proposal_write" && !r.ProposalCreated {
					t.Fatal("partial proposal not reported")
				}
			}
			if _, e = p.Stage(context.Background(), reviewed(o)); !errors.Is(e, ErrUncertain) {
				t.Fatal("uncertain plan retried")
			}
		})
	}
}

func TestCustodyPublicChainRejectsPrivateBlocksAndPreservesLeafPin(t *testing.T) {
	o, c, _ := custodyFixture(t)
	public, e := os.ReadFile(c.TLSCertificateFile)
	if e != nil {
		t.Fatal(e)
	}
	first, _ := pem.Decode(public)
	if first == nil {
		t.Fatal("missing fixture cert")
	}
	chain := append(append([]byte(nil), public...), public...)
	if e = os.WriteFile(c.TLSCertificateFile, chain, 0644); e != nil {
		t.Fatal(e)
	}
	p, e := PlanFor(o)
	if e != nil || !bytes.Equal(p.ClientConfig().ServerCertificate, first.Bytes) {
		t.Fatal("public chain did not pin exact leaf", Code(e))
	}
	// Deliberately malformed synthetic block, never real key bytes.
	invalid := append(append([]byte(nil), public...), []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")...)
	if e = os.WriteFile(c.TLSCertificateFile, invalid, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = PlanFor(o); !errors.Is(e, ErrConfiguration) {
		t.Fatal("non-certificate PEM block accepted")
	}
}

func TestCustodyRevalidatesPinnedReferenceMarkerCertificateAndDirectories(t *testing.T) {
	for _, kind := range []string{"reference", "marker", "certificate", "directory"} {
		t.Run(kind, func(t *testing.T) {
			o, c, _ := custodyFixture(t)
			p, e := PlanFor(o)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "directory" {
				dir := filepath.Dir(o.HandoffFile)
				if e = os.Rename(dir, dir+".old"); e != nil {
					t.Fatal(e)
				}
				if e = os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
			} else {
				path := c.OperatorAuthFile
				if kind == "marker" {
					path = filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile)
				}
				if kind == "certificate" {
					path = c.TLSCertificateFile
				}
				f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, _ = f.WriteString("\n")
				f.Close()
			}
			result, e := p.Stage(context.Background(), reviewed(o))
			if !errors.Is(e, ErrChanged) || result != (Result{}) {
				t.Fatal("changed pinned input admitted", result, Code(e))
			}
		})
	}
}
