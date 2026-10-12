//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
)

// All material is ephemeral fixture data. Loads/grant reads are injected because
// production Windows identity and protected stores must fail closed on Linux.
// The ready/config validation still reads actual bounded temporary fixture files.
type updateAuthorityFixture struct {
	material                    renewalMaterialFixture
	current                     Material
	grant                       WindowsUpdateRelayGrant
	peer                        windowsupdateipc.PeerConfig
	layout                      windowsservice.Layout
	now                         time.Time
	loadErr, grantErr, checkErr error
	onCheck                     func()
	onGrant                     func()
	loads, grants, checks       int
}

func newUpdateAuthorityFixture(t *testing.T) *updateAuthorityFixture {
	t.Helper()
	f := &updateAuthorityFixture{material: newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, false), now: time.Now().UTC().Truncate(time.Second)}
	f.current = f.material.material(t, f.material.initial)
	managerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	executorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	binding := job.Binding{ManagerID: f.material.initial.ManagerInstanceID, DeviceID: f.current.config.AgentID, IncarnationDigest: actionpermit.Digest(f.current.authorityDER()), ExecutorID: "executor_" + strings.Repeat("7", 32), ExecutorKeyID: actionpermit.Digest(executorKey), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: actionpermit.Digest(managerKey)}
	f.peer = windowsupdateipc.PeerConfig{Version: windowsupdateipc.PeerVersion, Binding: binding, ExecutorPublicKey: bytes.Clone(executorKey), Executable: `C:\Program Files\Tracebolt\Tracebolt.Windows.UpdateExecutor.exe`, ExecutableDigest: actionpermit.Digest([]byte("fixture executable")), ConfigurationDigest: actionpermit.Digest([]byte("fixture protected executor config"))}
	f.grant = WindowsUpdateRelayGrant{Version: WindowsUpdateRelayGrantVersion, Scope: WindowsUpdateRelayScope, Enabled: true, Acknowledged: true, SenderBinding: f.current.binding, ManagerOrigin: f.current.config.ManagerOrigin, Binding: binding, ManagerPublicKey: managerKey, ExecutorPublicKey: executorKey, ExpiresAt: f.now.Unix() + 300, ExecutorPeer: f.peer}
	f.layout = windowsservice.Layout{EnrollmentRoot: filepath.Dir(f.material.configPath), SenderRoot: f.current.config.StateDirectory}
	return f
}
func (f *updateAuthorityFixture) open(t *testing.T) *windowsUpdateExecutorAuthority {
	t.Helper()
	a, err := openWindowsUpdateExecutorAuthority(f.layout, f.peer, func(ctx context.Context) error {
		f.checks++
		if f.onCheck != nil {
			f.onCheck()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return f.checkErr
	}, windowsUpdateAuthorityReads{load: func(path string) (Material, error) {
		f.loads++
		if path != f.material.configPath {
			t.Fatal("request-selected or wrong configuration path")
		}
		return f.current, f.loadErr
	}, grant: func(Material) (WindowsUpdateRelayGrant, error) {
		f.grants++
		if f.onGrant != nil {
			f.onGrant()
		}
		return f.grant, f.grantErr
	}, now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func requireUpdateAuthorityDenied(t *testing.T, a *windowsUpdateExecutorAuthority) {
	t.Helper()
	called := false
	err := a.WithCurrent(context.Background(), a.binding, func(job.Current) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("denied local authority reached callback: %v", err)
	}
}

func TestWindowsUpdateExecutorAuthorityReadsLiveLeafAndOriginalGrant(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	a := f.open(t)
	var before, after job.Current
	if err := a.WithCurrent(context.Background(), f.peer.Binding, func(c job.Current) error { before = c; return nil }); err != nil {
		t.Fatal(err)
	}
	original := a.original
	f.current = f.material.material(t, f.material.renewed)
	if err := a.WithCurrent(context.Background(), f.peer.Binding, func(c job.Current) error { after = c; return nil }); err != nil {
		t.Fatal(err)
	}
	if before.Binding != after.Binding || before.LeafDigest == after.LeafDigest || before.LeafGeneration != 1 || after.LeafGeneration != 2 || after.LeafNotAfter != f.material.renewed.Intent.NotAfter || !after.Enabled || after.Revoked || a.original != original {
		t.Fatal("renewal changed original authority or failed to read current leaf")
	}
	f.current = f.material.material(t, f.material.initial)
	requireUpdateAuthorityDenied(t, a)
	f.current = f.material.material(t, f.material.renewed)
	f.now = time.Unix(f.grant.ExpiresAt, 0)
	requireUpdateAuthorityDenied(t, a)
}

func TestWindowsUpdateExecutorAuthorityRenewedLeafOutlivesOriginalAnchor(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	f.material = newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, true)
	f.current = f.material.material(t, f.material.renewed)
	f.layout = windowsservice.Layout{EnrollmentRoot: filepath.Dir(f.material.configPath), SenderRoot: f.current.config.StateDirectory}
	f.peer.Binding.IncarnationDigest = actionpermit.Digest(f.current.authorityDER())
	f.grant.Binding = f.peer.Binding
	f.grant.ExecutorPeer = f.peer
	f.grant.SenderBinding = f.current.binding
	a := f.open(t)
	if err := a.WithCurrent(context.Background(), f.peer.Binding, func(c job.Current) error {
		if c.LeafGeneration != 2 || c.LeafDigest == actionpermit.Digest(f.material.anchor.Raw) || c.LeafNotAfter != f.material.renewed.Intent.NotAfter {
			t.Fatal("authority used expired anchor as current credential")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsUpdateExecutorAuthorityRejectsMissingDisabledOrReplacedState(t *testing.T) {
	cases := map[string]func(*testing.T, *updateAuthorityFixture){
		"missing material": func(_ *testing.T, f *updateAuthorityFixture) { f.loadErr = errors.New("private source detail") },
		"missing grant":    func(_ *testing.T, f *updateAuthorityFixture) { f.grantErr = errors.New("private grant detail") },
		"disabled relay":   func(_ *testing.T, f *updateAuthorityFixture) { f.grant.Enabled = false },
		"replaced relay": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.Binding.GrantID = "grant_" + strings.Repeat("9", 32)
		},
		"extended relay expiry": func(_ *testing.T, f *updateAuthorityFixture) { f.grant.ExpiresAt++ },
		"changed peer executable": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.ExecutorPeer.ExecutableDigest = actionpermit.Digest([]byte("replacement"))
		},
		"changed peer config": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.ExecutorPeer.ConfigurationDigest = actionpermit.Digest([]byte("replacement"))
		},
		"disabled install consent": func(_ *testing.T, f *updateAuthorityFixture) { f.checkErr = errors.New("disabled immutable consent") },
		"missing activated receipt": func(t *testing.T, f *updateAuthorityFixture) {
			if err := os.Remove(filepath.Join(f.layout.EnrollmentRoot, "ready.json")); err != nil {
				t.Fatal(err)
			}
		},
		"changed config": func(_ *testing.T, f *updateAuthorityFixture) {
			f.current.config.ManagerOrigin = "https://replacement.invalid"
		},
		"foreign sender": func(_ *testing.T, f *updateAuthorityFixture) { f.grant.SenderBinding = strings.Repeat("0", 64) },
		"foreign anchor": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.Binding.IncarnationDigest = actionpermit.Digest([]byte("foreign"))
		},
		"http profile": func(_ *testing.T, f *updateAuthorityFixture) { f.current.config.Profile = "http-test" },
		"old relay version": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.Version = "tracebolt.windows-selected-update-observer-relay.v1"
		},
		"peer key mismatch": func(_ *testing.T, f *updateAuthorityFixture) {
			f.grant.ExecutorPeer.ExecutorPublicKey = f.grant.ManagerPublicKey
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newUpdateAuthorityFixture(t)
			a := f.open(t)
			change(t, f)
			requireUpdateAuthorityDenied(t, a)
		})
	}
}

func TestWindowsUpdateExecutorAuthorityRechecksAfterBlockingReads(t *testing.T) {
	for _, source := range []string{"grant", "runtime check"} {
		for _, expiry := range []string{"grant", "leaf"} {
			t.Run(source+"/"+expiry, func(t *testing.T) {
				f := newUpdateAuthorityFixture(t)
				if expiry == "leaf" {
					f.grant.ExpiresAt = f.material.initial.Intent.NotAfter + 10
				}
				a := f.open(t)
				advance := func() {
					if expiry == "grant" {
						f.now = time.Unix(f.grant.ExpiresAt, 0)
					} else {
						f.now = time.Unix(f.material.initial.Intent.NotAfter, 0)
					}
				}
				if source == "grant" {
					f.onGrant = advance
				} else {
					f.onCheck = advance
				}
				requireUpdateAuthorityDenied(t, a)
			})
		}
	}
	t.Run("replacement during runtime check", func(t *testing.T) {
		f := newUpdateAuthorityFixture(t)
		a := f.open(t)
		f.onCheck = func() { f.current = f.material.material(t, f.material.renewed) }
		requireUpdateAuthorityDenied(t, a)
		f.onCheck = nil
		if err := a.WithCurrent(context.Background(), f.peer.Binding, func(c job.Current) error {
			if c.LeafGeneration != 2 {
				t.Fatal("stale leaf")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWindowsUpdateExecutorAuthorityNoLockOrSecretEscapesCallback(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	a := f.open(t)
	calls := 0
	if err := a.WithCurrent(context.Background(), f.peer.Binding, func(job.Current) error {
		calls++
		return a.WithCurrent(context.Background(), f.peer.Binding, func(job.Current) error { calls++; return nil })
	}); err != nil || calls != 2 {
		t.Fatalf("nested short final-start recheck: %v, calls %d", err, calls)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, a); got != "<local Windows update authority>" {
			t.Fatalf("authority formatting exposed private state: %s", format)
		}
	}
	raw, err := json.Marshal(a)
	if err != nil || string(raw) != `{"redacted":true}` {
		t.Fatal("authority JSON exposed state")
	}
	before := f.loads
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a.WithCurrent(ctx, f.peer.Binding, func(job.Current) error { t.Fatal("canceled callback"); return nil }) == nil || f.loads != before {
		t.Fatal("canceled authority read")
	}
	if a.WithCurrent(nil, f.peer.Binding, func(job.Current) error { return nil }) == nil || a.WithCurrent(context.Background(), f.peer.Binding, nil) == nil {
		t.Fatal("missing context/callback accepted")
	}
	wrong := f.peer.Binding
	wrong.GrantID = "grant_" + strings.Repeat("9", 32)
	if a.WithCurrent(context.Background(), wrong, func(job.Current) error { t.Fatal("wrong binding callback"); return nil }) == nil || f.loads != before {
		t.Fatal("wrong binding reached source")
	}
}

func TestWindowsUpdateExecutorAuthorityOpenRequiresExactPeerAndFixedLayout(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	if _, err := OpenWindowsUpdateExecutorAuthority(f.peer, nil); err == nil {
		t.Fatal("missing protected install check accepted")
	}
	if _, err := OpenWindowsUpdateExecutorAuthority(f.peer, func(context.Context) error { return nil }); err == nil {
		t.Fatal("Linux acquired production Windows authority")
	}
	reads := windowsUpdateAuthorityReads{load: func(string) (Material, error) { t.Fatal("invalid layout reached credentials"); return Material{}, nil }, grant: func(Material) (WindowsUpdateRelayGrant, error) { return f.grant, nil }, now: time.Now}
	layout := f.layout
	layout.SenderRoot = filepath.Join(f.layout.EnrollmentRoot, "other")
	if _, err := openWindowsUpdateExecutorAuthority(layout, f.peer, func(context.Context) error { return nil }, reads); err == nil {
		t.Fatal("foreign installed sender path accepted")
	}
}

func TestWindowsUpdateExecutorAuthorityRejectsRenewalManagerMismatchAtOpen(t *testing.T) {
	f := newUpdateAuthorityFixture(t)
	f.peer.Binding.ManagerID = "manager_" + strings.Repeat("8", 32)
	f.grant.Binding = f.peer.Binding
	f.grant.ExecutorPeer = f.peer
	checked := false
	_, err := openWindowsUpdateExecutorAuthority(f.layout, f.peer, func(context.Context) error { checked = true; return nil }, windowsUpdateAuthorityReads{
		load:  func(string) (Material, error) { return f.current, nil },
		grant: func(Material) (WindowsUpdateRelayGrant, error) { return f.grant, nil },
		now:   func() time.Time { return f.now },
	})
	if err == nil || checked {
		t.Fatal("self-consistent fresh grant/peer replaced actual renewal manager binding")
	}
}
