package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	job "localrmm/internal/windowsupdatejob"
	"testing"
)

func TestCoordinatedWindowsMutationPairSetupAndReload(t *testing.T) {
	for _, order := range []string{"msi-first", "wua-first", "mismatched-peer", "legacy-wua"} {
		t.Run(order, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, false)
			ctx := context.Background()
			mk, me := f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey)
			wk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{117}, 32)).Public().(ed25519.PublicKey)
			we := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{118}, 32)).Public().(ed25519.PublicKey)
			m := managedStoreGrant(f)
			m.Version = msi.CoordinatedGrantVersion
			m.MutationPlanDigest = msi.Digest([]byte("fresh paired plan"))
			w := job.Consent{Version: job.CoordinatedConsentVersion, Scope: job.Scope, Binding: job.Binding{ManagerID: m.Binding.ManagerID, DeviceID: m.Binding.DeviceID, IncarnationDigest: m.Binding.IncarnationDigest, KeyID: msi.Digest(wk), ExecutorKeyID: msi.Digest(we), ExecutorID: id("executor", 8), GrantID: id("grant", 9)}, Enabled: true, Acknowledged: true, ExpiresAt: m.ExpiresAt, MutationPlanDigest: m.MutationPlanDigest}
			raw, _ := json.Marshal(w.Binding)
			m.PeerBindingDigest = msi.Digest(raw)
			raw, _ = json.Marshal(m.Binding)
			w.PeerBindingDigest = msi.Digest(raw)
			if !coordinatedWindowsMutationPair(m, w) {
				t.Fatal("invalid fixture")
			}
			setupM := func() error { return f.store.SetupWindowsManagedMSICreateOnly(ctx, mk, me, m, f.at) }
			setupW := func() error { return f.store.SetupWindowsUpdateJobsCreateOnly(ctx, wk, we, w, f.at) }
			first, second := setupM, setupW
			if order == "wua-first" {
				first, second = setupW, setupM
			}
			if e := first(); e != nil {
				t.Fatal("first participant:", e)
			}
			if order == "msi-first" {
				if e := f.store.Close(); e != nil {
					t.Fatal(e)
				}
				inspection, e := InspectWindowsUpdateJobSetup(ctx, f.path, f.fixture.issuerDER, m.Binding.DeviceID, f.at)
				if e != nil || inspection.Status != "absent" || inspection.CurrentLeafDigest != m.Binding.IncarnationDigest {
					t.Fatal("documented WUA finalize inspection:", e)
				}
				reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
				if e != nil {
					t.Fatal(e)
				}
				f.store = reopened
				defer reopened.Close()
			}
			if order == "mismatched-peer" {
				w.PeerBindingDigest = msi.Digest([]byte("other peer"))
			}
			if order == "legacy-wua" {
				w.Version = job.ConsentVersion
				w.PeerBindingDigest = ""
				w.MutationPlanDigest = ""
			}
			if order == "mismatched-peer" || order == "legacy-wua" {
				if e := second(); !errors.Is(e, job.ErrConflict) {
					t.Fatal("unpaired second participant admitted:", e)
				}
				mr, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, m.Binding, mk)
				if e != nil || mr.Grant != m {
					t.Fatal("rejected pair changed MSI:", e)
				}
				if e = f.store.OpenWindowsUpdateJobs(ctx, wk); !errors.Is(e, job.ErrUnavailable) {
					t.Fatal("rejected pair created WUA state:", e)
				}
				return
			}
			if e := second(); e != nil {
				t.Fatal("second reciprocal participant:", e)
			}
			if e := f.store.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if e != nil {
				t.Fatal("reload:", e)
			}
			defer reopened.Close()
			if e = reopened.OpenWindowsManagedMSI(ctx, mk); e != nil {
				t.Fatal("managed reopen:", e)
			}
			if e = reopened.OpenWindowsUpdateJobs(ctx, wk); e != nil {
				t.Fatal("WUA reopen:", e)
			}
			mr, e := reopened.ReadRegisteredWindowsManagedMSI(ctx, m.Binding, mk)
			if e != nil || mr.Grant != m {
				t.Fatal("managed registered record:", e)
			}
			wr, e := reopened.ReadRegisteredWindowsUpdateJob(ctx, w.Binding, wk)
			if e != nil || wr.Consent != w {
				t.Fatal("WUA registered record:", e)
			}
		})
	}
}
