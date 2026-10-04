package enrollmenttransport

import (
	"bytes"
	"context"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"net/http"
	"testing"
	"time"
)

func (f *fixture) inventoryRequest(t *testing.T, origin, op string, sequence uint64, raw []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := inventorywire.NewSignedRequest(context.Background(), origin, f.pair, op, sequence, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest(http.MethodPost, origin+inventorywire.PathPrefix+op, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func TestCompleteInventoryRealIngressAllChunksAtomicRetryRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			_, server, client := f.listen(t, nil)
			generation, e := inventorywire.GenerationID(f.snapshot.Approval.DeviceID, 1)
			if e != nil {
				t.Fatal(e)
			}
			rows := make([]linuxpackages.PackageRow, 513)
			for i := range rows {
				name := fmt.Sprintf("invented-package-%06d", i)
				rows[i] = linuxpackages.PackageRow{Name: name, Version: "1.0-1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1.0-1", SourceMapping: "binary-default", InstallState: "installed"}
			}
			at := time.Now().UTC().Add(-time.Second)
			m, chunks, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: rows}, nil)
			if e != nil {
				t.Fatal(e)
			}
			hash, _ := fullinventory.ManifestDigest(m)
			request := func(op string, payload any) []byte {
				t.Helper()
				raw, e := inventorywire.EncodeMessage(op, 1, generation, hash, payload)
				if e != nil {
					t.Fatal(e)
				}
				return raw
			}
			send := func(op string, raw []byte, want int) []byte {
				t.Helper()
				return response(t, client, f.inventoryRequest(t, server.URL, op, 1, raw), want)
			}
			begin := request("begin", m)
			first := send("begin", begin, 200)
			receipt, e := inventorywire.DecodeReceipt(first, "begin", begin)
			if e != nil || receipt.StartedAt.Before(at) {
				t.Fatal("bad begin receipt", e)
			}
			if again := send("begin", begin, 200); !bytes.Equal(first, again) {
				t.Fatal("begin retry refreshed committed receipt")
			}
			final := request("finalize", struct{}{})
			send("finalize", final, 409)
			for i, c := range chunks {
				raw := request("append", c)
				got := send("append", raw, 200)
				if _, e = inventorywire.DecodeReceipt(got, "append", raw); e != nil {
					t.Fatal(e)
				}
				if again := send("append", raw, 200); !bytes.Equal(got, again) {
					t.Fatal("chunk retry changed receipt")
				}
				view, e := f.store.InventoryView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
				if e != nil || view.Complete != nil {
					t.Fatal("partial chunks exposed as complete", i, e)
				}
			}
			status := request("status", struct{}{})
			state, e := inventorywire.DecodeReceipt(send("status", status, 200), "status", status)
			if e != nil || state.State != "pending" || state.AcceptedRows != 513 {
				t.Fatal("status mismatch", e)
			}
			completed := send("finalize", final, 200)
			finish, e := inventorywire.DecodeReceipt(completed, "finalize", final)
			if e != nil || !finish.CollectedAt.Equal(at) {
				t.Fatal("completion refreshed source time", e)
			}
			if again := send("finalize", final, 200); !bytes.Equal(completed, again) {
				t.Fatal("finalize retry changed receipt")
			}
			state, e = inventorywire.DecodeReceipt(send("status", status, 200), "status", status)
			if e != nil || state.State != "complete" || !state.CompletedAt.Equal(finish.CompletedAt) || state.AcceptedRows != 513 {
				t.Fatal("completion status inconsistent", e)
			}
			page, e := f.store.InventoryPage(context.Background(), f.snapshot.Approval.DeviceID, inventoryledger.PageRequest{GenerationID: generation, Limit: 100}, time.Now().UTC())
			if e != nil || page.TotalRows != 513 || len(page.Items) != 100 {
				t.Fatal("complete rows not retained", e)
			}
			f.revoke(t)
			send("finalize", final, 403)
		})
	}
}

func TestCompleteInventoryIngressFailureNeverBecomesEmptyComplete(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			_, server, client := f.listen(t, nil)
			generation, _ := inventorywire.GenerationID(f.snapshot.Approval.DeviceID, 1)
			at := time.Now().UTC().Add(-time.Second)
			raw, e := inventorywire.EncodeMessage("failure", 1, generation, "", map[string]any{"attemptedAt": at, "reason": "source_missing"})
			if e != nil {
				t.Fatal(e)
			}
			first := response(t, client, f.inventoryRequest(t, server.URL, "failure", 1, raw), 200)
			if _, e = inventorywire.DecodeReceipt(first, "failure", raw); e != nil {
				t.Fatal(e)
			}
			if next := response(t, client, f.inventoryRequest(t, server.URL, "failure", 1, raw), 200); !bytes.Equal(first, next) {
				t.Fatal("failure retry refreshed timestamp")
			}
			view, e := f.store.InventoryView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Complete != nil || view.Transfer != nil || view.Failure == nil || !view.Failure.Failure.AttemptedAt.Equal(at) {
				t.Fatal("source failure fabricated inventory", e)
			}
			// A valid residual-only source is independently explicit and may complete
			// zero retained rows at a new floor; failure above cannot stand for it.
			generation, _ = inventorywire.GenerationID(f.snapshot.Approval.DeviceID, 2)
			m, _, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: generation, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: []linuxpackages.PackageRow{}}, nil)
			if e != nil {
				t.Fatal(e)
			}
			hash, _ := fullinventory.ManifestDigest(m)
			for _, op := range []string{"begin", "finalize"} {
				var payload any = struct{}{}
				if op == "begin" {
					payload = m
				}
				body, e := inventorywire.EncodeMessage(op, 2, generation, hash, payload)
				if e != nil {
					t.Fatal(e)
				}
				receipt := response(t, client, f.inventoryRequest(t, server.URL, op, 2, body), 200)
				if _, e = inventorywire.DecodeReceipt(receipt, op, body); e != nil {
					t.Fatal(e)
				}
			}
			view, e = f.store.InventoryView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || view.Complete == nil || view.Complete.Manifest.ObservedCount != 0 || view.Failure != nil {
				t.Fatal("valid empty complete inventory lost", e)
			}
			response(t, client, f.inventoryRequest(t, server.URL, "failure", 1, raw), 409)
		})
	}
}

func TestCompleteInventoryRequiresFreshMatchingCollectionProfile(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			_, server, client := f.listen(t, nil)
			response(t, client, f.inventoryRequest(t, server.URL, "status", 1, []byte(`{}`)), 404)
		})
	}
}
