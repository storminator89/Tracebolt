package enrollmenttransport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"net/http"
	"sync"
	"testing"
	"time"
)

// All rows, certificates, stores and listeners are disposable test fixtures.
// These tests never invoke the real overview collector or read host telemetry.
func overviewSnapshotFixture(t *testing.T, n, volumes int, at time.Time) completeoverview.Snapshot {
	t.Helper()
	s := completeoverview.Empty(id("sample", 700), at, completeoverview.ReasonReadFailed)
	s.CaptureFinishedAt = at.Add(100 * time.Millisecond)
	pcount, vcount := uint64(n), uint64(volumes)
	s.Processes.Meta = completeoverview.SectionMeta{GenerationID: s.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &pcount, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: pcount}}
	for i := 1; i <= n; i++ {
		s.Processes.Items = append(s.Processes.Items, completeoverview.Process{PID: uint32(i), Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	}
	s.Volumes.Meta = completeoverview.SectionMeta{GenerationID: s.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &vcount, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: vcount}}
	for i := 1; i <= volumes; i++ {
		s.Volumes.Items = append(s.Volumes.Items, completeoverview.Volume{ID: fmt.Sprintf("mount_%d", i), MountPoint: fmt.Sprintf("/fixture/%05d", i), Filesystem: "ext4", Kind: "local", FilesystemGroup: fmt.Sprintf("fs_0_%d", i), CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	}
	if err := completeoverview.Validate(s); err != nil {
		t.Fatal(err)
	}
	return s
}
func (f *fixture) overviewRequest(t *testing.T, origin, op string, sequence uint64, raw []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, e := overviewwire.NewSignedRequest(context.Background(), origin, f.pair, op, sequence, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r, e := http.NewRequest(http.MethodPost, origin+overviewwire.PathPrefix+op, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func TestCompleteOverviewRealIngressIndependentSectionsAtomicRetryRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, false)
			if err := f.store.InitializeOverview(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, server, client := f.listen(t, nil)
			at := time.Now().UTC().Add(-time.Second)
			snapshot := overviewSnapshotFixture(t, 513, 3, at)
			for _, section := range []string{"processes", "volumes"} {
				generation, e := overviewwire.GenerationID(f.snapshot.Approval.DeviceID, section, 1)
				if e != nil {
					t.Fatal(e)
				}
				m, chunks, e := overviewgeneration.Build(context.Background(), snapshot, section, generation, nil)
				if e != nil {
					t.Fatal(e)
				}
				hash, _ := overviewgeneration.ManifestDigest(m)
				request := func(op string, payload any) []byte {
					t.Helper()
					raw, e := overviewwire.EncodeMessage(op, section, 1, generation, hash, payload)
					if e != nil {
						t.Fatal(e)
					}
					return raw
				}
				send := func(op string, raw []byte, want int) []byte {
					t.Helper()
					return response(t, client, f.overviewRequest(t, server.URL, op, 1, raw), want)
				}
				begin := request("begin", m)
				if section == "processes" {
					send("begin", begin, 403)
					f.activate(t)
				}
				first := send("begin", begin, 200)
				receipt, e := overviewwire.DecodeReceipt(first, "begin", begin)
				if e != nil || receipt.Section != section || receipt.StartedAt.Before(at) {
					t.Fatal("bad begin receipt", e)
				}
				if again := send("begin", begin, 200); !bytes.Equal(first, again) {
					t.Fatal("begin retry refreshed receipt")
				}
				final := request("finalize", struct{}{})
				send("finalize", final, 409)
				for _, c := range chunks {
					raw := request("append", c)
					got := send("append", raw, 200)
					if _, e = overviewwire.DecodeReceipt(got, "append", raw); e != nil {
						t.Fatal(e)
					}
					if again := send("append", raw, 200); !bytes.Equal(got, again) {
						t.Fatal("chunk retry changed receipt")
					}
					view, e := f.store.OverviewView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
					if e != nil {
						t.Fatal(e)
					}
					if section == "processes" && (view.Processes.Complete != nil || view.Volumes.Complete != nil) || section == "volumes" && (view.Processes.Complete == nil || view.Volumes.Complete != nil) {
						t.Fatal("partial or cross-section promotion")
					}
				}
				status := request("status", struct{}{})
				state, e := overviewwire.DecodeReceipt(send("status", status, 200), "status", status)
				if e != nil || state.State != "pending" || state.AcceptedRows != m.ObservedCount {
					t.Fatal("status mismatch", e)
				}
				completed := send("finalize", final, 200)
				finish, e := overviewwire.DecodeReceipt(completed, "finalize", final)
				if e != nil || !finish.CollectedAt.Equal(at) {
					t.Fatal("completion refreshed capture time", e)
				}
				if again := send("finalize", final, 200); !bytes.Equal(completed, again) {
					t.Fatal("finalize retry changed receipt")
				}
				state, e = overviewwire.DecodeReceipt(send("status", status, 200), "status", status)
				if e != nil || state.State != "complete" || !state.CompletedAt.Equal(finish.CompletedAt) || state.AcceptedRows != m.ObservedCount {
					t.Fatal("completion status inconsistent", e)
				}
				page, e := f.store.OverviewPage(context.Background(), f.snapshot.Approval.DeviceID, overviewledger.PageRequest{Section: section, GenerationID: generation, Limit: 100}, time.Now().UTC())
				if e != nil || page.TotalRows != m.ObservedCount || len(page.Items) == 0 || !page.Manifest.CaptureStartedAt.Equal(at) || !page.Manifest.CaptureFinishedAt.Equal(snapshot.CaptureFinishedAt) {
					t.Fatal("full rows/capture interval not retained", e)
				}
				if section == "processes" && (len(page.Items) != 100 || page.Items[0].Process == nil || page.Items[0].Volume != nil) || section == "volumes" && (len(page.Items) != 3 || page.Items[0].Volume == nil || page.Items[0].Process != nil) {
					t.Fatal("section query leaked other section")
				}
			}
			// A failed new process attempt leaves both previous successful sections
			// intact and never changes their source capture or completion clock.
			before, e := f.store.OverviewView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil {
				t.Fatal(e)
			}
			gen, _ := overviewwire.GenerationID(f.snapshot.Approval.DeviceID, "processes", 2)
			failure, e := overviewwire.EncodeMessage("failure", "processes", 2, gen, "", map[string]any{"attemptedAt": at, "reason": "collection_failed"})
			if e != nil {
				t.Fatal(e)
			}
			first := response(t, client, f.overviewRequest(t, server.URL, "failure", 2, failure), 200)
			if _, e := overviewwire.DecodeReceipt(first, "failure", failure); e != nil {
				t.Fatal(e)
			}
			if again := response(t, client, f.overviewRequest(t, server.URL, "failure", 2, failure), 200); !bytes.Equal(first, again) {
				t.Fatal("failure retry refreshed receipt")
			}
			after, e := f.store.OverviewView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || after.Processes.Failure == nil || after.Volumes.Failure != nil || after.Processes.Complete == nil || after.Volumes.Complete == nil || !after.Processes.Complete.CompletedAt.Equal(before.Processes.Complete.CompletedAt) || !after.Volumes.Complete.CompletedAt.Equal(before.Volumes.Complete.CompletedAt) {
				t.Fatal("failed section erased/refreshed successful section", e)
			}
			// A successful zero-row enumeration is separately explicit, and advances
			// only its own section after the failed attempt.
			empty := overviewSnapshotFixture(t, 0, 3, at.Add(100*time.Millisecond))
			gen3, _ := overviewwire.GenerationID(f.snapshot.Approval.DeviceID, "processes", 3)
			manifest, chunks, e := overviewgeneration.Build(context.Background(), empty, "processes", gen3, nil)
			if e != nil || len(chunks) != 0 {
				t.Fatal("empty enumeration invalid", e)
			}
			hash, _ := overviewgeneration.ManifestDigest(manifest)
			for _, op := range []string{"begin", "finalize"} {
				var payload any = struct{}{}
				if op == "begin" {
					payload = manifest
				}
				raw, e := overviewwire.EncodeMessage(op, "processes", 3, gen3, hash, payload)
				if e != nil {
					t.Fatal(e)
				}
				got := response(t, client, f.overviewRequest(t, server.URL, op, 3, raw), 200)
				if _, e = overviewwire.DecodeReceipt(got, op, raw); e != nil {
					t.Fatal(e)
				}
			}
			after, e = f.store.OverviewView(context.Background(), f.snapshot.Approval.DeviceID, time.Now().UTC())
			if e != nil || after.Processes.Complete == nil || after.Processes.Complete.Manifest.ObservedCount != 0 || after.Processes.Failure != nil || after.Volumes.Complete == nil || !after.Volumes.Complete.CompletedAt.Equal(before.Volumes.Complete.CompletedAt) {
				t.Fatal("zero enumeration erased sibling or retained failure", e)
			}
			response(t, client, f.overviewRequest(t, server.URL, "failure", 2, failure), 409)
			f.revoke(t)
			response(t, client, f.overviewRequest(t, server.URL, "failure", 2, failure), 403)
		})
	}
}
func TestCompleteOverviewRequiresFreshMatchingCollectionProfile(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t, profile, true)
			_, server, client := f.listen(t, nil)
			response(t, client, f.overviewRequest(t, server.URL, "status", 1, []byte(`{}`)), 404)
		})
	}
}

func TestCompleteOverviewSlowBodyReauthorizesCurrentCredential(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			if err := f.store.InitializeOverview(context.Background()); err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			_, server, client := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					r.Body = &gatedBody{ReadCloser: r.Body, entered: entered, release: release}
					next.ServeHTTP(w, r)
				})
			})
			gen, _ := overviewwire.GenerationID(f.snapshot.Approval.DeviceID, "processes", 1)
			raw, err := overviewwire.EncodeMessage("failure", "processes", 1, gen, "", map[string]any{"attemptedAt": time.Now().UTC(), "reason": "collection_failed"})
			if err != nil {
				t.Fatal(err)
			}
			r := f.overviewRequest(t, server.URL, "failure", 1, raw)
			finished := make(chan int, 1)
			go func() {
				resp, err := client.Do(r)
				if err != nil {
					finished <- 0
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				finished <- resp.StatusCode
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach body")
			}
			f.revoke(t)
			once.Do(func() { close(release) })
			select {
			case code := <-finished:
				if code != 403 {
					t.Fatalf("body outran revocation: %d", code)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request stuck")
			}
		})
	}
}
func TestCompleteOverviewRequiresExplicitStoreInitialization(t *testing.T) {
	f := newCollectionFixture(t, "http-test", enrollmentcrypto.CollectionProfileComplete, true)
	_, server, client := f.listen(t, nil)
	gen, _ := overviewwire.GenerationID(f.snapshot.Approval.DeviceID, "processes", 1)
	raw, err := overviewwire.EncodeMessage("failure", "processes", 1, gen, "", map[string]any{"attemptedAt": time.Now().UTC(), "reason": "collection_failed"})
	if err != nil {
		t.Fatal(err)
	}
	got := response(t, client, f.overviewRequest(t, server.URL, "failure", 1, raw), 409)
	if !bytes.Contains(got, []byte("overview_not_configured")) {
		t.Fatal("old v3 missing storage misreported")
	}
}
