//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/model"
	"localrmm/internal/signedhttp"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Every source below is invented. The actual complete sender, independently
// persisted domains, TLS/signed-HTTP ingress and current enrollment authority
// are exercised; no native collector, child binary or opt-in gate is invoked.
func completeRetrySystem(_ context.Context, generation string, at time.Time) (systeminventory.Snapshot, error) {
	count := uint64(1)
	meta := systeminventory.SectionMeta{GenerationID: generation, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}
	s := systeminventory.Snapshot{SchemaVersion: systeminventory.SchemaVersion, GenerationID: generation, CollectedAt: at, Scope: systeminventory.SnapshotScope,
		Services: systeminventory.ServiceSection{Meta: meta, Items: []systeminventory.Service{{Name: "invented.service", Runtime: &systeminventory.ServiceRuntime{LoadState: "loaded", ActiveState: "active", SubState: "running"}}}},
		Sockets:  systeminventory.SocketSection{Meta: meta, Items: []systeminventory.Socket{{Protocol: "tcp", Family: "ipv4", Kind: "listener", Local: systeminventory.Endpoint{Address: "127.0.0.1", Port: 43210}, Remote: systeminventory.Endpoint{Address: "0.0.0.0"}, State: "listen", Owners: []systeminventory.Owner{}, Attribution: systeminventory.Attribution{Coverage: systeminventory.AttributionUnavailable, Reason: systeminventory.ReasonPermissionDenied}}}}}
	return s, systeminventory.Validate(s)
}

func TestCompleteSyntheticAuthorityRetryStagesAndRestart(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, stage := range []string{"metrics", "system", "packages"} {
			t.Run(profile+"/"+stage, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				f := newOverviewAuthorityFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
				target := map[string]string{"metrics": signedhttp.Path, "system": systemwire.Path, "packages": inventorywire.PathPrefix + "append"}[stage]
				var mu sync.Mutex
				var bodies [][]byte
				var lost bool
				var committedSystem systemwire.Receipt
				_, server, _ := f.listen(t, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != target {
							next.ServeHTTP(w, r)
							return
						}
						raw, e := io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
						if e != nil {
							t.Error("synthetic request read")
							w.WriteHeader(500)
							return
						}
						r.Body = io.NopCloser(bytes.NewReader(raw))
						mu.Lock()
						bodies = append(bodies, bytes.Clone(raw))
						first := !lost
						lost = true
						mu.Unlock()
						if first {
							rec := httptest.NewRecorder()
							next.ServeHTTP(rec, r)
							if rec.Code != http.StatusOK {
								t.Error("real authority did not commit synthetic request")
								w.WriteHeader(500)
								return
							}
							if stage == "system" {
								receipt, e := systemwire.DecodeReceipt(rec.Body.Bytes(), f.snapshot.Approval.DeviceID, raw)
								if e != nil {
									t.Error("real authority receipt decode")
								}
								mu.Lock()
								committedSystem = receipt
								mu.Unlock()
							}
							// Simulate a temporarily unavailable receipt after the real commit.
							// Neither the body nor the original collection time is changed.
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						next.ServeHTTP(w, r)
					})
				})
				m, configPath := f.material(t, server.URL)
				identity := map[string][32]byte{}
				for _, path := range []string{configPath, m.config.CertificateFile, m.config.PrivateKeyFile, filepath.Join(filepath.Dir(configPath), "ready.json")} {
					raw, e := os.ReadFile(path)
					if e != nil {
						t.Fatal("synthetic identity read")
					}
					identity[path] = sha256.Sum256(raw)
				}
				originalAuthority, e := f.store.Get(ctx, f.snapshot.InvitationID)
				if e != nil {
					t.Fatal("synthetic authority read")
				}
				captures := [3]int{}
				var state *lanclientstate.State
				var system *systemSender
				var inventory *inventorySender
				now := func() time.Time { return time.Now().UTC() }
				open := func() {
					var err error
					state, err = openSenderState(m)
					if err != nil {
						t.Fatal("synthetic metrics ledger open")
					}
					system, err = openSystemSenderWithSource(m, func(c context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
						captures[1]++
						return completeRetrySystem(c, id, at)
					}, now)
					if err != nil {
						t.Fatal("synthetic system ledger open")
					}
					inventory, err = openInventorySenderWithSource(m, now, func(c context.Context, id string, at time.Time) (fullinventory.SourceInventory, error) {
						captures[2]++
						s, e := syntheticInventory(c, id, at, 1)
						ubuntu, version, codename := "ubuntu", "24.04", "noble"
						s.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: &ubuntu, VersionID: &version, VersionCodename: &codename}}
						return s, e
					})
					if err != nil {
						t.Fatal("synthetic package ledger open")
					}
				}
				closeSenders := func() {
					if inventory.Close() != nil || system.Close() != nil || state.Close() != nil {
						t.Fatal("synthetic sender close")
					}
				}
				open()
				defer func() { closeSenders() }()
				attempt := func() (Report, error) {
					return runPreparedAttemptWithSystem(ctx, m, state, system, inventory, func(c context.Context, mat Material, s *lanclientstate.State) (Report, error) {
						return runUsingStateWithSources(c, mat, s, unavailableOperations, nil, func() model.Device { captures[0]++; return syntheticPackageBasic() })
					})
				}
				failed, e := attempt()
				expectedError := map[string]error{"metrics": ErrTransport, "system": ErrSystemTransport, "packages": ErrInventoryTransport}[stage]
				if !errors.Is(e, expectedError) || failed.Sequence != 1 || failed.DiscardedStale || failed.SystemDiscardedStale {
					t.Fatal("synthetic failure did not retain its exact domain")
				}
				if stage == "metrics" && (failed.Status != "pending_retained" || failed.SystemStatus != "" || failed.SystemSequence != 0 || failed.InventoryStatus != "") {
					t.Fatal("metrics retry stage changed")
				}
				if stage == "system" && (failed.Status != "acknowledged" || failed.SystemStatus != "pending_retained" || failed.SystemSequence != 1 || failed.InventoryStatus != "") {
					t.Fatal("system retry stage changed")
				}
				if stage == "packages" && (failed.Status != "acknowledged" || failed.SystemStatus != "acknowledged" || failed.SystemSequence != 1 || failed.InventoryStatus != "pending_retained" || failed.InventorySequence != 1) {
					t.Fatal("package retry stage changed")
				}
				var pending []byte
				switch stage {
				case "metrics":
					p, e := state.Pending()
					if e != nil || p == nil {
						t.Fatal("metric pending missing")
					}
					pending = p.Body()
				case "system":
					p, e := system.state.Pending()
					if e != nil || p == nil {
						t.Fatal("system pending missing")
					}
					pending = p.Body()
				case "packages":
					p, ok, e := inventory.state.NextWork()
					if e != nil || !ok {
						t.Fatal("package pending missing")
					}
					pending = p.Body()
				}
				beforeRetry := captures
				closeSenders()
				open() // exact pending bytes must survive the process-owner boundary.
				var retained enrollmentstore.InventoryStatus
				var previousMetricAt, previousSystemAt time.Time
				for positive := uint64(1); positive <= 4; positive++ {
					r, e := attempt()
					metricSequence, systemSequence := positive, positive
					if stage != "metrics" {
						metricSequence++
					}
					if stage == "packages" {
						systemSequence++
					}
					if e != nil || r.Status != "acknowledged" || r.SystemStatus != "acknowledged" || r.Sequence != metricSequence || r.SystemSequence != systemSequence || r.DiscardedStale || r.SystemDiscardedStale {
						t.Fatal("retry domain accounting failed")
					}
					if positive == 1 {
						if stage == "metrics" && (!r.RetriedPending || !r.Duplicate || captures[0] != beforeRetry[0]) {
							t.Fatal("metric pending recollected")
						}
						if stage == "system" && (!r.SystemRetriedPending || captures[1] != beforeRetry[1]) {
							t.Fatal("system pending recollected")
						}
						if stage == "packages" && captures[2] != beforeRetry[2] {
							t.Fatal("package pending recollected")
						}
						mu.Lock()
						equal := len(bodies) >= 2 && bytes.Equal(bodies[0], bodies[1]) && bytes.Equal(pending, bodies[1])
						mu.Unlock()
						if !equal {
							t.Fatal("exact request bytes changed across retry/reopen")
						}
					}
					metric, e := f.store.OperationalView(ctx, m.config.AgentID, now())
					if e != nil || metric.Status != "fresh" || metric.Sequence == nil || *metric.Sequence != r.Sequence || metric.Snapshot == nil || !metric.Snapshot.CollectedAt.After(previousMetricAt) {
						t.Fatal("real-authority metric view mismatch")
					}
					current, e := f.store.SystemView(ctx, m.config.AgentID, now())
					if e != nil || current.Status != "fresh" || current.Sequence == nil || *current.Sequence != r.SystemSequence || current.Latest == nil || !current.Latest.CollectedAt.After(previousSystemAt) || current.ReceivedAt == nil {
						t.Fatal("real-authority system view mismatch")
					}
					for _, section := range []systeminventory.SectionMeta{current.Latest.Services, current.Latest.Sockets} {
						if section.Coverage != systeminventory.Complete || section.Reason != systeminventory.ReasonNone || !section.CountExact || section.ObservedCount == nil || *section.ObservedCount != 1 || section.GenerationID != current.Latest.GenerationID || !section.ObservedAt.Equal(current.Latest.CollectedAt) {
							t.Fatal("positive synthetic service/socket observation missing")
						}
					}
					if positive == 1 && stage == "system" {
						mu.Lock()
						receipt := committedSystem
						mu.Unlock()
						if !current.Latest.CollectedAt.Equal(receipt.CollectedAt) || !current.ReceivedAt.Equal(receipt.ReceivedAt) {
							t.Fatal("system retry refreshed original receipt or capture time")
						}
					}
					packages, e := f.store.InventoryView(ctx, m.config.AgentID, now())
					if e != nil || packages.DeviceID != m.config.AgentID || packages.Complete == nil || packages.Complete.State != "complete" || packages.CompleteBinding.Sequence != 1 || packages.Complete.Manifest.ObservedCount != 1 || packages.Complete.Manifest.InstalledCount != 1 || packages.Complete.Manifest.Release.Fields.Target() != linuxpackages.Ubuntu2404 || packages.Failure != nil {
						t.Fatal("positive synthetic package generation missing")
					}
					if positive == 1 {
						retained = packages
					} else if !reflect.DeepEqual(packages.Complete, retained.Complete) || packages.CompleteBinding != retained.CompleteBinding {
						t.Fatal("package generation or original age changed")
					}
					metricNext, e := state.NextSequence()
					if e != nil || metricNext != r.Sequence+1 {
						t.Fatal("metric durable floor mismatch")
					}
					systemNext, e := system.state.NextSequence()
					if e != nil || systemNext != r.SystemSequence+1 {
						t.Fatal("system durable floor mismatch")
					}
					packageFloor, e := inventory.state.SequenceFloor()
					if e != nil || packageFloor != 1 {
						t.Fatal("package durable floor mismatch")
					}
					if p, e := state.Pending(); e != nil || p != nil {
						t.Fatal("acknowledged metric still pending")
					}
					if p, e := system.state.Pending(); e != nil || p != nil {
						t.Fatal("acknowledged system still pending")
					}
					if _, ok, e := inventory.state.NextWork(); e != nil || ok {
						t.Fatal("acknowledged packages still pending")
					}
					previousMetricAt, previousSystemAt = metric.Snapshot.CollectedAt, current.Latest.CollectedAt
					if positive == 2 {
						closeSenders()
						open()
					}
				}
				expectedCaptures := [3]int{4, 4, 1}
				if stage != "metrics" {
					expectedCaptures[0]++
				}
				if stage == "packages" {
					expectedCaptures[1]++
				}
				if captures != expectedCaptures {
					t.Fatal("synthetic domain capture accounting changed")
				}
				for path, before := range identity {
					raw, e := os.ReadFile(path)
					if e != nil || sha256.Sum256(raw) != before {
						t.Fatal("retry/restart replaced enrollment identity")
					}
				}
				currentAuthority, e := f.store.Get(ctx, f.snapshot.InvitationID)
				if e != nil || !reflect.DeepEqual(currentAuthority, originalAuthority) {
					t.Fatal("retry/restart changed current authority")
				}
				t.Log("synthetic proof: temporary receipt failure; exact retry across reopen; four positive real-authority observations; independent durable counters; original package age and identity retained")
			})
		}
	}
}
